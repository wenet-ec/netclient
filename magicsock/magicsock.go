package magicsock

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gravitl/netmaker/logger"
	"go4.org/mem"
	"golang.org/x/exp/slog"
	"golang.org/x/sync/singleflight"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/netmon"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	tslogger "tailscale.com/types/logger"
)

// MagicBind is a custom conn.Bind that adds DERP relay support to WireGuard.
// Peers select a region and then a relay node using consistent hashing over
// (selfKey, peerKey), so both sides independently land on the same relay with
// no coordination. Connections are pooled by selected relay node.
// DERP map refreshes are TTL-cached and coalesced across concurrent peers.
type MagicBind struct {
	privateKey key.NodePrivate
	publicKey  key.NodePublic

	// UDP sockets
	pconn4 *net.UDPConn
	pconn6 *net.UDPConn
	port   uint16

	// DERP connections are pooled by selected relay node. derpPeerRegions maps
	// a WireGuard peer to its deterministic HRW-selected relay pool.
	derpRegionsMu   sync.RWMutex
	derpRegions     map[derpPoolKey]*derpRegionClient
	derpPeerRegions map[key.NodePublic]derpPoolKey
	peerConfigMu    sync.Mutex

	// Hybrid send failures are locally observable only when both transport
	// writes fail. Keep their operational signal useful without letting a
	// broken relay flood logs for every WireGuard packet.
	hybridFailureMu      sync.Mutex
	lastHybridFailureLog map[key.NodePublic]time.Time

	// Shared receive channel — all per-peer readers funnel packets here.
	derpRecvCh chan derpReadResult

	// Peer tracking - FOUR maps for different lookup scenarios:
	// 1. endpointMap: maps public endpoint IP:Port → peer public key
	// 2. allowedIPMap: maps VPN IP → peer public key
	// 3. derpPeerByIndex: maps peer index → peer public key (DERP-only peers)
	// 4. activePeers: tracks peer keys we're actively receiving from
	mu              sync.RWMutex
	endpointMap     map[netip.AddrPort]key.NodePublic
	allowedIPMap    map[netip.Addr]key.NodePublic
	derpPeerByIndex map[int]key.NodePublic
	activePeers     map[key.NodePublic]bool
	nextPeerIndex   int

	// Context for all DERP reader goroutines (cancelled on permanent shutdown).
	derpCtx    context.Context
	derpCancel context.CancelFunc

	// Bind lifecycle
	closed    bool
	bindMutex sync.Mutex

	// Per-cycle close channel — closed by Close(), recreated by Open().
	// receiveDERP returns net.ErrClosed when this fires.
	bindCloseCh chan struct{}

	logf tslogger.Logf
}

type derpReadResult struct {
	data []byte
	src  key.NodePublic
}

type derpRegionClient struct {
	region *tailcfg.DERPRegion
	client *derphttp.Client
}

// derpPoolKey identifies the selected relay for a peer pair. NodeID is stable
// across map reorderings, so adding or removing another node does not disturb
// peers whose selected relay remains present.
type derpPoolKey struct {
	regionID int
	nodeID   string
}

// NewMagicBind creates a new MagicBind. DERP map fetching and region selection
// happen lazily when the first peer connect attempt is made.
func NewMagicBind(wgPrivateKey wgtypes.Key) (*MagicBind, error) {
	privateKey := key.NodePrivateFromRaw32(mem.B(wgPrivateKey[:]))
	publicKey := privateKey.Public()

	ctx, cancel := context.WithCancel(context.Background())

	b := &MagicBind{
		privateKey:           privateKey,
		publicKey:            publicKey,
		derpRegions:          make(map[derpPoolKey]*derpRegionClient),
		derpPeerRegions:      make(map[key.NodePublic]derpPoolKey),
		lastHybridFailureLog: make(map[key.NodePublic]time.Time),
		derpRecvCh:           make(chan derpReadResult, 64),
		endpointMap:          make(map[netip.AddrPort]key.NodePublic),
		allowedIPMap:         make(map[netip.Addr]key.NodePublic),
		derpPeerByIndex:      make(map[int]key.NodePublic),
		activePeers:          make(map[key.NodePublic]bool),
		nextPeerIndex:        1,
		bindCloseCh:          make(chan struct{}),
		derpCtx:              ctx,
		derpCancel:           cancel,
		logf:                 func(format string, args ...any) { slog.Debug(fmt.Sprintf(format, args...)) },
	}

	slog.Debug("MagicBind: created", "pubkey", publicKey.ShortString())
	return b, nil
}

// selectDERPRegion picks a region for the (self, peer) pair using rendezvous
// hashing (highest random weight / HRW) over region IDs.
//
// For each region, we compute hash(pairSeed, regionID) and pick the region
// with the highest score. This is stable under region additions/removals:
// only pairs whose chosen region disappeared will re-map; all others stay put.
//
// Crucially, we hash over region IDs (integers) rather than the list length,
// so both sides arrive at the same answer even if their fetched maps differ
// slightly in count — as long as both have the winning region ID present.
// If the winning region is absent from one side's map, that side falls back
// to whichever region scored highest among the ones it does have, and the
// retry loop will re-fetch and re-select until both converge.
func selectDERPRegion(derpMap *tailcfg.DERPMap, selfKey, peerKey key.NodePublic) *tailcfg.DERPRegion {
	// Compute a symmetric pair seed — same regardless of which side calls it
	a := selfKey.AppendTo(nil)
	b := peerKey.AppendTo(nil)
	if bytes.Compare(a, b) > 0 {
		a, b = b, a
	}
	pairSeed := fnv.New32a()
	pairSeed.Write(a)
	pairSeed.Write(b)
	seed := pairSeed.Sum32()

	// Rendezvous hash: score each region as hash(seed, regionID), pick highest
	var bestRegion *tailcfg.DERPRegion
	var bestScore uint32
	for id, r := range derpMap.Regions {
		h := fnv.New32a()
		// Write seed bytes
		h.Write([]byte{byte(seed >> 24), byte(seed >> 16), byte(seed >> 8), byte(seed)})
		// Write region ID bytes
		h.Write([]byte{byte(id >> 24), byte(id >> 16), byte(id >> 8), byte(id)})
		score := h.Sum32()
		if bestRegion == nil || score > bestScore {
			bestScore = score
			bestRegion = r
		}
	}
	return bestRegion
}

// selectDERPNode ranks all nodes in region with the same symmetric pair seed
// used for region selection. The returned region is a shallow copy whose Nodes
// are ordered from deterministic primary through deterministic fallbacks.
func selectDERPNode(region *tailcfg.DERPRegion, selfKey, peerKey key.NodePublic) (*tailcfg.DERPRegion, derpPoolKey) {
	a := selfKey.AppendTo(nil)
	b := peerKey.AppendTo(nil)
	if bytes.Compare(a, b) > 0 {
		a, b = b, a
	}
	pairSeed := fnv.New32a()
	pairSeed.Write(a)
	pairSeed.Write(b)
	seed := pairSeed.Sum32()

	type rankedNode struct {
		node  *tailcfg.DERPNode
		id    string
		score uint32
	}
	ranked := make([]rankedNode, 0, len(region.Nodes))
	for _, node := range region.Nodes {
		if node == nil {
			continue
		}
		id := derpNodeIdentity(node)
		h := fnv.New32a()
		h.Write([]byte{byte(seed >> 24), byte(seed >> 16), byte(seed >> 8), byte(seed)})
		h.Write([]byte(id))
		ranked = append(ranked, rankedNode{node: node, id: id, score: h.Sum32()})
	}
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].score != ranked[j].score {
			return ranked[i].score > ranked[j].score
		}
		return ranked[i].id < ranked[j].id
	})

	selected := *region
	selected.Nodes = make([]*tailcfg.DERPNode, len(ranked))
	for i, node := range ranked {
		selected.Nodes[i] = node.node
	}
	if len(ranked) == 0 {
		return &selected, derpPoolKey{regionID: region.RegionID}
	}
	return &selected, derpPoolKey{regionID: region.RegionID, nodeID: ranked[0].id}
}

func derpNodeIdentity(node *tailcfg.DERPNode) string {
	if node.Name != "" {
		return node.Name
	}
	return fmt.Sprintf("%s|%s|%s|%d", node.HostName, node.IPv4, node.IPv6, node.DERPPort)
}

func selectDERPPool(derpMap *tailcfg.DERPMap, selfKey, peerKey key.NodePublic) (*tailcfg.DERPRegion, derpPoolKey) {
	region := selectDERPRegion(derpMap, selfKey, peerKey)
	if region == nil {
		return nil, derpPoolKey{}
	}
	return selectDERPNode(region, selfKey, peerKey)
}

// ensurePeerDERPRegion records peerKey's HRW-selected region and starts that
// region's shared DERP client if it is not already running.
func (b *MagicBind) ensurePeerDERPRegion(peerKey key.NodePublic) {
	derpMap := LoadDERPMap()
	if len(derpMap.Regions) == 0 {
		logger.Log(0, "MagicBind: cannot select a region from an empty DERP map")
		return
	}
	region, poolKey := selectDERPPool(derpMap, b.publicKey, peerKey)
	if len(region.Nodes) == 0 {
		logger.Log(0, fmt.Sprintf("MagicBind: cannot select a relay node from DERP region %d", region.RegionID))
		return
	}

	b.derpRegionsMu.Lock()
	b.derpPeerRegions[peerKey] = poolKey
	entry, exists := b.derpRegions[poolKey]
	if !exists {
		b.derpRegions[poolKey] = &derpRegionClient{region: region}
	} else if entry.client == nil {
		// Use updated node details on the next reconnect without disrupting an
		// already healthy connection.
		entry.region = region
	}
	b.derpRegionsMu.Unlock()

	if !exists {
		go b.runDERPRegion(poolKey)
	}
}

// runDERPRegion owns one DERP connection and one Recv loop for a selected
// relay pool. Its region Nodes list begins with the pool's selected node and
// then carries the deterministic fallback order.
// derphttp.Client serializes concurrent Send calls, so all peers assigned to
// this relay pool can safely share this client while this goroutine is its sole
// receiver.
func (b *MagicBind) runDERPRegion(poolKey derpPoolKey) {
	const connectTimeout = 10 * time.Second

	slog.Debug("MagicBind: DERP relay reader started", "region_id", poolKey.regionID, "node", poolKey.nodeID)
	defer slog.Debug("MagicBind: DERP relay reader exiting", "region_id", poolKey.regionID, "node", poolKey.nodeID)

	connectAttempt := 0
	for {
		select {
		case <-b.derpCtx.Done():
			return
		default:
		}

		b.derpRegionsMu.RLock()
		entry := b.derpRegions[poolKey]
		b.derpRegionsMu.RUnlock()
		if entry == nil {
			return
		}
		region := entry.region
		connectAttempt++

		slog.Debug("MagicBind: connecting to DERP",
			"attempt", connectAttempt,
			"region_id", region.RegionID,
			"region_code", region.RegionCode,
		)
		client := derphttp.NewRegionClient(
			b.privateKey,
			b.logf,
			netmon.NewStatic(),
			func() *tailcfg.DERPRegion { return region },
		)
		connectCtx, cancel := context.WithTimeout(b.derpCtx, connectTimeout)
		err := client.Connect(connectCtx)
		cancel()
		if err != nil {
			client.Close()
			logger.Log(0, fmt.Sprintf("MagicBind: DERP connect failed (attempt=%d region=%d): %v", connectAttempt, region.RegionID, err))
			if !b.refreshDERPRegionAssignments(poolKey) {
				return
			}
			if !b.waitDERPRetry(5 * time.Second) {
				return
			}
			continue
		}

		b.derpRegionsMu.Lock()
		if current := b.derpRegions[poolKey]; current != nil {
			current.client = client
		}
		b.derpRegionsMu.Unlock()
		slog.Debug("MagicBind: DERP connected", "region_id", region.RegionID, "region_code", region.RegionCode)
		connectAttempt = 0

		for {
			msg, err := client.Recv()
			if err != nil {
				if !b.derpRegionInUse(poolKey) {
					return
				}
				logger.Log(0, fmt.Sprintf("MagicBind: DERP recv error (region=%d): %v", region.RegionID, err))
				break
			}
			switch m := msg.(type) {
			case derp.ReceivedPacket:
				result := derpReadResult{data: append([]byte(nil), m.Data...), src: m.Source}
				select {
				case b.derpRecvCh <- result:
				case <-b.derpCtx.Done():
					client.Close()
					return
				}
			case derp.ServerInfoMessage, derp.KeepAliveMessage:
				// Expected control messages.
			default:
				slog.Debug("MagicBind: unexpected DERP message type", "type", fmt.Sprintf("%T", msg))
			}
		}

		client.Close()
		b.derpRegionsMu.Lock()
		if current := b.derpRegions[poolKey]; current != nil && current.client == client {
			current.client = nil
		}
		b.derpRegionsMu.Unlock()
		if !b.refreshDERPRegionAssignments(poolKey) {
			return
		}
		if !b.waitDERPRetry(time.Second) {
			return
		}
	}
}

// refreshDERPRegionAssignments preserves the old reconnect behavior: when a
// region fails, re-run HRW selection for peers using it. If the refreshed map
// no longer selects this region, their new regional pools are started and this
// runner can retire instead of retrying a removed relay forever.
func (b *MagicBind) refreshDERPRegionAssignments(poolKey derpPoolKey) bool {
	derpMap := LoadDERPMap()
	if len(derpMap.Regions) == 0 {
		return true
	}

	poolsToStart := make([]derpPoolKey, 0)
	b.derpRegionsMu.Lock()
	for peerKey, assignedPoolKey := range b.derpPeerRegions {
		if assignedPoolKey != poolKey {
			continue
		}
		region, newPoolKey := selectDERPPool(derpMap, b.publicKey, peerKey)
		if region == nil || len(region.Nodes) == 0 {
			continue
		}
		if newPoolKey == poolKey {
			if entry := b.derpRegions[poolKey]; entry != nil && entry.client == nil {
				entry.region = region
			}
			continue
		}
		b.derpPeerRegions[peerKey] = newPoolKey
		if _, exists := b.derpRegions[newPoolKey]; !exists {
			b.derpRegions[newPoolKey] = &derpRegionClient{region: region}
			poolsToStart = append(poolsToStart, newPoolKey)
		}
	}

	stillAssigned := false
	for _, assignedPoolKey := range b.derpPeerRegions {
		if assignedPoolKey == poolKey {
			stillAssigned = true
			break
		}
	}
	if !stillAssigned {
		delete(b.derpRegions, poolKey)
	}
	b.derpRegionsMu.Unlock()

	for _, newPoolKey := range poolsToStart {
		go b.runDERPRegion(newPoolKey)
	}
	return stillAssigned
}

func (b *MagicBind) waitDERPRetry(delay time.Duration) bool {
	select {
	case <-b.derpCtx.Done():
		return false
	case <-time.After(delay):
		return true
	}
}

// UpdatePeersFromConfig updates the peer mapping from WireGuard PeerConfig.
// It also assigns every peer to its selected shared DERP region.
func (b *MagicBind) UpdatePeersFromConfig(peers []wgtypes.PeerConfig) map[string]*net.UDPAddr {
	// Peer updates replace the authoritative WireGuard peer set. Serialize the
	// complete reconciliation so an older concurrent update cannot re-add a
	// peer or regional pool removed by a newer one.
	b.peerConfigMu.Lock()
	defer b.peerConfigMu.Unlock()

	b.mu.Lock()

	b.endpointMap = make(map[netip.AddrPort]key.NodePublic)
	b.allowedIPMap = make(map[netip.Addr]key.NodePublic)
	b.derpPeerByIndex = make(map[int]key.NodePublic)
	b.nextPeerIndex = 1

	derpEndpoints := make(map[string]*net.UDPAddr)
	derpPeers := make([]key.NodePublic, 0, len(peers))

	// FIRST PASS: active peers take priority for endpoint slot ownership
	for _, peer := range peers {
		if peer.Remove {
			continue
		}
		peerKey := key.NodePublicFromRaw32(mem.B(peer.PublicKey[:]))
		if !b.activePeers[peerKey] {
			continue
		}
		isDerpMagic := false
		if peer.Endpoint != nil && peer.Endpoint.IP != nil && peer.Endpoint.Port == DerpMagicPort {
			if ip4 := peer.Endpoint.IP.To4(); ip4 != nil && ip4[0] == 127 {
				isDerpMagic = true
			}
		}
		if peer.Endpoint != nil && peer.Endpoint.IP != nil && !isDerpMagic {
			addr, ok := netip.AddrFromSlice(peer.Endpoint.IP)
			if ok {
				if addr.Is4In6() {
					addr = netip.AddrFrom4(addr.As4())
				}
				b.endpointMap[netip.AddrPortFrom(addr, uint16(peer.Endpoint.Port))] = peerKey
			}
		}
	}

	// SECOND PASS: remaining peers
	for _, peer := range peers {
		if peer.Remove {
			continue
		}
		peerKey := key.NodePublicFromRaw32(mem.B(peer.PublicKey[:]))
		peerKeyStr := peer.PublicKey.String()

		isDerpMagic := false
		if peer.Endpoint != nil && peer.Endpoint.IP != nil && peer.Endpoint.Port == DerpMagicPort {
			if ip4 := peer.Endpoint.IP.To4(); ip4 != nil && ip4[0] == 127 {
				isDerpMagic = true
			}
		}

		if peer.Endpoint != nil && peer.Endpoint.IP != nil && !isDerpMagic {
			addr, ok := netip.AddrFromSlice(peer.Endpoint.IP)
			if ok {
				if addr.Is4In6() {
					addr = netip.AddrFrom4(addr.As4())
				}
				addrPort := netip.AddrPortFrom(addr, uint16(peer.Endpoint.Port))
				if _, exists := b.endpointMap[addrPort]; !exists {
					b.endpointMap[addrPort] = peerKey
				}
			}
		} else {
			// No real endpoint — assign DERP magic endpoint
			peerIndex := b.nextPeerIndex
			b.nextPeerIndex++
			b.derpPeerByIndex[peerIndex] = peerKey
			magicIP := net.IPv4(127, byte((peerIndex>>16)&0xFF), byte((peerIndex>>8)&0xFF), byte(peerIndex&0xFF))
			derpEndpoints[peerKeyStr] = &net.UDPAddr{IP: magicIP, Port: DerpMagicPort}
		}

		for _, allowedIP := range peer.AllowedIPs {
			addr, ok := netip.AddrFromSlice(allowedIP.IP)
			if !ok {
				continue
			}
			b.allowedIPMap[addr] = peerKey
		}

		derpPeers = append(derpPeers, peerKey)
	}

	endpointCount := len(b.endpointMap)
	allowedIPCount := len(b.allowedIPMap)
	derpOnlyCount := len(b.derpPeerByIndex)
	b.mu.Unlock()

	// Retire assignments and regional clients for peers no longer present in
	// the authoritative WireGuard configuration before adding missing ones.
	// This keeps normal membership churn from leaking DERP connections.
	b.reconcileActivePeers(derpPeers)
	b.reconcileDERPPeers(derpPeers)

	// Map fetches may perform HTTP requests, so never hold b.mu while selecting
	// a region or starting its shared connection.
	for _, peerKey := range derpPeers {
		b.ensurePeerDERPRegion(peerKey)
	}

	slog.Debug("MagicBind peers updated",
		"peers", len(peers),
		"endpoints", endpointCount,
		"allowed_ips", allowedIPCount,
		"derp_only", derpOnlyCount,
	)

	return derpEndpoints
}

// reconcileDERPPeers drops DERP state for peers absent from the latest
// WireGuard configuration and closes regional clients with no remaining peers.
// Removing the entry before Close makes the region reader exit after Recv
// unblocks, rather than reconnecting an intentionally retired pool.
func (b *MagicBind) reconcileDERPPeers(peers []key.NodePublic) {
	currentPeers := make(map[key.NodePublic]struct{}, len(peers))
	for _, peerKey := range peers {
		currentPeers[peerKey] = struct{}{}
	}

	clientsToClose := make([]*derphttp.Client, 0)
	b.derpRegionsMu.Lock()
	for peerKey := range b.derpPeerRegions {
		if _, current := currentPeers[peerKey]; !current {
			delete(b.derpPeerRegions, peerKey)
		}
	}

	regionsInUse := make(map[derpPoolKey]struct{}, len(b.derpPeerRegions))
	for _, poolKey := range b.derpPeerRegions {
		regionsInUse[poolKey] = struct{}{}
	}
	for poolKey, entry := range b.derpRegions {
		if _, inUse := regionsInUse[poolKey]; inUse {
			continue
		}
		delete(b.derpRegions, poolKey)
		if entry.client != nil {
			clientsToClose = append(clientsToClose, entry.client)
		}
	}
	b.derpRegionsMu.Unlock()

	for _, client := range clientsToClose {
		client.Close()
	}
}

func (b *MagicBind) reconcileActivePeers(peers []key.NodePublic) {
	currentPeers := make(map[key.NodePublic]struct{}, len(peers))
	for _, peerKey := range peers {
		currentPeers[peerKey] = struct{}{}
	}

	b.mu.Lock()
	for peerKey := range b.activePeers {
		if _, current := currentPeers[peerKey]; !current {
			delete(b.activePeers, peerKey)
		}
	}
	b.mu.Unlock()
}

func (b *MagicBind) derpRegionInUse(poolKey derpPoolKey) bool {
	b.derpRegionsMu.RLock()
	_, exists := b.derpRegions[poolKey]
	b.derpRegionsMu.RUnlock()
	return exists
}

// Open implements conn.Bind.Open
func (b *MagicBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.bindMutex.Lock()
	defer b.bindMutex.Unlock()

	b.closed = false
	b.bindCloseCh = make(chan struct{})

	addr4 := &net.UDPAddr{IP: net.IPv4zero, Port: int(port)}
	var err error
	for attempt := 0; attempt < 5; attempt++ {
		b.pconn4, err = net.ListenUDP("udp4", addr4)
		if err == nil {
			break
		}
		time.Sleep(time.Duration(attempt+1) * 200 * time.Millisecond)
	}
	if err != nil {
		// Requested port is unavailable (e.g. two interfaces both want 443).
		// Fall back to a kernel-assigned ephemeral port so DERP still works.
		logger.Log(0, fmt.Sprintf("MagicBind: port %d unavailable (%v), falling back to ephemeral port", port, err))
		addr4 = &net.UDPAddr{IP: net.IPv4zero, Port: 0}
		b.pconn4, err = net.ListenUDP("udp4", addr4)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to open IPv4 socket: %w", err)
		}
	}

	if port == 0 {
		port = uint16(b.pconn4.LocalAddr().(*net.UDPAddr).Port)
	}
	b.port = port

	addr6 := &net.UDPAddr{IP: net.IPv6zero, Port: int(port)}
	b.pconn6, _ = net.ListenUDP("udp6", addr6)

	fns := []conn.ReceiveFunc{b.receiveIPv4}
	if b.pconn6 != nil {
		fns = append(fns, b.receiveIPv6)
	}
	fns = append(fns, b.receiveDERP)
	return fns, port, nil
}

// receiveIPv4 implements conn.ReceiveFunc for IPv4. MagicBind deliberately
// advertises a batch size of one, so each receive function fills slot zero.
func (b *MagicBind) receiveIPv4(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	b.bindMutex.Lock()
	pconn := b.pconn4
	closed := b.closed
	b.bindMutex.Unlock()

	if closed || pconn == nil {
		return 0, net.ErrClosed
	}
	if len(packets) == 0 || len(sizes) == 0 || len(eps) == 0 {
		return 0, fmt.Errorf("MagicBind: receive buffers are empty")
	}
	n, addr, err := pconn.ReadFromUDPAddrPort(packets[0])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	eps[0] = b.createEndpointForReceive(addr)
	return 1, nil
}

// receiveIPv6 implements conn.ReceiveFunc for IPv6
func (b *MagicBind) receiveIPv6(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	b.bindMutex.Lock()
	pconn := b.pconn6
	closed := b.closed
	b.bindMutex.Unlock()

	if closed || pconn == nil {
		return 0, net.ErrClosed
	}
	if len(packets) == 0 || len(sizes) == 0 || len(eps) == 0 {
		return 0, fmt.Errorf("MagicBind: receive buffers are empty")
	}
	n, addr, err := pconn.ReadFromUDPAddrPort(packets[0])
	if err != nil {
		return 0, err
	}
	sizes[0] = n
	eps[0] = b.createEndpointForReceive(addr)
	return 1, nil
}

// createEndpointForReceive looks up the peer key for an incoming UDP address
func (b *MagicBind) createEndpointForReceive(addr netip.AddrPort) conn.Endpoint {
	b.mu.RLock()
	peerKey, found := b.endpointMap[addr]
	if !found {
		for epAddr, pk := range b.endpointMap {
			if epAddr.Addr() == addr.Addr() {
				peerKey = pk
				found = true
				break
			}
		}
	}
	b.mu.RUnlock()

	if found {
		return &hybridEndpoint{udpAddr: addr, peerKey: peerKey}
	}
	return &udpEndpoint{addr: addr}
}

// receiveDERP implements conn.ReceiveFunc for DERP.
// All region reader goroutines funnel packets into the shared derpRecvCh.
func (b *MagicBind) receiveDERP(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	b.bindMutex.Lock()
	closeCh := b.bindCloseCh
	b.bindMutex.Unlock()
	if len(packets) == 0 || len(sizes) == 0 || len(eps) == 0 {
		return 0, fmt.Errorf("MagicBind: receive buffers are empty")
	}

	for {
		select {
		case result := <-b.derpRecvCh:
			if len(result.data) == 0 {
				continue
			}
			n := copy(packets[0], result.data)
			b.learnPeerFromDERP(result.src)
			sizes[0] = n
			eps[0] = &derpEndpoint{peerKey: result.src}
			return 1, nil
		case <-closeCh:
			return 0, net.ErrClosed
		case <-b.derpCtx.Done():
			return 0, net.ErrClosed
		}
	}
}

// learnPeerFromDERP marks the peer as active when we receive a packet from it
func (b *MagicBind) learnPeerFromDERP(peerKey key.NodePublic) {
	b.mu.Lock()
	b.activePeers[peerKey] = true
	b.mu.Unlock()
}

// Send implements conn.Bind.Send. BatchSize reports one, but accepting a
// slice here keeps the bind correct if a caller supplies multiple packets.
func (b *MagicBind) Send(packets [][]byte, ep conn.Endpoint) error {
	for _, packet := range packets {
		var err error
		switch e := ep.(type) {
		case *hybridEndpoint:
			err = b.sendHybrid(packet, e)
		case *udpEndpoint:
			err = b.sendUDP(packet, e.addr)
		case *derpEndpoint:
			err = b.sendDERP(packet, e.peerKey)
		default:
			return fmt.Errorf("unknown endpoint type: %T", ep)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// sendHybrid sends via UDP and also via DERP for NAT traversal.
// Errors from the DERP leg are logged but don't fail the send — UDP may still
// land. Without this log, a dead DERP path is invisible when UDP also fails.
func (b *MagicBind) sendHybrid(buff []byte, ep *hybridEndpoint) error {
	udpErr := b.sendUDP(buff, ep.udpAddr)

	if !ep.peerKey.IsZero() {
		derpErr := b.sendDERP(buff, ep.peerKey)
		if derpErr != nil {
			slog.Debug("MagicBind: hybrid DERP send failed", "peer", ep.peerKey.ShortString(), "error", derpErr)
			if udpErr != nil {
				b.logHybridFailure(ep.peerKey, udpErr, derpErr)
			}
		}
	}

	if udpErr != nil && ep.peerKey.IsZero() {
		return udpErr
	}
	return nil
}

const hybridFailureLogInterval = 30 * time.Second

// logHybridFailure makes the otherwise silent "both local transport writes
// failed" condition visible, while preserving WireGuard's asynchronous loss
// handling and avoiding a log line for every packet during an outage.
func (b *MagicBind) logHybridFailure(peerKey key.NodePublic, udpErr, derpErr error) {
	now := time.Now()
	b.hybridFailureMu.Lock()
	lastLogged := b.lastHybridFailureLog[peerKey]
	if now.Sub(lastLogged) < hybridFailureLogInterval {
		b.hybridFailureMu.Unlock()
		return
	}
	b.lastHybridFailureLog[peerKey] = now
	b.hybridFailureMu.Unlock()

	logger.Log(0, fmt.Sprintf(
		"MagicBind: hybrid send failed (peer=%s udp_error=%v derp_error=%v)",
		peerKey.ShortString(), udpErr, derpErr,
	))
}

func (b *MagicBind) sendUDP(buff []byte, addr netip.AddrPort) error {
	b.bindMutex.Lock()
	var pconn *net.UDPConn
	if addr.Addr().Is4() {
		pconn = b.pconn4
	} else {
		pconn = b.pconn6
	}
	closed := b.closed
	b.bindMutex.Unlock()

	if closed {
		return net.ErrClosed
	}
	if pconn == nil {
		return fmt.Errorf("no socket for address family")
	}
	_, err := pconn.WriteToUDPAddrPort(buff, addr)
	return err
}

func (b *MagicBind) sendDERP(buff []byte, peerKey key.NodePublic) error {
	client, found := b.derpClientForPeer(peerKey)
	if !found || client == nil {
		return fmt.Errorf("DERP client not ready for peer %s", peerKey.ShortString())
	}
	if err := client.Send(peerKey, buff); err != nil {
		return fmt.Errorf("DERP send failed: %w", err)
	}
	return nil
}

func (b *MagicBind) derpClientForPeer(peerKey key.NodePublic) (*derphttp.Client, bool) {
	b.derpRegionsMu.RLock()
	poolKey, found := b.derpPeerRegions[peerKey]
	entry := b.derpRegions[poolKey]
	var client *derphttp.Client
	if entry != nil {
		client = entry.client
	}
	b.derpRegionsMu.RUnlock()
	return client, found
}

// DerpMagicPort is the magic port used to signal DERP-only endpoints.
// The peer index is encoded in the 127.x.x.x address.
const DerpMagicPort = 12345

// ParseEndpoint implements conn.Bind.ParseEndpoint
func (b *MagicBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	addr, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, fmt.Errorf("failed to parse endpoint: %s", s)
	}

	// DERP magic endpoint (127.x.x.x:12345) — peer index encoded in IP
	if addr.Port() == DerpMagicPort && addr.Addr().Is4() {
		ipBytes := addr.Addr().As4()
		if ipBytes[0] == 127 {
			peerIndex := int(ipBytes[1])<<16 | int(ipBytes[2])<<8 | int(ipBytes[3])
			b.mu.RLock()
			peerKey, found := b.derpPeerByIndex[peerIndex]
			b.mu.RUnlock()
			if found {
				return &derpEndpoint{peerKey: peerKey}, nil
			}
		}
	}

	b.mu.RLock()
	peerKey, found := b.endpointMap[addr]
	b.mu.RUnlock()

	if !found {
		return &udpEndpoint{addr: addr}, nil
	}
	return &hybridEndpoint{udpAddr: addr, peerKey: peerKey}, nil
}

// SetMark implements conn.Bind.SetMark
func (b *MagicBind) SetMark(mark uint32) error {
	return nil
}

// BatchSize implements conn.Bind. MagicBind performs one UDP or DERP read at
// a time; WireGuard will therefore provide at most one buffer to ReceiveFunc
// and Send.
func (b *MagicBind) BatchSize() int {
	return 1
}

// Close implements conn.Bind.Close.
// Closes UDP sockets (unblocks receive goroutines) and signals receiveDERP
// to exit this bind cycle. Per-peer DERP reader goroutines persist across
// Close/Open cycles — they are only stopped when derpCtx is cancelled.
func (b *MagicBind) Close() error {
	b.bindMutex.Lock()
	defer b.bindMutex.Unlock()

	if b.pconn4 != nil {
		b.pconn4.Close()
		b.pconn4 = nil
	}
	if b.pconn6 != nil {
		b.pconn6.Close()
		b.pconn6 = nil
	}

	if b.bindCloseCh != nil {
		select {
		case <-b.bindCloseCh:
		default:
			close(b.bindCloseCh)
		}
	}

	return nil
}

// EnsureOpen re-opens UDP sockets if they were closed by a spurious BindUpdate.
func (b *MagicBind) EnsureOpen() {
	b.bindMutex.Lock()
	defer b.bindMutex.Unlock()

	if b.pconn4 != nil {
		return
	}

	port := b.port
	addr4 := &net.UDPAddr{IP: net.IPv4zero, Port: int(port)}
	var err error
	b.pconn4, err = net.ListenUDP("udp4", addr4)
	if err != nil {
		logger.Log(0, "MagicBind: EnsureOpen failed to reopen IPv4 socket:", err.Error())
		return
	}

	if port == 0 {
		port = uint16(b.pconn4.LocalAddr().(*net.UDPAddr).Port)
		b.port = port
	}

	addr6 := &net.UDPAddr{IP: net.IPv6zero, Port: int(port)}
	b.pconn6, _ = net.ListenUDP("udp6", addr6)
	b.closed = false
}

// Endpoint implementations

type udpEndpoint struct {
	addr netip.AddrPort
}

func (e *udpEndpoint) ClearSrc() {}
func (e *udpEndpoint) DstToBytes() []byte {
	b, _ := e.addr.MarshalBinary()
	return b
}
func (e *udpEndpoint) DstIP() netip.Addr   { return e.addr.Addr() }
func (e *udpEndpoint) SrcIP() netip.Addr   { return e.addr.Addr() }
func (e *udpEndpoint) SrcToString() string { return e.addr.String() }
func (e *udpEndpoint) DstToString() string { return e.addr.String() }

type derpEndpoint struct {
	peerKey key.NodePublic
}

func (e *derpEndpoint) ClearSrc()          {}
func (e *derpEndpoint) DstToBytes() []byte { return e.peerKey.AppendTo(nil) }
func (e *derpEndpoint) DstIP() netip.Addr  { return tailcfg.DerpMagicIPAddr }
func (e *derpEndpoint) SrcIP() netip.Addr  { return tailcfg.DerpMagicIPAddr }

// SrcToString and DstToString must return a valid net.ResolveUDPAddr-parseable
// string. Tailscale's ShortString() wraps in [] which breaks parsing.
func (e *derpEndpoint) SrcToString() string { return fmt.Sprintf("127.0.0.1:%d", DerpMagicPort) }
func (e *derpEndpoint) DstToString() string { return fmt.Sprintf("127.0.0.1:%d", DerpMagicPort) }

type hybridEndpoint struct {
	udpAddr netip.AddrPort
	peerKey key.NodePublic
}

func (e *hybridEndpoint) ClearSrc() {}
func (e *hybridEndpoint) DstToBytes() []byte {
	b, _ := e.udpAddr.MarshalBinary()
	return b
}
func (e *hybridEndpoint) DstIP() netip.Addr   { return e.udpAddr.Addr() }
func (e *hybridEndpoint) SrcIP() netip.Addr   { return e.udpAddr.Addr() }
func (e *hybridEndpoint) SrcToString() string { return e.udpAddr.String() }
func (e *hybridEndpoint) DstToString() string { return e.udpAddr.String() }

// hardcodedDERPMap is the last-resort fallback used only when:
//   - Tailscale's live map fetch fails, AND
//   - No prior successful map has been cached in memory
//
// Sourced from https://login.tailscale.com/derpmap/default and verified
// unchanged on 2026-09-01 against the live map (28 regions / 88 nodes).
func hardcodedDERPMap() *tailcfg.DERPMap {
	return &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID: 1, RegionCode: "nyc", RegionName: "New York City", Latitude: 40.7128, Longitude: -74.006,
				Nodes: []*tailcfg.DERPNode{
					{Name: "1f", RegionID: 1, HostName: "derp1f.tailscale.com", IPv4: "199.38.181.104", IPv6: "2607:f740:f::bc", CanPort80: true},
					{Name: "1g", RegionID: 1, HostName: "derp1g.tailscale.com", IPv4: "209.177.145.120", IPv6: "2607:f740:f::3eb", CanPort80: true},
					{Name: "1h", RegionID: 1, HostName: "derp1h.tailscale.com", IPv4: "199.38.181.93", IPv6: "2607:f740:f::afd", CanPort80: true},
					{Name: "1i", RegionID: 1, HostName: "derp1i.tailscale.com", IPv4: "199.38.181.103", IPv6: "2607:f740:f::e19", CanPort80: true},
				},
			},
			2: {
				RegionID: 2, RegionCode: "sfo", RegionName: "San Francisco", Latitude: 37.7775, Longitude: -122.416389,
				Nodes: []*tailcfg.DERPNode{
					{Name: "2d", RegionID: 2, HostName: "derp2d.tailscale.com", IPv4: "192.73.252.65", IPv6: "2607:f740:0:3f::287", CanPort80: true},
					{Name: "2e", RegionID: 2, HostName: "derp2e.tailscale.com", IPv4: "192.73.252.134", IPv6: "2607:f740:0:3f::44c", CanPort80: true},
					{Name: "2f", RegionID: 2, HostName: "derp2f.tailscale.com", IPv4: "208.111.34.178", IPv6: "2607:f740:0:3f::f4", CanPort80: true},
				},
			},
			3: {
				RegionID: 3, RegionCode: "sin", RegionName: "Singapore", Latitude: 1.3521, Longitude: 103.8198,
				Nodes: []*tailcfg.DERPNode{
					{Name: "3e", RegionID: 3, HostName: "derp3e.tailscale.com", IPv4: "172.237.72.43", IPv6: "2600:3c15::2000:6cff:fee4:d799", CanPort80: true},
					{Name: "3f", RegionID: 3, HostName: "derp3f.tailscale.com", IPv4: "172.237.72.8", IPv6: "2600:3c15::2000:53ff:fe48:a668", CanPort80: true},
					{Name: "3g", RegionID: 3, HostName: "derp3g.tailscale.com", IPv4: "172.237.72.79", IPv6: "2600:3c15::2000:adff:fe08:6fab", CanPort80: true},
					{Name: "3h", RegionID: 3, HostName: "derp3h.tailscale.com", IPv4: "172.237.66.30", IPv6: "2600:3c15::2000:3dff:fe44:50aa", CanPort80: true},
				},
			},
			4: {
				RegionID: 4, RegionCode: "fra", RegionName: "Frankfurt", Latitude: 50.1109, Longitude: 8.6821,
				Nodes: []*tailcfg.DERPNode{
					{Name: "4f", RegionID: 4, HostName: "derp4f.tailscale.com", IPv4: "185.40.234.219", IPv6: "2a00:dd80:20::a25", CanPort80: true},
					{Name: "4g", RegionID: 4, HostName: "derp4g.tailscale.com", IPv4: "185.40.234.113", IPv6: "2a00:dd80:20::8f", CanPort80: true},
					{Name: "4h", RegionID: 4, HostName: "derp4h.tailscale.com", IPv4: "185.40.234.77", IPv6: "2a00:dd80:20::bcf", CanPort80: true},
					{Name: "4i", RegionID: 4, HostName: "derp4i.tailscale.com", IPv4: "185.40.234.53", IPv6: "2a00:dd80:20::8a6", CanPort80: true},
					{Name: "4j", RegionID: 4, HostName: "derp4j.tailscale.com", IPv4: "185.40.234.176", IPv6: "2a00:dd80:20::e67", CanPort80: true},
				},
			},
			5: {
				RegionID: 5, RegionCode: "syd", RegionName: "Sydney", Latitude: -33.867778, Longitude: 151.21,
				Nodes: []*tailcfg.DERPNode{
					{Name: "5e", RegionID: 5, HostName: "derp5e.tailscale.com", IPv4: "172.105.179.230", IPv6: "2400:8907::2000:ceff:fe8d:4f4e", CanPort80: true},
					{Name: "5f", RegionID: 5, HostName: "derp5f.tailscale.com", IPv4: "172.105.166.103", IPv6: "2400:8907::2000:ccff:fe1f:80da", CanPort80: true},
					{Name: "5g", RegionID: 5, HostName: "derp5g.tailscale.com", IPv4: "172.105.169.57", IPv6: "2400:8907::2000:2fff:fea7:57f4", CanPort80: true},
				},
			},
			6: {
				RegionID: 6, RegionCode: "blr", RegionName: "Bengaluru", Latitude: 12.9716, Longitude: 77.5946,
				Nodes: []*tailcfg.DERPNode{
					{Name: "6a", RegionID: 6, HostName: "derp6.tailscale.com", IPv4: "68.183.90.120", IPv6: "2400:6180:100:d0::982:d001", CanPort80: true},
				},
			},
			7: {
				RegionID: 7, RegionCode: "tok", RegionName: "Tokyo", Latitude: 35.6764, Longitude: 139.65,
				Nodes: []*tailcfg.DERPNode{
					{Name: "7e", RegionID: 7, HostName: "derp7e.tailscale.com", IPv4: "172.238.6.180", IPv6: "2600:3c18::2000:60ff:fe0f:6e83", CanPort80: true},
					{Name: "7f", RegionID: 7, HostName: "derp7f.tailscale.com", IPv4: "172.238.6.34", IPv6: "2600:3c18::2000:acff:fe8e:3ed5", CanPort80: true},
					{Name: "7g", RegionID: 7, HostName: "derp7g.tailscale.com", IPv4: "172.238.6.179", IPv6: "2600:3c18::2000:3fff:fe80:3ebd", CanPort80: true},
					{Name: "7h", RegionID: 7, HostName: "derp7h.tailscale.com", IPv4: "172.237.28.183", IPv6: "2600:3c18::2000:b1ff:fea9:4560", CanPort80: true},
				},
			},
			8: {
				RegionID: 8, RegionCode: "lhr", RegionName: "London", Latitude: 51.5072, Longitude: 0.1276,
				Nodes: []*tailcfg.DERPNode{
					{Name: "8e", RegionID: 8, HostName: "derp8e.tailscale.com", IPv4: "176.58.92.144", IPv6: "2a00:dd80:3a::b33", CanPort80: true},
					{Name: "8f", RegionID: 8, HostName: "derp8f.tailscale.com", IPv4: "176.58.88.183", IPv6: "2a00:dd80:3a::dfa", CanPort80: true},
					{Name: "8g", RegionID: 8, HostName: "derp8g.tailscale.com", IPv4: "176.58.92.254", IPv6: "2a00:dd80:3a::ed", CanPort80: true},
				},
			},
			9: {
				RegionID: 9, RegionCode: "dfw", RegionName: "Dallas", Latitude: 32.779167, Longitude: -96.808889,
				Nodes: []*tailcfg.DERPNode{
					{Name: "9d", RegionID: 9, HostName: "derp9d.tailscale.com", IPv4: "209.177.156.94", IPv6: "2607:f740:100::c05", CanPort80: true},
					{Name: "9e", RegionID: 9, HostName: "derp9e.tailscale.com", IPv4: "192.73.248.83", IPv6: "2607:f740:100::359", CanPort80: true},
					{Name: "9f", RegionID: 9, HostName: "derp9f.tailscale.com", IPv4: "209.177.156.197", IPv6: "2607:f740:100::cad", CanPort80: true},
				},
			},
			10: {
				RegionID: 10, RegionCode: "sea", RegionName: "Seattle", Latitude: 47.609722, Longitude: -122.333056,
				Nodes: []*tailcfg.DERPNode{
					{Name: "10b", RegionID: 10, HostName: "derp10b.tailscale.com", IPv4: "192.73.240.161", IPv6: "2607:f740:14::61c", CanPort80: true},
					{Name: "10c", RegionID: 10, HostName: "derp10c.tailscale.com", IPv4: "192.73.240.121", IPv6: "2607:f740:14::40c", CanPort80: true},
					{Name: "10d", RegionID: 10, HostName: "derp10d.tailscale.com", IPv4: "192.73.240.132", IPv6: "2607:f740:14::500", CanPort80: true},
				},
			},
			11: {
				RegionID: 11, RegionCode: "sao", RegionName: "São Paulo", Latitude: -23.55, Longitude: -46.633333,
				Nodes: []*tailcfg.DERPNode{
					{Name: "11e", RegionID: 11, HostName: "derp11e.tailscale.com", IPv4: "172.237.61.194", IPv6: "2600:3c0d::2000:d2ff:fe43:1790", CanPort80: true},
					{Name: "11f", RegionID: 11, HostName: "derp11f.tailscale.com", IPv4: "172.237.61.197", IPv6: "2600:3c0d::2000:3bff:fe44:6166", CanPort80: true},
					{Name: "11g", RegionID: 11, HostName: "derp11g.tailscale.com", IPv4: "172.237.61.190", IPv6: "2600:3c0d::2000:62ff:febe:2e67", CanPort80: true},
				},
			},
			12: {
				RegionID: 12, RegionCode: "ord", RegionName: "Chicago", Latitude: 41.881944, Longitude: -87.627778,
				Nodes: []*tailcfg.DERPNode{
					{Name: "12d", RegionID: 12, HostName: "derp12d.tailscale.com", IPv4: "209.177.158.246", IPv6: "2607:f740:e::811", CanPort80: true},
					{Name: "12e", RegionID: 12, HostName: "derp12e.tailscale.com", IPv4: "209.177.158.15", IPv6: "2607:f740:e::b17", CanPort80: true},
					{Name: "12f", RegionID: 12, HostName: "derp12f.tailscale.com", IPv4: "199.38.182.118", IPv6: "2607:f740:e::4c8", CanPort80: true},
				},
			},
			13: {
				RegionID: 13, RegionCode: "den", RegionName: "Denver", Latitude: 39.7392, Longitude: -104.9849,
				Nodes: []*tailcfg.DERPNode{
					{Name: "13b", RegionID: 13, HostName: "derp13b.tailscale.com", IPv4: "192.73.242.187", IPv6: "2607:f740:16::640", CanPort80: true},
					{Name: "13c", RegionID: 13, HostName: "derp13c.tailscale.com", IPv4: "192.73.242.28", IPv6: "2607:f740:16::5c", CanPort80: true},
					{Name: "13d", RegionID: 13, HostName: "derp13d.tailscale.com", IPv4: "192.73.242.204", IPv6: "2607:f740:16::c23", CanPort80: true},
				},
			},
			14: {
				RegionID: 14, RegionCode: "ams", RegionName: "Amsterdam", Latitude: 52.372778, Longitude: 4.893611,
				Nodes: []*tailcfg.DERPNode{
					{Name: "14b", RegionID: 14, HostName: "derp14b.tailscale.com", IPv4: "176.58.93.248", IPv6: "2a00:dd80:3c::807", CanPort80: true},
					{Name: "14c", RegionID: 14, HostName: "derp14c.tailscale.com", IPv4: "176.58.93.147", IPv6: "2a00:dd80:3c::b09", CanPort80: true},
					{Name: "14d", RegionID: 14, HostName: "derp14d.tailscale.com", IPv4: "176.58.93.154", IPv6: "2a00:dd80:3c::3d5", CanPort80: true},
				},
			},
			15: {
				RegionID: 15, RegionCode: "jnb", RegionName: "Johannesburg", Latitude: -26.204444, Longitude: 28.045556,
				Nodes: []*tailcfg.DERPNode{
					{Name: "15b", RegionID: 15, HostName: "derp15b.tailscale.com", IPv4: "102.67.165.90", IPv6: "2c0f:edb0:0:10::963", CanPort80: true},
					{Name: "15c", RegionID: 15, HostName: "derp15c.tailscale.com", IPv4: "102.67.165.185", IPv6: "2c0f:edb0:0:10::b59", CanPort80: true},
					{Name: "15d", RegionID: 15, HostName: "derp15d.tailscale.com", IPv4: "102.67.165.36", IPv6: "2c0f:edb0:0:10::599", CanPort80: true},
				},
			},
			16: {
				RegionID: 16, RegionCode: "mia", RegionName: "Miami", Latitude: 25.78, Longitude: -80.21,
				Nodes: []*tailcfg.DERPNode{
					{Name: "16b", RegionID: 16, HostName: "derp16b.tailscale.com", IPv4: "192.73.243.135", IPv6: "2607:f740:17::476", CanPort80: true},
					{Name: "16c", RegionID: 16, HostName: "derp16c.tailscale.com", IPv4: "192.73.243.229", IPv6: "2607:f740:17::4e4", CanPort80: true},
					{Name: "16d", RegionID: 16, HostName: "derp16d.tailscale.com", IPv4: "192.73.243.141", IPv6: "2607:f740:17::475", CanPort80: true},
				},
			},
			17: {
				RegionID: 17, RegionCode: "lax", RegionName: "Los Angeles", Latitude: 34.05, Longitude: -118.25,
				Nodes: []*tailcfg.DERPNode{
					{Name: "17b", RegionID: 17, HostName: "derp17b.tailscale.com", IPv4: "192.73.244.245", IPv6: "2607:f740:c::646", CanPort80: true},
					{Name: "17c", RegionID: 17, HostName: "derp17c.tailscale.com", IPv4: "208.111.40.12", IPv6: "2607:f740:c::10", CanPort80: true},
					{Name: "17d", RegionID: 17, HostName: "derp17d.tailscale.com", IPv4: "208.111.40.216", IPv6: "2607:f740:c::e1b", CanPort80: true},
				},
			},
			18: {
				RegionID: 18, RegionCode: "par", RegionName: "Paris", Latitude: 48.856667, Longitude: 2.352222,
				Nodes: []*tailcfg.DERPNode{
					{Name: "18b", RegionID: 18, HostName: "derp18b.tailscale.com", IPv4: "176.58.90.147", IPv6: "2a00:dd80:3e::363", CanPort80: true},
					{Name: "18c", RegionID: 18, HostName: "derp18c.tailscale.com", IPv4: "176.58.90.207", IPv6: "2a00:dd80:3e::c19", CanPort80: true},
					{Name: "18d", RegionID: 18, HostName: "derp18d.tailscale.com", IPv4: "176.58.90.104", IPv6: "2a00:dd80:3e::f2e", CanPort80: true},
				},
			},
			19: {
				RegionID: 19, RegionCode: "mad", RegionName: "Madrid", Latitude: 40.416944, Longitude: -3.703333,
				Nodes: []*tailcfg.DERPNode{
					{Name: "19b", RegionID: 19, HostName: "derp19b.tailscale.com", IPv4: "45.159.97.144", IPv6: "2a00:dd80:14:10::335", CanPort80: true},
					{Name: "19c", RegionID: 19, HostName: "derp19c.tailscale.com", IPv4: "45.159.97.61", IPv6: "2a00:dd80:14:10::20", CanPort80: true},
					{Name: "19d", RegionID: 19, HostName: "derp19d.tailscale.com", IPv4: "45.159.97.233", IPv6: "2a00:dd80:14:10::34a", CanPort80: true},
				},
			},
			20: {
				RegionID: 20, RegionCode: "hkg", RegionName: "Hong Kong", Latitude: 22.3193, Longitude: 114.1694,
				Nodes: []*tailcfg.DERPNode{
					{Name: "20b", RegionID: 20, HostName: "derp20b.tailscale.com", IPv4: "103.6.84.152", IPv6: "2403:2500:8000:1::ef6", CanPort80: true},
					{Name: "20c", RegionID: 20, HostName: "derp20c.tailscale.com", IPv4: "205.147.105.30", IPv6: "2403:2500:8000:1::5fb", CanPort80: true},
					{Name: "20d", RegionID: 20, HostName: "derp20d.tailscale.com", IPv4: "205.147.105.78", IPv6: "2403:2500:8000:1::e9a", CanPort80: true},
				},
			},
			21: {
				RegionID: 21, RegionCode: "tor", RegionName: "Toronto", Latitude: 43.741667, Longitude: -79.373333,
				Nodes: []*tailcfg.DERPNode{
					{Name: "21b", RegionID: 21, HostName: "derp21b.tailscale.com", IPv4: "162.248.221.199", IPv6: "2607:f740:50::1d1", CanPort80: true},
					{Name: "21c", RegionID: 21, HostName: "derp21c.tailscale.com", IPv4: "162.248.221.215", IPv6: "2607:f740:50::f10", CanPort80: true},
					{Name: "21d", RegionID: 21, HostName: "derp21d.tailscale.com", IPv4: "162.248.221.248", IPv6: "2607:f740:50::ca4", CanPort80: true},
				},
			},
			22: {
				RegionID: 22, RegionCode: "waw", RegionName: "Warsaw", Latitude: 52.23, Longitude: 21.011111,
				Nodes: []*tailcfg.DERPNode{
					{Name: "22b", RegionID: 22, HostName: "derp22b.tailscale.com", IPv4: "45.159.98.196", IPv6: "2a00:dd80:40:100::316", CanPort80: true},
					{Name: "22c", RegionID: 22, HostName: "derp22c.tailscale.com", IPv4: "45.159.98.253", IPv6: "2a00:dd80:40:100::3f", CanPort80: true},
					{Name: "22d", RegionID: 22, HostName: "derp22d.tailscale.com", IPv4: "45.159.98.145", IPv6: "2a00:dd80:40:100::211", CanPort80: true},
				},
			},
			23: {
				RegionID: 23, RegionCode: "dbi", RegionName: "Dubai", Latitude: 25.263056, Longitude: 55.297222,
				Nodes: []*tailcfg.DERPNode{
					{Name: "23b", RegionID: 23, HostName: "derp23b.tailscale.com", IPv4: "185.34.3.232", IPv6: "2a00:dd80:3f:100::76f", CanPort80: true},
					{Name: "23c", RegionID: 23, HostName: "derp23c.tailscale.com", IPv4: "185.34.3.207", IPv6: "2a00:dd80:3f:100::a50", CanPort80: true},
					{Name: "23d", RegionID: 23, HostName: "derp23d.tailscale.com", IPv4: "185.34.3.75", IPv6: "2a00:dd80:3f:100::97e", CanPort80: true},
				},
			},
			24: {
				RegionID: 24, RegionCode: "hnl", RegionName: "Honolulu", Latitude: 21.306944, Longitude: -157.858333,
				Nodes: []*tailcfg.DERPNode{
					{Name: "24b", RegionID: 24, HostName: "derp24b.tailscale.com", IPv4: "208.83.234.151", IPv6: "2001:19f0:c000:c586:5400:04ff:fe26:2ba6", CanPort80: true},
					{Name: "24c", RegionID: 24, HostName: "derp24c.tailscale.com", IPv4: "208.83.233.233", IPv6: "2001:19f0:c000:c591:5400:04ff:fe26:2c5f", CanPort80: true},
					{Name: "24d", RegionID: 24, HostName: "derp24d.tailscale.com", IPv4: "208.72.155.133", IPv6: "2001:19f0:c000:c564:5400:04ff:fe26:2ba8", CanPort80: true},
				},
			},
			25: {
				RegionID: 25, RegionCode: "nai", RegionName: "Nairobi", Latitude: -1.286389, Longitude: 36.817222,
				Nodes: []*tailcfg.DERPNode{
					{Name: "25b", RegionID: 25, HostName: "derp25b.tailscale.com", IPv4: "102.67.167.245", IPv6: "2c0f:edb0:2000:1::2e9", CanPort80: true},
					{Name: "25c", RegionID: 25, HostName: "derp25c.tailscale.com", IPv4: "102.67.167.37", IPv6: "2c0f:edb0:2000:1::2c7", CanPort80: true},
					{Name: "25d", RegionID: 25, HostName: "derp25d.tailscale.com", IPv4: "102.67.167.188", IPv6: "2c0f:edb0:2000:1::188", CanPort80: true},
				},
			},
			26: {
				RegionID: 26, RegionCode: "nue", RegionName: "Nuremberg", Latitude: 49.453889, Longitude: 11.0775,
				Nodes: []*tailcfg.DERPNode{
					{Name: "26b", RegionID: 26, HostName: "derp26b.tailscale.com", IPv4: "167.235.72.200", IPv6: "2a01:4f8:1c1c:47b6::1", CanPort80: true},
					{Name: "26c", RegionID: 26, HostName: "derp26c.tailscale.com", IPv4: "49.12.193.137", IPv6: "2a01:4f8:1c1c:5c70::1", CanPort80: true},
					{Name: "26d", RegionID: 26, HostName: "derp26d.tailscale.com", IPv4: "49.13.204.141", IPv6: "2a01:4f8:1c0c:7d06::1", CanPort80: true},
				},
			},
			27: {
				RegionID: 27, RegionCode: "iad", RegionName: "Ashburn", Latitude: 39.03, Longitude: -77.471111,
				Nodes: []*tailcfg.DERPNode{
					{Name: "27b", RegionID: 27, HostName: "derp27b.tailscale.com", IPv4: "5.161.218.233", IPv6: "2a01:4ff:f0:3db9::1", CanPort80: true},
					{Name: "27c", RegionID: 27, HostName: "derp27c.tailscale.com", IPv4: "178.156.152.91", IPv6: "2a01:4ff:f0:3913::1", CanPort80: true},
					{Name: "27d", RegionID: 27, HostName: "derp27d.tailscale.com", IPv4: "178.156.152.106", IPv6: "2a01:4ff:f0:3c8e::1", CanPort80: true},
					{Name: "27e", RegionID: 27, HostName: "derp27e.tailscale.com", IPv4: "178.156.134.232", IPv6: "2a01:4ff:f0:28d4::1", CanPort80: true},
				},
			},
			28: {
				RegionID: 28, RegionCode: "hel", RegionName: "Helsinki", Latitude: 60.170833, Longitude: 24.9375,
				Nodes: []*tailcfg.DERPNode{
					{Name: "28b", RegionID: 28, HostName: "derp28b.tailscale.com", IPv4: "65.109.143.62", IPv6: "2a01:4f9:c012:d55c::1", CanPort80: true},
					{Name: "28c", RegionID: 28, HostName: "derp28c.tailscale.com", IPv4: "95.217.2.165", IPv6: "2a01:4f9:c012:cd74::1", CanPort80: true},
					{Name: "28d", RegionID: 28, HostName: "derp28d.tailscale.com", IPv4: "157.180.28.32", IPv6: "2a01:4f9:c012:2e5b::1", CanPort80: true},
				},
			},
		},
	}
}

// fetchDERPMap fetches a DERP map from url with a short timeout.
// Returns nil on any error — caller handles fallback.
func fetchDERPMap(url string) *tailcfg.DERPMap {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		logger.Log(0, fmt.Sprintf("MagicBind: fetchDERPMap %s failed: %v", url, err))
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Log(0, fmt.Sprintf("MagicBind: fetchDERPMap %s returned HTTP %d", url, resp.StatusCode))
		return nil
	}

	var m tailcfg.DERPMap
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		logger.Log(0, fmt.Sprintf("MagicBind: fetchDERPMap decode %s failed: %v", url, err))
		return nil
	}

	if len(m.Regions) == 0 {
		logger.Log(0, "MagicBind: fetchDERPMap returned empty map from "+url)
		return nil
	}

	slog.Debug("MagicBind: DERP map fetched", "url", url, "regions", len(m.Regions))
	return &m
}

// derpMapCacheTTL bounds how often LoadDERPMap refetches upstream. A DERP map
// doesn't churn in seconds, and per-peer reconnect loops can call LoadDERPMap
// repeatedly under network flapping — without a TTL cache each attempt costs
// an HTTP fetch to Tailscale and every admin URL in DERP_MAP_URLS.
const derpMapCacheTTL = 60 * time.Second

// lastKnownDERPMap caches the currently selected map. It serves two purposes:
//  1. TTL-gated fast path — within derpMapCacheTTL of the last load, return it
//     directly without any HTTP call.
//  2. Avoid reconnecting to a different region while the selected source is
//     still fresh.
//
// lastKnownPublicDERPMap is deliberately separate. A Core map is preferred
// only while it can be fetched; if both a Core map and Tailscale's live map
// are unavailable, a stale public map is a safer last-known-good fallback than
// a stale Core map which may be the source of the outage.
var (
	lastKnownDERPMap       *tailcfg.DERPMap
	lastKnownPublicDERPMap *tailcfg.DERPMap
	lastKnownDERPMapTime   time.Time
	lastKnownDERPMapMu     sync.RWMutex
	derpMapRefreshGroup    singleflight.Group
)

// LoadDERPMap loads the DERP map using a priority chain:
//
//  1. TTL cache (60s) — skip all HTTP calls if the last load was recent
//  2. DERP_MAP_URLS — ordered comma-separated URLs for one canonical,
//     Core-owned map; the first usable source wins
//  3. Tailscale's public live map (20+ regions, availability fallback)
//  4. Last known good map — used only if the public live map is unavailable
//  5. Hardcoded fallback — last resort when the process has never loaded a live map
//
// A configured Core map is deliberately neither merged with another Core map
// nor overlaid on Tailscale's public map. DERP_MAP_URLS is an ordered mirror /
// hostname-migration list: every source must serve the same complete canonical
// map. Selecting the first usable source keeps all peers on one region set,
// avoiding divergent HRW selections during a migration. The public fleet is
// the immediate escape hatch when no Core source can be fetched.
//
// Called on every DERP connect attempt; the TTL cache keeps this cheap.
func LoadDERPMap() *tailcfg.DERPMap {
	if cached := freshDERPMap(); cached != nil {
		return cached
	}

	// A configuration update can make many peer region selections at once.
	// Coalesce their expired-cache refreshes into one HTTP fetch sequence.
	value, _, _ := derpMapRefreshGroup.Do("derp-map", func() (interface{}, error) {
		if cached := freshDERPMap(); cached != nil {
			return cached, nil
		}
		return loadDERPMapUncached(), nil
	})
	return value.(*tailcfg.DERPMap)
}

func freshDERPMap() *tailcfg.DERPMap {
	lastKnownDERPMapMu.RLock()
	cached := lastKnownDERPMap
	cachedAt := lastKnownDERPMapTime
	lastKnownDERPMapMu.RUnlock()
	if cached != nil && time.Since(cachedAt) < derpMapCacheTTL {
		return cached
	}
	return nil
}

func loadDERPMapUncached() *tailcfg.DERPMap {
	coreMapURLs := os.Getenv("DERP_MAP_URLS")
	if coreMapURLs != "" {
		for _, rawURL := range strings.Split(coreMapURLs, ",") {
			u := strings.TrimSpace(rawURL)
			if u == "" {
				continue
			}
			if coreMap := fetchDERPMap(u); coreMap != nil {
				slog.Info("MagicBind: loaded canonical Core DERP map", "url", u, "regions", len(coreMap.Regions))
				cacheDERPMap(coreMap)
				return coreMap
			}
		}
	}

	publicMap := fetchDERPMap(tailscaleDERPMapURL)
	if publicMap != nil {
		cachePublicDERPMap(publicMap)
		return publicMap
	}

	lastKnownDERPMapMu.RLock()
	lastKnownPublic := lastKnownPublicDERPMap
	lastKnownDERPMapMu.RUnlock()
	if lastKnownPublic != nil {
		slog.Info("MagicBind: Tailscale DERP map unavailable, using last known good public map")
		cacheDERPMap(lastKnownPublic)
		return lastKnownPublic
	}

	slog.Info("MagicBind: Tailscale DERP map unavailable, using hardcoded fallback")
	hardcoded := hardcodedDERPMap()
	cacheDERPMap(hardcoded)
	return hardcoded
}

var tailscaleDERPMapURL = "https://login.tailscale.com/derpmap/default"

func cacheDERPMap(derpMap *tailcfg.DERPMap) {
	lastKnownDERPMapMu.Lock()
	lastKnownDERPMap = derpMap
	lastKnownDERPMapTime = time.Now()
	lastKnownDERPMapMu.Unlock()
}

func cachePublicDERPMap(derpMap *tailcfg.DERPMap) {
	lastKnownDERPMapMu.Lock()
	lastKnownDERPMap = derpMap
	lastKnownPublicDERPMap = derpMap
	lastKnownDERPMapTime = time.Now()
	lastKnownDERPMapMu.Unlock()
}
