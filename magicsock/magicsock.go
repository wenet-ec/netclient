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
	"strings"
	"sync"
	"time"

	"github.com/gravitl/netmaker/logger"
	"go4.org/mem"
	"golang.org/x/exp/slog"
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
// Each peer gets its own DERP client connected to a region chosen by
// consistent hashing over (selfKey, peerKey) — so both sides independently
// land on the same server with no coordination required.
// The DERP map is re-fetched on every connect attempt, so a region that
// disappears from the live map is naturally evicted on the next retry.
type MagicBind struct {
	privateKey key.NodePrivate
	publicKey  key.NodePublic

	// UDP sockets
	pconn4 *net.UDPConn
	pconn6 *net.UDPConn
	port   uint16

	// Per-peer DERP clients. Each peer gets its own client connected to the
	// region selected by consistent hash(selfKey, peerKey).
	derpClientsMu sync.RWMutex
	derpClients   map[key.NodePublic]*derphttp.Client

	// Running per-peer reader goroutines — tracked to avoid duplicates.
	derpReadersMu sync.Mutex
	derpReaders   map[key.NodePublic]struct{}

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

// NewMagicBind creates a new MagicBind. DERP map fetching and region selection
// happen lazily when the first peer connect attempt is made.
func NewMagicBind(wgPrivateKey wgtypes.Key) (*MagicBind, error) {
	privateKey := key.NodePrivateFromRaw32(mem.B(wgPrivateKey[:]))
	publicKey := privateKey.Public()

	ctx, cancel := context.WithCancel(context.Background())

	b := &MagicBind{
		privateKey:      privateKey,
		publicKey:       publicKey,
		derpClients:     make(map[key.NodePublic]*derphttp.Client),
		derpReaders:     make(map[key.NodePublic]struct{}),
		derpRecvCh:      make(chan derpReadResult, 64),
		endpointMap:     make(map[netip.AddrPort]key.NodePublic),
		allowedIPMap:    make(map[netip.Addr]key.NodePublic),
		derpPeerByIndex: make(map[int]key.NodePublic),
		activePeers:     make(map[key.NodePublic]bool),
		nextPeerIndex:   1,
		bindCloseCh:     make(chan struct{}),
		derpCtx:         ctx,
		derpCancel:      cancel,
		logf:            func(format string, args ...any) { logger.Log(0, fmt.Sprintf(format, args...)) },
	}

	slog.Debug("MagicBind created", "pubkey", publicKey.ShortString())
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

// ensurePeerDERPReader starts a per-peer DERP reader goroutine if one is not
// already running for peerKey. Safe to call from UpdatePeersFromConfig.
func (b *MagicBind) ensurePeerDERPReader(peerKey key.NodePublic) {
	b.derpReadersMu.Lock()
	defer b.derpReadersMu.Unlock()

	if _, exists := b.derpReaders[peerKey]; exists {
		return
	}
	b.derpReaders[peerKey] = struct{}{}
	go b.runPeerDERPReader(peerKey)
}

// stopPeerDERPReader removes the reader tracking entry for peerKey.
// Called by runPeerDERPReader on exit so a future ensurePeerDERPReader
// call can restart it if the peer comes back.
func (b *MagicBind) stopPeerDERPReader(peerKey key.NodePublic) {
	b.derpReadersMu.Lock()
	delete(b.derpReaders, peerKey)
	b.derpReadersMu.Unlock()

	// Also remove the client so sendDERP doesn't use a dead connection
	b.derpClientsMu.Lock()
	delete(b.derpClients, peerKey)
	b.derpClientsMu.Unlock()
}

// runPeerDERPReader is the per-peer DERP goroutine.
// On every connect attempt it:
//  1. Fetches a fresh DERP map (falls back to hardcoded on failure)
//  2. Selects a region via consistent hash(selfKey, peerKey)
//  3. Creates a new derphttp.Client for that region
//  4. Connects and reads packets until error or shutdown
//
// If the previously-chosen region has disappeared from the live map,
// the hash over the shorter list picks a different region automatically.
func (b *MagicBind) runPeerDERPReader(peerKey key.NodePublic) {
	slog.Info("MagicBind: DERP reader started", "peer", peerKey.ShortString())
	defer func() {
		slog.Info("MagicBind: DERP reader exiting", "peer", peerKey.ShortString())
		b.stopPeerDERPReader(peerKey)
	}()

	const connectTimeout = 10 * time.Second

	connectAttempt := 0

	for {
		// Exit if permanently shut down
		select {
		case <-b.derpCtx.Done():
			return
		default:
		}

		connectAttempt++

		// Fetch a fresh DERP map on every attempt — region disappearing from
		// the live map is handled naturally (hash picks a different region)
		derpMap := LoadDERPMap()
		if len(derpMap.Regions) == 0 {
			logger.Log(0, fmt.Sprintf("MagicBind: empty DERP map on attempt %d, retrying", connectAttempt))
			time.Sleep(5 * time.Second)
			continue
		}

		region := selectDERPRegion(derpMap, b.publicKey, peerKey)
		slog.Info("MagicBind: connecting to DERP",
			"peer", peerKey.ShortString(),
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
			logger.Log(0, fmt.Sprintf("MagicBind: DERP connect failed (peer=%s attempt=%d region=%d): %v",
				peerKey.ShortString(), connectAttempt, region.RegionID, err))
			time.Sleep(5 * time.Second)
			continue
		}

		slog.Info("MagicBind: DERP connected",
			"peer", peerKey.ShortString(),
			"region_id", region.RegionID,
			"region_code", region.RegionCode,
		)
		connectAttempt = 0

		// Store the live client so sendDERP can use it
		b.derpClientsMu.Lock()
		b.derpClients[peerKey] = client
		b.derpClientsMu.Unlock()

		// Read packets until error
		disconnected := false
		for !disconnected {
			select {
			case <-b.derpCtx.Done():
				client.Close()
				return
			default:
			}

			msg, err := client.Recv()
			if err != nil {
				logger.Log(0, fmt.Sprintf("MagicBind: DERP recv error (peer=%s region=%d): %v",
					peerKey.ShortString(), region.RegionID, err))
				disconnected = true
				break
			}

			switch m := msg.(type) {
			case derp.ReceivedPacket:
				result := derpReadResult{
					data: append([]byte(nil), m.Data...),
					src:  m.Source,
				}
				select {
				case b.derpRecvCh <- result:
				case <-b.derpCtx.Done():
					client.Close()
					return
				}
			case derp.ServerInfoMessage:
				// Expected on connect, silently ignore
			case derp.KeepAliveMessage:
				// Silently ignore
			default:
				logger.Log(0, fmt.Sprintf("MagicBind: unexpected DERP message type %T", msg))
			}
		}

		// Clean up the dead client before retrying
		client.Close()
		b.derpClientsMu.Lock()
		if b.derpClients[peerKey] == client {
			delete(b.derpClients, peerKey)
		}
		b.derpClientsMu.Unlock()

		time.Sleep(1 * time.Second)
	}
}

// UpdatePeersFromConfig updates the peer mapping from WireGuard PeerConfig.
// Also starts a DERP reader goroutine for each new peer.
func (b *MagicBind) UpdatePeersFromConfig(peers []wgtypes.PeerConfig) map[string]*net.UDPAddr {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.endpointMap = make(map[netip.AddrPort]key.NodePublic)
	b.allowedIPMap = make(map[netip.Addr]key.NodePublic)
	b.derpPeerByIndex = make(map[int]key.NodePublic)
	b.nextPeerIndex = 1

	derpEndpoints := make(map[string]*net.UDPAddr)

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

		// Start a DERP reader for this peer if not already running
		b.ensurePeerDERPReader(peerKey)
	}

	slog.Debug("MagicBind peers updated",
		"peers", len(peers),
		"endpoints", len(b.endpointMap),
		"allowed_ips", len(b.allowedIPMap),
		"derp_only", len(b.derpPeerByIndex),
	)

	return derpEndpoints
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

// receiveIPv4 implements conn.ReceiveFunc for IPv4
func (b *MagicBind) receiveIPv4(buff []byte) (int, conn.Endpoint, error) {
	b.bindMutex.Lock()
	pconn := b.pconn4
	closed := b.closed
	b.bindMutex.Unlock()

	if closed || pconn == nil {
		return 0, nil, net.ErrClosed
	}
	n, addr, err := pconn.ReadFromUDPAddrPort(buff)
	if err != nil {
		return 0, nil, err
	}
	return n, b.createEndpointForReceive(addr), nil
}

// receiveIPv6 implements conn.ReceiveFunc for IPv6
func (b *MagicBind) receiveIPv6(buff []byte) (int, conn.Endpoint, error) {
	b.bindMutex.Lock()
	pconn := b.pconn6
	closed := b.closed
	b.bindMutex.Unlock()

	if closed || pconn == nil {
		return 0, nil, net.ErrClosed
	}
	n, addr, err := pconn.ReadFromUDPAddrPort(buff)
	if err != nil {
		return 0, nil, err
	}
	return n, b.createEndpointForReceive(addr), nil
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
// All per-peer reader goroutines funnel packets into the shared derpRecvCh.
func (b *MagicBind) receiveDERP(buff []byte) (int, conn.Endpoint, error) {
	b.bindMutex.Lock()
	closeCh := b.bindCloseCh
	b.bindMutex.Unlock()

	for {
		select {
		case result := <-b.derpRecvCh:
			if len(result.data) == 0 {
				continue
			}
			n := copy(buff, result.data)
			b.learnPeerFromDERP(result.src)
			return n, &derpEndpoint{peerKey: result.src}, nil
		case <-closeCh:
			return 0, nil, net.ErrClosed
		case <-b.derpCtx.Done():
			return 0, nil, net.ErrClosed
		}
	}
}

// learnPeerFromDERP marks the peer as active when we receive a packet from it
func (b *MagicBind) learnPeerFromDERP(peerKey key.NodePublic) {
	b.mu.Lock()
	b.activePeers[peerKey] = true
	b.mu.Unlock()
}

// Send implements conn.Bind.Send
func (b *MagicBind) Send(buff []byte, ep conn.Endpoint) error {
	switch e := ep.(type) {
	case *hybridEndpoint:
		return b.sendHybrid(buff, e)
	case *udpEndpoint:
		return b.sendUDP(buff, e.addr)
	case *derpEndpoint:
		return b.sendDERP(buff, e.peerKey)
	default:
		return fmt.Errorf("unknown endpoint type: %T", ep)
	}
}

// sendHybrid sends via UDP and also via DERP for NAT traversal
func (b *MagicBind) sendHybrid(buff []byte, ep *hybridEndpoint) error {
	udpErr := b.sendUDP(buff, ep.udpAddr)

	if !ep.peerKey.IsZero() {
		b.sendDERP(buff, ep.peerKey) //nolint:errcheck
	}

	if udpErr != nil && ep.peerKey.IsZero() {
		return udpErr
	}
	return nil
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
	b.derpClientsMu.RLock()
	client := b.derpClients[peerKey]
	b.derpClientsMu.RUnlock()

	if client == nil {
		return fmt.Errorf("DERP client not ready for peer %s", peerKey.ShortString())
	}
	if err := client.Send(peerKey, buff); err != nil {
		return fmt.Errorf("DERP send failed: %w", err)
	}
	return nil
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
func (e *udpEndpoint) DstIP() netip.Addr    { return e.addr.Addr() }
func (e *udpEndpoint) SrcIP() netip.Addr    { return e.addr.Addr() }
func (e *udpEndpoint) SrcToString() string  { return e.addr.String() }
func (e *udpEndpoint) DstToString() string  { return e.addr.String() }

type derpEndpoint struct {
	peerKey key.NodePublic
}

func (e *derpEndpoint) ClearSrc() {}
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

// hardcodedDERPMap is the last-resort fallback (no internet at startup).
// Sourced from tailscale/net/dnsfallback. Update periodically.
func hardcodedDERPMap() *tailcfg.DERPMap {
	return &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID: 1, RegionCode: "r1", RegionName: "New York City",
				Nodes: []*tailcfg.DERPNode{
					{Name: "1c", RegionID: 1, HostName: "derp1c.tailscale.com", IPv4: "104.248.8.210"},
					{Name: "1d", RegionID: 1, HostName: "derp1d.tailscale.com", IPv4: "165.22.33.71"},
					{Name: "1e", RegionID: 1, HostName: "derp1e.tailscale.com", IPv4: "64.225.56.166"},
				},
			},
			2: {
				RegionID: 2, RegionCode: "r2", RegionName: "San Francisco",
				Nodes: []*tailcfg.DERPNode{
					{Name: "2d", RegionID: 2, HostName: "derp2d.tailscale.com", IPv4: "192.73.252.65"},
					{Name: "2e", RegionID: 2, HostName: "derp2e.tailscale.com", IPv4: "192.73.252.134"},
					{Name: "2f", RegionID: 2, HostName: "derp2f.tailscale.com", IPv4: "208.111.34.178"},
				},
			},
			3: {
				RegionID: 3, RegionCode: "r3", RegionName: "Singapore",
				Nodes: []*tailcfg.DERPNode{
					{Name: "3a", RegionID: 3, HostName: "derp3.tailscale.com", IPv4: "68.183.179.66"},
				},
			},
			4: {
				RegionID: 4, RegionCode: "r4", RegionName: "Frankfurt",
				Nodes: []*tailcfg.DERPNode{
					{Name: "4c", RegionID: 4, HostName: "derp4c.tailscale.com", IPv4: "134.122.77.138"},
					{Name: "4d", RegionID: 4, HostName: "derp4d.tailscale.com", IPv4: "134.122.94.167"},
					{Name: "4e", RegionID: 4, HostName: "derp4e.tailscale.com", IPv4: "134.122.74.153"},
				},
			},
			5: {
				RegionID: 5, RegionCode: "r5", RegionName: "Sydney",
				Nodes: []*tailcfg.DERPNode{
					{Name: "5a", RegionID: 5, HostName: "derp5.tailscale.com", IPv4: "103.43.75.49"},
				},
			},
			6: {
				RegionID: 6, RegionCode: "r6", RegionName: "Bangalore",
				Nodes: []*tailcfg.DERPNode{
					{Name: "6a", RegionID: 6, HostName: "derp6.tailscale.com", IPv4: "68.183.90.120"},
				},
			},
			7: {
				RegionID: 7, RegionCode: "r7", RegionName: "Tokyo",
				Nodes: []*tailcfg.DERPNode{
					{Name: "7a", RegionID: 7, HostName: "derp7.tailscale.com", IPv4: "167.179.89.145"},
				},
			},
			8: {
				RegionID: 8, RegionCode: "r8", RegionName: "London",
				Nodes: []*tailcfg.DERPNode{
					{Name: "8b", RegionID: 8, HostName: "derp8b.tailscale.com", IPv4: "46.101.74.201"},
					{Name: "8c", RegionID: 8, HostName: "derp8c.tailscale.com", IPv4: "206.189.16.32"},
					{Name: "8d", RegionID: 8, HostName: "derp8d.tailscale.com", IPv4: "178.62.44.132"},
				},
			},
			9: {
				RegionID: 9, RegionCode: "r9", RegionName: "Dallas",
				Nodes: []*tailcfg.DERPNode{
					{Name: "9a", RegionID: 9, HostName: "derp9.tailscale.com", IPv4: "207.148.3.137"},
					{Name: "9b", RegionID: 9, HostName: "derp9b.tailscale.com", IPv4: "144.202.67.195"},
					{Name: "9c", RegionID: 9, HostName: "derp9c.tailscale.com", IPv4: "155.138.243.219"},
				},
			},
			10: {
				RegionID: 10, RegionCode: "r10", RegionName: "Seattle",
				Nodes: []*tailcfg.DERPNode{
					{Name: "10a", RegionID: 10, HostName: "derp10.tailscale.com", IPv4: "137.220.36.168"},
				},
			},
			11: {
				RegionID: 11, RegionCode: "r11", RegionName: "São Paulo",
				Nodes: []*tailcfg.DERPNode{
					{Name: "11a", RegionID: 11, HostName: "derp11.tailscale.com", IPv4: "18.230.97.74"},
				},
			},
			12: {
				RegionID: 12, RegionCode: "r12", RegionName: "Toronto",
				Nodes: []*tailcfg.DERPNode{
					{Name: "12a", RegionID: 12, HostName: "derp12.tailscale.com", IPv4: "216.128.144.130"},
					{Name: "12b", RegionID: 12, HostName: "derp12b.tailscale.com", IPv4: "45.63.71.144"},
					{Name: "12c", RegionID: 12, HostName: "derp12c.tailscale.com", IPv4: "149.28.119.105"},
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

// mergeDERPMaps merges overlay into base. Overlay wins on region ID conflict.
func mergeDERPMaps(base, overlay *tailcfg.DERPMap) *tailcfg.DERPMap {
	if overlay == nil {
		return base
	}
	merged := &tailcfg.DERPMap{
		Regions: make(map[int]*tailcfg.DERPRegion, len(base.Regions)+len(overlay.Regions)),
	}
	for id, r := range base.Regions {
		merged.Regions[id] = r
	}
	for id, r := range overlay.Regions {
		merged.Regions[id] = r
	}
	return merged
}

// LoadDERPMap loads the DERP map using a priority chain:
//
//  1. Tailscale's public live map (20+ regions, always up-to-date)
//  2. DERP_MAP_URLS env var — comma-separated admin-served maps merged on top
//  3. Hardcoded fallback — used only when all network fetches fail
//
// This is called on every DERP connect attempt so the map is always fresh.
// A region that disappears from the live map is evicted automatically.
func LoadDERPMap() *tailcfg.DERPMap {
	const tailscaleURL = "https://login.tailscale.com/derpmap/default"

	base := fetchDERPMap(tailscaleURL)
	if base == nil {
		slog.Info("MagicBind: Tailscale DERP map unavailable, using hardcoded fallback")
		base = hardcodedDERPMap()
	}

	adminURLs := os.Getenv("DERP_MAP_URLS")
	if adminURLs == "" {
		return base
	}

	for _, rawURL := range strings.Split(adminURLs, ",") {
		u := strings.TrimSpace(rawURL)
		if u == "" {
			continue
		}
		if overlay := fetchDERPMap(u); overlay != nil {
			slog.Info("MagicBind: merged admin DERP map", "url", u, "regions", len(overlay.Regions))
			base = mergeDERPMaps(base, overlay)
		}
	}

	return base
}
