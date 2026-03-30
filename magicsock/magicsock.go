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
		logf:            func(format string, args ...any) { slog.Debug(fmt.Sprintf(format, args...)) },
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
	slog.Debug("MagicBind: DERP reader started", "peer", peerKey.ShortString())
	defer func() {
		slog.Debug("MagicBind: DERP reader exiting", "peer", peerKey.ShortString())
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
		slog.Debug("MagicBind: connecting to DERP",
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

		slog.Debug("MagicBind: DERP connected",
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
				slog.Debug("MagicBind: unexpected DERP message type", "type", fmt.Sprintf("%T", msg))
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

// hardcodedDERPMap is the last-resort fallback used only when:
//   - Tailscale's live map fetch fails, AND
//   - No prior successful map has been cached in memory
//
// Sourced from https://login.tailscale.com/derpmap/default on 2026-03-27.
// 28 regions. Update by re-fetching that URL periodically.
func hardcodedDERPMap() *tailcfg.DERPMap {
	return &tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			1: {
				RegionID: 1, RegionCode: "nyc", RegionName: "New York City",
				Nodes: []*tailcfg.DERPNode{
					{Name: "1f", RegionID: 1, HostName: "derp1f.tailscale.com", IPv4: "199.38.181.104", IPv6: "2607:f740:f::bc"},
					{Name: "1g", RegionID: 1, HostName: "derp1g.tailscale.com", IPv4: "209.177.145.120", IPv6: "2607:f740:f::3eb"},
					{Name: "1h", RegionID: 1, HostName: "derp1h.tailscale.com", IPv4: "199.38.181.93", IPv6: "2607:f740:f::afd"},
					{Name: "1i", RegionID: 1, HostName: "derp1i.tailscale.com", IPv4: "199.38.181.103", IPv6: "2607:f740:f::e19"},
				},
			},
			2: {
				RegionID: 2, RegionCode: "sfo", RegionName: "San Francisco",
				Nodes: []*tailcfg.DERPNode{
					{Name: "2d", RegionID: 2, HostName: "derp2d.tailscale.com", IPv4: "192.73.252.65", IPv6: "2607:f740:0:3f::287"},
					{Name: "2e", RegionID: 2, HostName: "derp2e.tailscale.com", IPv4: "192.73.252.134", IPv6: "2607:f740:0:3f::44c"},
					{Name: "2f", RegionID: 2, HostName: "derp2f.tailscale.com", IPv4: "208.111.34.178", IPv6: "2607:f740:0:3f::f4"},
				},
			},
			3: {
				RegionID: 3, RegionCode: "sin", RegionName: "Singapore",
				Nodes: []*tailcfg.DERPNode{
					{Name: "3e", RegionID: 3, HostName: "derp3e.tailscale.com", IPv4: "172.237.72.43", IPv6: "2600:3c15::2000:6cff:fee4:d799"},
					{Name: "3f", RegionID: 3, HostName: "derp3f.tailscale.com", IPv4: "172.237.72.8", IPv6: "2600:3c15::2000:53ff:fe48:a668"},
					{Name: "3g", RegionID: 3, HostName: "derp3g.tailscale.com", IPv4: "172.237.72.79", IPv6: "2600:3c15::2000:adff:fe08:6fab"},
					{Name: "3h", RegionID: 3, HostName: "derp3h.tailscale.com", IPv4: "172.237.66.30", IPv6: "2600:3c15::2000:3dff:fe44:50aa"},
				},
			},
			4: {
				RegionID: 4, RegionCode: "fra", RegionName: "Frankfurt",
				Nodes: []*tailcfg.DERPNode{
					{Name: "4f", RegionID: 4, HostName: "derp4f.tailscale.com", IPv4: "185.40.234.219", IPv6: "2a00:dd80:20::a25"},
					{Name: "4g", RegionID: 4, HostName: "derp4g.tailscale.com", IPv4: "185.40.234.113", IPv6: "2a00:dd80:20::8f"},
					{Name: "4h", RegionID: 4, HostName: "derp4h.tailscale.com", IPv4: "185.40.234.77", IPv6: "2a00:dd80:20::bcf"},
					{Name: "4i", RegionID: 4, HostName: "derp4i.tailscale.com", IPv4: "185.40.234.53", IPv6: "2a00:dd80:20::8a6"},
				},
			},
			5: {
				RegionID: 5, RegionCode: "syd", RegionName: "Sydney",
				Nodes: []*tailcfg.DERPNode{
					{Name: "5e", RegionID: 5, HostName: "derp5e.tailscale.com", IPv4: "172.105.179.230", IPv6: "2400:8907::2000:ceff:fe8d:4f4e"},
					{Name: "5f", RegionID: 5, HostName: "derp5f.tailscale.com", IPv4: "172.105.166.103", IPv6: "2400:8907::2000:ccff:fe1f:80da"},
					{Name: "5g", RegionID: 5, HostName: "derp5g.tailscale.com", IPv4: "172.105.169.57", IPv6: "2400:8907::2000:2fff:fea7:57f4"},
				},
			},
			6: {
				RegionID: 6, RegionCode: "blr", RegionName: "Bengaluru",
				Nodes: []*tailcfg.DERPNode{
					{Name: "6a", RegionID: 6, HostName: "derp6.tailscale.com", IPv4: "68.183.90.120", IPv6: "2400:6180:100:d0::982:d001"},
				},
			},
			7: {
				RegionID: 7, RegionCode: "tok", RegionName: "Tokyo",
				Nodes: []*tailcfg.DERPNode{
					{Name: "7e", RegionID: 7, HostName: "derp7e.tailscale.com", IPv4: "172.238.6.180", IPv6: "2600:3c18::2000:60ff:fe0f:6e83"},
					{Name: "7f", RegionID: 7, HostName: "derp7f.tailscale.com", IPv4: "172.238.6.34", IPv6: "2600:3c18::2000:acff:fe8e:3ed5"},
					{Name: "7g", RegionID: 7, HostName: "derp7g.tailscale.com", IPv4: "172.238.6.179", IPv6: "2600:3c18::2000:3fff:fe80:3ebd"},
					{Name: "7h", RegionID: 7, HostName: "derp7h.tailscale.com", IPv4: "172.237.28.183", IPv6: "2600:3c18::2000:b1ff:fea9:4560"},
				},
			},
			8: {
				RegionID: 8, RegionCode: "lhr", RegionName: "London",
				Nodes: []*tailcfg.DERPNode{
					{Name: "8e", RegionID: 8, HostName: "derp8e.tailscale.com", IPv4: "176.58.92.144", IPv6: "2a00:dd80:3a::b33"},
					{Name: "8f", RegionID: 8, HostName: "derp8f.tailscale.com", IPv4: "176.58.88.183", IPv6: "2a00:dd80:3a::dfa"},
					{Name: "8g", RegionID: 8, HostName: "derp8g.tailscale.com", IPv4: "176.58.92.254", IPv6: "2a00:dd80:3a::ed"},
				},
			},
			9: {
				RegionID: 9, RegionCode: "dfw", RegionName: "Dallas",
				Nodes: []*tailcfg.DERPNode{
					{Name: "9d", RegionID: 9, HostName: "derp9d.tailscale.com", IPv4: "209.177.156.94", IPv6: "2607:f740:100::c05"},
					{Name: "9e", RegionID: 9, HostName: "derp9e.tailscale.com", IPv4: "192.73.248.83", IPv6: "2607:f740:100::359"},
					{Name: "9f", RegionID: 9, HostName: "derp9f.tailscale.com", IPv4: "209.177.156.197", IPv6: "2607:f740:100::cad"},
				},
			},
			10: {
				RegionID: 10, RegionCode: "sea", RegionName: "Seattle",
				Nodes: []*tailcfg.DERPNode{
					{Name: "10b", RegionID: 10, HostName: "derp10b.tailscale.com", IPv4: "192.73.240.161", IPv6: "2607:f740:14::61c"},
					{Name: "10c", RegionID: 10, HostName: "derp10c.tailscale.com", IPv4: "192.73.240.121", IPv6: "2607:f740:14::40c"},
					{Name: "10d", RegionID: 10, HostName: "derp10d.tailscale.com", IPv4: "192.73.240.132", IPv6: "2607:f740:14::500"},
				},
			},
			11: {
				RegionID: 11, RegionCode: "sao", RegionName: "São Paulo",
				Nodes: []*tailcfg.DERPNode{
					{Name: "11e", RegionID: 11, HostName: "derp11e.tailscale.com", IPv4: "172.237.61.194", IPv6: "2600:3c0d::2000:d2ff:fe43:1790"},
					{Name: "11f", RegionID: 11, HostName: "derp11f.tailscale.com", IPv4: "172.237.61.197", IPv6: "2600:3c0d::2000:3bff:fe44:6166"},
					{Name: "11g", RegionID: 11, HostName: "derp11g.tailscale.com", IPv4: "172.237.61.190", IPv6: "2600:3c0d::2000:62ff:febe:2e67"},
				},
			},
			12: {
				RegionID: 12, RegionCode: "ord", RegionName: "Chicago",
				Nodes: []*tailcfg.DERPNode{
					{Name: "12d", RegionID: 12, HostName: "derp12d.tailscale.com", IPv4: "209.177.158.246", IPv6: "2607:f740:e::811"},
					{Name: "12e", RegionID: 12, HostName: "derp12e.tailscale.com", IPv4: "209.177.158.15", IPv6: "2607:f740:e::b17"},
					{Name: "12f", RegionID: 12, HostName: "derp12f.tailscale.com", IPv4: "199.38.182.118", IPv6: "2607:f740:e::4c8"},
				},
			},
			13: {
				RegionID: 13, RegionCode: "den", RegionName: "Denver",
				Nodes: []*tailcfg.DERPNode{
					{Name: "13b", RegionID: 13, HostName: "derp13b.tailscale.com", IPv4: "192.73.242.187", IPv6: "2607:f740:16::640"},
					{Name: "13c", RegionID: 13, HostName: "derp13c.tailscale.com", IPv4: "192.73.242.28", IPv6: "2607:f740:16::5c"},
					{Name: "13d", RegionID: 13, HostName: "derp13d.tailscale.com", IPv4: "192.73.242.204", IPv6: "2607:f740:16::c23"},
				},
			},
			14: {
				RegionID: 14, RegionCode: "ams", RegionName: "Amsterdam",
				Nodes: []*tailcfg.DERPNode{
					{Name: "14b", RegionID: 14, HostName: "derp14b.tailscale.com", IPv4: "176.58.93.248", IPv6: "2a00:dd80:3c::807"},
					{Name: "14c", RegionID: 14, HostName: "derp14c.tailscale.com", IPv4: "176.58.93.147", IPv6: "2a00:dd80:3c::b09"},
					{Name: "14d", RegionID: 14, HostName: "derp14d.tailscale.com", IPv4: "176.58.93.154", IPv6: "2a00:dd80:3c::3d5"},
				},
			},
			15: {
				RegionID: 15, RegionCode: "jnb", RegionName: "Johannesburg",
				Nodes: []*tailcfg.DERPNode{
					{Name: "15b", RegionID: 15, HostName: "derp15b.tailscale.com", IPv4: "102.67.165.90", IPv6: "2c0f:edb0:0:10::963"},
					{Name: "15c", RegionID: 15, HostName: "derp15c.tailscale.com", IPv4: "102.67.165.185", IPv6: "2c0f:edb0:0:10::b59"},
					{Name: "15d", RegionID: 15, HostName: "derp15d.tailscale.com", IPv4: "102.67.165.36", IPv6: "2c0f:edb0:0:10::599"},
				},
			},
			16: {
				RegionID: 16, RegionCode: "mia", RegionName: "Miami",
				Nodes: []*tailcfg.DERPNode{
					{Name: "16b", RegionID: 16, HostName: "derp16b.tailscale.com", IPv4: "192.73.243.135", IPv6: "2607:f740:17::476"},
					{Name: "16c", RegionID: 16, HostName: "derp16c.tailscale.com", IPv4: "192.73.243.229", IPv6: "2607:f740:17::4e4"},
					{Name: "16d", RegionID: 16, HostName: "derp16d.tailscale.com", IPv4: "192.73.243.141", IPv6: "2607:f740:17::475"},
				},
			},
			17: {
				RegionID: 17, RegionCode: "lax", RegionName: "Los Angeles",
				Nodes: []*tailcfg.DERPNode{
					{Name: "17b", RegionID: 17, HostName: "derp17b.tailscale.com", IPv4: "192.73.244.245", IPv6: "2607:f740:c::646"},
					{Name: "17c", RegionID: 17, HostName: "derp17c.tailscale.com", IPv4: "208.111.40.12", IPv6: "2607:f740:c::10"},
					{Name: "17d", RegionID: 17, HostName: "derp17d.tailscale.com", IPv4: "208.111.40.216", IPv6: "2607:f740:c::e1b"},
				},
			},
			18: {
				RegionID: 18, RegionCode: "par", RegionName: "Paris",
				Nodes: []*tailcfg.DERPNode{
					{Name: "18b", RegionID: 18, HostName: "derp18b.tailscale.com", IPv4: "176.58.90.147", IPv6: "2a00:dd80:3e::363"},
					{Name: "18c", RegionID: 18, HostName: "derp18c.tailscale.com", IPv4: "176.58.90.207", IPv6: "2a00:dd80:3e::c19"},
					{Name: "18d", RegionID: 18, HostName: "derp18d.tailscale.com", IPv4: "176.58.90.104", IPv6: "2a00:dd80:3e::f2e"},
				},
			},
			19: {
				RegionID: 19, RegionCode: "mad", RegionName: "Madrid",
				Nodes: []*tailcfg.DERPNode{
					{Name: "19b", RegionID: 19, HostName: "derp19b.tailscale.com", IPv4: "45.159.97.144", IPv6: "2a00:dd80:14:10::335"},
					{Name: "19c", RegionID: 19, HostName: "derp19c.tailscale.com", IPv4: "45.159.97.61", IPv6: "2a00:dd80:14:10::20"},
					{Name: "19d", RegionID: 19, HostName: "derp19d.tailscale.com", IPv4: "45.159.97.233", IPv6: "2a00:dd80:14:10::34a"},
				},
			},
			20: {
				RegionID: 20, RegionCode: "hkg", RegionName: "Hong Kong",
				Nodes: []*tailcfg.DERPNode{
					{Name: "20b", RegionID: 20, HostName: "derp20b.tailscale.com", IPv4: "103.6.84.152", IPv6: "2403:2500:8000:1::ef6"},
					{Name: "20c", RegionID: 20, HostName: "derp20c.tailscale.com", IPv4: "205.147.105.30", IPv6: "2403:2500:8000:1::5fb"},
					{Name: "20d", RegionID: 20, HostName: "derp20d.tailscale.com", IPv4: "205.147.105.78", IPv6: "2403:2500:8000:1::e9a"},
				},
			},
			21: {
				RegionID: 21, RegionCode: "tor", RegionName: "Toronto",
				Nodes: []*tailcfg.DERPNode{
					{Name: "21b", RegionID: 21, HostName: "derp21b.tailscale.com", IPv4: "162.248.221.199", IPv6: "2607:f740:50::1d1"},
					{Name: "21c", RegionID: 21, HostName: "derp21c.tailscale.com", IPv4: "162.248.221.215", IPv6: "2607:f740:50::f10"},
					{Name: "21d", RegionID: 21, HostName: "derp21d.tailscale.com", IPv4: "162.248.221.248", IPv6: "2607:f740:50::ca4"},
				},
			},
			22: {
				RegionID: 22, RegionCode: "waw", RegionName: "Warsaw",
				Nodes: []*tailcfg.DERPNode{
					{Name: "22b", RegionID: 22, HostName: "derp22b.tailscale.com", IPv4: "45.159.98.196", IPv6: "2a00:dd80:40:100::316"},
					{Name: "22c", RegionID: 22, HostName: "derp22c.tailscale.com", IPv4: "45.159.98.253", IPv6: "2a00:dd80:40:100::3f"},
					{Name: "22d", RegionID: 22, HostName: "derp22d.tailscale.com", IPv4: "45.159.98.145", IPv6: "2a00:dd80:40:100::211"},
				},
			},
			23: {
				RegionID: 23, RegionCode: "dbi", RegionName: "Dubai",
				Nodes: []*tailcfg.DERPNode{
					{Name: "23b", RegionID: 23, HostName: "derp23b.tailscale.com", IPv4: "185.34.3.232", IPv6: "2a00:dd80:3f:100::76f"},
					{Name: "23c", RegionID: 23, HostName: "derp23c.tailscale.com", IPv4: "185.34.3.207", IPv6: "2a00:dd80:3f:100::a50"},
					{Name: "23d", RegionID: 23, HostName: "derp23d.tailscale.com", IPv4: "185.34.3.75", IPv6: "2a00:dd80:3f:100::97e"},
				},
			},
			24: {
				RegionID: 24, RegionCode: "hnl", RegionName: "Honolulu",
				Nodes: []*tailcfg.DERPNode{
					{Name: "24b", RegionID: 24, HostName: "derp24b.tailscale.com", IPv4: "208.83.234.151", IPv6: "2001:19f0:c000:c586:5400:04ff:fe26:2ba6"},
					{Name: "24c", RegionID: 24, HostName: "derp24c.tailscale.com", IPv4: "208.83.233.233", IPv6: "2001:19f0:c000:c591:5400:04ff:fe26:2c5f"},
					{Name: "24d", RegionID: 24, HostName: "derp24d.tailscale.com", IPv4: "208.72.155.133", IPv6: "2001:19f0:c000:c564:5400:04ff:fe26:2ba8"},
				},
			},
			25: {
				RegionID: 25, RegionCode: "nai", RegionName: "Nairobi",
				Nodes: []*tailcfg.DERPNode{
					{Name: "25b", RegionID: 25, HostName: "derp25b.tailscale.com", IPv4: "102.67.167.245", IPv6: "2c0f:edb0:2000:1::2e9"},
					{Name: "25c", RegionID: 25, HostName: "derp25c.tailscale.com", IPv4: "102.67.167.37", IPv6: "2c0f:edb0:2000:1::2c7"},
					{Name: "25d", RegionID: 25, HostName: "derp25d.tailscale.com", IPv4: "102.67.167.188", IPv6: "2c0f:edb0:2000:1::188"},
				},
			},
			26: {
				RegionID: 26, RegionCode: "nue", RegionName: "Nuremberg",
				Nodes: []*tailcfg.DERPNode{
					{Name: "26b", RegionID: 26, HostName: "derp26b.tailscale.com", IPv4: "167.235.72.200", IPv6: "2a01:4f8:1c1c:47b6::1"},
					{Name: "26c", RegionID: 26, HostName: "derp26c.tailscale.com", IPv4: "49.12.193.137", IPv6: "2a01:4f8:1c1c:5c70::1"},
					{Name: "26d", RegionID: 26, HostName: "derp26d.tailscale.com", IPv4: "49.13.204.141", IPv6: "2a01:4f8:1c0c:7d06::1"},
				},
			},
			27: {
				RegionID: 27, RegionCode: "iad", RegionName: "Ashburn",
				Nodes: []*tailcfg.DERPNode{
					{Name: "27b", RegionID: 27, HostName: "derp27b.tailscale.com", IPv4: "5.161.218.233", IPv6: "2a01:4ff:f0:3db9::1"},
					{Name: "27c", RegionID: 27, HostName: "derp27c.tailscale.com", IPv4: "178.156.152.91", IPv6: "2a01:4ff:f0:3913::1"},
					{Name: "27d", RegionID: 27, HostName: "derp27d.tailscale.com", IPv4: "178.156.152.106", IPv6: "2a01:4ff:f0:3c8e::1"},
					{Name: "27e", RegionID: 27, HostName: "derp27e.tailscale.com", IPv4: "178.156.134.232", IPv6: "2a01:4ff:f0:28d4::1"},
				},
			},
			28: {
				RegionID: 28, RegionCode: "hel", RegionName: "Helsinki",
				Nodes: []*tailcfg.DERPNode{
					{Name: "28b", RegionID: 28, HostName: "derp28b.tailscale.com", IPv4: "65.109.143.62", IPv6: "2a01:4f9:c012:d55c::1"},
					{Name: "28c", RegionID: 28, HostName: "derp28c.tailscale.com", IPv4: "95.217.2.165", IPv6: "2a01:4f9:c012:cd74::1"},
					{Name: "28d", RegionID: 28, HostName: "derp28d.tailscale.com", IPv4: "157.180.28.32", IPv6: "2a01:4f9:c012:2e5b::1"},
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

// lastKnownDERPMap caches the most recently successfully loaded map.
// Used as a fallback between the Tailscale live fetch and the hardcoded map —
// always more accurate than hardcoded IPs which rot over time.
var (
	lastKnownDERPMap   *tailcfg.DERPMap
	lastKnownDERPMapMu sync.RWMutex
)

// LoadDERPMap loads the DERP map using a priority chain:
//
//  1. Tailscale's public live map (20+ regions, always up-to-date)
//  2. DERP_MAP_URLS env var — comma-separated admin-served maps merged on top
//  3. Last known good map — cached in memory from the most recent successful load
//  4. Hardcoded fallback — last resort when the process has never loaded a live map
//
// This is called on every DERP connect attempt so the map is always fresh.
// A region that disappears from the live map is evicted automatically.
func LoadDERPMap() *tailcfg.DERPMap {
	const tailscaleURL = "https://login.tailscale.com/derpmap/default"

	base := fetchDERPMap(tailscaleURL)
	if base == nil {
		lastKnownDERPMapMu.RLock()
		cached := lastKnownDERPMap
		lastKnownDERPMapMu.RUnlock()
		if cached != nil {
			slog.Info("MagicBind: Tailscale DERP map unavailable, using last known good map")
			base = cached
		} else {
			slog.Info("MagicBind: Tailscale DERP map unavailable, using hardcoded fallback")
			base = hardcodedDERPMap()
		}
	}

	adminURLs := os.Getenv("DERP_MAP_URLS")
	if adminURLs == "" {
		// Cache and return — no overlay to merge
		lastKnownDERPMapMu.Lock()
		lastKnownDERPMap = base
		lastKnownDERPMapMu.Unlock()
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

	// Cache the fully merged map — this is what actually worked last time
	lastKnownDERPMapMu.Lock()
	lastKnownDERPMap = base
	lastKnownDERPMapMu.Unlock()

	return base
}
