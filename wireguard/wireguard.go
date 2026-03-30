package wireguard

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/gravitl/netclient/cache"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netmaker/logger"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	IPv4Network = "0.0.0.0/0"
	IPv6Network = "::/0"
)

// ShouldReplace - checks curr peers and incoming peers to see if the peers should be replaced
func ShouldReplace(incomingPeers []wgtypes.PeerConfig) bool {
	hostPeers := config.Netclient().HostPeers
	if len(incomingPeers) != len(hostPeers) {
		return true
	}

	hostpeerMap := make(map[string]struct{})
	for _, hostPeer := range hostPeers {
		hostpeerMap[hostPeer.PublicKey.String()] = struct{}{}
	}
	incomingPeerMap := make(map[string]struct{})
	for _, peer := range incomingPeers {
		incomingPeerMap[peer.PublicKey.String()] = struct{}{}
		if _, ok := hostpeerMap[peer.PublicKey.String()]; !ok {
			return true
		}
	}
	for _, hostPeer := range hostPeers {
		if _, ok := incomingPeerMap[hostPeer.PublicKey.String()]; !ok {
			return true
		}
	}
	return false
}

// SetPeers - sets peers on netmaker WireGuard interface
func SetPeers(replace bool) error {
	wgMutex.Lock()
	defer wgMutex.Unlock()
	peers := config.Netclient().HostPeers
	server := config.GetServer(config.CurrServer)
	if server == nil {
		return errors.New("server config not found")
	}
	data := getHAEgressDataForProcessing(server.MetricsPort)
	for i := range peers {
		peer := peers[i]
		if peer.Endpoint != nil && peer.Endpoint.IP == nil {
			peers[i].Endpoint = nil
		}
		if !peer.Remove && checkForBetterEndpoint(&peer) {
			peers[i] = peer
		}
		// set egress routes on correct peer
		if !peer.Remove && checkIfEgressHAPeer(&peer, data) {
			peers[i] = peer
		}

	}

	GetInterface().Config.Peers = peers
	// on freebsd, calling wgcltl.Client.ConfigureDevice() with []Peers{} causes an ioctl error --> ioctl: bad address
	if len(peers) == 0 {
		peers = nil
	}
	config := wgtypes.Config{
		ReplacePeers: replace,
		Peers:        peers,
	}
	return apply(&config)
}

// == private ==

// UpdatePeer replaces a wireguard peer
// temporarily making public func to pass staticchecks
// this function will be required in future when update node on server is refactored
func UpdatePeer(p *wgtypes.PeerConfig) error {
	config := wgtypes.Config{
		Peers:        []wgtypes.PeerConfig{*p},
		ReplacePeers: false,
	}
	return apply(&config)
}

func apply(c *wgtypes.Config) error {
	// IMPORTANT: Update MagicBind peer mappings BEFORE ConfigureDevice.
	// Peers must be in place before BindUpdate() fires so ParseEndpoint can find them.
	updateMagicBindPeersFromConfig(c.Peers)

	wg, err := wgctrl.New()
	if err != nil {
		return fmt.Errorf("wgctrl %w", err)
	}
	defer wg.Close()

	ifaceName := ncutils.GetInterfaceName()

	// For userspace WireGuard, ConfigureDevice deadlocks in IpcHandle.
	// Write UAPI commands directly to the socket instead.
	if os.Getenv("WG_QUICK_USERSPACE_IMPLEMENTATION") == "wireguard-go" {
		if err = configureViaDirectUAPI(ifaceName, c); err != nil {
			return err
		}
		// wireguard-go calls BindUpdate() during UAPI processing which triggers Close()
		// but does NOT always follow with Open(). Restore sockets if needed.
		if currentMagicBind != nil {
			currentMagicBind.EnsureOpen()
		}
		return nil
	}

	// Kernel WireGuard path
	return wg.ConfigureDevice(ifaceName, *c)
}

// updateMagicBindPeersFromConfig is a stub that will be implemented in wireguard_unix.go for userspace WireGuard
// For kernel WireGuard (or when not using userspace), this is a no-op
// This takes the peers from config directly, bypassing wgctrl which blocks on userspace WireGuard
var updateMagicBindPeersFromConfig = func(peers []wgtypes.PeerConfig) {
	// No-op by default (kernel WireGuard doesn't use MagicBind)
}

// returns if better endpoint has been calculated for this peer already
// if so sets it and returns true
func checkForBetterEndpoint(peer *wgtypes.PeerConfig) bool {
	if endpoint, ok := cache.EndpointCache.Load(peer.PublicKey.String()); ok && endpoint != nil {
		var cacheEndpoint cache.EndpointCacheValue
		cacheEndpoint, ok = endpoint.(cache.EndpointCacheValue)
		if ok {
			peer.Endpoint = cacheEndpoint.Endpoint
		}
		return ok
	}
	return false
}

func GetBetterEndpoint(peerKey string) (*net.UDPAddr, bool) {
	if endpoint, ok := cache.EndpointCache.Load(peerKey); ok && endpoint != nil {
		var cacheEndpoint cache.EndpointCacheValue
		cacheEndpoint, ok = endpoint.(cache.EndpointCacheValue)
		if ok {
			return cacheEndpoint.Endpoint, ok
		}
	}
	return nil, false
}

// EndpointDetectedAlready - checks if better endpoint has been detected already
func EndpointDetectedAlready(peerPubKey string) bool {
	if endpoint, ok := cache.EndpointCache.Load(peerPubKey); ok && endpoint != nil {
		return true
	}
	return false
}

func GetPeersFromDevice(ifaceName string) (map[string]wgtypes.Peer, error) {
	peerMap := make(map[string]wgtypes.Peer)
	wg, err := wgctrl.New()
	if err != nil {
		return nil, err
	}
	defer func() {
		err = wg.Close()
		if err != nil {
			logger.Log(0, "got error while closing wgctl: ", err.Error())
		}
	}()
	wgDevice, err := wg.Device(ifaceName)
	if err != nil {
		return nil, err
	}
	for _, peer := range wgDevice.Peers {
		peerMap[peer.PublicKey.String()] = peer
	}
	return peerMap, nil
}

// GetPeer - gets the peerinfo from the wg interface
func GetPeer(ifaceName, peerPubKey string) (wgtypes.Peer, error) {
	wg, err := wgctrl.New()
	if err != nil {
		return wgtypes.Peer{}, err
	}
	defer func() {
		err = wg.Close()
		if err != nil {
			logger.Log(0, "got error while closing wgctl: ", err.Error())
		}
	}()
	wgDevice, err := wg.Device(ifaceName)
	if err != nil {
		return wgtypes.Peer{}, err
	}
	for _, peer := range wgDevice.Peers {
		if peer.PublicKey.String() == peerPubKey {
			return peer, nil
		}
	}
	return wgtypes.Peer{}, fmt.Errorf("peer not found")
}

// GetOriginalDefaulGw - fetches system's original default gw
func GetOriginalDefaulGw() (gwIP net.IP, err error) {
	gwIP = config.Netclient().OriginalDefaultGatewayIp
	if gwIP.String() == "" {
		gwIP, err = GetDefaultGatewayIp()
	}
	return
}

// GetIPNetfromIp - converts ip into ipnet based network class
func GetIPNetfromIp(ip net.IP) (ipCidr *net.IPNet) {
	if ipv4 := ip.To4(); ipv4 != nil {
		_, ipCidr, _ = net.ParseCIDR(fmt.Sprintf("%s/32", ipv4.String()))

	} else {
		_, ipCidr, _ = net.ParseCIDR(fmt.Sprintf("%s/128", ipv4.String()))
	}
	return
}

// configureViaDirectUAPI writes UAPI commands directly to the WireGuard socket.
// This bypasses wgctrl.ConfigureDevice() which deadlocks with userspace WireGuard
// due to IpcHandle() holding the device lock during BindUpdate.
func configureViaDirectUAPI(ifaceName string, c *wgtypes.Config) error {
	socketPath := fmt.Sprintf("/var/run/wireguard/%s.sock", ifaceName)
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return fmt.Errorf("failed to connect to UAPI socket: %w", err)
	}
	defer conn.Close()

	// keyToHex converts a wgtypes.Key (base64) to lowercase hex.
	// UAPI protocol requires hex-encoded keys.
	keyToHex := func(key *wgtypes.Key) string {
		if key == nil {
			return ""
		}
		keyBytes := key[:]
		hexStr := make([]byte, len(keyBytes)*2)
		const hexDigits = "0123456789abcdef"
		for i, b := range keyBytes {
			hexStr[i*2] = hexDigits[b>>4]
			hexStr[i*2+1] = hexDigits[b&0xf]
		}
		return string(hexStr)
	}

	// Build UAPI command string.
	// "set=1\n" must be the first line — IpcHandle() dispatches on it.
	// Without it, IpcHandle hits the default case and closes immediately (silent rejection).
	var uapiCmd strings.Builder
	uapiCmd.WriteString("set=1\n")

	if c.PrivateKey != nil {
		uapiCmd.WriteString(fmt.Sprintf("private_key=%s\n", keyToHex(c.PrivateKey)))
	}
	if c.ListenPort != nil {
		uapiCmd.WriteString(fmt.Sprintf("listen_port=%d\n", *c.ListenPort))
	}
	if c.FirewallMark != nil {
		uapiCmd.WriteString(fmt.Sprintf("fwmark=%d\n", *c.FirewallMark))
	}
	if c.ReplacePeers {
		uapiCmd.WriteString("replace_peers=true\n")
	}

	for _, peer := range c.Peers {
		uapiCmd.WriteString(fmt.Sprintf("public_key=%s\n", keyToHex(&peer.PublicKey)))
		if peer.Remove {
			uapiCmd.WriteString("remove=true\n")
			continue
		}
		if peer.PresharedKey != nil && peer.PresharedKey.String() != "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" {
			uapiCmd.WriteString(fmt.Sprintf("preshared_key=%s\n", keyToHex(peer.PresharedKey)))
		}
		if peer.Endpoint != nil {
			uapiCmd.WriteString(fmt.Sprintf("endpoint=%s\n", peer.Endpoint.String()))
		}
		if peer.PersistentKeepaliveInterval != nil {
			uapiCmd.WriteString(fmt.Sprintf("persistent_keepalive_interval=%d\n", int(peer.PersistentKeepaliveInterval.Seconds())))
		}
		if peer.ReplaceAllowedIPs {
			uapiCmd.WriteString("replace_allowed_ips=true\n")
		}
		for _, allowedIP := range peer.AllowedIPs {
			uapiCmd.WriteString(fmt.Sprintf("allowed_ip=%s\n", allowedIP.String()))
		}
	}

	uapiCmdStr := uapiCmd.String()
	if !strings.HasSuffix(uapiCmdStr, "\n\n") {
		uapiCmdStr += "\n"
	}

	if _, err = conn.Write([]byte(uapiCmdStr)); err != nil {
		return fmt.Errorf("failed to write UAPI command: %w", err)
	}

	// wireguard-go sends "errno=0\n\n" then stays in the read loop — set deadline to avoid blocking.
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 4096)
	n, _ := conn.Read(buf)
	if n > 0 {
		response := string(buf[:n])
		if strings.Contains(response, "errno=") && !strings.Contains(response, "errno=0") {
			return fmt.Errorf("UAPI error: %s", strings.TrimSpace(response))
		}
	}
	return nil
}
