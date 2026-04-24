//go:build linux || darwin || freebsd
// +build linux darwin freebsd

package wireguard

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/magicsock"
	"github.com/vishvananda/netlink"
	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/ipc"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// == private ==

var tunDevice *device.Device
var wg sync.WaitGroup
var uapi net.Listener
var currentMagicBind *magicsock.MagicBind // Store reference to update peers

func init() {
	// Hook up the peer update function for userspace WireGuard
	// This uses config peers directly, bypassing wgctrl which blocks on userspace WireGuard
	updateMagicBindPeersFromConfig = updateMagicBindPeersFromConfigImpl
}

// bringInterfaceUp brings the network interface UP using netlink
// This is needed for userspace WireGuard - the TUN device exists but the interface is DOWN
func bringInterfaceUp(ifaceName string) error {
	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("failed to find interface %s: %w", ifaceName, err)
	}

	// Check if already up
	if link.Attrs().Flags&net.FlagUp != 0 {
		slog.Debug("Interface already up", "interface", ifaceName)
		return nil
	}

	// Bring interface up
	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring interface %s up: %w", ifaceName, err)
	}

	slog.Info("Brought interface up", "interface", ifaceName)
	return nil
}

func (nc *NCIface) createUserSpaceWG() error {
	wgMutex.Lock()
	defer wgMutex.Unlock()

	tunIface, err := tun.CreateTUN(nc.Name, config.Netclient().MTU)
	if err != nil {
		return err
	}
	nc.Iface = tunIface

	var bind conn.Bind

	// Skip DERP for test interfaces or when explicitly disabled via DERP_ENABLED=false.
	// Test interface names are "nmt-<pid-hex>" (Linux/FreeBSD, see cmd/root.go —
	// 12 chars, stays under Linux IFNAMSIZ=16) or "utun70" (darwin). Match by prefix.
	isTestInterface := strings.HasPrefix(nc.Name, "nmt-") || nc.Name == "utun70"
	derpDisabled := os.Getenv("DERP_ENABLED") == "false"

	if isTestInterface || derpDisabled {
		if derpDisabled && !isTestInterface {
			slog.Info("DERP disabled via DERP_ENABLED=false, using standard bind", "interface", nc.Name)
		}
		bind = conn.NewDefaultBind()
		currentMagicBind = nil
	} else {
		wgKey := config.Netclient().PrivateKey
		magicBind, err := magicsock.NewMagicBind(wgKey)
		if err != nil {
			slog.Warn("MagicBind creation failed, falling back to standard bind", "error", err)
			bind = conn.NewDefaultBind()
			currentMagicBind = nil
		} else {
			bind = magicBind
			currentMagicBind = magicBind
			slog.Info("MagicBind ready", "interface", nc.Name)
		}
	}

	tunDevice = device.NewDevice(tunIface, bind, device.NewLogger(device.LogLevelSilent, "[netclient] "))
	err = tunDevice.Up()
	if err != nil {
		return err
	}

	// CRITICAL: Bring the network interface UP after creating the WireGuard device
	// The TUN device exists but the network interface needs to be UP for ApplyAddrs() to work
	if err := bringInterfaceUp(nc.Name); err != nil {
		slog.Warn("Failed to bring interface up, continuing anyway", "error", err)
		// Don't return error - ApplyAddrs will try anyway
	}

	// NOTE: Don't call updateMagicBindPeers() here - peers haven't been configured yet!
	// Peers are added later via apply() → wg.ConfigureDevice() which calls updateMagicBindPeersIfUserspace()
	uapi, err = getUAPIByInterface(nc.Name)
	if err != nil {
		return err
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-tunDevice.Wait():
				return
			default:
				uapiConn, uapiErr := uapi.Accept()
				if uapiErr != nil {
					slog.Debug("uapi error:", "error", uapiErr)
					time.Sleep(100 * time.Millisecond)
					continue
				}
				go tunDevice.IpcHandle(uapiConn)
			}
		}
	}()
	return nil
}

func getUAPIByInterface(iface string) (net.Listener, error) {
	tunSock, err := ipc.UAPIOpen(iface)
	if err != nil {
		return nil, err
	}
	return ipc.UAPIListen(iface, tunSock)
}

func (nc *NCIface) closeUserspaceWg() error {
	wgMutex.Lock()
	defer wgMutex.Unlock()
	slog.Debug("Closing userspace WireGuard interface", "interface", nc.Name)

	if tunDevice != nil {
		tunDevice.Close()
	}
	if uapi != nil {
		uapi.Close()
	}
	wg.Wait()

	slog.Debug("Closed userspace WireGuard interface", "interface", nc.Name)

	return nil
}

func isEconnRefused(err error) bool {
	var errno syscall.Errno
	return errors.As(err, &errno) && errors.Is(errno, syscall.ECONNREFUSED)
}

// updateMagicBindPeersFromConfigImpl updates the MagicBind peer mapping from config peers
// This bypasses wgctrl which blocks on userspace WireGuard UAPI socket
// It also updates peers that have no real endpoint to use DERP magic endpoints
func updateMagicBindPeersFromConfigImpl(peers []wgtypes.PeerConfig) {
	if currentMagicBind == nil {
		return
	}

	derpEndpoints := currentMagicBind.UpdatePeersFromConfig(peers)

	// Assign DERP magic endpoints to peers without real endpoints
	for i := range peers {
		if peers[i].Endpoint == nil && !peers[i].Remove {
			peerKeyStr := peers[i].PublicKey.String()
			if derpEndpoint, ok := derpEndpoints[peerKeyStr]; ok {
				peers[i].Endpoint = derpEndpoint
			}
		}
	}
}
