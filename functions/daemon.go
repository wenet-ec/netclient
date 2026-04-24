package functions

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"io"
	"net"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	externalip "github.com/glendc/go-external-ip"
	"github.com/gravitl/netclient/auth"
	"github.com/gravitl/netclient/cache"
	"github.com/gravitl/netclient/config"
	"github.com/gravitl/netclient/daemon"
	"github.com/gravitl/netclient/dns"
	"github.com/gravitl/netclient/firewall"
	"github.com/gravitl/netclient/flow"
	"github.com/gravitl/netclient/local"
	"github.com/gravitl/netclient/ncutils"
	"github.com/gravitl/netclient/networking"
	"github.com/gravitl/netclient/stun"
	"github.com/gravitl/netclient/wireguard"
	"github.com/gravitl/netmaker/logger"
	"github.com/gravitl/netmaker/logic"
	"github.com/gravitl/netmaker/models"
	"github.com/gravitl/netmaker/schema"
	"golang.org/x/exp/slog"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	lastNodeUpdate   = "lnu"
	lastDNSUpdate    = "ldu"
	lastALLDNSUpdate = "ladu"
	// MQ_TIMEOUT - timeout for MQ
	MQ_TIMEOUT = 30
)

var (
	Mqclient     mqtt.Client
	messageCache = new(sync.Map)
)

type cachedMessage struct {
	Message  string
	LastSeen time.Time
}

// Daemon runs netclient daemon
func Daemon() {
	slog.Info("starting netclient daemon", "version", config.Version)
	daemon.SetDaemonMode()
	daemon.RemoveAllLockFiles()
	if err := ncutils.SavePID(); err != nil {
		slog.Error("unable to save PID on daemon startup", "error", err)
		os.Exit(1)
	}
	if err := local.SetIPForwarding(); err != nil {
		slog.Warn("unable to set IPForwarding", "error", err)
	}
	wg := sync.WaitGroup{}
	quit := make(chan os.Signal, 1)
	reset := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, os.Interrupt)
	signal.Notify(reset, syscall.SIGHUP)

	daemonStartTime := time.Now()
	lastCycleTime := daemonStartTime
	cancel := startGoRoutines(&wg)

	for {
		select {
		case sig := <-quit:
			logger.Log(0, fmt.Sprintf("received %s — beginning shutdown (uptime=%s, since_last_cycle=%s)",
				sig, time.Since(daemonStartTime).Round(time.Millisecond),
				time.Since(lastCycleTime).Round(time.Millisecond)))
			logSignalForensics(sig)
			dns.GetDNSServerInstance().Stop()
			_ = flow.GetManager().Stop()
			//check if it needs to restore the default gateway
			checkAndRestoreDefaultGateway()
			closeRoutines([]context.CancelFunc{
				cancel,
			}, &wg)
			config.FwClose()
			logger.Log(0, "shutdown complete — daemon exiting")
			return
		case sig := <-reset:
			logger.Log(0, fmt.Sprintf("received %s — beginning reset (uptime=%s, since_last_cycle=%s)",
				sig, time.Since(daemonStartTime).Round(time.Millisecond),
				time.Since(lastCycleTime).Round(time.Millisecond)))
			logSignalForensics(sig)
			dns.GetDNSServerInstance().Stop()
			_ = flow.GetManager().Stop()
			config.FwClose()
			//check if it needs to restore the default gateway
			checkAndRestoreDefaultGateway()
			closeRoutines([]context.CancelFunc{
				cancel,
			}, &wg)
			logger.Log(0, "resetting daemon — spawning new startGoRoutines cycle")
			cancel = startGoRoutines(&wg)
			lastCycleTime = time.Now()
		}
	}
}

// logSignalForensics writes a snapshot of surrounding process state when a
// signal lands on the daemon loop. Goal: identify who delivered the signal.
//
// Go's os/signal does not expose siginfo_t (sender PID/UID). On Linux,
// signalfd(2) could in principle capture siginfo, but it requires blocking
// the signal process-wide with PthreadSigmask — which in Go's M:N threading
// model is unreliable (see golang/go#20479). Instead we capture a best-effort
// snapshot: our own ppid, any tracer, and a minimal enumeration of live
// processes at the moment the signal was handled. The sender is usually
// still alive and will appear in the enumeration.
func logSignalForensics(sig os.Signal) {
	ppid := os.Getppid()
	tracer := readTracerPid()
	logger.Log(0, fmt.Sprintf("signal forensics: sig=%s self_pid=%d ppid=%d tracer_pid=%d",
		sig, os.Getpid(), ppid, tracer))

	entries, err := os.ReadDir("/proc")
	if err != nil {
		logger.Log(0, fmt.Sprintf("signal forensics: /proc read failed: %v", err))
		return
	}
	type procInfo struct {
		pid    int
		ppid   int
		state  string
		comm   string
	}
	var procs []procInfo
	for _, e := range entries {
		name := e.Name()
		if len(name) == 0 || name[0] < '0' || name[0] > '9' {
			continue
		}
		pid := 0
		for _, c := range name {
			if c < '0' || c > '9' {
				pid = -1
				break
			}
			pid = pid*10 + int(c-'0')
		}
		if pid <= 0 {
			continue
		}
		data, err := os.ReadFile("/proc/" + name + "/stat")
		if err != nil {
			continue
		}
		// /proc/PID/stat format: pid (comm) state ppid ...
		// comm may contain spaces and parens; scan for last ')' to delimit.
		s := string(data)
		lp := -1
		for i := len(s) - 1; i >= 0; i-- {
			if s[i] == ')' {
				lp = i
				break
			}
		}
		if lp < 0 {
			continue
		}
		commStart := -1
		for i := 0; i < len(s); i++ {
			if s[i] == '(' {
				commStart = i + 1
				break
			}
		}
		if commStart < 0 || commStart > lp {
			continue
		}
		comm := s[commStart:lp]
		rest := s[lp+1:]
		var state string
		var ppid2 int
		fmt.Sscanf(rest, " %s %d", &state, &ppid2)
		procs = append(procs, procInfo{pid: pid, ppid: ppid2, state: state, comm: comm})
	}
	for _, p := range procs {
		logger.Log(0, fmt.Sprintf("signal forensics: proc pid=%d ppid=%d state=%s comm=%q",
			p.pid, p.ppid, p.state, p.comm))
	}
}

func readTracerPid() int {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return -1
	}
	s := string(data)
	needle := "TracerPid:\t"
	i := 0
	for i = 0; i+len(needle) < len(s); i++ {
		if s[i:i+len(needle)] == needle {
			break
		}
	}
	if i+len(needle) >= len(s) {
		return -1
	}
	j := i + len(needle)
	v := 0
	for j < len(s) && s[j] >= '0' && s[j] <= '9' {
		v = v*10 + int(s[j]-'0')
		j++
	}
	return v
}

// checkAndRestoreDefaultGateway -check if it needs to restore the default gateway
func checkAndRestoreDefaultGateway() {
	if config.Netclient().CurrGwNmIP == nil {
		return
	}
	//get the current default gateway
	ip, err := wireguard.GetDefaultGatewayIp()
	if err != nil {
		slog.Error("error loading current default gateway", "error", err.Error())
		return
	}
	//restore the default gateway when the current default gateway is not the same as the one in config
	if !config.Netclient().OriginalDefaultGatewayIp.Equal(ip) {
		err = wireguard.RestoreInternetGw()
		if err != nil {
			slog.Error("error restoring default gateway", "error", err.Error())
			return
		}
	}
}

func closeRoutines(closers []context.CancelFunc, wg *sync.WaitGroup) {
	// Breadcrumbs around every step that could hang during SIGHUP teardown.
	// If the daemon gets stuck here during a reset and never produces the
	// startGoRoutines breadcrumbs below, the last line that DID appear tells
	// us exactly which step is hung. Kept at Info so they appear in default
	// log verbosity without having to bump to debug.
	logger.Log(0, fmt.Sprintf("closeRoutines: cancelling goroutine contexts (count=%d)", len(closers)))
	for i := range closers {
		closers[i]()
	}
	if Mqclient != nil {
		logger.Log(0, "closeRoutines: disconnecting MQTT client")
		Mqclient.Disconnect(250)
	}
	logger.Log(0, "closeRoutines: waiting for goroutines to exit")
	wg.Wait()
	logger.Log(0, "closeRoutines: goroutines exited, clearing caches")
	// clear cache
	auth.CleanJwtToken()
	networking.ClearPeerInfoCache()
	cache.EndpointCache = sync.Map{}
	cache.SkipEndpointCache = sync.Map{}
	cache.EgressRouteCache = sync.Map{}
	signalThrottleCache = sync.Map{}
	slog.Info("closing netmaker interface")
	iface := wireguard.GetInterface()
	iface.Close()
	logger.Log(0, "closeRoutines: interface closed, teardown complete")
}

// startGoRoutines starts the daemon goroutines
func startGoRoutines(wg *sync.WaitGroup) context.CancelFunc {
	// Breadcrumbs around every step. See closeRoutines comment above — same
	// rationale. These are paired with the teardown breadcrumbs so a stalled
	// restart cycle shows up as a specific last-line in the log.
	logger.Log(0, "startGoRoutines: beginning daemon restart cycle")
	ctx, cancel := context.WithCancel(context.Background())
	logger.Log(0, "startGoRoutines: reading netclient config")
	if _, err := config.ReadNetclientConfig(); err != nil {
		slog.Warn("error reading netclient config file", "error", err)
	}

	config.UpdateNetclient(*config.Netclient())
	ncutils.SetInterfaceName(config.Netclient().Interface)
	logger.Log(0, "startGoRoutines: reading server config")
	if err := config.ReadServerConf(); err != nil {
		slog.Warn("error reading server map from disk", "error", err)
	}
	if len(config.GetServers()) == 0 {
		if err := config.RestoreServerConfFromBackup(); err == nil {
			slog.Info("restored server config from backup after TOCTOU race")
			_ = config.ReadServerConf()
		} else {
			slog.Error("server config empty and backup restore failed — daemon will run without server config until next enrollment or pull", "error", err)
		}
	}
	if len(config.GetNodes()) == 0 {
		if err := config.RestoreNodeConfFromBackup(); err == nil {
			slog.Info("restored node config from backup after TOCTOU race")
			_ = config.ReadNodeConfig()
		} else {
			slog.Error("node config empty and backup restore failed — daemon will run without node config until next enrollment or pull", "error", err)
		}
	}
	// initialize firewall manager
	logger.Log(0, "startGoRoutines: initializing firewall")
	var err error
	config.FwClose, err = firewall.Init()
	if err != nil {
		slog.Info("failed to intialize firewall: ", "error", err.Error())
	}
	logger.Log(0, "startGoRoutines: firewall initialized")
	updateConfig := false

	config.SetServerCtx()
	server := config.GetServer(config.CurrServer)
	if server == nil {
		server = &config.Server{}
		server.Stun = true
		server.StunServers = ""
	}

	logger.Log(0, "startGoRoutines: loading STUN servers")
	if server.Stun && server.StunServers != "" {
		stun.LoadStunServers(server.StunServers)
	} else {
		stun.SetDefaultStunServers()
	}
	netclientCfg := config.Netclient()

	logger.Log(0, "startGoRoutines: initializing DNS manager")
	err = dns.Init()
	if err != nil {
		logger.Log(0, "error initializing dns manager:", err.Error())
	}
	slog.Info("configuring netmaker wireguard interface")
	var pullresp models.HostPull
	var pullErr error
	if server != nil && server.API != "" {
		logger.Log(0, "startGoRoutines: pulling config from server")
		pullresp, _, _, pullErr = Pull(false, true)
		if pullErr != nil {
			slog.Error("fail to pull config from server", "error", pullErr.Error())
		} else {
			logger.Log(0, "startGoRoutines: pull from server complete")
		}
	}

	if !netclientCfg.IsStaticPort {
		if freeport, err := ncutils.GetFreePort(ncutils.NetclientDefaultPort, netclientCfg.ListenPort, false); err != nil {
			slog.Warn("no free ports available for use by netclient", "error", err.Error())
		} else if freeport != netclientCfg.ListenPort {
			slog.Info("port has changed", "old port", netclientCfg.ListenPort, "new port", freeport)
			netclientCfg.ListenPort = freeport
			updateConfig = true
		}

	} else {
		netclientCfg.WgPublicListenPort = netclientCfg.ListenPort
		updateConfig = true
	}

	if !netclientCfg.IsStatic {
		// IPV4
		logger.Log(0, "startGoRoutines: hole-punching WG public port (IPv4 STUN)")
		config.HostPublicIP, config.WgPublicListenPort, config.HostNatType = holePunchWgPort(4, netclientCfg.ListenPort)
		slog.Info("wireguard public listen port: ", "port", config.WgPublicListenPort)
		if config.HostPublicIP != nil && !config.HostPublicIP.IsUnspecified() {
			netclientCfg.EndpointIP = config.HostPublicIP
			updateConfig = true
		} else {
			slog.Warn("GetPublicIPv4 error:", "Warn", "no ipv4 found")
			if netclientCfg.EndpointIP != nil {
				config.HostPublicIP = netclientCfg.EndpointIP
				slog.Info("seeded HostPublicIP from stored endpoint", "ip", netclientCfg.EndpointIP)
			}
		}
		if netclientCfg.NatType == "" {
			netclientCfg.NatType = config.HostNatType
			updateConfig = true
		}
		// IPV6
		logger.Log(0, "startGoRoutines: hole-punching WG public port (IPv6 STUN)")
		publicIP6, wgport, natType := holePunchWgPort(6, netclientCfg.ListenPort)
		if publicIP6 != nil && !publicIP6.IsUnspecified() {
			netclientCfg.EndpointIPv6 = publicIP6
			config.HostPublicIP6 = publicIP6
			if config.HostPublicIP == nil {
				config.WgPublicListenPort = wgport
				config.HostNatType = natType
			}
			updateConfig = true
		} else {
			slog.Warn("GetPublicIPv6 Warn: ", "Warn", "no ipv6 found")
			if netclientCfg.EndpointIPv6 != nil {
				config.HostPublicIP6 = netclientCfg.EndpointIPv6
				slog.Info("seeded HostPublicIP6 from stored endpoint", "ip", netclientCfg.EndpointIPv6)
			}
		}
		if netclientCfg.WgPublicListenPort != config.WgPublicListenPort {
			netclientCfg.WgPublicListenPort = config.WgPublicListenPort
			updateConfig = true
		}

	}

	originalDefaultGwIP, err := wireguard.GetDefaultGatewayIp()
	if err == nil && originalDefaultGwIP != nil && (netclientCfg.CurrGwNmIP == nil || !netclientCfg.CurrGwNmIP.Equal(originalDefaultGwIP)) {
		netclientCfg.OriginalDefaultGatewayIp = originalDefaultGwIP
		updateConfig = true
	}

	if updateConfig {
		config.UpdateNetclient(*netclientCfg)
		if err := config.WriteNetclientConfig(); err != nil {
			slog.Warn("error writing endpoint/port netclient config file", "error", err)
		}
	}

	logger.Log(0, "startGoRoutines: creating netclient interface")
	nc := wireguard.NewNCIface(netclientCfg, config.GetNodes())
	if err := nc.Create(); err != nil {
		slog.Error("error creating netclient interface", "error", err)
	}
	logger.Log(0, "startGoRoutines: configuring netclient interface")
	if err := nc.Configure(); err != nil {
		slog.Error("error configuring netclient interface", "error", err)
	}
	logger.Log(0, "startGoRoutines: applying peer configuration")
	wireguard.SetPeers(true)
	logger.Log(0, "startGoRoutines: peers applied")
	if len(pullresp.EgressRoutes) > 0 {
		wireguard.SetEgressRoutes(pullresp.EgressRoutes)
		wireguard.SetEgressRoutesInCache(pullresp.EgressRoutes)
	} else {
		wireguard.RemoveEgressRoutes()
	}
	setAutoRelayNodes(pullresp.AutoRelayNodes, pullresp.GwNodes, pullresp.Nodes)
	if pullErr == nil && pullresp.EndpointDetection {
		go handleEndpointDetection(pullresp.Peers, pullresp.HostNetworkInfo)
	} else {
		cache.EndpointCache = sync.Map{}
		cache.SkipEndpointCache = sync.Map{}
	}
	server = config.GetServer(config.CurrServer)
	if server == nil {
		logger.Log(0, "startGoRoutines: early return — no server config after peers applied; daemon will have no message queue / checkin / iface metrics / DNS until next enrollment or successful pull")
		return cancel
	}
	logger.Log(1, "started daemon for server ", server.Name)
	// set original default gw info

	// check if default gw needs to be set
	if pullErr == nil {
		gwIP, err := wireguard.GetDefaultGatewayIp()
		if err == nil {
			if pullresp.ChangeDefaultGw && !pullresp.DefaultGwIp.Equal(gwIP) {
				if !wireguard.GetIGWMonitor().IsCurrentIGW(gwIP) {
					var igw wgtypes.PeerConfig
					for _, peer := range pullresp.Peers {
						for _, peerIP := range peer.AllowedIPs {
							if peerIP.String() == wireguard.IPv4Network || peerIP.String() == wireguard.IPv6Network {
								igw = peer
								break
							}
						}
					}

					// unlikely that the gwIP is netmaker IP, but still
					// reset the igw.
					_ = wireguard.RestoreInternetGw()

					err = wireguard.SetInternetGw(igw.PublicKey.String(), pullresp.DefaultGwIp)
					if err != nil {
						slog.Warn("failed to set inet gw", "error", err)
					}
				}
			}
		}
	}

	logger.Log(0, "startGoRoutines: spawning message queue + checkin + iface metrics goroutines")
	wg.Add(1)
	go messageQueue(ctx, wg, server)
	wg.Add(1)
	go Checkin(ctx, wg)
	networking.InitialiseIfaceMetricsServer(ctx, wg)
	if server.IsPro {
		wg.Add(1)
		go watchPeerConnections(ctx, wg)
		wg.Add(1)
		go wireguard.StartEgressHAFailOverThread(ctx, wg)
	} else {
		wg.Add(1)
		go networking.CheckPeerEndpoints(ctx, wg)
	}
	wg.Add(1)
	go mqFallback(ctx, wg)

	if server.ManageDNS {
		if dns.GetDNSServerInstance().AddrStr == "" {
			logger.Log(0, "startGoRoutines: starting DNS listener")
			dns.GetDNSServerInstance().Start()
		}
	} else {
		dns.GetDNSServerInstance().Stop()
	}
	go func() {
		time.Sleep(time.Second * 45)
		callPublishMetrics(true)
	}()
	go handleFwUpdate(server.Server, &pullresp.FwUpdate)
	logger.Log(0, "startGoRoutines: daemon restart cycle complete")
	return cancel
}

// sets up Message Queue and subsribes/publishes updates to/from server
// the client should subscribe to ALL nodes that exist on server locally
func messageQueue(ctx context.Context, wg *sync.WaitGroup, server *config.Server) {
	defer wg.Done()
	slog.Info("netclient message queue started for server:", "server", server.Name)
	err := setupMQTT(server)
	if err != nil {
		slog.Error("unable to connect to broker", "server", server.Broker, "error", err)
		return
	}
	defer func() {
		if Mqclient != nil {
			Mqclient.Disconnect(250)
		}
	}()
	<-ctx.Done()
	slog.Info("shutting down message queue", "server", server.Name)
}

// setupMQTT creates a connection to broker
func setupMQTT(server *config.Server) error {
	opts := mqtt.NewClientOptions()
	opts.AddBroker(server.Broker)
	if server.BrokerType == "emqx" {
		opts.SetUsername(config.Netclient().ID.String())
		opts.SetPassword(config.Netclient().HostPass)
	} else {
		opts.SetUsername(server.MQUserName)
		opts.SetPassword(server.MQPassword)
	}
	opts.SetClientID(logic.RandomString(23))
	opts.SetAutoReconnect(true)
	opts.SetConnectRetry(true)
	opts.SetConnectRetryInterval(time.Second << 2)
	opts.SetKeepAlive(time.Second * 15)
	opts.SetWriteTimeout(time.Minute)
	opts.SetCleanSession(true)
	opts.SetOnConnectHandler(func(client mqtt.Client) {
		slog.Info("mqtt connect handler")
		nodes := config.GetNodes()
		for _, node := range nodes {
			node := node
			setSubscriptions(client, &node)
			setDNSSubscriptions(client, &node, server.Name)
		}
		setHostSubscription(client, server.Name)
		time.Sleep(time.Second * 3)
		checkin()
	})
	opts.SetOrderMatters(false)
	opts.SetResumeSubs(true)
	opts.SetConnectionLostHandler(func(c mqtt.Client, e error) {
		slog.Warn("detected broker connection lost for", "server", server.Broker)
	})
	Mqclient = mqtt.NewClient(opts)
	var connecterr error
	for count := 0; count < 3; count++ {
		connecterr = nil
		if token := Mqclient.Connect(); !token.WaitTimeout(30*time.Second) || token.Error() != nil {
			logger.Log(0, "unable to connect to broker, retrying ...")
			if token.Error() == nil {
				connecterr = errors.New("connect timeout")
			} else {
				connecterr = token.Error()
			}
		}
	}
	if connecterr != nil {
		slog.Error("unable to connect to broker", "server", server.Broker, "error", connecterr)
		return connecterr
	}
	if err := PublishHostUpdate(server.Name, models.Acknowledgement); err != nil {
		slog.Error("failed to send initial ACK to server", "server", server.Name, "error", err)
	} else {
		slog.Info("successfully requested ACK on server", "server", server.Name)
	}
	return nil
}

// func setMQTTSingenton creates a connection to broker for single use (ie to publish a message)
// only to be called from cli (eg. connect/disconnect, join, leave) and not from daemon ---
func setupMQTTSingleton(server *config.Server, publishOnly bool) error {
	opts := mqtt.NewClientOptions()
	opts.AddBroker(server.Broker)
	if server.BrokerType == "emqx" {
		opts.SetUsername(config.Netclient().ID.String())
		opts.SetPassword(config.Netclient().HostPass)
	} else {
		opts.SetUsername(server.MQUserName)
		opts.SetPassword(server.MQPassword)
	}
	opts.SetClientID(logic.RandomString(9))
	opts.SetAutoReconnect(true)
	opts.SetConnectRetry(true)
	opts.SetConnectRetryInterval(time.Second * 4)
	opts.SetKeepAlive(time.Second * 30)
	opts.SetWriteTimeout(time.Minute)
	opts.SetCleanSession(true)
	opts.SetOnConnectHandler(func(client mqtt.Client) {
		if !publishOnly {
			slog.Info("mqtt connect handler")
			nodes := config.GetNodes()
			for _, node := range nodes {
				node := node
				setSubscriptions(client, &node)
				setDNSSubscriptions(client, &node, server.Name)
			}
			setHostSubscription(client, server.Name)
		}
		slog.Info("successfully connected to", "server", server.Broker)
	})
	opts.SetOrderMatters(true)
	opts.SetResumeSubs(true)
	opts.SetConnectionLostHandler(func(c mqtt.Client, e error) {
		slog.Warn("detected broker connection lost for", "server", server.Broker)
	})
	Mqclient = mqtt.NewClient(opts)

	var connecterr error
	if token := Mqclient.Connect(); !token.WaitTimeout(5*time.Second) || token.Error() != nil {
		if token.Error() == nil {
			connecterr = errors.New("connect timeout")
		} else {
			connecterr = token.Error()
		}
		slog.Error("unable to connect to broker", "server", server.Broker, "error", connecterr)
	}
	return connecterr
}

// setHostSubscription sets MQ client subscriptions for host
// should be called for each server host is registered on.
func setHostSubscription(client mqtt.Client, server string) {
	hostID := config.Netclient().ID
	slog.Info("subscribing to host updates for", "host", hostID, "server", server)
	//clearRetainedMsg(client, fmt.Sprintf("peers/host/%s/%s", hostID.String(), server))
	if token := client.Subscribe(fmt.Sprintf("peers/host/%s/%s", hostID.String(), server), 0, mqtt.MessageHandler(HostPeerUpdate)); token.Wait() && token.Error() != nil {
		slog.Error("unable to subscribe to host peer updates", "host", hostID, "server", server, "error", token.Error())
		return
	}
	//clearRetainedMsg(client, fmt.Sprintf("host/update/%s/%s", hostID.String(), server))
	slog.Info("subscribing to host updates for", "host", hostID, "server", server)
	if token := client.Subscribe(fmt.Sprintf("host/update/%s/%s", hostID.String(), server), 0, mqtt.MessageHandler(HostUpdate)); token.Wait() && token.Error() != nil {
		slog.Error("unable to subscribe to host updates", "host", hostID, "server", server, "error", token.Error())
		return
	}

}

// setSubcriptions sets MQ client subscriptions for a specific node config
// should be called for each node belonging to a given server
func setSubscriptions(client mqtt.Client, node *config.Node) {
	if token := client.Subscribe(fmt.Sprintf("node/update/%s/%s", node.Network, node.ID), 0, mqtt.MessageHandler(NodeUpdate)); token.WaitTimeout(MQ_TIMEOUT*time.Second) && token.Error() != nil {
		if token.Error() == nil {
			slog.Error("unable to subscribe to updates for node ", "node", node.ID, "error", "connection timeout")
		} else {
			slog.Error("unable to subscribe to updates for node ", "node", node.ID, "error", token.Error())
		}
		return
	}
	slog.Info("subscribed to updates for node", "node", node.ID, "network", node.Network)
}

// setDNSSubscriptions sets MQ client subscriptions for a specific node config
// should be called for each node belonging to a given server
func setDNSSubscriptions(client mqtt.Client, node *config.Node, server string) {
	if token := client.Subscribe(fmt.Sprintf("host/dns/sync/%s/%s", node.Network, server), 0, mqtt.MessageHandler(DNSSync)); token.WaitTimeout(MQ_TIMEOUT*time.Second) && token.Error() != nil {
		if token.Error() == nil {
			slog.Error("unable to subscribe to DNS sync for node ", "node", node.ID, "error", "connection timeout")
		} else {
			slog.Error("unable to subscribe to DNS sync for node ", "node", node.ID, "error", token.Error())
		}
		return
	}
	slog.Info("subscribed to DNS sync for node", "node", node.ID, "network", node.Network)
}

func unzipPayload(data []byte) (resData []byte, err error) {
	b := bytes.NewBuffer(data)

	var r io.Reader
	r, err = gzip.NewReader(b)
	if err != nil {
		return
	}

	var resB bytes.Buffer
	_, err = resB.ReadFrom(r)
	if err != nil {
		return
	}

	resData = resB.Bytes()

	return
}

func decryptMsg(serverName string, msg []byte) ([]byte, error) {
	if len(msg) <= 24 { // make sure message is of appropriate length
		return nil, fmt.Errorf("received invalid message from broker %v", msg)
	}
	host := config.Netclient()
	// setup the keys
	diskKey, err := ncutils.ConvertBytesToKey(host.TrafficKeyPrivate)
	if err != nil {
		return nil, err
	}

	server := config.GetServer(serverName)
	if server == nil {
		return nil, errors.New("nil server for " + serverName)
	}
	serverPubKey, err := ncutils.ConvertBytesToKey(server.TrafficKey)
	if err != nil {
		return nil, err
	}
	return DeChunk(msg, serverPubKey, diskKey)
}

func decryptAESGCM(key, ciphertext []byte) ([]byte, error) {
	// Create AES block cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Create GCM (Galois/Counter Mode) cipher
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Separate nonce and ciphertext
	nonceSize := aesGCM.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	// Decrypt the data
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func read(network, which string) string {
	val, isok := messageCache.Load(fmt.Sprintf("%s%s", network, which))
	if isok {
		var readMessage = val.(cachedMessage) // fetch current cached message
		if readMessage.LastSeen.IsZero() {
			return ""
		}
		if time.Now().After(readMessage.LastSeen.Add(time.Hour * 24)) { // check if message has been there over a minute
			messageCache.Delete(fmt.Sprintf("%s%s", network, which)) // remove old message if expired
			return ""
		}
		return readMessage.Message // return current message if not expired
	}
	return ""
}

func insert(network, which, cache string) {
	var newMessage = cachedMessage{
		Message:  cache,
		LastSeen: time.Now(),
	}
	messageCache.Store(fmt.Sprintf("%s%s", network, which), newMessage)
}

// on a delete usually, pass in the nodecfg to unsubscribe client broker communications
// for the node in nodeCfg
func unsubscribeNode(client mqtt.Client, node *config.Node) {
	var ok = true
	if token := client.Unsubscribe(fmt.Sprintf("node/update/%s/%s", node.Network, node.ID)); token.WaitTimeout(MQ_TIMEOUT*time.Second) && token.Error() != nil {
		if token.Error() == nil {
			slog.Error("unable to unsubscribe from updates for node ", "node", node.ID, "error", "connection timeout")
		} else {
			slog.Error("unable to unsubscribe from updates for node ", "node", node.ID, "error", token.Error())
		}
		ok = false
	} // peer updates belong to host now

	if token := client.Unsubscribe(fmt.Sprintf("host/dns/sync/%s", node.Network)); token.WaitTimeout(MQ_TIMEOUT*time.Second) && token.Error() != nil {
		if token.Error() == nil {
			slog.Error("unable to unsubscribe from DNS sync for node ", "node", node.ID, "error", "connection timeout")
		} else {
			slog.Error("unable to unsubscribe from DNS sync for node ", "node", node.ID, "error", token.Error())
		}
		ok = false
	}

	if ok {
		slog.Info("unsubscribed from updates for node", "node", node.ID, "network", node.Network)
	}
}

// unsubscribe client broker communications for host topics
func unsubscribeHost(client mqtt.Client, server string) {
	hostID := config.Netclient().ID
	slog.Info("removing subscription for host peer updates", "host", hostID, "server", server)
	if token := client.Unsubscribe(fmt.Sprintf("peers/host/%s/%s", hostID.String(), server)); token.WaitTimeout(MQ_TIMEOUT*time.Second) && token.Error() != nil {
		slog.Error("unable to unsubscribe from host peer updates", "host", hostID, "server", server, "error", token.Error())
		return
	}
	slog.Info("removing subscription for host updates", "host", hostID, "server", server)
	if token := client.Unsubscribe(fmt.Sprintf("host/update/%s/%s", hostID.String(), server)); token.WaitTimeout(MQ_TIMEOUT*time.Second) && token.Error() != nil {
		slog.Error("unable to unsubscribe from host updates", "host", hostID, "server", server, "error", token.Error)
		return
	}
}

// UpdateKeys -- updates private key and returns new publickey
func UpdateKeys() error {
	var err error
	slog.Info("received message to update wireguard keys")
	host := config.Netclient()
	host.PrivateKey, err = wgtypes.GeneratePrivateKey()
	if err != nil {
		slog.Error("error generating privatekey ", "error", err)
		return err
	}
	host.PublicKey = schema.WgKey{
		Key: host.PrivateKey.PublicKey(),
	}
	if err := config.WriteNetclientConfig(); err != nil {
		slog.Error("error saving netclient config:", "error", err)
	}
	PublishHostUpdate(config.CurrServer, models.UpdateHost)
	daemon.Restart()
	return nil
}

func holePunchWgPort(proto, portToStun int) (pubIP net.IP, pubPort int, natType string) {
	defer func() {
		//ncutils.TraceCaller()
		slog.Debug("holePunchWgPort", "proto", proto, "PortToStun", portToStun, "PubIP", pubIP.String(), "PubPort", pubPort, "NatType", natType)
	}()
	server := config.GetServer(config.CurrServer)
	if server == nil {
		server = &config.Server{}
		server.Stun = true
		stun.SetDefaultStunServers()
	}
	_, ipErr := GetPublicIP(uint(proto))
	if ipErr != nil {
		return
	}
	if server.Stun {
		pubIP, pubPort, natType = stun.HolePunch(portToStun, proto)
	} else {
		pubIP, _ = GetPublicIP(uint(proto))
		pubPort = config.Netclient().ListenPort
		natType = "public"
	}
	if pubIP == nil || pubIP.IsUnspecified() { // if stun has failed fallback to ip service to get publicIP
		publicIP, err := GetPublicIP(uint(proto))
		if err != nil {
			slog.Warn("failed to get publicIP", "error", err)
			return
		}
		pubIP = publicIP
		pubPort = portToStun
	}
	return
}

func GetPublicIP(proto uint) (net.IP, error) {
	// Create the default consensus,
	// using the default configuration and no logger.
	consensus := externalip.NewConsensus(&externalip.ConsensusConfig{
		Timeout: time.Second * 10,
	}, nil)
	consensus.AddVoter(externalip.NewHTTPSource("https://icanhazip.com/"), 3)
	consensus.AddVoter(externalip.NewHTTPSource("https://ifconfig.me/ip"), 3)
	consensus.AddVoter(externalip.NewHTTPSource("https://myexternalip.com/raw"), 3)
	// By default Ipv4 or Ipv6 is returned,
	// use the function below to limit yourself to IPv4,
	// or pass in `6` instead to limit yourself to IPv6.
	consensus.UseIPProtocol(proto)
	// Get your IP,
	return consensus.ExternalIP()
}
