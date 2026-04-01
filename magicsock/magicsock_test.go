package magicsock

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sync/singleflight"
	"tailscale.com/derp/derphttp"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const coreDERPMapJSON = `{
  "Regions": {
    "900": {
      "RegionID": 900,
      "RegionCode": "core-region",
      "RegionName": "Core Region",
      "Nodes": [{"Name": "900a", "RegionID": 900, "HostName": "derp.example.test", "DERPPort": 443}]
    }
  }
}`

const publicDERPMapJSON = `{
  "Regions": {
    "1": {
      "RegionID": 1,
      "RegionCode": "public-region",
      "RegionName": "Public Region",
      "Nodes": [{"Name": "1a", "RegionID": 1, "HostName": "derp-public.example.test", "DERPPort": 443}]
    }
  }
}`

func TestLoadDERPMapPrefersConfiguredCoreMap(t *testing.T) {
	resetDERPMapCache(t)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(coreDERPMapJSON))
	}))
	defer server.Close()

	t.Setenv("DERP_MAP_URLS", server.URL)
	derpMap := LoadDERPMap()

	if len(derpMap.Regions) != 1 {
		t.Fatalf("LoadDERPMap returned %d regions; want only the configured Core region", len(derpMap.Regions))
	}
	if _, ok := derpMap.Regions[900]; !ok {
		t.Fatal("LoadDERPMap did not return the configured Core region")
	}
}

func TestLoadDERPMapUsesFirstUsableCanonicalCoreMap(t *testing.T) {
	resetDERPMapCache(t)

	var firstRequests atomic.Int32
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		firstRequests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(coreDERPMapJSON))
	}))
	defer first.Close()

	secondMap := `{"Regions":{"901":{"RegionID":901,"RegionCode":"different","RegionName":"Different","Nodes":[{"Name":"901a","RegionID":901,"HostName":"other.example.test","DERPPort":443}]}}}`
	var secondRequests atomic.Int32
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		secondRequests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(secondMap))
	}))
	defer second.Close()

	t.Setenv("DERP_MAP_URLS", first.URL+","+second.URL)
	derpMap := LoadDERPMap()

	if len(derpMap.Regions) != 1 || derpMap.Regions[900] == nil {
		t.Fatalf("LoadDERPMap returned %#v; want only the first canonical Core map", derpMap.Regions)
	}
	if got := firstRequests.Load(); got != 1 {
		t.Fatalf("first Core map fetched %d times; want one", got)
	}
	if got := secondRequests.Load(); got != 0 {
		t.Fatalf("second Core map fetched %d times; want none after first source succeeded", got)
	}
}

func TestLoadDERPMapFallsBackToNextCanonicalCoreMap(t *testing.T) {
	resetDERPMapCache(t)

	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
	}))
	defer first.Close()

	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(coreDERPMapJSON))
	}))
	defer second.Close()

	t.Setenv("DERP_MAP_URLS", first.URL+","+second.URL)
	derpMap := LoadDERPMap()

	if len(derpMap.Regions) != 1 || derpMap.Regions[900] == nil {
		t.Fatalf("LoadDERPMap returned %#v; want the next usable canonical Core map", derpMap.Regions)
	}
}

func TestLoadDERPMapFallsBackToPublicMapWhenCoreMapIsTemporarilyUnavailable(t *testing.T) {
	resetDERPMapCache(t)

	var available atomic.Bool
	available.Store(true)
	coreServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if !available.Load() {
			http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(coreDERPMapJSON))
	}))
	defer coreServer.Close()

	publicServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(publicDERPMapJSON))
	}))
	defer publicServer.Close()

	previousPublicURL := tailscaleDERPMapURL
	tailscaleDERPMapURL = publicServer.URL
	t.Cleanup(func() { tailscaleDERPMapURL = previousPublicURL })

	t.Setenv("DERP_MAP_URLS", coreServer.URL)
	first := LoadDERPMap()
	if _, ok := first.Regions[900]; !ok {
		t.Fatal("initial Core map load failed")
	}

	available.Store(false)
	lastKnownDERPMapMu.Lock()
	lastKnownDERPMapTime = time.Now().Add(-derpMapCacheTTL)
	lastKnownDERPMapMu.Unlock()

	second := LoadDERPMap()
	if len(second.Regions) != 1 {
		t.Fatalf("LoadDERPMap returned %d regions; want the public fallback region", len(second.Regions))
	}
	if _, ok := second.Regions[1]; !ok {
		t.Fatal("LoadDERPMap did not fall back to the public DERP map")
	}
}

func TestHardcodedDERPMapContainsCurrentPublicSnapshot(t *testing.T) {
	derpMap := hardcodedDERPMap()
	if len(derpMap.Regions) != 28 {
		t.Fatalf("hardcodedDERPMap returned %d regions; want 28", len(derpMap.Regions))
	}

	nodes := 0
	for _, region := range derpMap.Regions {
		nodes += len(region.Nodes)
	}
	if nodes != 88 {
		t.Fatalf("hardcodedDERPMap returned %d nodes; want 88", nodes)
	}
}

func TestLoadDERPMapCoalescesConcurrentRefreshes(t *testing.T) {
	resetDERPMapCache(t)

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		time.Sleep(20 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(publicDERPMapJSON))
	}))
	defer server.Close()

	previousPublicURL := tailscaleDERPMapURL
	tailscaleDERPMapURL = server.URL
	t.Cleanup(func() { tailscaleDERPMapURL = previousPublicURL })
	t.Setenv("DERP_MAP_URLS", "")

	const callers = 16
	start := make(chan struct{})
	done := make(chan struct{}, callers)
	for i := 0; i < callers; i++ {
		go func() {
			<-start
			if got := LoadDERPMap(); got.Regions[1] == nil {
				t.Errorf("LoadDERPMap did not return the public map")
			}
			done <- struct{}{}
		}()
	}
	close(start)
	for i := 0; i < callers; i++ {
		<-done
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("public DERP map fetched %d times; want one coalesced refresh", got)
	}
}

func TestDERPClientLookupSharesSelectedNodeClient(t *testing.T) {
	peerOne := key.NewNode().Public()
	peerTwo := key.NewNode().Public()
	client := &derphttp.Client{}
	poolKey := derpPoolKey{regionID: 900, nodeID: "900a"}
	b := &MagicBind{
		derpRegions: map[derpPoolKey]*derpRegionClient{
			poolKey: {client: client},
		},
		derpPeerRegions: map[key.NodePublic]derpPoolKey{
			peerOne: poolKey,
			peerTwo: poolKey,
		},
	}

	gotOne, foundOne := b.derpClientForPeer(peerOne)
	gotTwo, foundTwo := b.derpClientForPeer(peerTwo)
	if !foundOne || !foundTwo || gotOne != client || gotTwo != client {
		t.Fatal("peers assigned to one relay node did not resolve to its shared DERP client")
	}
}

func TestSelectDERPNodeIsSymmetricAndSpreadsPairs(t *testing.T) {
	region := &tailcfg.DERPRegion{RegionID: 900, Nodes: []*tailcfg.DERPNode{
		{Name: "900a", RegionID: 900, HostName: "a.example.test"},
		{Name: "900b", RegionID: 900, HostName: "b.example.test"},
		{Name: "900c", RegionID: 900, HostName: "c.example.test"},
	}}
	self := key.NewNode().Public()
	peer := key.NewNode().Public()
	_, forward := selectDERPNode(region, self, peer)
	_, reverse := selectDERPNode(region, peer, self)
	if forward != reverse {
		t.Fatalf("selection is not symmetric: forward=%+v reverse=%+v", forward, reverse)
	}

	selected := map[string]bool{}
	for i := 0; i < 256; i++ {
		_, poolKey := selectDERPNode(region, self, key.NewNode().Public())
		selected[poolKey.nodeID] = true
	}
	if len(selected) != len(region.Nodes) {
		t.Fatalf("HRW selected %d of %d relay nodes", len(selected), len(region.Nodes))
	}
}

func TestReconcileDERPPeersRetiresRemovedPeerAndRegion(t *testing.T) {
	peerOne := key.NewNode().Public()
	peerTwo := key.NewNode().Public()
	b := &MagicBind{
		derpRegions: map[derpPoolKey]*derpRegionClient{
			{regionID: 900, nodeID: "900a"}: {},
			{regionID: 901, nodeID: "901a"}: {},
		},
		derpPeerRegions: map[key.NodePublic]derpPoolKey{
			peerOne: {regionID: 900, nodeID: "900a"},
			peerTwo: {regionID: 901, nodeID: "901a"},
		},
		activePeers: map[key.NodePublic]bool{
			peerOne: true,
			peerTwo: true,
		},
	}

	b.reconcileActivePeers([]key.NodePublic{peerOne})
	b.reconcileDERPPeers([]key.NodePublic{peerOne})

	if got := b.derpPeerRegions[peerOne]; got != (derpPoolKey{regionID: 900, nodeID: "900a"}) {
		t.Fatalf("retained peer assigned to pool %+v; want 900a", got)
	}
	if _, found := b.derpPeerRegions[peerTwo]; found {
		t.Fatal("removed peer retained a DERP region assignment")
	}
	if _, found := b.derpRegions[derpPoolKey{regionID: 900, nodeID: "900a"}]; !found {
		t.Fatal("relay pool still used by a peer was retired")
	}
	if _, found := b.derpRegions[derpPoolKey{regionID: 901, nodeID: "901a"}]; found {
		t.Fatal("relay pool used only by a removed peer was not retired")
	}
	if b.activePeers[peerTwo] {
		t.Fatal("removed peer retained active-peer state")
	}
}

func resetDERPMapCache(t *testing.T) {
	t.Helper()
	lastKnownDERPMapMu.Lock()
	lastKnownDERPMap = nil
	lastKnownPublicDERPMap = nil
	lastKnownDERPMapTime = time.Time{}
	derpMapRefreshGroup = singleflight.Group{}
	lastKnownDERPMapMu.Unlock()
	t.Cleanup(func() {
		lastKnownDERPMapMu.Lock()
		lastKnownDERPMap = nil
		lastKnownPublicDERPMap = nil
		lastKnownDERPMapTime = time.Time{}
		derpMapRefreshGroup = singleflight.Group{}
		lastKnownDERPMapMu.Unlock()
	})
}
