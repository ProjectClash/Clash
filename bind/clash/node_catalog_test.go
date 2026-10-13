package clash

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/adapter/outboundgroup"
	"github.com/ProjectClash/Clash/component/dialer"
	"github.com/ProjectClash/Clash/config"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/tunnel"
)

func groupMembers(t *testing.T, cfg *config.Config) map[string][]string {
	t.Helper()
	out := map[string][]string{}
	for name, proxy := range cfg.Proxies {
		group, ok := proxy.Adapter().(outboundgroup.ProxyGroup)
		if !ok {
			continue
		}
		holder := proxy.Adapter().(interface{ GetProxies(bool) []C.Proxy })
		for _, member := range holder.GetProxies(false) {
			out[name] = append(out[name], member.Name()+"|"+member.Type().String())
		}
		out[name] = append(out[name], "now="+group.Now())
	}
	return out
}

func TestGroupsListTheSameMembersWithTheCatalog(t *testing.T) {
	catalog := groupMembers(t, parseNodeCatalogDocument(t, 40))
	previous := adapter.SetNodeCatalog(false)
	upstream := groupMembers(t, parseNodeCatalogDocument(t, 40))
	adapter.SetNodeCatalog(previous)
	if len(catalog) != 6 {
		t.Fatalf("%d groups", len(catalog))
	}
	for name, members := range upstream {
		if strings.Join(catalog[name], "\n") != strings.Join(members, "\n") {
			t.Fatalf("group %s lists\n%v\nwith the catalog, and\n%v\nwithout", name, catalog[name], members)
		}
	}
}

func TestNodeCatalogFollowsTheGroups(t *testing.T) {
	cfg := parseNodeCatalogDocument(t, 40)
	previousProxies, previousProviders := tunnel.Proxies(), tunnel.Providers()
	tunnel.UpdateProxies(cfg.Proxies, cfg.Providers)
	t.Cleanup(func() {
		tunnel.UpdateProxies(previousProxies, previousProviders)
		refreshNodeCatalog()
	})
	refreshNodeCatalog()
	if got := outbound.NodeCatalogLimit(); got != 64 {
		t.Fatalf("limit %d with 6 groups; want 64", got)
	}
	if nodeCatalogLimit(40, 0) != 90 || nodeCatalogLimit(1, 100) != 112 {
		t.Fatal("40 groups keep 2 x 40 + 10")
	}
	var chosen []string
	for name, proxy := range cfg.Proxies {
		if _, ok := proxy.Adapter().(outboundgroup.ProxyGroup); !ok {
			continue
		}
		node := chosenNodeOf(proxy)
		if node == nil {
			continue
		}
		if catalog, _ := outbound.IsCatalogNode(node.Adapter()); catalog && !outbound.IsCatalogNodePinned(node.Adapter()) {
			t.Fatalf("group %s's choice %s is not pinned", name, node.Name())
		}
		chosen = append(chosen, node.Name())
	}
	sort.Strings(chosen)
	if len(chosen) == 0 {
		t.Fatal("no group chose a node")
	}
	hop, sg := cfg.Proxies["JP 1"], cfg.Proxies["SG 3"]
	if outbound.IsCatalogNodePinned(hop.Adapter()) && !slices.Contains(chosen, "JP 1") {
		t.Fatal("JP 1 pinned before anything uses it")
	}
	_ = sg.Adapter().(interface{ DialOptions() []dialer.Option }).DialOptions()
	refreshNodeCatalog()
	if !outbound.IsCatalogNodePinned(hop.Adapter()) {
		t.Fatal("the dialer-proxy of a node holding an outbound is not pinned")
	}
}

func TestNodeCatalogKeepsRoomForLoadBalanceMembers(t *testing.T) {
	var doc strings.Builder
	doc.WriteString("proxies:\n")
	for i := 0; i < 70; i++ {
		fmt.Fprintf(&doc, "  - {name: \"N %d\", type: ss, server: n%d.example.net, port: 8388, cipher: aes-128-gcm, password: p}\n", i, i)
	}
	doc.WriteString(`proxy-groups:
  - {name: spread, type: load-balance, include-all: true, strategy: round-robin, lazy: true}
  - {name: spread-again, type: load-balance, include-all: true, strategy: consistent-hashing, lazy: true}
  - {name: pick, type: select, include-all: true}
rules:
  - MATCH,pick
`)
	cfg, err := config.Parse([]byte(doc.String()))
	if err != nil {
		t.Fatal(err)
	}
	previousProxies, previousProviders := tunnel.Proxies(), tunnel.Providers()
	tunnel.UpdateProxies(cfg.Proxies, cfg.Providers)
	t.Cleanup(func() {
		tunnel.UpdateProxies(previousProxies, previousProviders)
		refreshNodeCatalog()
	})
	refreshNodeCatalog()
	if got, want := outbound.NodeCatalogLimit(), 2*4+10+70; got != want {
		t.Fatalf("limit %d; want %d", got, want)
	}
}

func TestTheNodeCatalogSweepsWhatKilledProcessesLeft(t *testing.T) {
	home := t.TempDir()
	previous := C.Path.HomeDir()
	C.SetHomeDir(home)
	t.Cleanup(func() {
		C.SetHomeDir(previous)
		adapter.SetNodeCatalogDirectory("")
	})
	dir := filepath.Join(home, nodeCatalogDirectoryName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	gone := exec.Command("true")
	if err := gone.Run(); err != nil {
		t.Fatal(err)
	}
	dead := gone.Process.Pid
	alive := fmt.Sprintf("nodes-%d-2.catalog", os.Getppid())
	reused := fmt.Sprintf("nodes-%d-%d.tmp", os.Getpid(), uint64(1)<<62)
	for _, name := range []string{fmt.Sprintf("nodes-%d-1.tmp", dead), fmt.Sprintf("nodes-%d-3.catalog", dead), alive, reused, "notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	armNodeCatalog(&recordingPlatform{lines: make(chan string, 16), underNetworkExtension: true})
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, entry := range entries {
		left = append(left, entry.Name())
	}
	sort.Strings(left)
	want := []string{alive, "notes.txt"}
	sort.Strings(want)
	if !slices.Equal(left, want) {
		t.Fatalf("left %v; want %v", left, want)
	}
}
