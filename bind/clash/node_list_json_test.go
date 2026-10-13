package clash

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outboundgroup"
	"github.com/ProjectClash/Clash/config"
	C "github.com/ProjectClash/Clash/constant"
)

func nodeCatalogDocument(nodes int) string {
	var b strings.Builder
	b.WriteString("mode: rule\nproxies:\n")
	for i := 0; i < nodes; i++ {
		switch i % 4 {
		case 0:
			fmt.Fprintf(&b, "  - {name: \"HK <%d> & co\", type: ss, server: hk%d.example.net, port: 8388, cipher: aes-128-gcm, password: p%d, udp: true}\n", i, i, i)
		case 1:
			fmt.Fprintf(&b, "  - {name: \"JP %d\", type: trojan, server: jp%d.example.net, port: 443, password: p%d, sni: jp.example.net}\n", i, i, i)
		case 2:
			fmt.Fprintf(&b, "  - {name: \"US %d\", type: hysteria2, server: us%d.example.net, port: 443, password: p%d}\n", i, i, i)
		case 3:
			fmt.Fprintf(&b, "  - {name: \"SG %d\", type: vmess, server: sg%d.example.net, port: 443, uuid: 0123abcd-4567-89ef-0123-456789abcdef, alterId: 0, cipher: auto, network: ws, ws-opts: {path: /ray}, dialer-proxy: \"JP 1\"}\n", i, i)
		}
	}
	b.WriteString("proxy-providers:\n  airport:\n    type: inline\n    payload:\n")
	for i := 0; i < nodes; i++ {
		fmt.Fprintf(&b, "      - {name: \"P-%d %s\", type: %s, server: p%d.example.net, port: 443, password: p%d, cipher: aes-128-gcm}\n",
			i, []string{"HK", "JP", "US"}[i%3], []string{"ss", "trojan", "hysteria2"}[i%3], i, i)
	}
	b.WriteString(`proxy-groups:
  - {name: all, type: select, include-all: true}
  - {name: hk, type: select, include-all: true, filter: "HK"}
  - {name: not-hk, type: url-test, include-all: true, exclude-filter: "HK", lazy: true}
  - {name: no-hy2, type: fallback, include-all: true, exclude-type: "Hysteria2|hysteria2", lazy: true}
  - {name: nested, type: select, proxies: [hk, not-hk, DIRECT]}
rules:
  - MATCH,all
`)
	return b.String()
}

func parseNodeCatalogDocument(t *testing.T, nodes int) *config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(nodeCatalogDocument(nodes)))
	if err != nil {
		t.Fatal(err)
	}
	for _, provider := range cfg.Providers {
		if closer, ok := provider.(interface{ Close() error }); ok {
			t.Cleanup(func() { _ = closer.Close() })
		}
	}
	return cfg
}

func upstreamProxyJSON(t *testing.T, p C.Proxy) json.RawMessage {
	t.Helper()
	inner, err := p.Adapter().MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	mapping := map[string]any{}
	_ = json.Unmarshal(inner, &mapping)
	mapping["history"] = p.DelayHistory()
	mapping["extra"] = p.ExtraDelayHistories()
	mapping["alive"] = p.AliveForTestUrl("")
	mapping["name"] = p.Name()
	mapping["udp"] = p.SupportUDP()
	mapping["uot"] = p.SupportUOT()
	info := p.ProxyInfo()
	mapping["xudp"], mapping["tfo"], mapping["mptcp"], mapping["smux"] = info.XUDP, info.TFO, info.MPTCP, info.SMUX
	mapping["interface"], mapping["routing-mark"] = info.Interface, info.RoutingMark
	mapping["provider-name"], mapping["dialer-proxy"] = info.ProviderName, info.DialerProxy
	out, err := json.Marshal(mapping)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestProxiesJSONIsUpstreamsBytes(t *testing.T) {
	cfg := parseNodeCatalogDocument(t, 40)
	want := map[string]json.RawMessage{}
	for name, proxy := range cfg.Proxies {
		want[name] = upstreamProxyJSON(t, proxy)
	}
	wantBytes, err := json.Marshal(map[string]any{"proxies": want})
	if err != nil {
		t.Fatal(err)
	}
	if got := proxiesJSON(cfg.Proxies); got != string(wantBytes) {
		t.Fatalf("ProxiesJSON:\n got  %.600s\n want %.600s", got, wantBytes)
	}
	if got := mustJSON(map[string]any{"proxies": cfg.Proxies}); got != string(wantBytes) {
		t.Fatal("encoding/json over the proxies writes other bytes")
	}
	for name, provider := range cfg.Providers {
		got, err := json.Marshal(provider)
		if err != nil {
			t.Fatal(err)
		}
		var decoded struct {
			Proxies []json.RawMessage `json:"proxies"`
		}
		if err := json.Unmarshal(got, &decoded); err != nil {
			t.Fatal(err)
		}
		for i, proxy := range provider.Proxies() {
			if string(decoded.Proxies[i]) != string(upstreamProxyJSON(t, proxy)) {
				t.Fatalf("provider %s node %s:\n got  %s\n want %s", name, proxy.Name(), decoded.Proxies[i], upstreamProxyJSON(t, proxy))
			}
		}
	}
}

func TestProxyDelaysJSONListsMeasuredNodesOnly(t *testing.T) {
	cfg, err := config.Parse([]byte(`proxies:
  - {name: "JP 1", type: http, server: 127.0.0.1, port: 1}
  - {name: "JP 2", type: http, server: 127.0.0.1, port: 1}
proxy-providers:
  airport:
    type: inline
    payload:
      - {name: "P-1", type: socks5, server: 127.0.0.1, port: 1}
      - {name: "P-2 US", type: socks5, server: 127.0.0.1, port: 1}
proxy-groups:
  - {name: pick, type: select, proxies: ["JP 2", "JP 1"]}
  - {name: fast, type: url-test, proxies: ["JP 1", "JP 2"], url: "http://127.0.0.1:1/fast", lazy: true}
  - {name: spread, type: load-balance, proxies: ["JP 1", "JP 2"], lazy: true}
`))
	if err != nil {
		t.Fatal(err)
	}
	for _, provider := range cfg.Providers {
		if closer, ok := provider.(interface{ Close() error }); ok {
			t.Cleanup(func() { _ = closer.Close() })
		}
	}
	type record struct {
		Alive *bool
		Delay *uint16
		Time  time.Time
		Extra map[string]struct {
			Alive bool
			Delay uint16
			Time  time.Time
		}
	}
	type group struct {
		Now   *string
		Fixed *string
		Delay *uint16
	}
	var decoded struct {
		Revision  string
		Groups    map[string]group
		Proxies   map[string]record
		Providers map[string]map[string]record
	}
	decode := func() string {
		t.Helper()
		got := proxyDelaysJSON(cfg.Proxies, cfg.Providers, 7)
		decoded.Groups, decoded.Proxies, decoded.Providers = nil, nil, nil
		if err := json.Unmarshal([]byte(got), &decoded); err != nil {
			t.Fatalf("%v: %s", err, got)
		}
		return got
	}
	got := decode()
	if len(decoded.Proxies) != 0 || decoded.Providers["airport"] == nil || len(decoded.Providers["airport"]) != 0 || decoded.Revision == "" {
		t.Fatalf("unmeasured: %s", got)
	}
	pick, fast, spread := decoded.Groups["pick"], decoded.Groups["fast"], decoded.Groups["spread"]
	if pick.Now == nil || *pick.Now != "JP 2" || pick.Fixed != nil {
		t.Fatalf("select group: %s", got)
	}
	if fast.Now == nil || fast.Fixed == nil || *fast.Fixed != "" {
		t.Fatalf("url-test group: %s", got)
	}
	if spread.Now != nil || spread.Fixed != nil {
		t.Fatalf("load-balance group: %s", got)
	}
	if len(decoded.Groups) != 4 || decoded.Groups["GLOBAL"].Now == nil {
		t.Fatalf("groups: %s", got)
	}
	adapter.SetURLTestAdmission(nil)
	probe := func(p C.Proxy, url string) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _ = p.URLTest(ctx, url, nil)
	}
	probe(cfg.Proxies["JP 1"], "http://127.0.0.1:1/")
	probe(cfg.Providers["airport"].Proxies()[1], "http://127.0.0.1:1/")
	probe(cfg.Proxies["JP 2"], "http://127.0.0.1:1/fast")
	probe(cfg.Proxies["pick"], "http://127.0.0.1:1/")
	got = decode()
	if len(decoded.Proxies) != 2 || len(decoded.Providers["airport"]) != 1 {
		t.Fatalf("delays: %s", got)
	}
	if r := decoded.Proxies["JP 1"]; r.Alive == nil || *r.Alive || r.Delay == nil || *r.Delay != 0 || r.Time.IsZero() || len(r.Extra) != 1 {
		t.Fatalf("JP 1: %s", got)
	}
	jp2 := decoded.Proxies["JP 2"]
	if jp2.Delay == nil || jp2.Alive == nil || len(jp2.Extra) != 1 {
		t.Fatalf("JP 2, measured under the group's URL: %s", got)
	}
	if extra := jp2.Extra["http://127.0.0.1:1/fast"]; extra.Alive || extra.Delay != 0 || extra.Time.IsZero() {
		t.Fatalf("JP 2's record for the group's URL: %s", got)
	}
	if _, ok := decoded.Providers["airport"]["P-2 US"]; !ok {
		t.Fatalf("provider node missing: %s", got)
	}
	if _, ok := decoded.Proxies["pick"]; ok || decoded.Groups["pick"].Delay == nil {
		t.Fatalf("a measured group's record is the group's, not a node's: %s", got)
	}
	var upstream map[string]map[string]json.RawMessage
	if err := json.Unmarshal([]byte(proxiesJSON(cfg.Proxies)), &struct {
		Proxies *map[string]map[string]json.RawMessage
	}{&upstream}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"JP 1", "JP 2"} {
		var history []struct{ Delay uint16 }
		var extra map[string]struct{ History []struct{ Delay uint16 } }
		_ = json.Unmarshal(upstream[name]["history"], &history)
		_ = json.Unmarshal(upstream[name]["extra"], &extra)
		if len(history) != 1 || len(extra) != len(decoded.Proxies[name].Extra) || string(upstream[name]["alive"]) != "false" {
			t.Fatalf("/proxies %s: %s", name, upstream[name])
		}
		for url := range extra {
			if _, ok := decoded.Proxies[name].Extra[url]; !ok {
				t.Fatalf("%s: /proxies has a record under %s: %s", name, url, got)
			}
		}
	}
}

func TestProxyDelaysRevisionFollowsTheNodeList(t *testing.T) {
	cfg := parseNodeCatalogDocument(t, 8)
	revision := func(generation uint64) string {
		t.Helper()
		var decoded struct{ Revision string }
		if err := json.Unmarshal([]byte(proxyDelaysJSON(cfg.Proxies, cfg.Providers, generation)), &decoded); err != nil || decoded.Revision == "" {
			t.Fatalf("revision: %v", err)
		}
		return decoded.Revision
	}
	first := revision(1)
	if again := revision(1); again != first {
		t.Fatalf("nothing changed and the revision did: %s, %s", first, again)
	}
	if next := revision(2); next == first {
		t.Fatal("another proxy table kept the revision")
	}
}

func TestNodeListsAllocateAboutWhatTheyWrite(t *testing.T) {
	if testing.Short() {
		t.Skip("parses 10,000 nodes")
	}
	cfg := parseNodeCatalogDocument(t, 10000)
	measure := func(write func() int) (int, uint64) {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		n := write()
		runtime.ReadMemStats(&after)
		return n, after.TotalAlloc - before.TotalAlloc
	}
	written, allocated := measure(func() int { return len(proxiesJSON(cfg.Proxies)) })
	t.Logf("ProxiesJSON, first read: %d B written, %d B allocated (%.2fx)", written, allocated, float64(allocated)/float64(written))
	written, allocated = measure(func() int { return len(proxiesJSON(cfg.Proxies)) })
	t.Logf("ProxiesJSON, a later read: %d B written, %d B allocated (%.2fx)", written, allocated, float64(allocated)/float64(written))
	if allocated > 3*uint64(written) {
		t.Errorf("ProxiesJSON allocated %d B to write %d B; want at most three times", allocated, written)
	}
	written, allocated = measure(func() int { return len(proxyDelaysJSON(cfg.Proxies, cfg.Providers, 1)) })
	t.Logf("ProxyDelaysJSON: %d B written, %d B allocated", written, allocated)
	if allocated > 1<<20 {
		t.Errorf("ProxyDelaysJSON allocated %d B", allocated)
	}
}

func TestMeasuredDelaysAllocateAboutWhatTheyWrite(t *testing.T) {
	if testing.Short() {
		t.Skip("measures 4,000 nodes")
	}
	var b strings.Builder
	b.WriteString("proxies:\n")
	for i := 0; i < 2000; i++ {
		fmt.Fprintf(&b, "  - {name: \"JP %d\", type: socks5, server: 127.0.0.1, port: 1}\n", i)
	}
	b.WriteString("proxy-providers:\n  airport:\n    type: inline\n    payload:\n")
	for i := 0; i < 2000; i++ {
		fmt.Fprintf(&b, "      - {name: \"P-%d\", type: socks5, server: 127.0.0.1, port: 1}\n", i)
	}
	b.WriteString("proxy-groups:\n  - {name: all, type: select, include-all: true}\n")
	cfg, err := config.Parse([]byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	for _, provider := range cfg.Providers {
		if closer, ok := provider.(interface{ Close() error }); ok {
			t.Cleanup(func() { _ = closer.Close() })
		}
	}
	adapter.SetURLTestAdmission(nil)
	probe := func(p C.Proxy) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _ = p.URLTest(ctx, "http://127.0.0.1:1/", nil)
	}
	for name, proxy := range cfg.Proxies {
		if strings.HasPrefix(name, "JP ") {
			probe(proxy)
		}
	}
	for _, proxy := range cfg.Providers["airport"].Proxies() {
		probe(proxy)
	}
	measure := func() (int, uint64) {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		n := len(proxyDelaysJSON(cfg.Proxies, cfg.Providers, 1))
		runtime.ReadMemStats(&after)
		return n, after.TotalAlloc - before.TotalAlloc
	}
	measure()
	written, allocated := measure()
	t.Logf("ProxyDelaysJSON, 4,000 measured nodes: %d B written, %d B allocated (%.2fx)", written, allocated, float64(allocated)/float64(written))
	if allocated > 2*uint64(written) {
		t.Errorf("ProxyDelaysJSON allocated %d B to write %d B; want at most twice", allocated, written)
	}
}

func TestProxyDelaysComeInPagesAndSinceAPoll(t *testing.T) {
	cfg := parseNodeCatalogDocument(t, 40)
	adapter.SetURLTestAdmission(nil)
	var nodes []C.Proxy
	for name, proxy := range cfg.Proxies {
		if _, group := proxy.Adapter().(outboundgroup.ProxyGroup); !group && !slices.Contains(builtinProxyNames[:], name) {
			nodes = append(nodes, proxy)
		}
	}
	nodes = append(nodes, cfg.Providers["airport"].Proxies()...)
	probeAll := func(nodes []C.Proxy) {
		var wg sync.WaitGroup
		for _, node := range nodes {
			wg.Add(1)
			go func(p C.Proxy) {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()
				_, _ = p.URLTest(ctx, "http://127.0.0.1:1/", nil)
			}(node)
		}
		wg.Wait()
	}
	probeAll(nodes)
	time.Sleep(1200 * time.Millisecond)
	type document struct {
		Proxies   map[string]json.RawMessage
		Providers map[string]map[string]json.RawMessage
		Now       int64
		Next      string
	}
	read := func(page proxyDelaysPage) document {
		t.Helper()
		var d document
		if err := json.Unmarshal([]byte(proxyDelaysPageJSON(cfg.Proxies, cfg.Providers, 1, C.ProxySlice(nil), page)), &d); err != nil {
			t.Fatal(err)
		}
		return d
	}
	keys := func(d document) []string {
		var out []string
		for name := range d.Proxies {
			out = append(out, "p/"+name)
		}
		for provider, nodes := range d.Providers {
			for name := range nodes {
				out = append(out, "v/"+provider+"/"+name)
			}
		}
		return out
	}
	whole := read(proxyDelaysPage{})
	want := keys(whole)
	if len(want) != len(nodes) {
		t.Fatalf("%d measured nodes listed of %d", len(want), len(nodes))
	}
	seen := map[string]bool{}
	after, pages := "", 0
	for {
		page := read(proxyDelaysPage{after: after, limit: 7})
		got := keys(page)
		if len(got) > 7 {
			t.Fatalf("a page of %d", len(got))
		}
		for _, key := range got {
			if seen[key] {
				t.Fatalf("%s on two pages", key)
			}
			seen[key] = true
		}
		pages++
		if page.Next == "" {
			break
		}
		if pages > len(nodes) {
			t.Fatal("the pages do not end")
		}
		after = page.Next
	}
	if len(seen) != len(want) {
		t.Fatalf("pages held %d of %d nodes", len(seen), len(want))
	}
	again := []C.Proxy{nodes[1], nodes[len(nodes)-1], nodes[len(nodes)/2]}
	probeAll(again)
	since := read(proxyDelaysPage{since: whole.Now})
	if got := keys(since); len(got) != len(again) {
		t.Fatalf("since the last poll: %v, want the %d measured again", got, len(again))
	}
}
