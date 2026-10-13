package adapter

import (
	"encoding/json"
	"fmt"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter/outbound"
	atomic2 "github.com/ProjectClash/Clash/common/atomic"
	"github.com/ProjectClash/Clash/common/queue"
	C "github.com/ProjectClash/Clash/constant"
)


func clashRecordProbe(p *Proxy, url string, delay uint16, alive bool) {
	record := C.DelayHistory{Time: time.Date(2026, 10, 11, 12, 0, 0, 123456789, time.UTC), Delay: delay}
	p.alive.Store(alive)
	p.history.Put(record)
	state, _ := p.extra.LoadOrStoreFn(url, func() *internalProxyState {
		return &internalProxyState{history: queue.New[C.DelayHistory](defaultHistoriesNum), alive: atomic2.NewBool(true)}
	})
	state.alive.Store(alive)
	state.history.Put(record)
}

func TestACatalogNodeWritesUpstreamsJSON(t *testing.T) {
	names := []string{"plain", "HK <01> & \"quoted\" \\ back", "line\u2028para\u2029", "🇭🇰 香港 01", "bad \xff utf8", "tab\tnl\n", ""}
	for i, name := range names {
		mapping := clashMixedNode(t, i)
		mapping["name"] = name
		mapping["dialer-proxy"] = "<hop & co>"
		mapping["interface-name"] = "en0"
		mapping["routing-mark"] = 1234
		config, ok := encodeNodeConfig(mapping)
		if !ok {
			t.Fatal("not encoded")
		}
		const providerName = "provider <&>"
		built, err := buildCatalogNode(config, nil, nil, providerName)
		if err != nil {
			t.Fatalf("%q: %v", name, err)
		}
		reference := NewProxy(outbound.NewAutoCloseProxyAdapter(built))
		node, ok := outbound.NewSingleCatalogNode(built, config, providerName, nil, nil, buildCatalogNode)
		if !ok {
			t.Fatal("no catalog node")
		}
		proxy := NewProxy(outbound.NewAutoCloseProxyAdapter(node))
		if _, ok := outbound.CatalogNodeID(proxy.Adapter()); !ok {
			t.Fatalf("%q: not written field by field", name)
		}
		for round := 0; round < 3; round++ {
			want, err := reference.MarshalJSON()
			if err != nil {
				t.Fatal(err)
			}
			got, err := proxy.MarshalJSON()
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != string(want) {
				t.Fatalf("%q round %d:\n got  %s\n want %s", name, round, got, want)
			}
			for _, p := range []*Proxy{reference, proxy} {
				clashRecordProbe(p, "https://example.net/"+strconv.Itoa(round), uint16(100*round), round != 1)
			}
		}
		_ = proxy.Close()
	}
}

func TestTheNodeListIsJSONMarshals(t *testing.T) {
	proxies := map[string]C.Proxy{"DIRECT": NewProxy(outbound.NewDirect())}
	for i := 0; i < 50; i++ {
		proxy := clashParse(t, clashMixedNode(t, i))
		if i%7 == 0 {
			clashRecordProbe(proxy, "https://example.net/", 42, i%2 == 0)
		}
		proxies[proxy.Name()] = proxy
	}
	smux := clashParse(t, map[string]any{"name": "ss-smux <&>", "type": "ss", "server": "127.0.0.1", "port": 9, "cipher": "aes-128-gcm", "password": "p", "smux": map[string]any{"enabled": true}})
	if _, ok := outbound.CatalogNodeID(smux.Adapter()); ok {
		t.Fatal("a smux node's JSON is not Base's and must go upstream's way")
	}
	proxies[smux.Name()] = smux
	want, err := json.Marshal(proxies)
	if err != nil {
		t.Fatal(err)
	}
	got, err := AppendProxiesJSON(nil, proxies)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatalf("node list:\n got  %s\n want %s", got, want)
	}
}

func TestWritingTheNodeListAllocatesAboutWhatItWrites(t *testing.T) {
	const n = 2000
	proxies := make(map[string]C.Proxy, n)
	for i := 0; i < n; i++ {
		proxy := clashParse(t, clashMixedNode(t, i))
		proxies[proxy.Name()] = proxy
	}
	measure := func(write func() int) (written int, allocated uint64) {
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		written = write()
		runtime.ReadMemStats(&after)
		return written, after.TotalAlloc - before.TotalAlloc
	}
	for _, proxy := range proxies {
		for round := 0; round < 3; round++ {
			clashRecordProbe(proxy.(*Proxy), "https://example.net/a", uint16(100+round), true)
			clashRecordProbe(proxy.(*Proxy), "https://example.net/b", 0, false)
		}
	}
	written, allocated := measure(func() int {
		b, err := AppendProxiesJSON(nil, proxies)
		if err != nil {
			t.Fatal(err)
		}
		return len(b)
	})
	upstreamWritten, upstreamAllocated := measure(func() int {
		b, err := json.Marshal(map[string]any{"proxies": proxies})
		if err != nil {
			t.Fatal(err)
		}
		return len(b)
	})
	t.Logf("%d nodes: field by field %d B written, %d B allocated (%.1fx); json.Marshal %d B, %d B (%.1fx)",
		n, written, allocated, float64(allocated)/float64(written), upstreamWritten, upstreamAllocated, float64(upstreamAllocated)/float64(upstreamWritten))
	if allocated > 3*uint64(written) {
		t.Fatalf("writing %d B allocated %d B", written, allocated)
	}
}

func clashUpstreamMarshal(p *Proxy) ([]byte, error) {
	inner, err := p.ProxyAdapter.MarshalJSON()
	if err != nil {
		return inner, err
	}
	mapping := map[string]any{}
	_ = json.Unmarshal(inner, &mapping)
	mapping["history"] = p.DelayHistory()
	mapping["extra"] = p.ExtraDelayHistories()
	mapping["alive"] = p.alive.Load()
	mapping["name"] = p.Name()
	mapping["udp"] = p.SupportUDP()
	mapping["uot"] = p.SupportUOT()
	proxyInfo := p.ProxyInfo()
	mapping["xudp"] = proxyInfo.XUDP
	mapping["tfo"] = proxyInfo.TFO
	mapping["mptcp"] = proxyInfo.MPTCP
	mapping["smux"] = proxyInfo.SMUX
	mapping["interface"] = proxyInfo.Interface
	mapping["routing-mark"] = proxyInfo.RoutingMark
	mapping["provider-name"] = proxyInfo.ProviderName
	mapping["dialer-proxy"] = proxyInfo.DialerProxy
	return json.Marshal(mapping)
}

type clashJSONAdapter struct {
	outbound.ProxyAdapter
	json string
}

func (a *clashJSONAdapter) MarshalJSON() ([]byte, error) { return []byte(a.json), nil }

func TestAnyProxyWritesUpstreamsJSON(t *testing.T) {
	members := make([]string, 0, 300)
	for i := 0; i < 300; i++ {
		members = append(members, fmt.Sprintf("%q", fmt.Sprint("HK <", i, "> & 🇭🇰")))
	}
	group := `{"all":[` + strings.Join(members, ",") + `],"emptyFallback":"COMPATIBLE","hidden":false,"icon":"","now":"HK","testUrl":"","type":"Selector"}`
	if escaped, err := json.Marshal(json.RawMessage(group)); err == nil {
		group = string(escaped)
	}
	cases := []struct {
		inner  string
		merged bool
	}{
		{group, true},
		{`{"type":"URLTest","fixed":"","expectedStatus":"*"}`, false},
		{`{"nested":{"a":1,"b":[true,false,null]},"type":"x"}`, true},
		{`{"nested":{"b":1,"a":2},"type":"x"}`, false},
		{`{"big":12345678901234567,"type":"x"}`, false},
		{`{"f":1.5,"type":"x"}`, false},
		{`{"e":1e3,"type":"x"}`, false},
		{`{"neg":-12,"type":"x","zero":0}`, true},
		{`{"s":"a\u003cb","type":"x"}`, true},
		{`{"s":"a\/b","type":"x"}`, false},
		{`{"name":"inner name","type":"x","udp":false}`, true},
		{`{"type":"x","type":"y"}`, false},
		{`{}`, true},
		{`[]`, false},
		{`{"a":1} `, false},
		{`not json`, false},
		{`{"a":"\ud800"}`, false},
	}
	for _, c := range cases {
		p := NewProxy(&clashJSONAdapter{ProxyAdapter: outbound.NewDirect(), json: c.inner})
		clashRecordProbe(p, "https://example.net/", 7, true)
		if _, merged := p.clashAppendMergedJSON(nil); merged != c.merged {
			t.Errorf("%.80s: merged %v, want %v", c.inner, merged, c.merged)
		}
		want, wantErr := clashUpstreamMarshal(p)
		got, gotErr := p.MarshalJSON()
		if string(got) != string(want) || (gotErr == nil) != (wantErr == nil) {
			t.Errorf("%.80s:\n got  %s (%v)\n want %s (%v)", c.inner, got, gotErr, want, wantErr)
		}
	}
}

func TestAnUnwritableTimeFailsAsUpstream(t *testing.T) {
	proxy := clashParse(t, clashMixedNode(t, 0))
	proxy.history.Put(C.DelayHistory{Time: time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC), Delay: 1})
	_, wantErr := clashUpstreamMarshal(proxy)
	_, gotErr := proxy.MarshalJSON()
	if wantErr == nil || gotErr == nil {
		t.Fatalf("upstream %v, catalog %v; want both to fail", wantErr, gotErr)
	}
	for _, offset := range []int{0, 3600, -5 * 3600, 23*3600 + 59*60} {
		zone := time.FixedZone("z", offset)
		p := clashParse(t, clashMixedNode(t, 1))
		p.history.Put(C.DelayHistory{Time: time.Date(2026, 10, 11, 1, 2, 3, 4, zone), Delay: 9})
		want, _ := clashUpstreamMarshal(p)
		got, err := p.MarshalJSON()
		if err != nil || string(got) != string(want) {
			t.Fatalf("offset %d: %s (%v), want %s", offset, got, err, want)
		}
	}
}
