package clash

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter/outboundgroup"
	"github.com/ProjectClash/Clash/component/geodata"
)

const catalogProviderA = `proxies:
  - {name: "香港 01", type: ss, server: 127.0.0.1, port: 1, cipher: aes-128-gcm, password: x}
  - {name: "美国 01", type: ss, server: 127.0.0.1, port: 2, cipher: aes-128-gcm, password: x}
  - {name: "日本 01", type: trojan, server: 127.0.0.1, port: 3, password: x}
  - {name: "剩余流量：4.61 GB", type: hysteria2, server: 127.0.0.1, port: 4, password: x}
  - {name: "距离下次重置剩余：19 天", type: hysteria2, server: 127.0.0.1, port: 5, password: x}
  - {name: "套餐到期：2026-10-12", type: hysteria2, server: 127.0.0.1, port: 6, password: x}
  - {name: "美国 02 维护", type: ss, server: 127.0.0.1, port: 7, cipher: aes-128-gcm, password: x}
`

const catalogProviderB = `proxies:
  - {name: "新加坡 01", type: ss, server: 127.0.0.1, port: 11, cipher: aes-128-gcm, password: x, interface-name: en0}
  - {name: "美国 03", type: vmess, server: 127.0.0.1, port: 12, uuid: 11111111-1111-1111-1111-111111111111, alterId: 0, cipher: auto, routing-mark: 7}
  - {name: "香港 02", type: ss, server: 127.0.0.1, port: 13, cipher: aes-128-gcm, password: x}
`

func catalogProviderURIList() string {
	lines := []string{
		"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:x")) + "@127.0.0.1:21#%E6%97%A5%E6%9C%AC%2002",
		"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:x")) + "@127.0.0.1:22#%E5%8F%B0%E6%B9%BE%2001",
	}
	return base64.StdEncoding.EncodeToString([]byte(strings.Join(lines, "\n")))
}

func catalogConfig(dir string) string {
	return `
mode: rule
proxies:
  - {name: "inline 美国", type: ss, server: 127.0.0.1, port: 31, cipher: aes-128-gcm, password: x}
  - {name: "inline 香港", type: http, server: 127.0.0.1, port: 32}
  - {name: "inline 日本", type: ss, server: 127.0.0.1, port: 33, cipher: aes-128-gcm, password: x}
proxy-providers:
  airport:
    type: http
    url: https://airport.invalid/sub
    interval: 3600
    health-check: {enable: true, url: http://127.0.0.1:1/generate_204, interval: 1, lazy: false}
  second:
    type: file
    path: ` + filepath.Join(dir, "second.yaml") + `
    filter: "美国|香港|新加坡"
    exclude-filter: "香港 02"
    override:
      additional-prefix: "[B] "
  urilist:
    type: http
    url: https://airport.invalid/uri
    interval: 3600
  never-fetched:
    type: http
    url: https://airport.invalid/never
    interval: 3600
  with-fallback:
    type: http
    url: https://airport.invalid/fallback
    interval: 3600
    payload:
      - {name: "兜底 香港", type: ss, server: 127.0.0.1, port: 41, cipher: aes-128-gcm, password: x}
  unmapped:
    type: http
    url: http://127.0.0.1:1/unmapped
    path: ` + filepath.Join(dir, "unmapped.yaml") + `
    interval: 3600
  embedded:
    type: inline
    payload:
      - {name: "内嵌 美国", type: ss, server: 127.0.0.1, port: 51, cipher: aes-128-gcm, password: x}
proxy-groups:
  - {name: Subscribe, type: select, filter: "剩余|到期|重置", include-all-providers: true, proxies: ["更新: 2026-09-23 15:06:51"]}
  - {name: "更新: 2026-09-23 15:06:51", type: select, hidden: true, proxies: [DIRECT]}
  - {name: 多条筛选, type: select, use: [second, airport], filter: "香港` + "`" + `美国", exclude-filter: "维护"}
  - {name: 排除类型, type: select, include-all-providers: true, exclude-type: "Shadowsocks|hysteria2"}
  - {name: 内联筛选, type: select, include-all-proxies: true, filter: "美国|香港", exclude-type: http}
  - {name: 全部, type: url-test, include-all: true, url: http://127.0.0.1:1/generate_204, interval: 1, lazy: false, icon: "https://icon.invalid/a.png"}
  - {name: 筛空, type: select, include-all-providers: true, filter: "不存在的地区", empty-fallback: REJECT}
  - {name: 自动, type: fallback, use: [urilist, never-fetched, with-fallback, embedded, unmapped], url: http://127.0.0.1:1/generate_204, interval: 1, lazy: false}
  - {name: 手选, type: select, default-selected: 自动, proxies: [全部, 自动, DIRECT, "更新: 2026-09-23 15:06:51"]}
  - {name: 过期选择, type: select, default-selected: 全部, proxies: [自动, 全部]}
  - {name: 固定测速, type: url-test, proxies: [inline 美国, inline 日本], url: http://127.0.0.1:1/generate_204, interval: 300}
rules:
  - MATCH,手选
`
}

type catalogFixture struct {
	dir         string
	resourceMap string
}

func stageCatalogFixture(t *testing.T) catalogFixture {
	t.Helper()
	options := testOptions(t)
	if err := os.MkdirAll(options.WorkingPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { setStartupBreadcrumbRecording(false) })
	dir := filepath.Join(options.WorkingPath, "providers")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{
		"airport.yaml":  catalogProviderA,
		"second.yaml":   catalogProviderB,
		"urilist.txt":   catalogProviderURIList(),
		"unmapped.yaml": "proxies:\n  - {name: \"未映射 日本\", type: ss, server: 127.0.0.1, port: 61, cipher: aes-128-gcm, password: x, interface-name: en0}\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	resources, _ := json.Marshal(map[string]any{"providerPaths": map[string]string{
		"proxy:airport":       filepath.Join(dir, "airport.yaml"),
		"proxy:urilist":       filepath.Join(dir, "urilist.txt"),
		"proxy:never-fetched": filepath.Join(dir, "never-fetched.yaml"),
		"proxy:with-fallback": filepath.Join(dir, "with-fallback.yaml"),
	}})
	return catalogFixture{dir: dir, resourceMap: string(resources)}
}

type catalogView struct {
	Proxies   map[string]map[string]any `json:"proxies"`
	Providers map[string]map[string]any `json:"providers"`
}

func stopHealthChecks(t *testing.T, closers []io.Closer) {
	t.Helper()
	for _, closer := range closers {
		_ = closer.Close()
	}
	deadline := time.Now().Add(10 * time.Second)
	buf := make([]byte, 1<<22)
	for {
		stacks := string(buf[:runtime.Stack(buf, true)])
		if !strings.Contains(stacks, "adapter/provider.(*HealthCheck)") {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the yardstick's health checks did not stop within ten seconds of their providers closing")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func tunnelView(t *testing.T, content, resourceMap string, selections map[string]string) catalogView {
	t.Helper()
	finalized, err := FinalizeForIOS(content, resourceMap)
	if err != nil {
		t.Fatal(err)
	}
	cfg, runtime, err := parseConfigForIOSRuntime(finalized.Value, true, "catalog-yardstick")
	if err != nil {
		t.Fatal(err)
	}
	if runtime != nil {
		t.Cleanup(runtime.close)
	}
	var closers []io.Closer
	for _, provider := range cfg.Providers {
		_ = provider.Initial()
		if closer, ok := provider.(io.Closer); ok {
			closers = append(closers, closer)
		}
	}
	defer stopHealthChecks(t, closers)
	if cfg.Profile.StoreSelected {
		for group, member := range selections {
			if selectable, ok := cfg.Proxies[group].Adapter().(outboundgroup.SelectAble); ok {
				selectable.ForceSet(member)
			}
		}
	}
	for group, member := range selections {
		if selectable, ok := cfg.Proxies[group].Adapter().(outboundgroup.SelectAble); ok {
			_ = selectable.Set(member)
		}
	}
	var view catalogView
	data, err := json.Marshal(map[string]any{"proxies": cfg.Proxies, "providers": cfg.Providers})
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &view); err != nil {
		t.Fatal(err)
	}
	return view
}

func catalogFor(t *testing.T, content, resourceMap string, selections map[string]string) catalogView {
	t.Helper()
	selectionsJSON, _ := json.Marshal(selections)
	box, err := ProxyCatalogForIOS(content, resourceMap, string(selectionsJSON))
	if err != nil {
		t.Fatal(err)
	}
	var view catalogView
	if err := json.Unmarshal([]byte(box.Value), &view); err != nil {
		t.Fatal(err)
	}
	return view
}

var catalogGroupFields = []string{"type", "all", "now", "hidden", "icon", "testUrl", "fixed", "emptyFallback"}

func assertCatalogMatchesTunnel(t *testing.T, want, got catalogView) {
	t.Helper()
	for name, reference := range want.Proxies {
		entry, ok := got.Proxies[name]
		if !ok {
			t.Errorf("%q is in /proxies but not in the catalog", name)
			continue
		}
		if _, isGroup := reference["all"]; !isGroup {
			if entry["type"] != reference["type"] {
				t.Errorf("%q: type %v, the tunnel says %v", name, entry["type"], reference["type"])
			}
			continue
		}
		for _, field := range catalogGroupFields {
			if field == "now" && reference["type"] != "Selector" {
				continue
			}
			if field == "fixed" && reference["type"] == "Fallback" {
				continue
			}
			if !reflect.DeepEqual(entry[field], reference[field]) {
				t.Errorf("group %q field %q: catalog %v, the tunnel says %v", name, field, entry[field], reference[field])
			}
		}
	}
	for name := range got.Proxies {
		if _, ok := want.Proxies[name]; !ok {
			t.Errorf("%q is in the catalog but not in /proxies", name)
		}
	}
	for name, reference := range want.Providers {
		entry, ok := got.Providers[name]
		if !ok {
			t.Errorf("provider %q is in /providers/proxies but not in the catalog", name)
			continue
		}
		for _, field := range []string{"name", "type", "vehicleType", "testUrl", "expectedStatus"} {
			if !reflect.DeepEqual(entry[field], reference[field]) {
				t.Errorf("provider %q field %q: catalog %v, the tunnel says %v", name, field, entry[field], reference[field])
			}
		}
		if !reflect.DeepEqual(providerNodes(entry), providerNodes(reference)) {
			t.Errorf("provider %q nodes: catalog %v, the tunnel says %v", name, providerNodes(entry), providerNodes(reference))
		}
	}
	for name := range got.Providers {
		if _, ok := want.Providers[name]; !ok {
			t.Errorf("provider %q is in the catalog but not in /providers/proxies", name)
		}
	}
}

func providerNodes(provider map[string]any) []string {
	var out []string
	list, _ := provider["proxies"].([]any)
	for _, raw := range list {
		node, _ := raw.(map[string]any)
		name, _ := node["name"].(string)
		kind, _ := node["type"].(string)
		iface, _ := node["interface"].(string)
		mark := fmt.Sprint(node["routing-mark"])
		out = append(out, name+"|"+kind+"|"+iface+"|"+mark)
	}
	return out
}

func TestProxyCatalogIsWhatTheTunnelWouldRun(t *testing.T) {
	for _, storeSelected := range []bool{true, false} {
		t.Run("store-selected="+strconv.FormatBool(storeSelected), func(t *testing.T) {
			fixture := stageCatalogFixture(t)
			content := strings.ReplaceAll(catalogConfig(fixture.dir), "interval: 1, lazy: false", "interval: 3600, lazy: true")
			if !storeSelected {
				content += "profile: {store-selected: false}\n"
			}
			selections := map[string]string{
				"手选":        "自动",
				"固定测速":      "inline 日本",
				"Subscribe": "套餐到期：2026-10-12",
				"自动":        "台湾 01",
				"过期选择":      "改名前的节点",
				"全部":        "也不存在了",
			}
			assertCatalogMatchesTunnel(t,
				tunnelView(t, content, fixture.resourceMap, selections),
				catalogFor(t, content, fixture.resourceMap, selections))
		})
	}
}

func TestProxyCatalogDrawsTheSubscriptionInfoGroupAsOtherClientsDo(t *testing.T) {
	fixture := stageCatalogFixture(t)
	got := catalogFor(t, catalogConfig(fixture.dir), fixture.resourceMap, nil)

	wantMembers := []any{"更新: 2026-09-23 15:06:51", "剩余流量：4.61 GB", "距离下次重置剩余：19 天", "套餐到期：2026-10-12"}
	if members := got.Proxies["Subscribe"]["all"]; !reflect.DeepEqual(members, wantMembers) {
		t.Fatalf("Subscribe members %v, want %v", members, wantMembers)
	}
	if hidden := got.Proxies["更新: 2026-09-23 15:06:51"]["hidden"]; hidden != true {
		t.Fatalf("the hidden group must say so, got hidden=%v", hidden)
	}
	wantFiltered := []any{"香港 01", "[B] 美国 03", "美国 01"}
	if members := got.Proxies["多条筛选"]["all"]; !reflect.DeepEqual(members, wantFiltered) {
		t.Fatalf("多条筛选 members %v, want %v", members, wantFiltered)
	}
	pinned := catalogFor(t, catalogConfig(fixture.dir), fixture.resourceMap,
		map[string]string{"自动": "台湾 01", "过期选择": "改名前的节点"})
	if fixed := pinned.Proxies["自动"]["fixed"]; fixed != "台湾 01" {
		t.Fatalf("the fallback pin before Connect is %v, want 台湾 01", fixed)
	}
	if now := pinned.Proxies["过期选择"]["now"]; now != "自动" {
		t.Fatalf("a renamed-away selection shows %v, want the first member 自动", now)
	}
}

func TestProxyCatalogDoesNotNeedWhatOnlyRulesRead(t *testing.T) {
	fixture := stageCatalogFixture(t)
	content := strings.Replace(catalogConfig(fixture.dir), "rules:\n  - MATCH,手选\n",
		"rules:\n  - GEOIP,CN,DIRECT\n  - GEOSITE,google,手选\n  - RULE-SET,unfetched,DIRECT\n  - MATCH,手选\n"+
			"rule-providers:\n  unfetched: {type: http, url: https://rules.invalid/x.mrs, behavior: domain, format: mrs}\n"+
			"dns:\n  enable: true\n  nameserver-policy: {\"geosite:cn\": 223.5.5.5}\n", 1)
	got := catalogFor(t, content, fixture.resourceMap, nil)
	if members, _ := got.Proxies["Subscribe"]["all"].([]any); len(members) != 4 {
		t.Fatalf("Subscribe members %v", members)
	}
}

func TestProxyCatalogTouchesNoNetworkAndWritesNothing(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var hits atomic.Int32
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})}
	go server.Serve(listener)
	t.Cleanup(func() { _ = server.Close() })
	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)

	fixture := stageCatalogFixture(t)
	content := strings.ReplaceAll(catalogConfig(fixture.dir), "127.0.0.1:1/", "127.0.0.1:"+port+"/")
	content = strings.ReplaceAll(content, "https://airport.invalid/", "http://127.0.0.1:"+port+"/")
	content = strings.Replace(content, "type: http, server: 127.0.0.1, port: 32}", "type: http, server: 127.0.0.1, port: "+port+"}", 1)
	probe := catalogProviderA + `  - {name: "探针", type: http, server: 127.0.0.1, port: ` + port + "}\n"
	if err := os.WriteFile(filepath.Join(fixture.dir, "airport.yaml"), []byte(probe), 0o644); err != nil {
		t.Fatal(err)
	}
	home := filepath.Dir(fixture.dir)
	before := snapshotTree(t, home)

	catalogFor(t, content, fixture.resourceMap, map[string]string{"手选": "全部", "自动": "台湾 01"})
	time.Sleep(1500 * time.Millisecond)

	if n := hits.Load(); n != 0 {
		t.Fatalf("the catalog made %d requests", n)
	}
	if after := snapshotTree(t, home); !reflect.DeepEqual(before, after) {
		t.Fatalf("the catalog changed the home directory:\nbefore %v\nafter  %v", catalogTreeKeys(before), catalogTreeKeys(after))
	}
	if breadcrumbRecording.Load() {
		t.Fatal("the catalog armed the startup record")
	}
}

func snapshotTree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		data, _ := os.ReadFile(path)
		rel, _ := filepath.Rel(root, path)
		out[rel] = info.ModTime().String() + "|" + string(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func catalogTreeKeys(m map[string]string) []string {
	var out []string
	for key := range m {
		out = append(out, key)
	}
	return out
}

func TestProxyCatalogReportsAnUnreadablePayloadAndKeepsTheRest(t *testing.T) {
	fixture := stageCatalogFixture(t)
	if err := os.WriteFile(filepath.Join(fixture.dir, "urilist.txt"), []byte("<html>not a subscription</html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	box, err := ProxyCatalogForIOS(catalogConfig(fixture.dir), fixture.resourceMap, "")
	if err != nil {
		t.Fatal(err)
	}
	var decoded struct {
		Proxies        map[string]map[string]any `json:"proxies"`
		ProviderErrors map[string]string         `json:"providerErrors"`
	}
	if err := json.Unmarshal([]byte(box.Value), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.ProviderErrors["urilist"] == "" {
		t.Fatalf("the unreadable payload must be reported: %v", decoded.ProviderErrors)
	}
	if members, _ := decoded.Proxies["Subscribe"]["all"].([]any); len(members) != 4 {
		t.Fatalf("the other providers must still fill their groups: %v", members)
	}
}

func TestProxyCatalogRefusesWhatItCannotRead(t *testing.T) {
	stageCatalogFixture(t)
	if _, err := ProxyCatalogForIOS("proxies: [", "", ""); err == nil {
		t.Fatal("a document that does not parse must be an error")
	}
	if _, err := ProxyCatalogForIOS("mode: rule\n", "not json", ""); err == nil {
		t.Fatal("a resource map that is not JSON must be an error")
	}
	if _, err := ProxyCatalogForIOS("mode: rule\n", "", "not json"); err == nil {
		t.Fatal("a selection map that is not JSON must be an error")
	}
	if _, err := ProxyCatalogForIOS("mode: rule\n", "", ""); err != nil {
		t.Fatalf("empty maps must be accepted: %v", err)
	}
}

func TestCheckConfigLeavesNoStartupRecord(t *testing.T) {
	fixture := stageCatalogFixture(t)
	home := filepath.Dir(fixture.dir)
	setStartupBreadcrumbRecording(false)
	if err := CheckConfig("mode: rule\nproxies: []\nrules:\n  - MATCH,DIRECT\n"); err != nil {
		t.Fatal(err)
	}
	if breadcrumbRecording.Load() {
		t.Fatal("CheckConfig armed the startup record")
	}
	if _, err := os.Stat(filepath.Join(home, "startup-breadcrumb.json")); err == nil {
		t.Fatal("CheckConfig wrote a startup record")
	}
}

func TestProxyCatalogRestoresTheGeodataFlags(t *testing.T) {
	fixture := stageCatalogFixture(t)
	for _, want := range []bool{false, true} {
		geodata.SetCompiledGeoSiteOnly(want)
		geodata.SetCompiledGeoIPOnly(want)
		catalogFor(t, catalogConfig(fixture.dir), fixture.resourceMap, nil)
		if geodata.CompiledGeoSiteOnly() != want || geodata.CompiledGeoIPOnly() != want {
			t.Fatalf("flags were %v before the catalog and %v/%v after", want, geodata.CompiledGeoSiteOnly(), geodata.CompiledGeoIPOnly())
		}
	}
	geodata.SetCompiledGeoSiteOnly(false)
	geodata.SetCompiledGeoIPOnly(false)
}
