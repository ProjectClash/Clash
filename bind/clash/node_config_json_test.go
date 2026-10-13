package clash

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/adapter"
)

type nodeConfigAnswer struct {
	Found    bool           `json:"found"`
	Provider string         `json:"provider"`
	Config   map[string]any `json:"config"`
	Error    string         `json:"error"`
}

func nodeConfigCatalog(t *testing.T, library bool) *NodeCatalog {
	t.Helper()
	options := testOptions(t)
	if err := os.MkdirAll(options.WorkingPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(options.WorkingPath, "providers")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	links := strings.Join([]string{
		"ss://" + base64.RawURLEncoding.EncodeToString([]byte("aes-128-gcm:link-secret")) + "@127.0.0.1:21#%E6%97%A5%E6%9C%AC%2002",
		"trojan://trojan-secret@127.0.0.1:443?sni=example.invalid#Trojan%2001",
	}, "\n")
	payloads := map[string]string{
		"prefixed": "proxies:\n  - {name: N0, type: ss, server: 127.0.0.1, port: 10, cipher: aes-128-gcm, password: prefixed-secret}\n",
		"renamed":  "proxies:\n  - {name: HK 01, type: ss, server: 127.0.0.1, port: 11, cipher: aes-128-gcm, password: renamed-secret}\n",
		"links":    base64.StdEncoding.EncodeToString([]byte(links)),
		"zeta":     "proxies:\n  - {name: same, type: ss, server: 127.0.0.1, port: 12, cipher: aes-128-gcm, password: zeta-secret}\n",
		"alpha":    "proxies:\n  - {name: same, type: ss, server: 127.0.0.1, port: 13, cipher: aes-128-gcm, password: alpha-secret}\n",
	}
	paths := map[string]string{}
	for name, body := range payloads {
		path := filepath.Join(dir, name+".txt")
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		paths["proxy:"+name] = path
	}
	resources := map[string]any{"providerPaths": paths}
	if library {
		resources["nodeLibraryDirectory"] = filepath.Join(options.WorkingPath, "node-libraries")
	}
	resourceMap, _ := json.Marshal(resources)
	content := `mode: rule
proxies:
  - {name: own, type: ss, server: 127.0.0.1, port: 9, cipher: aes-128-gcm, password: own-secret}
proxy-providers:
  zeta: {type: http, url: "https://zeta.invalid/sub", interval: 3600}
  prefixed:
    type: http
    url: https://prefixed.invalid/sub
    interval: 3600
    override: {additional-prefix: "aws | "}
  renamed:
    type: http
    url: https://renamed.invalid/sub
    interval: 3600
    override:
      proxy-name:
        - {pattern: "^HK (\\d+)$", target: "香港 $1"}
  links: {type: http, url: "https://links.invalid/sub", interval: 3600}
  alpha: {type: http, url: "https://alpha.invalid/sub", interval: 3600}
proxy-groups:
  - {name: all, type: select, include-all: true}
rules:
  - MATCH,all
`
	catalog, err := OpenNodeCatalogForIOS(content, string(resourceMap), "{}")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(catalog.Close)
	return catalog
}

func nodeConfigOf(t *testing.T, catalog *NodeCatalog, provider, name string) nodeConfigAnswer {
	t.Helper()
	var answer nodeConfigAnswer
	raw := catalog.NodeConfigJSON(provider, name)
	if err := json.Unmarshal([]byte(raw), &answer); err != nil {
		t.Fatalf("%s: %v", raw, err)
	}
	if answer.Error != "" {
		t.Fatalf("NodeConfigJSON(%q, %q): %s", provider, name, answer.Error)
	}
	return answer
}

func TestNodeConfigJSONAnswersTheMappingANodeRunsFrom(t *testing.T) {
	for _, library := range []bool{true, false} {
		name := map[bool]string{true: "library", false: "no library"}[library]
		t.Run(name, func(t *testing.T) {
			catalog := nodeConfigCatalog(t, library)
			for _, c := range []struct {
				provider, name, wantProvider, password, server string
				port                                           string
			}{
				{"*", "aws | N0", "prefixed", "prefixed-secret", "127.0.0.1", "10"},
				{"prefixed", "aws | N0", "prefixed", "prefixed-secret", "127.0.0.1", "10"},
				{"*", "香港 01", "renamed", "renamed-secret", "127.0.0.1", "11"},
				{"*", "日本 02", "links", "link-secret", "127.0.0.1", "21"},
				{"*", "Trojan 01", "links", "trojan-secret", "127.0.0.1", "443"},
				{"*", "own", "", "own-secret", "127.0.0.1", "9"},
				{"", "own", "", "own-secret", "127.0.0.1", "9"},
				{"*", "same", "zeta", "zeta-secret", "127.0.0.1", "12"},
				{"alpha", "same", "alpha", "alpha-secret", "127.0.0.1", "13"},
			} {
				answer := nodeConfigOf(t, catalog, c.provider, c.name)
				if !answer.Found || answer.Provider != c.wantProvider {
					t.Fatalf("(%q, %q): found %v in %q, want %q", c.provider, c.name, answer.Found, answer.Provider, c.wantProvider)
				}
				if answer.Config["name"] != c.name || answer.Config["password"] != c.password ||
					answer.Config["server"] != c.server || fmt.Sprint(answer.Config["port"]) != c.port {
					t.Fatalf("(%q, %q): config %v", c.provider, c.name, answer.Config)
				}
			}
			if answer := nodeConfigOf(t, catalog, "*", "Trojan 01"); answer.Config["type"] != "trojan" || answer.Config["sni"] != "example.invalid" {
				t.Fatalf("a share link's mapping: %v", answer.Config)
			}
			for _, c := range []struct{ provider, name string }{
				{"*", "N0"},
				{"*", "all"},
				{"*", "DIRECT"},
				{"", "aws | N0"},
				{"zeta", "香港 01"},
				{"missing", "same"},
			} {
				if answer := nodeConfigOf(t, catalog, c.provider, c.name); answer.Found {
					t.Fatalf("(%q, %q) answered %+v", c.provider, c.name, answer)
				}
			}
		})
	}
}

func TestNodeConfigJSONReadsTheSubscriptionForANodeWithNoRecord(t *testing.T) {
	previous := adapter.SetNodeCatalog(false)
	t.Cleanup(func() { adapter.SetNodeCatalog(previous) })
	catalog := nodeConfigCatalog(t, false)
	for _, c := range []struct{ name, provider, password string }{
		{"aws | N0", "prefixed", "prefixed-secret"},
		{"香港 01", "renamed", "renamed-secret"},
		{"日本 02", "links", "link-secret"},
	} {
		answer := nodeConfigOf(t, catalog, "*", c.name)
		if !answer.Found || answer.Provider != c.provider || answer.Config["name"] != c.name || answer.Config["password"] != c.password {
			t.Fatalf("%q: %+v", c.name, answer)
		}
	}
}

func TestNodeConfigJSONFindsANodeOfASubscriptionTheTunnelDownloads(t *testing.T) {
	for _, size := range []string{"small", "large"} {
		t.Run(size, func(t *testing.T) {
			nodes := 7
			if size == "large" {
				for len(subscriptionPayload("N", nodes)) <= startTextSeedLimit {
					nodes *= 2
				}
			}
			payload := subscriptionPayload("N", nodes)
			fixture := newRefreshFixture(t, refreshFixtureOptions{kind: "proxy", served: payload, mapped: true})
			document := fmt.Sprintf(`mode: rule
proxy-providers:
  refreshed:
    type: http
    url: %s/nodes
    interval: 3600
    proxy: DIRECT
    override: {additional-prefix: "aws | "}
proxy-groups:
  - {name: "My🌍", type: select, use: [refreshed]}
rules:
  - MATCH,My🌍
`, fixture.server.URL)
			libraries := filepath.Join(fixture.home, "node-libraries")
			resources, _ := json.Marshal(map[string]any{"nodeLibraryDirectory": libraries})
			finalized, err := FinalizeForIOS(document, string(resources))
			if err != nil {
				t.Fatal(err)
			}
			fixture.finalized = finalized.Value
			open := func() *NodeCatalog {
				catalog, err := OpenNodeCatalogForIOS(fixture.finalized, string(resources), "{}")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(catalog.Close)
				return catalog
			}
			openWritten := func() *NodeCatalog {
				catalog, err := OpenNodeCatalogForIOS(document, string(resources), "{}")
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(catalog.Close)
				return catalog
			}
			want := func(catalog *NodeCatalog, when string) {
				t.Helper()
				answer := nodeConfigOf(t, catalog, "*", "aws | N 3")
				if !answer.Found || answer.Provider != "refreshed" || answer.Config["name"] != "aws | N 3" || answer.Config["server"] != "n3.example.net" {
					t.Fatalf("%s: %+v", when, answer)
				}
			}

			fixture.serve(http.StatusServiceUnavailable, "")
			fixture.start()
			fixture.waitForResult(providerRefreshFailed)
			var nothing struct {
				Found     bool     `json:"found"`
				NotLoaded []string `json:"notLoaded"`
			}
			_ = json.Unmarshal([]byte(open().NodeConfigJSON("*", "aws | N 3")), &nothing)
			if nothing.Found || len(nothing.NotLoaded) != 1 || nothing.NotLoaded[0] != "refreshed" {
				t.Fatalf("before the tunnel has the subscription: %+v", nothing)
			}

			fixture.serve(http.StatusOK, payload)
			if answer := UpdateProviderJSON("proxy", "refreshed", 15000); !strings.Contains(answer, providerRefreshUpdated) && !strings.Contains(answer, providerRefreshPendingApp) {
				t.Fatalf("the tunnel's download: %s", answer)
			}
			_, entry := fixture.state()
			if size == "large" && (entry == nil || entry.Result != providerRefreshPendingApp) {
				t.Fatalf("the large subscription the tunnel downloaded does not wait for the App: %+v", entry)
			}
			if size == "small" && (entry == nil || entry.Result != providerRefreshUpdated || entry.PendingSHA256 != "") {
				t.Fatalf("the small subscription the tunnel downloaded does not run: %+v", entry)
			}
			want(open(), "downloaded by the tunnel")
			want(openWritten(), "downloaded by the tunnel, the configuration as written")

			if size == "large" {
				if results := compilePendingNow(t, fixture); len(results) != 1 || results[0].Result != providerRefreshUpdated {
					t.Fatalf("the App's compile: %+v", results)
				}
				if _, entry := fixture.state(); entry == nil || entry.PendingSHA256 != "" {
					t.Fatalf("the compile left the content waiting: %+v", entry)
				}
				want(open(), "compiled by the App")
				want(openWritten(), "compiled by the App, the configuration as written")
			}
		})
	}
}

func openNodeConfigCatalog(t *testing.T, content string, payloads map[string]string) *NodeCatalog {
	t.Helper()
	options := testOptions(t)
	if err := os.MkdirAll(options.WorkingPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	paths := map[string]string{}
	for name, body := range payloads {
		path := filepath.Join(options.WorkingPath, name+".txt")
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		paths["proxy:"+name] = path
	}
	resourceMap, _ := json.Marshal(map[string]any{"providerPaths": paths, "nodeLibraryDirectory": filepath.Join(options.WorkingPath, "node-libraries")})
	catalog, err := OpenNodeCatalogForIOS(content, string(resourceMap), "{}")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(catalog.Close)
	return catalog
}

func TestNodeConfigJSONReadsTheWrittenOrderThroughAliasesAndMerges(t *testing.T) {
	payloads := map[string]string{
		"zeta":  "proxies:\n  - {name: same, type: ss, server: 127.0.0.1, port: 12, cipher: aes-128-gcm, password: zeta-secret}\n",
		"alpha": "proxies:\n  - {name: same, type: ss, server: 127.0.0.1, port: 13, cipher: aes-128-gcm, password: alpha-secret}\n",
	}
	for name, content := range map[string]string{
		"alias": `x-providers: &providers
  zeta: {type: http, url: "https://zeta.invalid/sub", interval: 3600}
  alpha: {type: http, url: "https://alpha.invalid/sub", interval: 3600}
proxy-providers: *providers
proxy-groups:
  - {name: all, type: select, include-all: true}
rules:
  - MATCH,all
`,
		"merge": `x-zeta: &zeta
  zeta: {type: http, url: "https://zeta.invalid/sub", interval: 3600}
proxy-providers:
  <<: *zeta
  alpha: {type: http, url: "https://alpha.invalid/sub", interval: 3600}
proxy-groups:
  - {name: all, type: select, include-all: true}
rules:
  - MATCH,all
`,
		"byte-order mark": "\ufeffproxy-providers:\n  zeta: {type: http, url: \"https://zeta.invalid/sub\", interval: 3600}\n  alpha: {type: http, url: \"https://alpha.invalid/sub\", interval: 3600}\nproxy-groups:\n  - {name: all, type: select, include-all: true}\nrules:\n  - MATCH,all\n",
	} {
		t.Run(name, func(t *testing.T) {
			catalog := openNodeConfigCatalog(t, content, payloads)
			if answer := nodeConfigOf(t, catalog, "*", "same"); !answer.Found || answer.Provider != "zeta" || answer.Config["password"] != "zeta-secret" {
				t.Fatalf("written zeta before alpha: %+v", answer)
			}
		})
	}
}

func TestNodeConfigJSONReadsAnInlineProvidersPayload(t *testing.T) {
	previous := adapter.SetNodeCatalog(false)
	t.Cleanup(func() { adapter.SetNodeCatalog(previous) })
	catalog := openNodeConfigCatalog(t, `proxy-providers:
  inline:
    type: inline
    override: {additional-prefix: "in | "}
    payload:
      - {name: i1, type: ss, server: 127.0.0.1, port: 14, cipher: aes-128-gcm, password: inline-secret}
proxy-groups:
  - {name: all, type: select, include-all: true}
rules:
  - MATCH,all
`, nil)
	if answer := nodeConfigOf(t, catalog, "*", "in | i1"); !answer.Found || answer.Provider != "inline" || answer.Config["password"] != "inline-secret" {
		t.Fatalf("an inline provider's node: %+v", answer)
	}
}

func TestNodeConfigJSONWritesNumberKeysAsStrings(t *testing.T) {
	catalog := openNodeConfigCatalog(t, `proxies:
  - {name: own, type: ss, server: 127.0.0.1, port: 9, cipher: aes-128-gcm, password: own-secret, x-meta: {1: one}}
proxy-groups:
  - {name: all, type: select, include-all: true}
rules:
  - MATCH,all
`, nil)
	answer := nodeConfigOf(t, catalog, "", "own")
	meta, _ := answer.Config["x-meta"].(map[string]any)
	if !answer.Found || meta["1"] != "one" {
		t.Fatalf("a mapping keyed by a number: %+v", answer)
	}
}

func TestNodeConfigJSONTurnsAPanicIntoAnError(t *testing.T) {
	catalog := nodeConfigCatalog(t, false)
	name := "NodeConfigJSON"
	appCallTestPanic.Store(&name)
	t.Cleanup(func() { appCallTestPanic.Store(nil) })
	var answer nodeConfigAnswer
	if err := json.Unmarshal([]byte(catalog.NodeConfigJSON("*", "own")), &answer); err != nil || answer.Found || answer.Error == "" {
		t.Fatalf("a panic answered %+v (%v)", answer, err)
	}
}

func TestNodeConfigJSONNamesOnlyWhatIsNotDownloadedAsNotLoaded(t *testing.T) {
	catalog := openNodeConfigCatalog(t, `proxy-providers:
  filtered:
    type: http
    url: https://filtered.invalid/sub
    interval: 3600
    filter: "^nothing-matches$"
  missing:
    type: http
    url: https://missing.invalid/sub
    interval: 3600
proxy-groups:
  - {name: all, type: select, include-all: true}
rules:
  - MATCH,all
`, map[string]string{"filtered": "proxies:\n  - {name: n1, type: ss, server: 127.0.0.1, port: 15, cipher: aes-128-gcm, password: x}\n"})
	var answer struct {
		Found     bool     `json:"found"`
		NotLoaded []string `json:"notLoaded"`
	}
	_ = json.Unmarshal([]byte(catalog.NodeConfigJSON("*", "n1")), &answer)
	if answer.Found || len(answer.NotLoaded) != 1 || answer.NotLoaded[0] != "missing" {
		t.Fatalf("answered %+v, want only the provider with nothing on disk", answer)
	}
}

func TestNodeConfigJSONReadsAnOwnNodeWithNoRecordFromALargeSection(t *testing.T) {
	previous := adapter.SetNodeCatalog(false)
	t.Cleanup(func() { adapter.SetNodeCatalog(previous) })
	var b strings.Builder
	b.WriteString("proxies:\n")
	for i := 0; b.Len() <= nodeConfigWholeLimit; i++ {
		fmt.Fprintf(&b, "  - {name: \"own %d\", type: ss, server: 127.0.0.1, port: 9, cipher: aes-128-gcm, password: secret-%d}\n", i, i)
	}
	b.WriteString("proxy-groups:\n  - {name: all, type: select, include-all: true}\nrules:\n  - MATCH,all\n")
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	catalog, err := OpenNodeCatalogForIOS(b.String(), "{}", "{}")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(catalog.Close)
	if answer := nodeConfigOf(t, catalog, "", "own 7"); !answer.Found || answer.Config["password"] != "secret-7" {
		t.Fatalf("an own node with no record in a section past 1 MiB: %+v", answer)
	}
}

func TestJSONKeysReachesListsOfMappings(t *testing.T) {
	value := map[string]any{"list": []map[any]any{{1: "one"}}, "maps": []map[string]any{{"k": map[any]any{2: "two"}}}}
	if _, err := json.Marshal(jsonKeys(value)); err != nil {
		t.Fatal(err)
	}
}

func TestOnlyTheConfigurationsOwnNodesWithoutARecordAreReadBack(t *testing.T) {
	catalog := openNodeConfigCatalog(t, `proxies:
  - {name: own, type: ss, server: 127.0.0.1, port: 9, cipher: aes-128-gcm, password: own-secret}
  - {name: my-direct, type: direct, x-created: 2026-10-13}
proxy-groups:
  - {name: all, type: select, include-all: true}
rules:
  - MATCH,all
`, nil)
	var without []string
	for name, proxy := range catalog.cfg.Proxies {
		if ownNodeWithoutRecord(name, proxy) {
			without = append(without, name)
		}
	}
	if len(without) != 1 || without[0] != "my-direct" {
		t.Fatalf("own nodes without a record: %v, want only my-direct", without)
	}
	answer := nodeConfigOf(t, catalog, "", "my-direct")
	if !answer.Found || answer.Config["type"] != "direct" || answer.Config["x-created"] == nil {
		t.Fatalf("a direct node of the configuration's own with no record: %+v", answer)
	}
}
