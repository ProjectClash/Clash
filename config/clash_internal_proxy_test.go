package config

import (
	"fmt"
	"testing"

	"github.com/ProjectClash/Clash/adapter/outboundgroup"
	C "github.com/ProjectClash/Clash/constant"
	"go.yaml.in/yaml/v3"
)

func internalProxy() map[string]any {
	return map[string]any{"name": "ENGINE", "type": "http", "server": "192.0.2.254", "port": 8080, "x-clash-internal": true}
}

const internalProxyGroups = `proxy-groups:
  - {name: all, type: url-test, include-all-proxies: true, url: "http://127.0.0.1:1/never", interval: 300}
  - {name: trojans, type: select, include-all-proxies: true, filter: "Trojan|ENGINE"}
  - {name: named, type: select, proxies: [ENGINE, "SS 0"]}
rules:
  - MATCH,all
`

func groupNames(t *testing.T, cfg *Config, name string) (selection, checked map[string]bool) {
	t.Helper()
	proxy, ok := cfg.Proxies[name]
	if !ok {
		t.Fatalf("no group %s", name)
	}
	group := proxy.Adapter().(outboundgroup.ProxyGroup)
	selection, checked = map[string]bool{}, map[string]bool{}
	for _, member := range group.Proxies() {
		selection[member.Name()] = true
	}
	for _, provider := range group.Providers() {
		for _, member := range provider.Proxies() {
			checked[member.Name()] = true
		}
	}
	return selection, checked
}

func TestAnInternalOutboundIsInNoIncludeAllGroup(t *testing.T) {
	proxies := libraryTestProxies(9)
	inlineYAML := mustYAML(t, map[string]any{"proxies": append(append([]map[string]any(nil), proxies...), internalProxy())})
	path, sum := writeLibrary(t, t.TempDir(), proxies)
	libraryYAML := fmt.Sprintf("x-clash-node-library: {path: %q, sha256: %s}\n", path, sum) + mustYAML(t, map[string]any{"proxies": []map[string]any{internalProxy()}})
	for _, tc := range []struct{ name, text string }{
		{"inline", inlineYAML + internalProxyGroups},
		{"library", libraryYAML + internalProxyGroups},
	} {
		cfg, err := Parse([]byte(tc.text))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		for _, group := range []string{"all", "trojans"} {
			selection, checked := groupNames(t, cfg, group)
			if selection["ENGINE"] || checked["ENGINE"] {
				t.Errorf("%s: include-all group %s has the internal outbound (selection %v, health check %v)", tc.name, group, selection["ENGINE"], checked["ENGINE"])
			}
			if len(selection) == 0 {
				t.Errorf("%s: include-all group %s lost its other members", tc.name, group)
			}
		}
		if selection, _ := groupNames(t, cfg, "all"); len(selection) != len(proxies) {
			t.Errorf("%s: include-all group all has %d members, want the %d nodes", tc.name, len(selection), len(proxies))
		}
		if selection, _ := groupNames(t, cfg, "named"); !selection["ENGINE"] {
			t.Errorf("%s: a group that names the internal outbound does not have it", tc.name)
		}
		if _, ok := cfg.Proxies["ENGINE"]; !ok {
			t.Errorf("%s: the internal outbound is not in the configuration", tc.name)
		}
	}
}

func TestAProxyListWithoutSkipsOnlyItsPositions(t *testing.T) {
	var base C.ProxySlice
	cfg, err := Parse([]byte(mustYAML(t, map[string]any{"proxies": libraryTestProxies(6)})))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 6; i++ {
		base = append(base, everyProxy(cfg)[libraryTestProxies(6)[i]["name"].(string)])
	}
	for _, skip := range [][]int{nil, {0}, {5}, {1, 2}, {0, 3, 5}} {
		list := C.ProxyListWithout(base, skip)
		var want []string
		for i := range base {
			skipped := false
			for _, at := range skip {
				skipped = skipped || at == i
			}
			if !skipped {
				want = append(want, base[i].Name())
			}
		}
		if list.Len() != len(want) {
			t.Fatalf("skip %v: %d members, want %d", skip, list.Len(), len(want))
		}
		for i, name := range want {
			if got := list.At(i).Name(); got != name {
				t.Fatalf("skip %v: member %d is %s, want %s", skip, i, got, name)
			}
		}
	}
}

func mustYAML(t *testing.T, v any) string {
	t.Helper()
	out, err := yaml.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}
