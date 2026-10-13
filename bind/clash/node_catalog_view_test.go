package clash

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func catalogFromHandle(t *testing.T, catalog *NodeCatalog, size int32) catalogView {
	t.Helper()
	view := catalogView{Proxies: map[string]map[string]any{}, Providers: map[string]map[string]any{}}
	for after := ""; ; {
		var page struct {
			Proxies map[string]map[string]any
			Next    string
		}
		if err := json.Unmarshal([]byte(catalog.ProxiesPageJSON(after, size)), &page); err != nil {
			t.Fatal(err)
		}
		for name, proxy := range page.Proxies {
			view.Proxies[name] = proxy
		}
		if page.Next == "" {
			break
		}
		after = page.Next
	}
	var summary struct {
		Total     int
		Groups    map[string]map[string]any
		Providers map[string]map[string]any
	}
	if err := json.Unmarshal([]byte(catalog.SummaryJSON()), &summary); err != nil {
		t.Fatal(err)
	}
	if summary.Total != len(view.Proxies) {
		t.Fatalf("the summary counts %d proxies, the pages hold %d", summary.Total, len(view.Proxies))
	}
	for name, group := range summary.Groups {
		var all []any
		for offset := int32(0); ; offset += size {
			var page struct {
				Total   int
				Members []struct{ Name string }
			}
			if err := json.Unmarshal([]byte(catalog.GroupMembersJSON(name, offset, size)), &page); err != nil {
				t.Fatal(err)
			}
			for _, member := range page.Members {
				all = append(all, member.Name)
			}
			if int(offset+size) >= page.Total {
				break
			}
		}
		if group["total"] != float64(len(all)) {
			t.Fatalf("group %s: total %v, %d members in pages", name, group["total"], len(all))
		}
		if all == nil {
			all = []any{}
		}
		view.Proxies[name]["all"] = all
	}
	for name, provider := range summary.Providers {
		var nodes []any
		for offset := int32(0); ; offset += size {
			var page struct {
				Total   int
				Proxies []any
			}
			if err := json.Unmarshal([]byte(catalog.ProviderNodesJSON(name, offset, size)), &page); err != nil {
				t.Fatal(err)
			}
			nodes = append(nodes, page.Proxies...)
			if int(offset+size) >= page.Total {
				break
			}
		}
		provider["proxies"] = nodes
		view.Providers[name] = provider
	}
	return view
}

func TestANodeCatalogIsWhatTheTunnelWouldRun(t *testing.T) {
	fixture := stageCatalogFixture(t)
	content := strings.ReplaceAll(catalogConfig(fixture.dir), "interval: 1, lazy: false", "interval: 3600, lazy: true")
	selections := map[string]string{"手选": "自动", "固定测速": "inline 日本", "Subscribe": "套餐到期：2026-10-12", "过期选择": "改名前的节点"}
	selectionsJSON, _ := json.Marshal(selections)
	want := tunnelView(t, content, fixture.resourceMap, selections)
	var resources map[string]any
	_ = json.Unmarshal([]byte(fixture.resourceMap), &resources)
	resources["nodeLibraryDirectory"] = filepath.Join(fixture.dir, "node-libraries")
	withLibrary, _ := json.Marshal(resources)
	for name, resourceMap := range map[string]string{"library": string(withLibrary), "no library": fixture.resourceMap} {
		t.Run(name, func(t *testing.T) {
			for round := 0; round < 2; round++ {
				catalog, err := OpenNodeCatalogForIOS(content, resourceMap, string(selectionsJSON))
				if err != nil {
					t.Fatal(err)
				}
				assertCatalogMatchesTunnel(t, want, catalogFromHandle(t, catalog, 2))
				catalog.Close()
				if name == "library" {
					libraries, _ := filepath.Glob(filepath.Join(fixture.dir, "node-libraries", "nodes-*.library"))
					stubs, _ := filepath.Glob(filepath.Join(fixture.dir, "node-libraries", "nodes-p*.stub"))
					if len(libraries) < 2 || len(stubs) < 1 {
						t.Fatalf("libraries %v, provider stubs %v", libraries, stubs)
					}
				}
				if answer := catalog.SummaryJSON(); !strings.Contains(answer, "closed") {
					t.Fatalf("a closed catalog answered %s", answer)
				}
			}
		})
	}
}

func TestANodeCatalogSearchFindsEveryNameThatHoldsTheQuery(t *testing.T) {
	fixture := stageCatalogFixture(t)
	content := strings.ReplaceAll(catalogConfig(fixture.dir), "interval: 1, lazy: false", "interval: 3600, lazy: true")
	var resources map[string]any
	_ = json.Unmarshal([]byte(fixture.resourceMap), &resources)
	resources["nodeLibraryDirectory"] = filepath.Join(fixture.dir, "node-libraries")
	withLibrary, _ := json.Marshal(resources)
	catalog, err := OpenNodeCatalogForIOS(content, string(withLibrary), "{}")
	if err != nil {
		t.Fatal(err)
	}
	defer catalog.Close()
	whole := catalogFromHandle(t, catalog, 50)
	type item struct{ Name, Type, Source string }
	for _, query := range []string{"美国", "INLINE", "s", "不存在"} {
		var want []item
		var groups, inline []string
		for name, proxy := range whole.Proxies {
			if !strings.Contains(strings.ToLower(name), strings.ToLower(query)) {
				continue
			}
			if _, isGroup := proxy["all"]; isGroup {
				groups = append(groups, name)
			} else {
				inline = append(inline, name)
			}
		}
		sort.Strings(groups)
		sort.Strings(inline)
		for _, name := range groups {
			want = append(want, item{name, whole.Proxies[name]["type"].(string), "group"})
		}
		for _, name := range inline {
			want = append(want, item{name, whole.Proxies[name]["type"].(string), "inline"})
		}
		var providers []string
		for name, provider := range whole.Providers {
			if provider["vehicleType"] != "Compatible" {
				providers = append(providers, name)
			}
		}
		sort.Strings(providers)
		for _, name := range providers {
			nodes, _ := whole.Providers[name]["proxies"].([]any)
			for _, raw := range nodes {
				node := raw.(map[string]any)
				if strings.Contains(strings.ToLower(node["name"].(string)), strings.ToLower(query)) {
					want = append(want, item{node["name"].(string), node["type"].(string), name})
				}
			}
		}
		var got []item
		for offset := int32(0); ; offset += 2 {
			var page struct {
				Total int
				Items []item
			}
			if err := json.Unmarshal([]byte(catalog.SearchJSON(query, offset, 2)), &page); err != nil {
				t.Fatal(err)
			}
			if page.Total != len(want) {
				t.Fatalf("%q: total %d, want %d", query, page.Total, len(want))
			}
			got = append(got, page.Items...)
			if int(offset+2) >= page.Total {
				break
			}
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("%q:\n got  %v\n want %v", query, got, want)
		}
	}
	if answer := catalog.SearchJSON(" ", 0, 10); !strings.Contains(answer, "no query") {
		t.Fatalf("an empty query answered %s", answer)
	}
}

func TestANodeCatalogOpensTheConfigurationAsPublished(t *testing.T) {
	stageCatalogFixture(t)
	dir := t.TempDir()
	resources, _ := json.Marshal(map[string]any{"nodeLibraryDirectory": dir})
	document := libraryTestDocument(120) + "proxy-groups:\n  - {name: AUTO, type: url-test, include-all: true, url: http://127.0.0.1:1/generate_204, interval: 3600, lazy: true}\n  - {name: N1x, type: select, include-all: true, filter: \"N 1\"}\n"
	document = strings.Replace(document, "proxy-groups:\n  - {name: all, type: select, include-all-proxies: true}\n", "", 1)
	document = strings.Replace(document, "rules:\n  - MATCH,all\n", "", 1) + "rules:\n  - MATCH,AUTO\n"
	finalized, err := FinalizeForIOS(document, string(resources))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(finalized.Value, "x-clash-node-library") {
		t.Fatal("the publish wrote no library")
	}
	read := func(content string) catalogView {
		catalog, err := OpenNodeCatalogForIOS(content, string(resources), "{}")
		if err != nil {
			t.Fatal(err)
		}
		defer catalog.Close()
		var summary struct{ Nodes int }
		_ = json.Unmarshal([]byte(catalog.SummaryJSON()), &summary)
		if summary.Nodes != 120+testMeshNodes {
			t.Fatalf("own nodes %d", summary.Nodes)
		}
		return catalogFromHandle(t, catalog, 37)
	}
	fromSource, fromPublished := read(document), read(finalized.Value)
	for _, group := range []string{"AUTO", "N1x", "GLOBAL"} {
		if got, want := fmt.Sprint(fromPublished.Proxies[group]["all"]), fmt.Sprint(fromSource.Proxies[group]["all"]); got != want || got == "[]" {
			t.Fatalf("%s: published %.200s, source %.200s", group, got, want)
		}
	}
	if len(fromPublished.Proxies) != len(fromSource.Proxies) {
		t.Fatalf("%d proxies from the published configuration, %d from its source", len(fromPublished.Proxies), len(fromSource.Proxies))
	}
	var reference struct{ Path string }
	for _, line := range strings.Split(finalized.Value, "\n") {
		if strings.Contains(line, "path:") && strings.Contains(line, nodeLibraryPrefix) {
			reference.Path = strings.TrimSpace(strings.SplitN(line, "path:", 2)[1])
		}
	}
	libraries, _ := filepath.Glob(filepath.Join(dir, nodeLibraryPrefix+"*"+nodeLibrarySuffix))
	for _, library := range libraries {
		_ = os.Remove(library)
	}
	if _, err := OpenNodeCatalogForIOS(finalized.Value, string(resources), "{}"); err == nil || !strings.Contains(err.Error(), NodeLibraryUnavailablePrefix) {
		t.Fatalf("with the library gone the open answered %v (library %s)", err, reference.Path)
	}
}

func TestProxyCatalogForIOSHoldsALibrarysNodes(t *testing.T) {
	stageCatalogFixture(t)
	resources, _ := json.Marshal(map[string]any{"nodeLibraryDirectory": t.TempDir()})
	document := libraryTestDocument(60)
	finalized, err := FinalizeForIOS(document, string(resources))
	if err != nil {
		t.Fatal(err)
	}
	for _, content := range []string{document, finalized.Value} {
		view := catalogFor(t, content, string(resources), nil)
		all, _ := view.Proxies["all"]["all"].([]any)
		if len(all) != 60+testMeshNodes {
			t.Fatalf("the group names %d members", len(all))
		}
		for _, name := range all {
			if _, ok := view.Proxies[name.(string)]; !ok {
				t.Fatalf("%v is a member but not in the catalog's proxies", name)
			}
		}
	}
}
