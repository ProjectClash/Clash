package clash

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/config"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	"github.com/ProjectClash/Clash/tunnel"
)

func TestTheNodeListAndAGroupsMembersComeInPages(t *testing.T) {
	dir := t.TempDir()
	resources, _ := json.Marshal(map[string]any{"nodeLibraryDirectory": dir})
	finalized, err := FinalizeForIOS(libraryTestDocument(230), string(resources))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := parseAfterLookups(finalized.Value)
	if err != nil {
		t.Fatal(err)
	}
	previousProxies, previousProviders := tunnel.Proxies(), tunnel.Providers()
	tunnel.UpdateProxies(cfg.Proxies, cfg.Providers, cfg.ProxyLibrary)
	t.Cleanup(func() { tunnel.UpdateProxies(previousProxies, previousProviders) })

	var whole bytes.Buffer
	if err := adapter.WriteProxiesJSON(&whole, cfg.Proxies, cfg.ProxyLibrary); err != nil {
		t.Fatal(err)
	}
	var want map[string]json.RawMessage
	_ = json.Unmarshal(whole.Bytes(), &want)
	got, after, pages := map[string]json.RawMessage{}, "", 0
	var order []string
	for {
		var page struct {
			Proxies map[string]json.RawMessage
			Next    string
		}
		text := ProxiesPageJSON(after, 17)
		if err := json.Unmarshal([]byte(text), &page); err != nil {
			t.Fatalf("%v: %.200s", err, text)
		}
		if len(page.Proxies) > 17 {
			t.Fatalf("a page of %d", len(page.Proxies))
		}
		for name, raw := range page.Proxies {
			if _, seen := got[name]; seen {
				t.Fatalf("%s on two pages", name)
			}
			got[name] = raw
			order = append(order, name)
		}
		pages++
		if page.Next == "" {
			break
		}
		after = page.Next
	}
	if len(got) != len(want) || pages < 2 {
		t.Fatalf("%d proxies in %d pages, the whole holds %d", len(got), pages, len(want))
	}
	groups := 0
	for name, raw := range want {
		if _, isGroup := runningNodeView().groupMembers(name); isGroup {
			groups++
			var whole, paged map[string]any
			_ = json.Unmarshal(raw, &whole)
			_ = json.Unmarshal(got[name], &paged)
			all, _ := whole["all"].([]any)
			if paged["all"] != nil || paged["total"] != float64(len(all)) || paged["type"] != whole["type"] || paged["now"] != whole["now"] {
				t.Fatalf("group %s: %s", name, got[name])
			}
			continue
		}
		if string(got[name]) != string(raw) {
			t.Fatalf("%s differs", name)
		}
	}
	if groups < 2 {
		t.Fatalf("%d groups among the pages", groups)
	}

	var members []string
	for offset := int32(0); ; offset += 50 {
		var page struct {
			Total   int
			Members []struct{ Name, Type string }
		}
		_ = json.Unmarshal([]byte(GroupMembersJSON("all", offset, 50)), &page)
		for _, member := range page.Members {
			if member.Type == "" {
				t.Fatalf("%s comes without its type", member.Name)
			}
			members = append(members, member.Name)
		}
		if int(offset)+50 >= page.Total {
			break
		}
	}
	encoded, _ := json.Marshal(cfg.Proxies["all"])
	var group struct{ All []string }
	_ = json.Unmarshal(encoded, &group)
	if strings.Join(members, ",") != strings.Join(group.All, ",") {
		t.Fatalf("members in pages: %d, the group's: %d", len(members), len(group.All))
	}
	if answer := GroupMembersJSON("all", 0, 1); !strings.Contains(answer, `"revision":"`) {
		t.Fatalf("a page of the running list carries no revision: %s", answer)
	}
	if answer := GroupMembersJSON("nope", 0, 10); !strings.Contains(answer, "no such group") {
		t.Fatalf("an unknown group: %s", answer)
	}

	var summary struct {
		Revision string
		Total    int
		Groups   map[string]map[string]any
	}
	if err := json.Unmarshal([]byte(ProxiesSummaryJSON()), &summary); err != nil || summary.Revision == "" || summary.Total != len(want) ||
		len(summary.Groups) != groups || summary.Groups["all"]["total"] != float64(len(group.All)) || summary.Groups["all"]["all"] != nil {
		t.Fatalf("summary %+v (%v)", summary, err)
	}
}

func TestAProvidersNodesComeInPages(t *testing.T) {
	var b strings.Builder
	b.WriteString("proxy-providers:\n  in:\n    type: inline\n    payload:\n")
	for i := 0; i < 23; i++ {
		b.WriteString("      - {name: \"p" + strings.Repeat("x", i%3) + string(rune('a'+i)) + "\", type: socks5, server: s.example.net, port: 1080}\n")
	}
	b.WriteString("proxy-groups:\n  - {name: g, type: select, use: [in]}\nrules:\n  - MATCH,g\n")
	cfg, err := parseAfterLookups(b.String())
	if err != nil {
		t.Fatal(err)
	}
	view := nodeView{proxies: cfg.Proxies, library: cfg.ProxyLibrary, providers: cfg.Providers}
	whole, _ := json.Marshal(cfg.Providers["in"])
	var want struct{ Proxies []json.RawMessage }
	_ = json.Unmarshal(whole, &want)
	var got []json.RawMessage
	for offset := 0; ; offset += 5 {
		answer, status := view.providerNodesAnswer("in", offset, 5)
		var page struct {
			Total   int
			Proxies []json.RawMessage
		}
		if status != 200 || json.Unmarshal([]byte(answer), &page) != nil || page.Total != 23 {
			t.Fatalf("%d %s", status, answer)
		}
		got = append(got, page.Proxies...)
		if offset+5 >= page.Total {
			break
		}
	}
	if len(got) != len(want.Proxies) {
		t.Fatalf("%d nodes in pages, %d in the provider", len(got), len(want.Proxies))
	}
	for i := range got {
		if string(got[i]) != string(want.Proxies[i]) {
			t.Fatalf("node %d: %s, the provider's %s", i, got[i], want.Proxies[i])
		}
	}
	if _, status := view.providerNodesAnswer("nope", 0, 5); status != 404 {
		t.Fatalf("an unknown provider answered %d", status)
	}
}

func TestGroupMembersSayWhoseNodeEachIs(t *testing.T) {
	document := `proxies:
  - {name: dup, type: socks5, server: a.example.net, port: 1080}
  - {name: own, type: socks5, server: b.example.net, port: 1080}
proxy-providers:
  in:
    type: inline
    payload:
      - {name: dup, type: socks5, server: c.example.net, port: 1080}
      - {name: theirs, type: socks5, server: d.example.net, port: 1080}
proxy-groups:
  - {name: g, type: select, proxies: [dup, own, DIRECT], use: [in]}
rules:
  - MATCH,g
`
	cfg, err := parseAfterLookups(document)
	if err != nil {
		t.Fatal(err)
	}
	view := nodeView{proxies: cfg.Proxies, library: cfg.ProxyLibrary, providers: cfg.Providers}
	answer, status := view.membersAnswer("g", 0, 0)
	var page struct {
		Members []struct {
			Name, Type, PlaceholderType string
			Inline                      bool
		}
	}
	if status != 200 || json.Unmarshal([]byte(answer), &page) != nil {
		t.Fatalf("%d %s", status, answer)
	}
	var got []string
	for _, m := range page.Members {
		got = append(got, fmt.Sprintf("%s:%v:%s", m.Name, m.Inline, m.PlaceholderType))
	}
	if want := "dup:true: own:true: DIRECT:true: dup:false: theirs:false:"; strings.Join(got, " ") != want {
		t.Fatalf("members %s, want %s", strings.Join(got, " "), want)
	}
	var summary struct {
		Nodes  int
		Groups map[string]struct {
			NowMember struct {
				Name   string
				Inline bool
			}
		}
	}
	if json.Unmarshal([]byte(view.summaryJSON()), &summary) != nil || summary.Nodes != 2 {
		t.Fatalf("own nodes counted %d, want 2: %s", summary.Nodes, view.summaryJSON())
	}
	if now := summary.Groups["g"].NowMember; now.Name != "dup" || !now.Inline {
		t.Fatalf("the group's chosen member: %+v", now)
	}
	_ = cfg.Proxies["g"].Adapter().(interface{ ForceSet(string) })
	cfg.Proxies["g"].Adapter().(interface{ ForceSet(string) }).ForceSet("theirs")
	_ = json.Unmarshal([]byte(view.summaryJSON()), &summary)
	if now := summary.Groups["g"].NowMember; now.Name != "theirs" || now.Inline {
		t.Fatalf("the group's chosen subscription member: %+v", now)
	}
	if got := placeholderType(adapter.NewProxy(placeholderForTest{outbound.NewReject()})); got != "easytier" {
		t.Fatalf("placeholder %q", got)
	}
	if got := placeholderType(cfg.Proxies["own"]); got != "" {
		t.Fatalf("a node said it was a placeholder for %q", got)
	}
}

type placeholderForTest struct{ *outbound.Reject }

func (placeholderForTest) ClashDeclaredType() C.AdapterType { return C.EasyTier }

func TestAGroupInSummaryIsItsJSONWithoutItsMembers(t *testing.T) {
	document := `proxies:
  - {name: a, type: socks5, server: a.example.net, port: 1080}
  - {name: b, type: socks5, server: b.example.net, port: 1080}
proxy-groups:
  - {name: sel, type: select, proxies: [a, b], icon: "https://i.example/<x>.png"}
  - {name: auto, type: url-test, proxies: [a, b], url: "http://127.0.0.1:1/t", interval: 3600, lazy: true}
  - {name: fb, type: fallback, proxies: [a, b], url: "http://127.0.0.1:1/t", interval: 3600, lazy: true}
  - {name: lb, type: load-balance, proxies: [a, b], url: "http://127.0.0.1:1/t", interval: 3600, lazy: true}
rules:
  - MATCH,sel
`
	cfg, err := parseAfterLookups(document)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"sel", "auto", "fb", "lb", "GLOBAL"} {
		whole, err := adapter.AppendProxyJSON(nil, cfg.Proxies[name])
		if err != nil {
			t.Fatal(err)
		}
		var want map[string]any
		_ = json.Unmarshal(whole, &want)
		all, _ := want["all"].([]any)
		delete(want, "all")
		want["total"] = float64(len(all))
		summary, err := adapter.AppendProxySummaryJSON(nil, cfg.Proxies[name])
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]any
		if err := json.Unmarshal(summary, &got); err != nil {
			t.Fatalf("%s: %v: %s", name, err, summary)
		}
		if fmt.Sprint(got) != fmt.Sprint(want) || strings.Contains(string(summary), `"all"`) {
			t.Fatalf("%s:\n got  %s\n want %v", name, summary, want)
		}
	}
}

type changingProvider struct {
	P.ProxyProvider
	version uint32
}

func (p *changingProvider) VehicleType() P.VehicleType { return P.HTTP }
func (p *changingProvider) Version() uint32            { p.version++; return p.version }

func TestAPageOfAListChangingUnderEveryReadIsRefused(t *testing.T) {
	table := uint64(1)
	changing := &changingProvider{}
	view := nodeView{providers: map[string]P.ProxyProvider{"p": changing}, table: &table}
	reads := 0
	answer, status := view.consistentPage(func() (string, int) { reads++; return `{"page":1}`, 200 })
	if status != 503 || !strings.Contains(answer, `"error"`) || reads != 3 {
		t.Fatalf("a list changing under every read answered %d %s after %d reads", status, answer, reads)
	}
	still := nodeView{providers: map[string]P.ProxyProvider{}, table: &table}
	if answer, status := still.consistentPage(func() (string, int) { return `{"page":1}`, 200 }); status != 200 || answer != `{"page":1}` {
		t.Fatalf("a still list answered %d %s", status, answer)
	}
}

func TestTheChosenMemberIsTheOneTheGroupDials(t *testing.T) {
	const testURL = "http://127.0.0.1:1/generate_204"
	document := `proxies:
  - {name: dup, type: socks5, server: 127.0.0.1, port: 1}
proxy-providers:
  in:
    type: inline
    health-check: {enable: false, url: ` + testURL + `}
    payload:
      - {name: dup, type: socks5, server: 127.0.0.1, port: 2}
proxy-groups:
  - {name: f, type: fallback, proxies: [dup], use: [in], url: ` + testURL + `, interval: 0}
rules:
  - MATCH,f
`
	cfg := parseConfigForTest(t, document)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := cfg.Proxies["dup"].URLTest(ctx, testURL, nil); err == nil {
		t.Fatal("a test through a closed port passed")
	}
	view := nodeView{proxies: cfg.Proxies, library: cfg.ProxyLibrary, providers: cfg.Providers}
	var summary struct {
		Groups map[string]struct {
			Now       string
			NowMember struct {
				Name   string
				Inline bool
			}
		}
	}
	if err := json.Unmarshal([]byte(view.summaryJSON()), &summary); err != nil {
		t.Fatal(err)
	}
	if g := summary.Groups["f"]; g.Now != "dup" || g.NowMember.Name != "dup" || g.NowMember.Inline {
		t.Fatalf("the fallback dials the subscription's dup; the summary says %+v", g)
	}
	stale := []byte(`{"now":"other","type":"Fallback"}`)
	if got := view.appendNowMember(stale, 0, cfg.Proxies["f"]); string(got) != `{"now":"other","type":"Fallback"}` {
		t.Fatalf("a stale now got %s", got)
	}
	if got := view.appendNowMember([]byte(`{"now":"dup","type":"Fallback"}`), 0, cfg.Proxies["f"]); !strings.Contains(string(got), `"nowMember":{"name":"dup"`) {
		t.Fatalf("a current now got %s", got)
	}
}

func parseConfigForTest(t *testing.T, text string) *config.Config {
	t.Helper()
	cfg, err := parseAfterLookups(text)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func parseAfterLookups(text string) (*config.Config, error) {
	deadline := time.Now().Add(20 * time.Second)
	buf := make([]byte, 1<<20)
	for time.Now().Before(deadline) {
		stacks := buf[:runtime.Stack(buf, true)]
		if !bytes.Contains(stacks, []byte("mihomo/dns.batchExchange")) && !bytes.Contains(stacks, []byte("mihomo/component/resolver.LookupIP")) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	return config.Parse([]byte(text))
}

func TestAGroupsMembersAreSearchedInItsOrder(t *testing.T) {
	cfg := parseConfigForTest(t, `proxies:
  - {name: dup, type: socks5, server: a.example.net, port: 1080}
  - {name: own, type: socks5, server: b.example.net, port: 1080}
proxy-providers:
  in:
    type: inline
    payload:
      - {name: dup, type: socks5, server: c.example.net, port: 1080}
      - {name: theirs, type: socks5, server: d.example.net, port: 1080}
proxy-groups:
  - {name: g, type: select, proxies: [dup, own, DIRECT], use: [in]}
rules:
  - MATCH,g
`)
	view := nodeView{proxies: cfg.Proxies, library: cfg.ProxyLibrary, providers: cfg.Providers}
	page := func(query string, offset, limit int) string {
		answer, status := view.memberSearchAnswer("g", query, offset, limit)
		var decoded struct {
			Group   string
			Total   int
			Members []struct {
				Name   string
				Inline bool
			}
		}
		if status != 200 || json.Unmarshal([]byte(answer), &decoded) != nil || decoded.Group != "g" {
			t.Fatalf("%q: %d %s", query, status, answer)
		}
		got := fmt.Sprint(decoded.Total)
		for _, m := range decoded.Members {
			got += fmt.Sprintf(" %s:%v", m.Name, m.Inline)
		}
		return got
	}
	for _, c := range []struct {
		query         string
		offset, limit int
		want          string
	}{
		{"DUP", 0, 0, "2 dup:true dup:false"},
		{"dUp", 1, 1, "2 dup:false"},
		{"t", 0, 0, "2 DIRECT:true theirs:false"},
		{"zzz", 0, 0, "0"},
	} {
		if got := page(c.query, c.offset, c.limit); got != c.want {
			t.Fatalf("%q from %d: %s, want %s", c.query, c.offset, got, c.want)
		}
	}
	if _, status := view.memberSearchAnswer("g", " ", 0, 0); status != 400 {
		t.Fatalf("an empty query answered %d", status)
	}
	if _, status := view.memberSearchAnswer("nope", "dup", 0, 0); status != 404 {
		t.Fatalf("a group there is not answered %d", status)
	}
}

func TestTheSummaryKeepsTheGroupsOrderAndANameIsLookedUp(t *testing.T) {
	document := `proxies:
  - {name: a, type: socks5, server: a.example.net, port: 1080}
  - {name: b, type: socks5, server: b.example.net, port: 1080}
proxy-providers:
  in:
    type: inline
    payload:
      - {name: sub1, type: socks5, server: c.example.net, port: 1080}
proxy-groups:
  - {name: Zed, type: select, proxies: [a, b]}
  - {name: Alpha, type: select, proxies: [Zed, b], use: [in]}
  - {name: Mid, type: url-test, url: "http://probe.test/", interval: 0, proxies: [a]}
rules:
  - MATCH,Alpha
`
	resources, _ := json.Marshal(map[string]any{"nodeLibraryDirectory": t.TempDir()})
	finalized, err := FinalizeForIOS(document, string(resources))
	if err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{"library": finalized.Value, "inline": document} {
		cfg := parseConfigForTest(t, text)
		view := nodeView{proxies: cfg.Proxies, library: cfg.ProxyLibrary, providers: cfg.Providers}
		var summary struct{ GroupOrder []string }
		if err := json.Unmarshal([]byte(view.summaryJSON()), &summary); err != nil {
			t.Fatal(err)
		}
		if got := strings.Join(summary.GroupOrder, ","); got != "Zed,Alpha,Mid,GLOBAL" {
			t.Fatalf("%s: group order %s", name, got)
		}
		for query, want := range map[string]string{
			"Alpha":  `{"name":"Alpha","found":true,"type":"Selector","source":"group"}`,
			"a":      `{"name":"a","found":true,"type":"Socks5","source":"inline"}`,
			"DIRECT": `{"name":"DIRECT","found":true,"type":"Direct","source":"inline"}`,
			"sub1":   `{"name":"sub1","found":false}`,
			"alpha":  `{"name":"alpha","found":false}`,
		} {
			if got, status := view.lookupAnswer(query); status != 200 || got != want {
				t.Fatalf("%s: lookup %q answered %d %s", name, query, status, got)
			}
		}
		if _, status := view.lookupAnswer(""); status != 400 {
			t.Fatalf("%s: an empty name answered %d", name, status)
		}
	}
	cfg := parseConfigForTest(t, strings.Replace(document, "proxy-groups:\n", "proxy-groups:\n  - {name: GLOBAL, type: select, proxies: [Alpha, a]}\n", 1))
	view := nodeView{proxies: cfg.Proxies, library: cfg.ProxyLibrary, providers: cfg.Providers}
	var summary struct{ GroupOrder []string }
	_ = json.Unmarshal([]byte(view.summaryJSON()), &summary)
	if got := strings.Join(summary.GroupOrder, ","); got != "GLOBAL,Zed,Alpha,Mid" {
		t.Fatalf("a configuration's own GLOBAL: group order %s", got)
	}
}
