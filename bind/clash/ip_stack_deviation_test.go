package clash

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/log"
	"go.yaml.in/yaml/v3"
)

func ipStackNodeDocument(mode, controller string) string {
	stack := ""
	if mode != "" {
		stack += "mode: " + mode + ", "
	}
	if controller != "" {
		stack += "congestion-controller: " + controller + ", "
	}
	node := func(name, extra string) string {
		return "  - {name: " + name + ", type: wireguard, server: 192.0.2.1, port: 51820, ip: 10.0.0.2/32, " +
			"private-key: aGFrbwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=, public-key: aGFrbwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" +
			extra + "}\n"
	}
	document := "proxies:\n" + node("plain", "")
	if stack != "" {
		document += node("written", ", ip-stack: {"+strings.TrimSuffix(stack, ", ")+"}")
	}
	return document + "proxy-groups: []\nrules:\n  - MATCH,DIRECT\n"
}

func TestANodesWrittenIPStackStartsOnTheGoStackAndIsWarnedOf(t *testing.T) {
	previous := publishedDeviations.Load()
	t.Cleanup(func() { publishedDeviations.Store(previous) })
	subscription := log.Subscribe()
	t.Cleanup(func() { log.UnSubscribe(subscription) })

	warnings := func(t *testing.T, document string) (lines []string) {
		t.Helper()
		if _, _, err := parseConfigForIOSRuntime(document, true, deviationEntryStart); err != nil {
			t.Fatalf("the file was refused: %v", err)
		}
		rows := -1
		deadline := time.After(5 * time.Second)
		for rows != 0 {
			select {
			case event := <-subscription:
				if rows < 0 {
					if _, count, found := strings.Cut(event.Payload, "[Apple] deviations published:"); found {
						if _, err := fmt.Sscanf(count[strings.LastIndex(count, "rows="):], "rows=%d", &rows); err != nil {
							t.Fatalf("the summary line counts no rows: %s", event.Payload)
						}
					}
					continue
				}
				if !strings.Contains(event.Payload, "[Apple] deviation ") {
					continue
				}
				rows--
				if strings.Contains(event.Payload, "].ip-stack.") {
					if event.LogLevel != log.WARNING {
						t.Fatalf("the line is %s, not a warning: %s", event.LogLevel, event.Payload)
					}
					lines = append(lines, event.Payload)
				}
			case <-deadline:
				t.Fatal("the publish and its rows are not all in the log within 5 s")
			}
		}
		return lines
	}

	for _, mode := range []string{"auto", "gvisor", "mips", "GVisor"} {
		lines := warnings(t, ipStackNodeDocument(mode, ""))
		if len(lines) != 1 || !strings.Contains(lines[0], "[Apple] deviation proxies[wireguard].ip-stack.mode:") ||
			!strings.Contains(lines[0], `given="written (proxies[1]): `+mode+`"`) || !strings.Contains(lines[0], `effective="go`) {
			t.Fatalf("mode %s: want one warning that the node at proxies[1] wrote %s and go runs, got %q", mode, mode, lines)
		}
	}
	lines := warnings(t, ipStackNodeDocument("", "bbr3"))
	if len(lines) != 1 || !strings.Contains(lines[0], "[Apple] deviation proxies[wireguard].ip-stack.congestion-controller:") ||
		!strings.Contains(lines[0], `given="written (proxies[1]): bbr3"`) || !strings.Contains(lines[0], `effective="bbr`) {
		t.Fatalf("bbr3: want one warning that the node at proxies[1] wrote bbr3 and bbr runs, got %q", lines)
	}
	if lines := warnings(t, ipStackNodeDocument("gvisor", "bbr3")); len(lines) != 2 {
		t.Fatalf("mode and bbr3 both written: want a warning for each, got %q", lines)
	}
	for _, controller := range []string{"", "cubic", "reno", "bbr"} {
		if lines := warnings(t, ipStackNodeDocument("", controller)); len(lines) != 0 {
			t.Fatalf("congestion-controller %q and no mode: the node runs as written, yet is warned of: %q", controller, lines)
		}
	}
}

func TestTheCatalogDecidesANodesIPStackMode(t *testing.T) {
	for _, profile := range []string{RuntimeProfileIOSPacketTunnel, RuntimeProfileMacOSPacketTunnel, RuntimeProfileTVOSPacketTunnel, RuntimeProfileMacOSApplication} {
		catalog := mustCatalog(t, profile)
		fields := map[string]syntaxField{}
		for _, field := range catalog.Fields {
			fields[field.Path] = field
		}
		keys := map[string]syntaxPlatformKey{}
		for _, key := range catalog.PlatformDecidedKeys {
			keys[key.Path] = key
		}
		for _, nodeType := range ipStackNodeTypes {
			mode := "proxies[" + nodeType + "].ip-stack.mode"
			field, listed := fields[mode]
			if !listed {
				t.Fatalf("%s: the catalog has no %s", profile, mode)
			}
			if decision := field.PlatformDecision; !field.PlatformDecided || decision == nil || decision.When != "always" ||
				decision.Value != "" || !strings.HasPrefix(decision.Effective, "go") {
				t.Fatalf("%s: %s is not decided go: %+v", profile, mode, field)
			}
			if key, listed := keys[mode]; !listed || key.Value != "" || key.Category != deviationForced || !strings.HasPrefix(key.Effective, "go") {
				t.Fatalf("%s: platformDecidedKeys has no forced %s: %+v", profile, mode, key)
			}
			controller := "proxies[" + nodeType + "].ip-stack.congestion-controller"
			field = fields[controller]
			if field.PlatformDecision != nil || field.PlatformDecided {
				t.Fatalf("%s: %s is decided whole, though only bbr3 is replaced: %+v", profile, controller, field)
			}
			if len(field.UnavailableValues) != 1 || field.UnavailableValues[0].Value != "bbr3" || field.UnavailableValues[0].Alternative != "bbr" {
				t.Fatalf("%s: %s offers %+v as unavailable; want bbr3 alone, bbr instead", profile, controller, field.UnavailableValues)
			}
		}
	}
}

const ipStackLibraryDocument = "proxies:\n" +
	"  - {name: wg1, type: wireguard, server: 192.0.2.1, port: 51820, ip: 10.0.0.2/32, private-key: aGFrbwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=, public-key: aGFrbwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=, ip-stack: {mode: gvisor}}\n" +
	"  - {name: wg2, type: wireguard, server: 192.0.2.2, port: 51820, ip: 10.0.0.3/32, private-key: aGFrbwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=, public-key: aGFrbwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=, ip-stack: {mode: mips, congestion-controller: bbr3}}\n" +
	"  - {name: zt, type: zerotier, network: 8056c2e21c000001, ip-stack: {mode: gvisor}}\n" +
	"  - {name: wg3, type: wireguard, server: 192.0.2.3, port: 51820, ip: 10.0.0.4/32, private-key: aGFrbwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=, public-key: aGFrbwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=}\n" +
	"rules:\n  - MATCH,DIRECT\n"

func ipStackRowsOf(t *testing.T, document string) map[string]string {
	t.Helper()
	box, err := ConfigDeviationsJSON(document, RuntimeProfileIOSPacketTunnel)
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Deviations []configDeviation `json:"deviations"`
	}
	if err := json.Unmarshal([]byte(box.Value), &report); err != nil {
		t.Fatal(err)
	}
	rows := map[string]string{}
	for _, row := range report.Deviations {
		if strings.Contains(row.Field, "].ip-stack.") {
			if _, twice := rows[row.Field]; twice {
				t.Fatalf("%s reported twice: %+v", row.Field, report.Deviations)
			}
			rows[row.Field] = row.Given
		}
	}
	return rows
}

func TestANodeLibrarysIPStackNodesAreReportedAsTheFileIs(t *testing.T) {
	want := map[string]string{
		"proxies[wireguard].ip-stack.mode":                  "2 nodes, the first wg1 (proxies[0]): gvisor",
		"proxies[wireguard].ip-stack.congestion-controller": "wg2 (proxies[1]): bbr3",
		"proxies[zerotier].ip-stack.mode":                   "zt (proxies[2]): gvisor",
	}
	if got := ipStackRowsOf(t, ipStackLibraryDocument); !reflect.DeepEqual(got, want) {
		t.Fatalf("the file's rows:\n got %v\nwant %v", got, want)
	}
	resources, _ := json.Marshal(map[string]any{"nodeLibraryDirectory": t.TempDir()})
	finalized, err := FinalizeForIOS(ipStackLibraryDocument, string(resources))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(finalized.Value, "x-clash-node-library") || strings.Contains(finalized.Value, "192.0.2.1") {
		t.Fatalf("the WireGuard nodes did not go into a library:\n%s", finalized.Value)
	}
	if got := ipStackRowsOf(t, finalized.Value); !reflect.DeepEqual(got, want) {
		t.Fatalf("the published file's rows:\n got %v\nwant %v\n%s", got, want, finalized.Value)
	}
	var root map[string]any
	if err := yaml.Unmarshal([]byte(finalized.Value), &root); err != nil {
		t.Fatal(err)
	}
	policy := runtimePolicyFor(runtimeProfileIOSPacketTunnel, true)
	if whole, kept := ipStackNodeDeviations(root, policy), ipStackNodeDeviations(deviationDocumentOf(root), policy); !reflect.DeepEqual(whole, kept) {
		t.Fatalf("what a Start keeps of the published file reports otherwise:\nwhole %+v\n kept %+v", whole, kept)
	}
}

func TestTheIPStackRowsReadInlineAtAsTheRuntimeDoes(t *testing.T) {
	policy := runtimePolicyFor(runtimeProfileIOSPacketTunnel, true)
	zerotier := map[string]any{"name": "zt", "type": "zerotier", "ip-stack": map[string]any{"mode": "gvisor"}}
	for name, places := range map[string]any{
		"fits":       []any{7},
		"too many":   []any{7, 9},
		"none":       []any{},
		"not whole":  []any{7.5},
		"a name":     []any{"seven"},
		"negative":   []any{-1},
		"not a list": "7",
	} {
		root := map[string]any{"proxies": []any{zerotier}, "x-clash-node-library": map[string]any{"inline-at": places}}
		want := "zt (proxies[0]): gvisor"
		if name == "fits" {
			want = "zt (proxies[7]): gvisor"
		}
		rows := ipStackNodeDeviations(root, policy)
		if len(rows) != 1 || rows[0].Given != want {
			t.Fatalf("inline-at %s (%v): rows %+v, want one %q", name, places, rows, want)
		}
	}
	runsAsWritten := map[string]any{"name": "wg", "type": "wireguard", "ip-stack": map[string]any{"congestion-controller": "cubic"}}
	if kept, _ := deviationDocumentOf(map[string]any{"proxies": []any{runsAsWritten}})["proxies"].([]any); len(kept) != 1 || kept[0] != nil {
		t.Fatalf("a node that writes cubic alone is kept: %v", kept)
	}
}
