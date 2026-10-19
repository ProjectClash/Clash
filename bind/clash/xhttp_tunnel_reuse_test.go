package clash

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/adapter/outbound"
)

const xhttpReuseDocument = "proxies:\n" +
	"  - {name: plain, type: vless, server: 10.0.0.1, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, network: xhttp, xhttp-opts: {path: /}}\n" +
	"  - {name: own, type: vless, server: 10.0.0.2, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, network: xhttp, xhttp-opts: {reuse-settings: {max-concurrency: '1'}}}\n" +
	"  - {name: ws, type: vless, server: 10.0.0.3, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, network: ws}\n" +
	"  - {name: spelled, type: vless, server: 10.0.0.4, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, Network: xhttp, xhttp_opts: {Reuse_Settings: {max-concurrency: '1'}}}\n" +
	"  - {name: nulled, type: vless, server: 10.0.0.5, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, network: xhttp, xhttp-opts: {reuse-settings: ~}}\n" +
	"rules:\n  - MATCH,DIRECT\n"

func xhttpReuseRows(t *testing.T, profile string) []map[string]any {
	t.Helper()
	box, err := ConfigDeviationsJSON(xhttpReuseDocument, profile)
	if err != nil {
		t.Fatalf("ConfigDeviationsJSON: %v", err)
	}
	var report struct {
		Deviations []map[string]any `json:"deviations"`
	}
	if err := json.Unmarshal([]byte(box.Value), &report); err != nil {
		t.Fatal(err)
	}
	var rows []map[string]any
	for _, row := range report.Deviations {
		if row["field"] == xhttpTunnelReuseRule.field {
			rows = append(rows, row)
		}
	}
	return rows
}

func TestTheTunnelsReportTheXHTTPReuseDefaultPerNode(t *testing.T) {
	for _, profile := range []string{RuntimeProfileIOSPacketTunnel, RuntimeProfileTVOSPacketTunnel} {
		rows := xhttpReuseRows(t, profile)
		if len(rows) != 2 {
			t.Fatalf("%s: %d rows, want the two nodes that run the default: %v", profile, len(rows), rows)
		}
		for i, node := range []string{"plain (proxies[0])", "nulled (proxies[4])"} {
			given, _ := rows[i]["given"].(string)
			if !strings.HasPrefix(given, node+": not set") || rows[i]["written"] != false ||
				rows[i]["category"] != deviationForced || rows[i]["recoverable"] != true {
				t.Fatalf("%s: row %d %v, want %s", profile, i, rows[i], node)
			}
		}
	}
	for _, profile := range []string{RuntimeProfileMacOSPacketTunnel, RuntimeProfileMacOSApplication} {
		if rows := xhttpReuseRows(t, profile); len(rows) != 0 {
			t.Fatalf("%s keeps upstream's behaviour, yet reports %v", profile, rows)
		}
	}
}

func TestSetupSetsTheXHTTPReuseDefaultByProfile(t *testing.T) {
	t.Cleanup(func() { applyXHTTPTunnelReuse(currentRuntimeProfile()) })
	for _, profile := range allRuntimeProfiles() {
		applyXHTTPTunnelReuse(profile)
		node, err := outbound.NewVless(outbound.VlessOption{
			Name: "x", Server: "127.0.0.1", Port: 443, UUID: "b831381d-6324-4d53-ad4f-8cda48b30811",
			TLS: true, Network: "xhttp", XHTTPOpts: outbound.XHTTPOptions{Path: "/"},
		})
		if err != nil {
			t.Fatal(err)
		}
		upload, _ := node.XHTTPReuseConfigs()
		_ = node.Close()
		if got, want := upload != nil, profile.inheritsIOSPacketTunnelBehavior(); got != want {
			t.Errorf("%v: reuses %v, want %v", profile, got, want)
		}
	}
}

func TestTheNodeLibrarysXHTTPNodesAreReported(t *testing.T) {
	dir := t.TempDir()
	resources, _ := json.Marshal(map[string]any{"nodeLibraryDirectory": dir})
	finalized, err := FinalizeForIOS(xhttpReuseDocument, string(resources))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(finalized.Value, "x-clash-node-library") || strings.Contains(finalized.Value, "10.0.0.1") {
		t.Fatalf("the nodes did not go into a library:\n%s", finalized.Value)
	}
	rowsOf := func(profile string) []map[string]any {
		box, err := ConfigDeviationsJSON(finalized.Value, profile)
		if err != nil {
			t.Fatal(err)
		}
		var report struct {
			Deviations []map[string]any `json:"deviations"`
		}
		if err := json.Unmarshal([]byte(box.Value), &report); err != nil {
			t.Fatal(err)
		}
		var rows []map[string]any
		for _, row := range report.Deviations {
			if row["field"] == xhttpTunnelReuseRule.field {
				rows = append(rows, row)
			}
		}
		return rows
	}
	rows := rowsOf(RuntimeProfileIOSPacketTunnel)
	if len(rows) != 1 {
		t.Fatalf("%d rows, want one for the library: %v", len(rows), rows)
	}
	if given, _ := rows[0]["given"].(string); !strings.HasPrefix(given, "2 nodes in the node library, the first plain (proxies[0]): not set") {
		t.Fatalf("row %q", given)
	}
	if rows := rowsOf(RuntimeProfileMacOSPacketTunnel); len(rows) != 0 {
		t.Fatalf("macOS reports %v", rows)
	}
}
