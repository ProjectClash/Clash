package clash

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/adapter/outbound"
)

const mieruMultiplexingDocument = "mixed-port: 7890\nproxies:\n" +
	"  - {name: plain, type: mieru, server: 10.0.0.1, port: 2999, transport: TCP, username: u, password: p}\n" +
	"  - {name: own, type: mieru, server: 10.0.0.2, port: 2999, transport: TCP, username: u, password: p, multiplexing: MULTIPLEXING_HIGH}\n" +
	"  - {name: blank, type: mieru, server: 10.0.0.3, port: 2999, transport: TCP, username: u, password: p, multiplexing: \"\"}\n" +
	"  - {name: nulled, type: mieru, server: 10.0.0.4, port: 2999, transport: TCP, username: u, password: p, multiplexing: ~}\n" +
	"  - {name: default-level, type: mieru, server: 10.0.0.5, port: 2999, transport: TCP, username: u, password: p, multiplexing: MULTIPLEXING_DEFAULT}\n" +
	"  - {name: other-key, type: mieru, server: 10.0.0.6, port: 2999, transport: TCP, username: u, password: p, Multiplexing: MULTIPLEXING_LOW}\n" +
	"  - {name: off, type: mieru, server: 10.0.0.9, port: 2999, transport: TCP, username: u, password: p, multiplexing: MULTIPLEXING_OFF}\n" +
	"  - {name: udp-transport, type: mieru, server: 10.0.0.8, port: 2999, transport: UDP, username: u, password: p}\n" +
	"  - {name: udp-level, type: mieru, server: 10.0.0.10, port: 2999, transport: UDP, username: u, password: p, multiplexing: MULTIPLEXING_HIGH}\n" +
	"  - {name: tcp, type: trojan, server: 10.0.0.7, port: 443, password: p}\n" +
	"rules:\n  - MATCH,DIRECT\n"

const (
	mieruMultiplexingUnwritten = "3 nodes, the first plain (proxies[0]): not set (core default: MULTIPLEXING_LOW (flows share a connection))"
	mieruMultiplexingWritten   = "3 nodes, the first own (proxies[1]): MULTIPLEXING_HIGH"
)

func mieruMultiplexingRows(t *testing.T, document, profile string) []map[string]any {
	t.Helper()
	box, err := ConfigDeviationsJSON(document, profile)
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
		if row["field"] == mieruMultiplexingField {
			rows = append(rows, row)
		}
	}
	return rows
}

func mieruMultiplexingRowsByWritten(t *testing.T, document, profile string) (unwritten, written map[string]any) {
	t.Helper()
	for _, row := range mieruMultiplexingRows(t, document, profile) {
		slot := &unwritten
		if row["written"] == true {
			slot = &written
		}
		if *slot != nil {
			t.Fatalf("%s: two rows with written %v: %v and %v", profile, row["written"], *slot, row)
		}
		*slot = row
	}
	return unwritten, written
}

func TestTheTunnelsReportAMieruNodeWhoseMultiplexingTheyReplace(t *testing.T) {
	for _, profile := range []string{RuntimeProfileIOSPacketTunnel, RuntimeProfileTVOSPacketTunnel} {
		unwritten, written := mieruMultiplexingRowsByWritten(t, mieruMultiplexingDocument, profile)
		for _, c := range []struct {
			row   map[string]any
			given string
		}{{unwritten, mieruMultiplexingUnwritten}, {written, mieruMultiplexingWritten}} {
			if c.row == nil || c.row["given"] != c.given || c.row["category"] != deviationForced || c.row["recoverable"] != false {
				t.Fatalf("%s: row %v, want given %q, forced and not recoverable", profile, c.row, c.given)
			}
			if effective, _ := c.row["effective"].(string); !strings.HasPrefix(effective, outbound.MieruTunnelMultiplexing) {
				t.Fatalf("%s: the row's effective value %q does not open with the level the outbound runs, %s", profile, effective, outbound.MieruTunnelMultiplexing)
			}
		}
	}
	for _, profile := range []string{RuntimeProfileMacOSPacketTunnel, RuntimeProfileMacOSApplication} {
		if rows := mieruMultiplexingRows(t, mieruMultiplexingDocument, profile); len(rows) != 0 {
			t.Fatalf("%s keeps the module's default, yet reports %v", profile, rows)
		}
	}
}

func TestTheNodeLibrarysMieruNodesAreReported(t *testing.T) {
	dir := t.TempDir()
	resources, _ := json.Marshal(map[string]any{"nodeLibraryDirectory": dir})
	finalized, err := FinalizeForIOS(mieruMultiplexingDocument, string(resources))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(finalized.Value, "x-clash-node-library") || strings.Contains(finalized.Value, "10.0.0.1") {
		t.Fatalf("the nodes did not go into a library:\n%s", finalized.Value)
	}
	unwritten, written := mieruMultiplexingRowsByWritten(t, finalized.Value, RuntimeProfileIOSPacketTunnel)
	if unwritten == nil || unwritten["given"] != mieruMultiplexingUnwritten || written == nil || written["given"] != mieruMultiplexingWritten {
		t.Fatalf("the library's mieru rows %v and %v, want given %q and %q", unwritten, written, mieruMultiplexingUnwritten, mieruMultiplexingWritten)
	}
	if rows := mieruMultiplexingRows(t, finalized.Value, RuntimeProfileMacOSPacketTunnel); len(rows) != 0 {
		t.Fatalf("macOS reports %v", rows)
	}
}

func TestOnlyAMieruNodeWhoseMultiplexingIsReplacedIsKeptForTheRows(t *testing.T) {
	node := func(name, transport string, level any) map[string]any {
		proxy := map[string]any{"name": name, "type": "mieru", "server": "10.0.0.1", "port": 2999, "transport": transport, "username": "u", "password": "p"}
		if level != nil {
			proxy["multiplexing"] = level
		}
		return proxy
	}
	kept, _ := deviationDocumentOf(map[string]any{"proxies": []any{
		node("plain", "TCP", nil), node("own", "TCP", "MULTIPLEXING_LOW"), node("off", "TCP", "MULTIPLEXING_OFF"), node("udp", "UDP", nil), node("udp-level", "UDP", "MULTIPLEXING_HIGH"),
	}})["proxies"].([]any)
	if len(kept) != 5 || kept[2] != nil || kept[3] != nil || kept[4] != nil {
		t.Fatalf("kept %v; the node that writes MULTIPLEXING_OFF and the two on the UDP transport have no row and are not kept", kept)
	}
	plain, _ := kept[0].(map[string]any)
	if replaced, written := mieruMultiplexingReplaced(plain); !replaced || written != "" || plain["server"] != nil || plain["password"] != nil || plain["name"] != "plain" {
		t.Fatalf("the node that writes no level is kept as %v; want its type, name and transport only", plain)
	}
	own, _ := kept[1].(map[string]any)
	if replaced, written := mieruMultiplexingReplaced(own); !replaced || written != "MULTIPLEXING_LOW" || own["server"] != nil {
		t.Fatalf("the node that writes a level is kept as %v; want its type, name, transport and level", own)
	}
}

func TestTheCatalogSaysAMieruNodesMultiplexingIsTheTunnels(t *testing.T) {
	for _, profile := range []string{RuntimeProfileIOSPacketTunnel, RuntimeProfileTVOSPacketTunnel} {
		found := false
		catalog := mustCatalog(t, profile)
		for _, field := range catalog.Fields {
			if field.Path != mieruMultiplexingField {
				continue
			}
			found = true
			decision := field.PlatformDecision
			if decision == nil || decision.When != "always" || decision.Value != outbound.MieruTunnelMultiplexing ||
				decision.Category != deviationForced || decision.Reason == "" || !strings.Contains(decision.Effective, "TCP transport") ||
				!strings.Contains(decision.Effective, "UDP transport") {
				t.Errorf("%s: decision %+v, want %s always, and a text that names the two transports", profile, decision, outbound.MieruTunnelMultiplexing)
			}
		}
		if !found {
			t.Fatalf("%s: %s is not in the catalog", profile, mieruMultiplexingField)
		}
		listed := false
		for _, key := range catalog.PlatformDecidedKeys {
			if key.Path == mieruMultiplexingField {
				listed = true
				if key.DefaultOnly || key.Value != outbound.MieruTunnelMultiplexing || key.Category != deviationForced {
					t.Errorf("%s platformDecidedKeys: %+v, want %s, not a default only", profile, key, outbound.MieruTunnelMultiplexing)
				}
			}
		}
		if !listed {
			t.Errorf("%s: platformDecidedKeys does not list %s", profile, mieruMultiplexingField)
		}
	}
	mac := mustCatalog(t, RuntimeProfileMacOSPacketTunnel)
	for _, field := range mac.Fields {
		if field.Path == mieruMultiplexingField && field.PlatformDecision != nil {
			t.Errorf("macOS: decision %+v; it runs the module's default", field.PlatformDecision)
		}
	}
	for _, key := range mac.PlatformDecidedKeys {
		if key.Path == mieruMultiplexingField {
			t.Errorf("macOS platformDecidedKeys lists %s", key.Path)
		}
	}
}

func TestTheCatalogSaysWhichMieruNodesTheTunnelsDecide(t *testing.T) {
	want := map[string]any{"transport": []any{outbound.MieruTunnelMultiplexingTransport}}
	for _, profile := range []string{RuntimeProfileIOSPacketTunnel, RuntimeProfileTVOSPacketTunnel, RuntimeProfileMacOSPacketTunnel, RuntimeProfileMacOSApplication} {
		tunnel := profile == RuntimeProfileIOSPacketTunnel || profile == RuntimeProfileTVOSPacketTunnel
		fields, keys := catalogWire(t, profile)
		for path, field := range fields {
			decision, _ := field["platformDecision"].(map[string]any)
			onlyWhere, has := decision["onlyWhere"]
			switch {
			case path == mieruMultiplexingField && tunnel:
				if !reflect.DeepEqual(onlyWhere, want) {
					t.Errorf("%s: %s decision's onlyWhere %v, want %v", profile, path, onlyWhere, want)
				}
			case has:
				t.Errorf("%s: %s carries onlyWhere %v", profile, path, onlyWhere)
			}
		}
		listed := false
		for _, key := range keys {
			onlyWhere, has := key["onlyWhere"]
			if key["path"] == mieruMultiplexingField {
				listed = true
				if !reflect.DeepEqual(onlyWhere, want) {
					t.Errorf("%s: platformDecidedKeys %s onlyWhere %v, want %v", profile, mieruMultiplexingField, onlyWhere, want)
				}
			} else if has {
				t.Errorf("%s: platformDecidedKeys %v carries onlyWhere", profile, key["path"])
			}
		}
		if listed != tunnel {
			t.Errorf("%s: platformDecidedKeys lists %s: %v", profile, mieruMultiplexingField, listed)
		}
	}
}

func TestTheCatalogsOnlyWhereIsTheNodesWhoseMultiplexingIsReplaced(t *testing.T) {
	fields, _ := catalogWire(t, RuntimeProfileIOSPacketTunnel)
	decision, _ := fields[mieruMultiplexingField]["platformDecision"].(map[string]any)
	onlyWhere, _ := decision["onlyWhere"].(map[string]any)
	if len(onlyWhere) == 0 {
		t.Fatalf("%s: decision %v has no onlyWhere", mieruMultiplexingField, decision)
	}
	meeting := map[string]any{"type": "mieru", "name": "n", "server": "10.0.0.1", "port": 2999, "username": "u", "password": "p"}
	for key, values := range onlyWhere {
		listed, _ := values.([]any)
		if len(listed) == 0 {
			t.Fatalf("onlyWhere %s lists no value: %v", key, values)
		}
		meeting[key] = listed[0]
	}
	with := func(key string, value any, level any) map[string]any {
		node := map[string]any{}
		for k, v := range meeting {
			if k != key {
				node[k] = v
			}
		}
		if value != nil {
			node[key] = value
		}
		if level != nil {
			node["multiplexing"] = level
		}
		return node
	}
	for key, values := range onlyWhere {
		listed := map[string]bool{}
		for _, raw := range values.([]any) {
			value, _ := raw.(string)
			listed[value] = true
			for _, spelling := range []string{key, strings.ToUpper(key), strings.ToUpper(key[:1]) + strings.ReplaceAll(key[1:], "-", "_")} {
				for _, level := range []any{nil, "MULTIPLEXING_HIGH"} {
					node := with(key, nil, level)
					node[spelling] = value
					if replaced, _ := mieruMultiplexingReplaced(node); !replaced {
						t.Errorf("%v meets onlyWhere %s: %v, and the tunnel leaves its multiplexing as written", node, key, values)
					}
				}
			}
			if other := strings.ToLower(value); other != value {
				if replaced, _ := mieruMultiplexingReplaced(with(key, other, nil)); replaced {
					t.Errorf("%s: %q is not %q, and the tunnel replaces the node's multiplexing", key, other, value)
				}
			}
		}
		sibling, ok := fields["proxies[mieru]."+key]
		if !ok {
			t.Fatalf("onlyWhere names %s, which a mieru node does not read", key)
		}
		offered, _ := sibling["values"].([]any)
		for _, raw := range offered {
			if value, _ := raw.(string); !listed[value] {
				if replaced, _ := mieruMultiplexingReplaced(with(key, value, nil)); replaced {
					t.Errorf("%s: %s is not in onlyWhere, and the tunnel replaces the node's multiplexing", key, value)
				}
			}
		}
		if replaced, _ := mieruMultiplexingReplaced(with(key, nil, nil)); replaced {
			t.Errorf("a node that does not write %s does not meet onlyWhere, and the tunnel replaces its multiplexing", key)
		}
	}
}
