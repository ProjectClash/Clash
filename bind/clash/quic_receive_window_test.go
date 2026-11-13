package clash

import (
	"encoding/json"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/adapter/outbound"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/metacubex/http"
)

const quicWindowDocument = "proxies:\n" +
	"  - {name: plain, type: hysteria2, server: 10.0.0.1, port: 443, password: p}\n" +
	"  - {name: own-connection, type: hysteria2, server: 10.0.0.2, port: 443, password: p, max-connection-receive-window: 4194304}\n" +
	"  - {name: zeroed, type: tuic, server: 10.0.0.3, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, password: p, recv-window-conn: 0}\n" +
	"  - {name: spelled, type: tuic, server: 10.0.0.4, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, password: p, Recv_Window_Conn: 2097152, recv_window: 4194304}\n" +
	"  - {name: second, type: hysteria2, server: 10.0.0.5, port: 443, password: p}\n" +
	"  - {name: initial-only, type: hysteria2, server: 10.0.0.7, port: 443, password: p, initial-stream-receive-window: 2097152}\n" +
	"  - {name: tcp, type: trojan, server: 10.0.0.6, port: 443, password: p}\n" +
	"rules:\n  - MATCH,DIRECT\n"

func quicWindowRows(t *testing.T, document, profile string) map[string]map[string]any {
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
	rows := map[string]map[string]any{}
	for _, row := range report.Deviations {
		field, _ := row["field"].(string)
		if isQUICWindowField(field) {
			if rows[field] != nil {
				t.Fatalf("%s: two rows for %s: %v and %v", profile, field, rows[field], row)
			}
			rows[field] = row
		}
	}
	return rows
}

func TestTheTunnelsReportTheQUICWindowDefaultPerWindow(t *testing.T) {
	want := map[string]string{
		"proxies[hysteria2].initial-stream-receive-window":     "3 nodes, the first plain (proxies[0]): not set (core default: 8388608 (8 MiB, from the first byte))",
		"proxies[hysteria2].initial-connection-receive-window": "3 nodes, the first plain (proxies[0]): not set (core default: 20971520 (20 MiB, from the first byte))",
	}
	if outbound.QUICTunnelMaxConnection < quicHysteria2OwnConnection {
		want["proxies[hysteria2].max-connection-receive-window"] = "3 nodes, the first plain (proxies[0]): not set (core default: 20971520 (20 MiB))"
	}
	if outbound.QUICTunnelGrowingMaxConnection != 0 {
		want["proxies[tuic].recv-window"] = "zeroed (proxies[2]): not set (core default: 67108864 (grows from 6.4 MiB to 64 MiB))"
	}
	for _, profile := range []string{RuntimeProfileIOSPacketTunnel, RuntimeProfileTVOSPacketTunnel} {
		rows := quicWindowRows(t, quicWindowDocument, profile)
		if len(rows) != len(want) {
			t.Fatalf("%s: rows for %d windows, want %d: %v", profile, len(rows), len(want), rows)
		}
		for field, given := range want {
			row := rows[field]
			if row == nil || row["given"] != given || row["written"] != false ||
				row["category"] != deviationForced || row["recoverable"] != true {
				t.Fatalf("%s: %s row %v, want given %q", profile, field, row, given)
			}
		}
	}
	for _, profile := range []string{RuntimeProfileMacOSPacketTunnel, RuntimeProfileMacOSApplication} {
		if rows := quicWindowRows(t, quicWindowDocument, profile); len(rows) != 0 {
			t.Fatalf("%s keeps upstream's windows, yet reports %v", profile, rows)
		}
	}
}

func TestSetupSetsTheQUICWindowDefaultByProfile(t *testing.T) {
	t.Cleanup(func() { applyQUICTunnelReceiveWindows(currentRuntimeProfile()) })
	for _, profile := range allRuntimeProfiles() {
		applyQUICTunnelReceiveWindows(profile)
		windows := outbound.QUICDefaultReceiveWindows()
		if got, want := windows != nil, profile.inheritsIOSPacketTunnelBehavior(); got != want {
			t.Errorf("%v: a default %v, want %v", profile, got, want)
		}
		if want := (outbound.QUICReceiveWindows{InitialStream: 1 << 20, InitialConnection: 12 << 20, MaxConnection: 20 << 20,
			GrowingMaxConnection: outbound.QUICTunnelGrowingMaxConnection}); windows != nil && *windows != want {
			t.Errorf("%v: windows %+v, want %+v", profile, *windows, want)
		}
	}
}

func TestTheNodeLibrarysQUICNodesAreReported(t *testing.T) {
	dir := t.TempDir()
	resources, _ := json.Marshal(map[string]any{"nodeLibraryDirectory": dir})
	finalized, err := FinalizeForIOS(quicWindowDocument, string(resources))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(finalized.Value, "x-clash-node-library") || strings.Contains(finalized.Value, "10.0.0.1") {
		t.Fatalf("the nodes did not go into a library:\n%s", finalized.Value)
	}
	rows := quicWindowRows(t, finalized.Value, RuntimeProfileIOSPacketTunnel)
	stream := rows["proxies[hysteria2].initial-stream-receive-window"]
	if given, _ := stream["given"].(string); given != "3 nodes, the first plain (proxies[0]): not set (core default: 8388608 (8 MiB, from the first byte))" {
		t.Fatalf("the library's Hysteria2 stream window row %v", stream)
	}
	want := len(quicHysteria2WindowPairs)
	if outbound.QUICTunnelMaxConnection < quicHysteria2OwnConnection {
		want++
	}
	if outbound.QUICTunnelGrowingMaxConnection != 0 {
		want++
	}
	if len(rows) != want {
		t.Fatalf("rows for %d windows, want %d: %v", len(rows), want, rows)
	}
	if rows := quicWindowRows(t, finalized.Value, RuntimeProfileMacOSPacketTunnel); len(rows) != 0 {
		t.Fatalf("macOS reports %v", rows)
	}
}

func TestTheShedEstimateUsesTheTunnelsQUICWindows(t *testing.T) {
	before := outbound.QUICDefaultReceiveWindows()
	t.Cleanup(func() { outbound.SetQUICDefaultReceiveWindows(before) })
	outbound.SetQUICDefaultReceiveWindows(outbound.QUICTunnelReceiveWindows())
	const mib = 1 << 20
	growingCeiling := int64(67108864)
	if outbound.QUICTunnelGrowingMaxConnection != 0 {
		growingCeiling = outbound.QUICTunnelGrowingMaxConnection
	}
	for adapterType, want := range map[C.AdapterType]quicDefaultWindows{
		C.Hysteria2:  {8 * mib, int64(outbound.QUICTunnelMaxConnection), 8 * mib, int64(outbound.QUICTunnelMaxConnection)},
		C.Tuic:       {15728640 / 10, 67108864 / 10, 15728640, growingCeiling},
		C.Hysteria:   {15728640, growingCeiling, 15728640, growingCeiling},
		C.ShadowQuic: {shedUnknownQUICWindow, shedUnknownQUICWindow, 15728640, growingCeiling},
	} {
		if got, ok := quicWindowDefaults(adapterType); !ok || got != want {
			t.Errorf("%v: %+v (%v), want %+v", adapterType, got, ok, want)
		}
	}
	growing := outbound.QUICTunnelReceiveWindows()
	growing.MaxConnection, growing.GrowingMaxConnection = 16*mib, 16*mib
	outbound.SetQUICDefaultReceiveWindows(growing)
	for adapterType, want := range map[C.AdapterType]quicDefaultWindows{
		C.Hysteria2:  {8 * mib, 16 * mib, 8 * mib, 16 * mib},
		C.Tuic:       {15728640 / 10, 67108864 / 10, 15728640, 16 * mib},
		C.Hysteria:   {15728640, 16 * mib, 15728640, 16 * mib},
		C.ShadowQuic: {shedUnknownQUICWindow, shedUnknownQUICWindow, 15728640, 16 * mib},
	} {
		if got, ok := quicWindowDefaults(adapterType); !ok || got != want {
			t.Errorf("with a 16 MiB ceiling, %v: %+v (%v), want %+v", adapterType, got, ok, want)
		}
	}
	if got, _ := quicWindowDefaults(C.Masque); got.maxConnection != 15*mib {
		t.Errorf("MASQUE's bound %d, want quic-go's 15 MiB", got.maxConnection)
	}
	outbound.SetQUICDefaultReceiveWindows(nil)
	if stream, connection, _ := quicWindow(quicWindowAdapterTypes[0]); stream != 8<<20 || connection != 20<<20 {
		t.Errorf("without the default, Hysteria2 estimates %d / %d, want its own 8 MiB / 20 MiB", stream, connection)
	}
	if got, _ := quicWindowDefaults(C.Tuic); got.maxConnection != 67108864 {
		t.Errorf("without the default, TUIC's bound %d, want its own 64 MiB", got.maxConnection)
	}
}

var quicWindowAdapterTypes = []C.AdapterType{C.Hysteria2, C.Tuic, C.Hysteria, C.ShadowQuic}

func TestSetupGivesTheTunnelsTheQUICWindows(t *testing.T) {
	before := outbound.QUICDefaultReceiveWindows()
	scratch := http.SetHTTP2StreamingBodyScratchMax(0)
	http.SetHTTP2StreamingBodyScratchMax(scratch)
	onDemand := http.HTTP2StreamingBodyScratchOnDemand()
	t.Cleanup(func() {
		outbound.SetQUICDefaultReceiveWindows(before)
		http.SetHTTP2StreamingBodyScratchMax(scratch)
		http.SetHTTP2StreamingBodyScratchOnDemand(onDemand)
		setStartupBreadcrumbRecording(false)
	})
	for _, profile := range []string{RuntimeProfileMacOSPacketTunnel, RuntimeProfileTVOSPacketTunnel, RuntimeProfileIOSPacketTunnel} {
		base := t.TempDir()
		if err := Setup(&SetupOptions{BasePath: base, WorkingPath: filepath.Join(base, "w"), TempPath: filepath.Join(base, "t"), RuntimeProfile: profile}); err != nil {
			t.Fatal(err)
		}
		windows := outbound.QUICDefaultReceiveWindows()
		if got, want := windows != nil, profile != RuntimeProfileMacOSPacketTunnel; got != want {
			t.Fatalf("%s: windows set %v, want %v", profile, got, want)
		}
	}
}

func TestTheConnectionCeilingRowIsIssuedOnlyBelowTheProtocolsOwn(t *testing.T) {
	if own, _ := quicProtocolWindows(C.Hysteria2); own.maxConnection != quicHysteria2OwnConnection {
		t.Fatalf("Hysteria2's own connection window is %d, the rows measure against %d", own.maxConnection, quicHysteria2OwnConnection)
	}
	for _, c := range []struct {
		maxConnection, growingMaxConnection uint64
		want                                bool
	}{{20 << 20, 0, false}, {16 << 20, 0, true}, {20 << 20, 16 << 20, true}} {
		if got := quicTunnelHasACeiling(c.maxConnection, c.growingMaxConnection); got != c.want {
			t.Errorf("a ceiling with %d / %d: %v, want %v", c.maxConnection, c.growingMaxConnection, got, c.want)
		}
	}
	issued := false
	for _, pair := range quicWindowPairs {
		issued = issued || pair.field == quicHysteria2CeilingPairs[0].field
	}
	if want := quicTunnelHasACeiling(outbound.QUICTunnelMaxConnection, 0); issued != want {
		t.Errorf("the ceiling row issued %v with the tunnels' connection window at %d, want %v", issued, uint64(outbound.QUICTunnelMaxConnection), want)
	}
	ceiling := quicTunnelHasACeiling(outbound.QUICTunnelMaxConnection, outbound.QUICTunnelGrowingMaxConnection)
	if got := quicWindowReason() == quicWindowReasonCeiling; got != ceiling {
		t.Errorf("the reason names a ceiling's cost: %v, want %v", got, ceiling)
	}
	if !ceiling && strings.Contains(quicWindowReason(), "16 MiB") {
		t.Errorf("no ceiling, and the reason names one: %s", quicWindowReason())
	}
}

func TestEveryQUICWindowPairIsRegisteredOnce(t *testing.T) {
	registered := map[string]int{}
	for _, rule := range deviationRules {
		if isQUICWindowField(rule.field) {
			registered[rule.field]++
		}
	}
	for _, pair := range quicWindowPairs {
		if registered[pair.field] != 1 {
			t.Errorf("%s registered %d times, want once", pair.field, registered[pair.field])
		}
	}
	if len(registered) != len(quicWindowPairs) {
		t.Errorf("%d window fields registered, %d pairs in the table", len(registered), len(quicWindowPairs))
	}
}

func TestAWindowTheDecoderReadsAsZeroIsReportedAsUnwritten(t *testing.T) {
	document := "proxies:\n" +
		"  - {name: quoted, type: tuic, server: 10.0.0.3, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, password: p, recv-window: \"0\"}\n" +
		"  - {name: untrue, type: hysteria2, server: 10.0.0.1, port: 443, password: p, max-connection-receive-window: false, initial-stream-receive-window: \"0x0\"}\n" +
		"  - {name: own, type: tuic, server: 10.0.0.4, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811, password: p, recv-window: \"4194304\"}\n" +
		"rules:\n  - MATCH,DIRECT\n"
	rows := quicWindowRows(t, document, RuntimeProfileIOSPacketTunnel)
	want := map[string]string{
		"proxies[hysteria2].initial-stream-receive-window":     "untrue (proxies[1]): not set (core default: 8388608 (8 MiB, from the first byte))",
		"proxies[hysteria2].initial-connection-receive-window": "untrue (proxies[1]): not set (core default: 20971520 (20 MiB, from the first byte))",
	}
	if outbound.QUICTunnelMaxConnection < quicHysteria2OwnConnection {
		want["proxies[hysteria2].max-connection-receive-window"] = "untrue (proxies[1]): not set (core default: 20971520 (20 MiB))"
	}
	if outbound.QUICTunnelGrowingMaxConnection != 0 {
		want["proxies[tuic].recv-window"] = "quoted (proxies[0]): not set (core default: 67108864 (grows from 6.4 MiB to 64 MiB))"
	}
	for field, given := range want {
		if row := rows[field]; row == nil || row["given"] != given {
			t.Errorf("%s row %v, want given %q", field, row, given)
		}
	}
	if len(rows) != len(want) {
		t.Errorf("rows for %d windows, want %d: %v", len(rows), len(want), rows)
	}
}

func TestOnlyAQUICNodeThatLeavesAWindowIsKeptForTheRows(t *testing.T) {
	plain := map[string]any{"name": "plain", "type": "hysteria2", "server": "10.0.0.1", "port": 443, "password": "p"}
	written := map[string]any{"name": "written", "type": "hysteria2", "server": "10.0.0.2", "port": 443, "password": "p",
		"initial-stream-receive-window": 1048576, "max-stream-receive-window": 1048576,
		"initial-connection-receive-window": 8388608, "max-connection-receive-window": 8388608}
	own := map[string]any{"name": "own", "type": "tuic", "server": "10.0.0.3", "port": 443, "recv-window": 4194304}
	kept, _ := deviationDocumentOf(map[string]any{"proxies": []any{plain, written, own}})["proxies"].([]any)
	if len(kept) != 3 || kept[1] != nil || kept[2] != nil {
		t.Fatalf("kept %v; the two nodes that write their windows have no row and are not kept", kept)
	}
	first, _ := kept[0].(map[string]any)
	rows := 0
	for _, pair := range quicWindowPairs {
		if pair.nodeType == "hysteria2" {
			rows++
		}
	}
	if fields := quicWindowDefaulted(first); len(fields) != rows || first["server"] != nil {
		t.Fatalf("the node that writes no window is kept as %v (rows for %v); want its type, name and windows only", first, fields)
	}
}

func TestTheCatalogSaysWhereAHysteria2NodesUnwrittenWindowsStart(t *testing.T) {
	windows := outbound.QUICTunnelReceiveWindows()
	want := map[string]string{
		"proxies[hysteria2].initial-stream-receive-window":     strconv.FormatUint(windows.InitialStream, 10),
		"proxies[hysteria2].initial-connection-receive-window": strconv.FormatUint(windows.InitialConnection, 10),
	}
	for _, profile := range []string{RuntimeProfileIOSPacketTunnel, RuntimeProfileTVOSPacketTunnel} {
		found := 0
		for _, field := range mustCatalog(t, profile).Fields {
			value, ok := want[field.Path]
			if !ok {
				continue
			}
			found++
			decision := field.PlatformDecision
			if decision == nil || decision.When != "default" || decision.Value != value ||
				decision.Category != deviationForced || decision.Effective == "" || decision.Reason == "" {
				t.Errorf("%s %s: decision %+v, want a default of %s", profile, field.Path, decision, value)
			}
			if field.PlatformDecided {
				t.Errorf("%s %s: marked platformDecided; a window the node writes runs as written", profile, field.Path)
			}
		}
		if found != len(want) {
			t.Fatalf("%s: %d of the %d window fields are in the catalog", profile, found, len(want))
		}
	}
	mac := mustCatalog(t, RuntimeProfileMacOSPacketTunnel)
	for _, field := range mac.Fields {
		if _, ok := want[field.Path]; ok && field.PlatformDecision != nil {
			t.Errorf("macOS %s: decision %+v; it runs the protocol's own windows", field.Path, field.PlatformDecision)
		}
	}
	for _, profile := range []string{RuntimeProfileIOSPacketTunnel, RuntimeProfileTVOSPacketTunnel} {
		listed := 0
		for _, key := range mustCatalog(t, profile).PlatformDecidedKeys {
			if value, ok := want[key.Path]; ok {
				listed++
				if !key.DefaultOnly || key.Value != value || key.Category != deviationForced {
					t.Errorf("%s platformDecidedKeys %s: %+v, want a default of %s", profile, key.Path, key, value)
				}
			}
		}
		if listed != len(want) {
			t.Errorf("%s: platformDecidedKeys lists %d of the %d window fields", profile, listed, len(want))
		}
	}
	for _, key := range mac.PlatformDecidedKeys {
		if _, ok := want[key.Path]; ok {
			t.Errorf("macOS platformDecidedKeys lists %s", key.Path)
		}
	}
}

func TestAQUICWindowsCatalogValueIsItsRowsFigure(t *testing.T) {
	for _, pairs := range [][]quicWindowPair{quicHysteria2WindowPairs, quicHysteria2CeilingPairs, quicGrowingWindowPairs} {
		for _, pair := range pairs {
			if pair.value != "" && !strings.HasPrefix(pair.effective, pair.value+" (") {
				t.Errorf("%s: the catalog's value %s, the row's text %q", pair.field, pair.value, pair.effective)
			}
		}
	}
	for field := range ipStackRules() {
		if isQUICWindowField(field) || !strings.Contains(field, "].ip-stack.") {
			t.Errorf("ip-stack's table holds %s", field)
		}
	}
	if len(ipStackRules()) != 2*len(ipStackNodeTypes) {
		t.Errorf("ip-stack's table holds %d registrations, want two for each of the %d node types", len(ipStackRules()), len(ipStackNodeTypes))
	}
}
