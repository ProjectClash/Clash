package clash

import (
	"encoding/json"
	"github.com/ProjectClash/Clash/adapter/outbound"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/log"
	"github.com/metacubex/http"
)

func fixedHeapSources(views []shedView, types map[string]C.AdapterType, smuxUnread int64) heapSources {
	return heapSources{
		views: func() []shedView { return views },
		nodeType: func() func(string) (C.AdapterType, bool) {
			return func(name string) (C.AdapterType, bool) { adapterType, ok := types[name]; return adapterType, ok }
		},
		smuxUnread: func() int64 { return smuxUnread },
		grpcFlows:  func() int64 { return 0 },
	}
}

func TestTheHeapAttributionCountsWhatHoldsMemory(t *testing.T) {
	withProtocolQUICWindows(t)
	types := map[string]C.AdapterType{"hy2-a": C.Hysteria2, "hy2-b": C.Hysteria2, "hy2-udp": C.Hysteria2,
		"tuic": C.Tuic, "trojan": C.Trojan}
	views := []shedView{
		{network: C.TCP, node: "hy2-a", queuedKnown: true, queued: 512 << 10, sinceDownload: 5 * time.Second},
		{network: C.TCP, node: "hy2-a", queuedKnown: true},
		{network: C.TCP, node: "hy2-a", queuedKnown: true},
		{network: C.UDP, node: "hy2-a"},
		{network: C.TCP, node: "hy2-b", queuedKnown: true, queued: 4 << 10},
		{network: C.UDP, node: "hy2-udp"},
		{network: C.TCP, node: "tuic", queuedKnown: true},
		{network: C.TCP, node: "trojan", queuedKnown: true},
		{network: C.TCP, node: "gone", queuedKnown: true},
	}
	report := attributeHeap(fixedHeapSources(views, types, 300<<10))
	if report.Incomplete || report.UDPSessions != 2 || report.AppQueuedBytes != 516<<10 || report.StalledFlows != 1 {
		t.Fatalf("udp %d, queued %d, stalled %d (incomplete %v); want 2, %d, 1", report.UDPSessions,
			report.AppQueuedBytes, report.StalledFlows, report.Incomplete, 516<<10)
	}
	if report.SmuxUnreadBytes != 300<<10 {
		t.Fatalf("smux unread %d, want %d", report.SmuxUnreadBytes, 300<<10)
	}
	if got := report.Hysteria2; got.Connections != 3 || got.TCPFlows != 4 || got.UnreadBoundBytes != 28<<20 {
		t.Fatalf("Hysteria2 %+v, want 3 connections 4 TCP flows at most 28 MiB", got)
	}
	if got := report.Tuic; got.Connections != 1 || got.TCPFlows != 1 || got.UnreadBoundBytes != 15728640 {
		t.Fatalf("TUIC %+v, want 1 connection 1 TCP flow at most 15 MiB", got)
	}
}

func TestTheHeapAttributionsBoundFollowsTheTunnelsQUICWindows(t *testing.T) {
	before := outbound.QUICDefaultReceiveWindows()
	outbound.SetQUICDefaultReceiveWindows(outbound.QUICTunnelReceiveWindows())
	t.Cleanup(func() { outbound.SetQUICDefaultReceiveWindows(before) })
	types := map[string]C.AdapterType{"hy2-a": C.Hysteria2, "hy2-b": C.Hysteria2, "tuic": C.Tuic}
	views := []shedView{
		{network: C.TCP, node: "hy2-a", queuedKnown: true},
		{network: C.TCP, node: "hy2-a", queuedKnown: true},
		{network: C.TCP, node: "hy2-a", queuedKnown: true},
		{network: C.TCP, node: "hy2-b", queuedKnown: true},
		{network: C.TCP, node: "tuic", queuedKnown: true},
		{network: C.TCP, node: "tuic", queuedKnown: true},
	}
	report := attributeHeap(fixedHeapSources(views, types, 0))
	if got, want := report.Hysteria2, int64(outbound.QUICTunnelMaxConnection)+8<<20; got.Connections != 2 || got.TCPFlows != 4 || got.UnreadBoundBytes != want {
		t.Fatalf("Hysteria2 %+v, want 2 connections 4 TCP flows at most the tunnels' connection window and a stream's 8 MiB (%d)", got, want)
	}
	tuicBound := int64(2 * 15728640)
	if ceiling := int64(outbound.QUICTunnelGrowingMaxConnection); ceiling != 0 && ceiling < tuicBound {
		tuicBound = ceiling
	}
	if got := report.Tuic; got.Connections != 1 || got.TCPFlows != 2 || got.UnreadBoundBytes != tuicBound {
		t.Fatalf("TUIC %+v, want 1 connection 2 TCP flows at most two streams' 15 MiB or the tunnels' ceiling (%d)", got, tuicBound)
	}
}

func TestTheHeapAttributionLineSaysTheQUICFigureIsABound(t *testing.T) {
	line := heapAttribution{
		UDPSessions: 12, AppQueuedBytes: 2 << 10, StalledFlows: 1,
		SmuxUnreadBytes: 3 << 20,
		Hysteria2:       quicAttribution{Connections: 1, TCPFlows: 34, UnreadBoundBytes: 20 << 20},
	}.logLine()
	for _, want := range []string{"12 UDP sessions", "2 KiB held for apps, 1 flows stalled on it",
		"smux sessions of every kind 3.0 MiB unread",
		"Hysteria2 1 connections 34 TCP flows, at most 20.0 MiB unread (bound from the default windows, one connection a node; not measured)"} {
		if !strings.Contains(line, want) {
			t.Fatalf("the line %q lacks %q", line, want)
		}
	}
	for _, absent := range []string{"TUIC", "gRPC", "h2mux", "yamux"} {
		if strings.Contains(line, absent) {
			t.Fatalf("the line %q names %s, which holds nothing", line, absent)
		}
	}
	if line := (heapAttribution{Masque: quicAttribution{Connections: 1}}).logLine(); !strings.Contains(line, "MASQUE 1 connections, datagrams only") ||
		strings.Contains(line, "at most") {
		t.Fatalf("the line %q gives datagrams a bound", line)
	}
	if line := (heapAttribution{SmuxUnreadBytes: 600}).logLine(); !strings.Contains(line, "smux sessions of every kind 600 B unread") {
		t.Fatalf("the line %q rounds 600 bytes away", line)
	}
}

func TestAFailureCountingTheHeapLeavesTheRecordIncomplete(t *testing.T) {
	sources := fixedHeapSources(nil, nil, 0)
	sources.views = func() []shedView { panic("a tracker with a nil inside") }
	report := attributeHeap(sources)
	if !report.Incomplete || report.logLine() != "[Memory] heap attribution: not counted (counting failed)" {
		t.Fatalf("a counting failure gave %+v, %q", report, report.logLine())
	}
}

func TestACriticalPressureRecordSaysWhoHeldTheHeap(t *testing.T) {
	path := setupOOMEvidenceTest(t)
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	if err := service.Start(helloYAML); err != nil {
		t.Fatal(err)
	}
	if err := RecordMemoryPressureEvidence(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > oomEvidenceMaxBytes {
		t.Fatalf("evidence %d bytes, past its %d", len(raw), oomEvidenceMaxBytes)
	}
	var report oomEvidence
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	if report.HeapAttribution == nil || report.HeapAttribution.Incomplete {
		t.Fatalf("a critical record without its heap attribution: %s", raw)
	}
}

func TestACriticalPressureNotificationLogsWhoHoldsTheHeap(t *testing.T) {
	setupOOMEvidenceTest(t)
	heapAttributionCriticalLogged.Store(0)
	t.Cleanup(func() { heapAttributionCriticalLogged.Store(0) })
	subscription := log.Subscribe()
	defer log.UnSubscribe(subscription)
	lines := make(chan int, 1)
	go func() {
		count := 0
		deadline := time.After(2 * time.Second)
		var settle <-chan time.Time
		for {
			select {
			case event, open := <-subscription:
				if !open {
					lines <- count
					return
				}
				if event.LogLevel == log.WARNING && strings.Contains(event.Payload, "[Memory] heap attribution: ") {
					count++
					if settle == nil {
						settle = time.After(300 * time.Millisecond)
					}
				}
			case <-settle:
				lines <- count
				return
			case <-deadline:
				lines <- count
				return
			}
		}
	}()
	handleMemoryPressureWith(40<<20, 0)
	handleMemoryPressureWith(41<<20, 0)
	if got := <-lines; got != 1 {
		t.Fatalf("%d attribution lines for two notifications together, want 1", got)
	}
}

func TestTheHeapAttributionCountsGRPCFlows(t *testing.T) {
	sources := fixedHeapSources(nil, nil, 0)
	sources.grpcFlows = func() int64 { return 63 }
	report := attributeHeap(sources)
	if report.GRPCFlows != 63 || !strings.Contains(report.logLine(), "gRPC 63 flows open") {
		t.Fatalf("gRPC flows %d, line %q; want 63 named", report.GRPCFlows, report.logLine())
	}
	if line := attributeHeap(fixedHeapSources(nil, nil, 0)).logLine(); strings.Contains(line, "gRPC") {
		t.Fatalf("the line %q names gRPC with no flow open", line)
	}
}

func TestSetupCapsTheHTTP2RequestBodyScratchByProfile(t *testing.T) {
	t.Cleanup(func() { setStartupBreadcrumbRecording(false) })
	before := http.SetHTTP2StreamingBodyScratchMax(0)
	http.SetHTTP2StreamingBodyScratchMax(before)
	onDemand := http.HTTP2StreamingBodyScratchOnDemand()
	t.Cleanup(func() {
		http.SetHTTP2StreamingBodyScratchMax(before)
		http.SetHTTP2StreamingBodyScratchOnDemand(onDemand)
	})
	for _, c := range []struct {
		profile string
		want    int64
	}{{RuntimeProfileMacOSPacketTunnel, 512 << 10}, {RuntimeProfileTVOSPacketTunnel, 64 << 10}, {RuntimeProfileIOSPacketTunnel, 64 << 10}} {
		base := t.TempDir()
		if err := Setup(&SetupOptions{BasePath: base, WorkingPath: filepath.Join(base, "w"), TempPath: filepath.Join(base, "t"), RuntimeProfile: c.profile}); err != nil {
			t.Fatal(err)
		}
		if got := http.HTTP2RequestBodyScratchMax(-1); got != c.want {
			t.Fatalf("%s: a streaming body's scratch at most %d, want %d", c.profile, got, c.want)
		}
		if got, want := http.HTTP2StreamingBodyScratchOnDemand(), c.profile != RuntimeProfileMacOSPacketTunnel; got != want {
			t.Fatalf("%s: a streaming body's scratch taken on demand %v, want %v", c.profile, got, want)
		}
		if got := http.HTTP2RequestBodyScratchMax(4096); got != 512<<10 {
			t.Fatalf("%s: a body of known length capped at %d, want upstream's 512 KiB", c.profile, got)
		}
	}
}

func TestTheAttributionsNodeLookupAnswersAsTheTableDoes(t *testing.T) {
	setupOOMEvidenceTest(t)
	if err := os.WriteFile(C.Path.Resolve("attribution-provider.yaml"), []byte(`proxies:
  - {name: sub-trojan, type: trojan, server: 192.0.2.1, port: 443, password: x}
  - {name: shared, type: trojan, server: 192.0.2.2, port: 443, password: x}
`), 0o600); err != nil {
		t.Fatal(err)
	}
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	if err := service.Start(`mode: rule
proxies:
  - {name: own-ss, type: ss, server: 192.0.2.3, port: 8388, cipher: aes-128-gcm, password: x}
  - {name: shared, type: ss, server: 192.0.2.4, port: 8388, cipher: aes-128-gcm, password: x}
proxy-providers:
  sub: {type: file, path: ./attribution-provider.yaml}
proxy-groups:
  - {name: PROXY, type: select, use: [sub], proxies: [own-ss]}
rules:
  - MATCH,PROXY
`); err != nil {
		t.Fatal(err)
	}
	table, lookup := liveNodeTypes(), liveNodeTypeLookup()
	for _, name := range []string{"sub-trojan", "shared", "own-ss", "PROXY", "DIRECT", "absent", "shared"} {
		wantType, wantOK := table(name)
		gotType, gotOK := lookup(name)
		if gotType != wantType || gotOK != wantOK {
			t.Errorf("%s: the lookup answers %v %v, the table %v %v", name, gotType, gotOK, wantType, wantOK)
		}
	}
	if adapterType, _ := lookup("shared"); adapterType != C.Trojan {
		t.Errorf("shared is %v, want the subscription's trojan", adapterType)
	}
}

func TestTheHeapAttributionCountsWhatMieruSessionsHold(t *testing.T) {
	sources := fixedHeapSources(nil, nil, 0)
	sources.mieruQueued = func() (int64, int) { return 3 << 20, 12 }
	report := attributeHeap(sources)
	if report.MieruQueuedBytes != 3<<20 || report.MieruSessions != 12 {
		t.Fatalf("mieru %d bytes in %d sessions, want %d in 12", report.MieruQueuedBytes, report.MieruSessions, 3<<20)
	}
	if line := report.logLine(); !strings.Contains(line, "mieru 12 sessions 3.0 MiB unread") {
		t.Fatalf("the line does not say what mieru holds: %s", line)
	}
	if line := attributeHeap(fixedHeapSources(nil, nil, 0)).logLine(); strings.Contains(line, "mieru") {
		t.Fatalf("with no mieru session the line names it: %s", line)
	}
	live := liveHeapSources()
	if live.mieruQueued == nil {
		t.Fatal("the live sources do not count mieru")
	}
}
