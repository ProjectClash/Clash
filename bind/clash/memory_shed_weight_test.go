package clash

import (
	"fmt"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter/outbound"
	C "github.com/ProjectClash/Clash/constant"
	mieru "github.com/enfein/mieru/v3/pkg/protocol"
)

func shedNodeTypes(types map[string]C.AdapterType) func(string) (C.AdapterType, bool) {
	return func(name string) (C.AdapterType, bool) {
		adapterType, ok := types[name]
		return adapterType, ok
	}
}

func activeFlow(id, node string) shedView {
	return shedView{id: id, network: C.TCP, node: node, age: time.Minute, sinceDownload: 10 * time.Millisecond, sinceUpload: 10 * time.Millisecond, queuedKnown: true}
}

func stalledFlow(id, node string) shedView {
	view := activeFlow(id, node)
	view.queued = 128 << 10
	view.sinceDownload = 5 * time.Second
	view.sinceUpload = shedWedgedIdle
	return view
}

func TestAWedgedQUICNodeGoesWhole(t *testing.T) {
	withProtocolQUICWindows(t)
	types := shedNodeTypes(map[string]C.AdapterType{"HY2": C.Hysteria2, "Trojan": C.Trojan})
	var views []shedView
	for i := 0; i < 20; i++ {
		views = append(views, stalledFlow(fmt.Sprintf("hy2-stalled-%02d", i), "HY2"))
	}
	for i := 0; i < 10; i++ {
		stuck := activeFlow(fmt.Sprintf("hy2-stuck-%02d", i), "HY2")
		stuck.sinceDownload, stuck.sinceUpload = shedWedgedIdle, shedWedgedIdle
		views = append(views, stuck)
	}
	for i := 0; i < 5; i++ {
		views = append(views, activeFlow(fmt.Sprintf("trojan-%02d", i), "Trojan"))
	}
	ranked := rankShedCandidates(views, types)
	if len(ranked) != 35 {
		t.Fatalf("%d candidates, want all 35", len(ranked))
	}
	for i, c := range ranked {
		switch {
		case i < 20:
			if c.group != "HY2" || !c.stalled() || c.weight != shedTCPBaseBytes+128<<10+1<<20 {
				t.Fatalf("rank %d = %+v; the stalled HY2 flows come first, 20 MiB shared by 20", i, c)
			}
		case c.node == "HY2":
			if c.group != "HY2" {
				t.Fatalf("%s is stuck on the wedged node but not grouped", c.id)
			}
		default:
			if c.group != "" {
				t.Fatalf("%s on a TCP outbound was grouped as %q", c.id, c.group)
			}
		}
	}
}

func TestAPartlyWedgedQUICNodeIsLeftAlone(t *testing.T) {
	withProtocolQUICWindows(t)
	types := shedNodeTypes(map[string]C.AdapterType{"HY2": C.Hysteria2, "Trojan": C.Trojan, "TUIC": C.Tuic})
	views := []shedView{activeFlow("hy2-moving", "HY2"), stalledFlow("trojan-stalled", "Trojan"), stalledFlow("tuic-alone", "TUIC")}
	for i := 0; i < 20; i++ {
		views = append(views, stalledFlow(fmt.Sprintf("hy2-stalled-%02d", i), "HY2"))
	}
	ranked := rankShedCandidates(views, types)
	for _, c := range ranked {
		if c.node == "HY2" {
			t.Fatalf("%s on a node that is still moving became a candidate", c.id)
		}
	}
	if len(ranked) != 2 || ranked[0].id != "tuic-alone" || ranked[0].group != "TUIC" {
		t.Fatalf("ranked %+v; the lone stalled TUIC flow is its whole wedged node, 1.5 MiB stream window", ranked)
	}
	if ranked[1].id != "trojan-stalled" || ranked[1].group != "" || ranked[1].weight != shedTCPBaseBytes+128<<10 {
		t.Fatalf("rank 1 = %+v; a stalled TCP-outbound flow holds its send buffer and no window", ranked[1])
	}
}

func TestOnlyAFullBufferWithNothingTakenIsAStall(t *testing.T) {
	withProtocolQUICWindows(t)
	types := shedNodeTypes(map[string]C.AdapterType{"HY2": C.Hysteria2})
	busy := activeFlow("busy", "HY2")
	busy.queued = 128 << 10
	quiet := activeFlow("quiet", "HY2")
	quiet.sinceDownload, quiet.sinceUpload = time.Minute, time.Minute
	unknown := stalledFlow("unknown", "HY2")
	unknown.queuedKnown = false
	for _, view := range []shedView{busy, quiet, unknown} {
		if view.stalled() {
			t.Fatalf("%s reads as stalled", view.id)
		}
	}
	ranked := rankShedCandidates([]shedView{busy, quiet, unknown}, types)
	if len(ranked) != 3 || ranked[0].id != "busy" || ranked[0].weight != shedTCPBaseBytes+128<<10 {
		t.Fatalf("a full buffer still counts as bytes held: %+v", ranked[0])
	}
	if ranked[1].id != "quiet" {
		t.Fatalf("among equals the idlest goes first, got %s", ranked[1].id)
	}
}

func TestYoungConnectionsAreNotCandidates(t *testing.T) {
	young := stalledFlow("young", "HY2")
	young.age = time.Second
	if ranked := rankShedCandidates([]shedView{young}, shedNodeTypes(nil)); len(ranked) != 0 {
		t.Fatalf("a %v old connection was a candidate", young.age)
	}
}

func TestAnUploadIsMovement(t *testing.T) {
	withProtocolQUICWindows(t)
	types := shedNodeTypes(map[string]C.AdapterType{"HY2": C.Hysteria2})
	uploading := activeFlow("hy2-uploading", "HY2")
	uploading.sinceDownload = time.Minute
	uploading.sinceUpload = time.Millisecond
	ranked := rankShedCandidates([]shedView{stalledFlow("hy2-stalled", "HY2"), uploading}, types)
	if len(ranked) != 0 {
		t.Fatalf("candidates %+v; a node with a flow still sending is not wedged", ranked)
	}
}

func TestAWedgedNodeNeedsEveryOtherFlowQuietForLong(t *testing.T) {
	withProtocolQUICWindows(t)
	types := shedNodeTypes(map[string]C.AdapterType{"HY2": C.Hysteria2})
	for _, c := range []struct {
		quiet time.Duration
		want  int
	}{
		{shedWedgedIdle - time.Second, 0},
		{shedWedgedIdle, 2},
	} {
		quiet := activeFlow("hy2-quiet", "HY2")
		quiet.sinceDownload, quiet.sinceUpload = c.quiet, c.quiet
		ranked := rankShedCandidates([]shedView{stalledFlow("hy2-stalled", "HY2"), quiet}, types)
		if len(ranked) != c.want {
			t.Fatalf("quiet %v: %d candidates (%+v), want %d", c.quiet, len(ranked), ranked, c.want)
		}
		for _, r := range ranked {
			if r.group != "HY2" {
				t.Fatalf("quiet %v: %s not grouped under its wedged node", c.quiet, r.id)
			}
		}
	}
}

func TestAStalledFlowThatSendsIsMovement(t *testing.T) {
	withProtocolQUICWindows(t)
	types := shedNodeTypes(map[string]C.AdapterType{"HY2": C.Hysteria2})
	for _, c := range []struct {
		sinceUpload time.Duration
		want        int
	}{
		{time.Millisecond, 0},
		{shedWedgedIdle - time.Second, 0},
		{shedWedgedIdle, 3},
	} {
		sending := stalledFlow("hy2-stalled-sending", "HY2")
		sending.sinceUpload = c.sinceUpload
		ranked := rankShedCandidates([]shedView{stalledFlow("hy2-stalled-a", "HY2"), stalledFlow("hy2-stalled-b", "HY2"), sending}, types)
		if len(ranked) != c.want {
			t.Fatalf("a stalled flow that sent %v ago: %d candidates (%+v), want %d", c.sinceUpload, len(ranked), ranked, c.want)
		}
	}
}

func withProtocolQUICWindows(t *testing.T) {
	t.Helper()
	before := outbound.QUICDefaultReceiveWindows()
	outbound.SetQUICDefaultReceiveWindows(nil)
	t.Cleanup(func() { outbound.SetQUICDefaultReceiveWindows(before) })
}

func TestAWedgedQUICNodeGoesWholeUnderTheTunnelsWindows(t *testing.T) {
	before := outbound.QUICDefaultReceiveWindows()
	outbound.SetQUICDefaultReceiveWindows(outbound.QUICTunnelReceiveWindows())
	t.Cleanup(func() { outbound.SetQUICDefaultReceiveWindows(before) })
	types := shedNodeTypes(map[string]C.AdapterType{"HY2": C.Hysteria2, "Trojan": C.Trojan})
	var views []shedView
	for i := 0; i < 20; i++ {
		views = append(views, stalledFlow(fmt.Sprintf("hy2-stalled-%02d", i), "HY2"))
	}
	for i := 0; i < 5; i++ {
		views = append(views, activeFlow(fmt.Sprintf("trojan-%02d", i), "Trojan"))
	}
	ranked := rankShedCandidates(views, types)
	share := int64(outbound.QUICTunnelMaxConnection) / 20
	for i, c := range ranked[:20] {
		if c.group != "HY2" || c.weight != shedTCPBaseBytes+128<<10+share {
			t.Fatalf("rank %d = %+v; the stalled HY2 flows come first, the tunnels' connection window shared by 20", i, c)
		}
	}
	for _, c := range ranked[20:] {
		if c.group != "" {
			t.Fatalf("%s on a TCP outbound was grouped as %q", c.id, c.group)
		}
	}
}

func TestAFlowStalledOnAMieruNodeWeighsWhatItsSessionCanHold(t *testing.T) {
	types := shedNodeTypes(map[string]C.AdapterType{"Mieru": C.Mieru, "Trojan": C.Trojan})
	views := []shedView{stalledFlow("trojan-stalled", "Trojan"), stalledFlow("mieru-stalled", "Mieru"), activeFlow("mieru-active", "Mieru")}
	weights := func() map[string]int64 {
		byID := map[string]int64{}
		for _, candidate := range rankShedCandidates(views, types) {
			byID[candidate.id] = candidate.weight
		}
		return byID
	}
	before := mieru.SetStreamReceiveByteLimit(0)
	t.Cleanup(func() { mieru.SetStreamReceiveByteLimit(before) })

	shipped := weights()
	if shipped["mieru-stalled"] != shipped["trojan-stalled"] {
		t.Fatalf("with no limit a stalled mieru flow weighs %d and a Trojan one %d", shipped["mieru-stalled"], shipped["trojan-stalled"])
	}

	mieru.SetStreamReceiveByteLimit(tunnelMieruStreamReceiveLimit)
	bounded := weights()
	if extra := bounded["mieru-stalled"] - bounded["trojan-stalled"]; extra != tunnelMieruStreamReceiveLimit+2*mieru.StreamSegmentPayload {
		t.Fatalf("a stalled mieru flow weighs %d more than a Trojan one, want the limit and two segments, %d",
			extra, tunnelMieruStreamReceiveLimit+2*mieru.StreamSegmentPayload)
	}
	if bounded["mieru-active"] != shipped["mieru-active"] {
		t.Fatalf("a mieru flow its app is reading weighs %d, it weighed %d", bounded["mieru-active"], shipped["mieru-active"])
	}
	if first := rankShedCandidates(views, types)[0].id; first != "mieru-stalled" {
		t.Fatalf("the heaviest is %s, want the stalled mieru flow", first)
	}
}
