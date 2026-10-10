package tunnel

import (
	"net/netip"
	"testing"

	C "github.com/ProjectClash/Clash/constant"
	R "github.com/ProjectClash/Clash/rules"
)

type doorProxy struct {
	C.Proxy
	name string
	typ  C.AdapterType
}

func (p doorProxy) Name() string                     { return p.name }
func (p doorProxy) Type() C.AdapterType              { return p.typ }
func (p doorProxy) Unwrap(*C.Metadata, bool) C.Proxy { return nil }
func (p doorProxy) SupportUDP() bool                 { return true }

func tunFlowTo(dst string) *C.Metadata {
	return &C.Metadata{
		NetWork: C.TCP,
		Type:    C.TUN,
		SrcIP:   netip.MustParseAddr("fdfe:dcba:9876::1"),
		SrcPort: 40000,
		DstIP:   netip.MustParseAddr(dst),
		DstPort: 443,
	}
}

func withDoorTestTunnel(t *testing.T, matchTarget string) {
	t.Helper()
	prevMode, prevProxies, prevRules := Mode(), loadProxies(), rules_()
	t.Cleanup(func() {
		SetMode(prevMode)
		UpdateProxies(prevProxies, nil)
		UpdateRules(prevRules, nil, nil)
	})
	UpdateProxies(map[string]C.Proxy{
		"DIRECT": doorProxy{name: "DIRECT", typ: C.Direct},
		"REJECT": doorProxy{name: "REJECT", typ: C.Reject},
		"relay":  doorProxy{name: "relay", typ: C.Shadowsocks},
	}, nil)
	match, err := R.ParseRule("MATCH", "", matchTarget, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	UpdateRules([]C.Rule{match}, nil, nil)
	SetMode(Rule)
}

func rules_() []C.Rule { return Rules() }

func TestWouldDialPhysicallyFollowsTheOutbound(t *testing.T) {
	withDoorTestTunnel(t, "DIRECT")
	if !WouldDialPhysically(tunFlowTo("2001:db8::10")) {
		t.Fatal("MATCH,DIRECT dials the destination on the physical path")
	}
	withDoorTestTunnel(t, "relay")
	if WouldDialPhysically(tunFlowTo("2001:db8::10")) {
		t.Fatal("MATCH,relay hands the destination to a proxy; the door must leave it alone")
	}
}

func TestWouldDialPhysicallyHonoursTheTunnelMode(t *testing.T) {
	withDoorTestTunnel(t, "relay")
	SetMode(Direct)
	if !WouldDialPhysically(tunFlowTo("2001:db8::10")) {
		t.Fatal("direct mode dials everything physically, whatever the rules say")
	}
}

func TestWouldDialPhysicallyDoesNotDisturbTheCallersMetadata(t *testing.T) {
	withDoorTestTunnel(t, "DIRECT")
	flow := tunFlowTo("2001:db8::10")
	before := flow.String() + "|" + flow.Host + "|" + flow.DstIP.String() + "|" + flow.DNSMode.String()
	_ = WouldDialPhysically(flow)
	after := flow.String() + "|" + flow.Host + "|" + flow.DstIP.String() + "|" + flow.DNSMode.String()
	if after != before {
		t.Fatalf("the door's look-ahead must work on a copy; metadata changed: %s -> %s", before, after)
	}
}
