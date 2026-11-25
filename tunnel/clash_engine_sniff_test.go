package tunnel

import (
	"context"
	"sync"
	"testing"
	"time"

	N "github.com/ProjectClash/Clash/common/net"
	"github.com/ProjectClash/Clash/common/utils"
	"github.com/ProjectClash/Clash/component/sniffer"
	C "github.com/ProjectClash/Clash/constant"
	CS "github.com/ProjectClash/Clash/constant/sniffer"
	icontext "github.com/ProjectClash/Clash/context"
	R "github.com/ProjectClash/Clash/rules"
)

type engineProxy struct{ *dialProxy }

func (engineProxy) ClashConnectsSniffedHost() bool { return true }
func (p engineProxy) Adapter() C.ProxyAdapter      { return p }

func engineRule(host string) [3]string {
	return [3]string{"AND", "((IN-TYPE,TUN),(NETWORK,TCP),(DST-PORT,443),(DOMAIN," + host + "))", "MODULE-ENGINE"}
}

func TestAGlobalIPv6FlowTheEngineMayTakeIsReadBeforeItsDial(t *testing.T) {
	events := &eventLog{}
	engine := engineProxy{&dialProxy{doorProxy: doorProxy{name: "MODULE-ENGINE", typ: C.Http}, dial: func() (C.Conn, error) {
		events.add("dialled MODULE-ENGINE")
		return nil, errRefused
	}}}
	direct := &dialProxy{doorProxy: doorProxy{name: "DIRECT", typ: C.Direct}, dial: func() (C.Conn, error) {
		events.add("dialled DIRECT")
		return nil, errRefused
	}}
	withRules(t, map[string]C.Proxy{"DIRECT": direct, "REJECT": doorProxy{name: "REJECT", typ: C.Reject}, "MODULE-ENGINE": engine},
		engineRule("app.bilibili.com"),
		[3]string{"MATCH", "", "DIRECT"},
	)
	withSnifferOn(t)
	conn := newVerdictConn(true)
	conn.events = events
	conn.payload <- clientHelloFor(t, "app.bilibili.com")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	handleTCPConnContext(ctx, icontext.NewConnContext(conn, tunFlowTo("2001:db8::10")))
	if got := events.all(); len(got) < 2 || got[0] != "answered-by-a-read" || got[1] != "dialled MODULE-ENGINE" {
		t.Fatalf("an IPv6 flow whose ClientHello names a host the engine decrypts went %q, want read first and then the engine", got)
	}
}

func TestAGlobalIPv6FlowTheEngineCannotTakeKeepsItsDialFirst(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rules [][3]string
		port  uint16
	}{
		{"no module decrypts", [][3]string{{"DOMAIN", "app.bilibili.com", "PROXY"}, {"MATCH", "", "DIRECT"}}, 443},
		{"the engine decrypts, on another port the sniffer reads", [][3]string{engineRule("app.bilibili.com"), {"MATCH", "", "DIRECT"}}, 80},
		{"a domain rule to the engine's proxy that is not the engine", [][3]string{{"DOMAIN", "app.bilibili.com", "PLAIN-HTTP"}, {"MATCH", "", "DIRECT"}}, 443},
		{"a rule before the engine's takes the address", [][3]string{{"IP-CIDR6", "2001:db8::/32", "DIRECT"}, engineRule("app.bilibili.com"), {"MATCH", "", "DIRECT"}}, 443},
	} {
		t.Run(tc.name, func(t *testing.T) {
			events := &eventLog{}
			direct := &dialProxy{doorProxy: doorProxy{name: "DIRECT", typ: C.Direct}, dial: func() (C.Conn, error) {
				events.add("dialled")
				return nil, errRefused
			}}
			engine := engineProxy{&dialProxy{doorProxy: doorProxy{name: "MODULE-ENGINE", typ: C.Http}, dial: func() (C.Conn, error) {
				events.add("dialled MODULE-ENGINE")
				return nil, errRefused
			}}}
			proxies := map[string]C.Proxy{
				"DIRECT": direct, "REJECT": doorProxy{name: "REJECT", typ: C.Reject}, "MODULE-ENGINE": engine,
				"PROXY": &dialProxy{doorProxy: doorProxy{name: "PROXY", typ: C.Shadowsocks}, dial: func() (C.Conn, error) {
					events.add("dialled PROXY")
					return nil, errRefused
				}},
				"PLAIN-HTTP": &dialProxy{doorProxy: doorProxy{name: "PLAIN-HTTP", typ: C.Http}, dial: func() (C.Conn, error) {
					events.add("dialled PLAIN-HTTP")
					return nil, errRefused
				}},
			}
			withRules(t, proxies, tc.rules...)
			withSnifferOn(t)
			conn := newVerdictConn(true)
			conn.events = events
			conn.payload <- clientHelloFor(t, "app.bilibili.com")
			metadata := tunFlowTo("2001:db8::10")
			metadata.DstPort = tc.port
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			handleTCPConnContext(ctx, icontext.NewConnContext(conn, metadata))
			if got := events.all(); len(got) == 0 || got[0] != "dialled" {
				t.Fatalf("want the dial first, got %q", got)
			}
		})
	}
}

func TestAGlobalIPv6FlowTheEngineDoesNotTakeIsReadAndGoesItsWay(t *testing.T) {
	events := &eventLog{}
	engine := engineProxy{&dialProxy{doorProxy: doorProxy{name: "MODULE-ENGINE", typ: C.Http}, dial: func() (C.Conn, error) {
		events.add("dialled MODULE-ENGINE")
		return nil, errRefused
	}}}
	direct := &dialProxy{doorProxy: doorProxy{name: "DIRECT", typ: C.Direct}, dial: func() (C.Conn, error) {
		events.add("dialled DIRECT")
		return nil, errRefused
	}}
	withRules(t, map[string]C.Proxy{"DIRECT": direct, "REJECT": doorProxy{name: "REJECT", typ: C.Reject}, "MODULE-ENGINE": engine},
		engineRule("app.bilibili.com"),
		[3]string{"MATCH", "", "DIRECT"},
	)
	withSnifferOn(t)
	conn := newVerdictConn(true)
	conn.events = events
	conn.payload <- clientHelloFor(t, "www.example.com")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	handleTCPConnContext(ctx, icontext.NewConnContext(conn, tunFlowTo("2001:db8::10")))
	if got := events.all(); len(got) < 2 || got[0] != "answered-by-a-read" || got[1] != "dialled DIRECT" {
		t.Fatalf("an IPv6 flow to 443 whose name the engine does not take went %q, want read first and then DIRECT", got)
	}
}

func TestWithNoSnifferTheProtocolReaderStandsAsideDespiteTheEngine(t *testing.T) {
	engine := engineProxy{&dialProxy{doorProxy: doorProxy{name: "MODULE-ENGINE", typ: C.Http}}}
	withRules(t, map[string]C.Proxy{
		"DIRECT": doorProxy{name: "DIRECT", typ: C.Direct}, "REJECT": doorProxy{name: "REJECT", typ: C.Reject}, "MODULE-ENGINE": engine,
	},
		engineRule("app.bilibili.com"),
		[3]string{"MATCH", "", "DIRECT"},
	)
	previous := snifferDispatcher.Load()
	UpdateSniffer(nil)
	t.Cleanup(func() { UpdateSniffer(previous) })
	held := newVerdictConn(true)
	var peek sync.Mutex
	_ = tcpProtocolProbe(N.NewBufferedConn(held), &peek, tunFlowTo("2001:db8::10"))()
	if !held.HandshakeDeferred() {
		t.Fatal("with no sniffer the reader answered the held-back handshake of a flow only the engine's rule could want read")
	}
	_ = held.Close()
}

func TestAFlowOnAPortTheSnifferDoesNotReadIsNotHeldForTheEngine(t *testing.T) {
	engine := engineProxy{&dialProxy{doorProxy: doorProxy{name: "MODULE-ENGINE", typ: C.Http}}}
	withRules(t, map[string]C.Proxy{
		"DIRECT": doorProxy{name: "DIRECT", typ: C.Direct}, "REJECT": doorProxy{name: "REJECT", typ: C.Reject}, "MODULE-ENGINE": engine,
	},
		[3]string{"AND", "((IN-TYPE,TUN),(NETWORK,TCP),(DST-PORT,8443),(DOMAIN,app.bilibili.com))", "MODULE-ENGINE"},
		[3]string{"MATCH", "", "DIRECT"},
	)
	withSnifferOn(t)
	held := newVerdictConn(true)
	var peek sync.Mutex
	metadata := tunFlowTo("2001:db8::10")
	metadata.DstPort = 8443
	_ = tcpProtocolProbe(N.NewBufferedConn(held), &peek, metadata)()
	if !held.HandshakeDeferred() {
		t.Fatal("a flow on a port the sniffer does not read was answered for the engine")
	}
	_ = held.Close()
}

func TestOutsideRuleModeOnlyTheEveryModeRulesCanSendAFlowToTheEngine(t *testing.T) {
	engine := engineProxy{&dialProxy{doorProxy: doorProxy{name: "MODULE-ENGINE", typ: C.Http}}}
	withRules(t, map[string]C.Proxy{
		"DIRECT": doorProxy{name: "DIRECT", typ: C.Direct}, "REJECT": doorProxy{name: "REJECT", typ: C.Reject}, "MODULE-ENGINE": engine,
	},
		engineRule("app.bilibili.com"),
		[3]string{"MATCH", "", "DIRECT"},
	)
	SetMode(Direct)
	flow := tunFlowTo("2001:db8::10")
	if engineMayTakeOnceNamed(flow) {
		t.Fatal("in direct mode with no every-mode rules, a flow is held for an engine the tunnel never asks")
	}
	prevRouting := loadVersion().routing
	t.Cleanup(func() { UpdateClashRouting(prevRouting) })
	line := engineRule("app.bilibili.com")
	everyMode, err := R.ParseRule(line[0], line[1], line[2], nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	UpdateClashRouting(C.ClashRouting{EveryModeRules: []C.Rule{everyMode}})
	if !engineMayTakeOnceNamed(flow) {
		t.Fatal("in direct mode with the engine's rule among the every-mode rules, a flow to 443 is not held for it")
	}
}

func TestABareFlowTheSnifferWillNotParseIsNotHeldForTheEngine(t *testing.T) {
	engine := engineProxy{&dialProxy{doorProxy: doorProxy{name: "MODULE-ENGINE", typ: C.Http}}}
	withRules(t, map[string]C.Proxy{
		"DIRECT": doorProxy{name: "DIRECT", typ: C.Direct}, "REJECT": doorProxy{name: "REJECT", typ: C.Reject}, "MODULE-ENGINE": engine,
	},
		engineRule("app.bilibili.com"),
		[3]string{"MATCH", "", "DIRECT"},
	)
	ports, err := utils.NewUnsignedRanges[uint16]("80,443")
	if err != nil {
		t.Fatal(err)
	}
	dispatcher, err := sniffer.NewDispatcher(&sniffer.Config{
		Enable:      true,
		ParsePureIp: false,
		Sniffers:    map[CS.Type]sniffer.SnifferConfig{CS.TLS: {Ports: ports}, CS.HTTP: {Ports: ports}},
	})
	if err != nil {
		t.Fatal(err)
	}
	previous := snifferDispatcher.Load()
	UpdateSniffer(dispatcher)
	t.Cleanup(func() { UpdateSniffer(previous) })
	held := newVerdictConn(true)
	var peek sync.Mutex
	_ = tcpProtocolProbe(N.NewBufferedConn(held), &peek, tunFlowTo("2001:db8::10"))()
	if !held.HandshakeDeferred() {
		t.Fatal("a bare flow the sniffer will not parse was answered for the engine")
	}
	_ = held.Close()
}
