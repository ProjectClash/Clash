package tunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	N "github.com/ProjectClash/Clash/common/net"
	C "github.com/ProjectClash/Clash/constant"
	R "github.com/ProjectClash/Clash/rules"
	RC "github.com/ProjectClash/Clash/rules/common"
)

func testAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

func quicInitial(version uint32, typeBits byte) []byte {
	b := make([]byte, 1200)
	b[0] = 0xc0 | typeBits<<4
	binary.BigEndian.PutUint32(b[1:5], version)
	return b
}

func stunBindingRequest(attributes int) []byte {
	b := make([]byte, 20+attributes)
	binary.BigEndian.PutUint16(b[0:2], 0x0001)
	binary.BigEndian.PutUint16(b[2:4], uint16(attributes))
	binary.BigEndian.PutUint32(b[4:8], stunMagicCookie)
	return b
}

func TestClassifyDatagramKnowsAQUICInitialAndASTUNMessage(t *testing.T) {
	for name, tc := range map[string]struct {
		datagram []byte
		want     string
	}{
		"QUIC v1 Initial":          {quicInitial(quicVersion1, 0), RC.ProtocolQUIC},
		"QUIC v2 Initial":          {quicInitial(quicVersion2, 1), RC.ProtocolQUIC},
		"QUIC draft-29 Initial":    {quicInitial(0xff00001d, 0), RC.ProtocolQUIC},
		"QUIC v1 Handshake":        {quicInitial(quicVersion1, 2), ""},
		"QUIC v2 type 0 (0-RTT)":   {quicInitial(quicVersion2, 0), ""},
		"short QUIC-like datagram": {quicInitial(quicVersion1, 0)[:600], ""},
		"unknown version":          {quicInitial(0x0a0a0a0a, 0), ""},
		"STUN binding request":     {stunBindingRequest(0), RC.ProtocolSTUN},
		"STUN with attributes":     {stunBindingRequest(8), RC.ProtocolSTUN},
		"STUN length off":          {append(stunBindingRequest(8), 0, 0, 0, 0), ""},
		"no magic cookie":          {append([]byte{0, 1, 0, 0}, make([]byte, 16)...), ""},
		"DNS query":                {[]byte{0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0}, ""},
		"empty":                    {nil, ""},
	} {
		if got := classifyDatagram(tc.datagram); got != tc.want {
			t.Errorf("%s: classified %q, want %q", name, got, tc.want)
		}
	}
}

func TestClassifyStreamStartKnowsAClientHelloAndAnHTTPRequest(t *testing.T) {
	for name, tc := range map[string]struct {
		start []byte
		want  string
	}{
		"TLS 1.0 record, ClientHello": {[]byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00}, RC.ProtocolHTTPS},
		"TLS record, ServerHello":     {[]byte{0x16, 0x03, 0x03, 0x00, 0x40, 0x02}, ""},
		"TLS alert":                   {[]byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02}, ""},
		"GET":                         {[]byte("GET / HTTP/1.1\r\n"), RC.ProtocolHTTP},
		"OPTIONS":                     {[]byte("OPTIONS * HTTP/1.1"), RC.ProtocolHTTP},
		"HTTP/2 preface":              {[]byte("PRI * HTTP/2.0\r\n"), RC.ProtocolHTTP},
		"GETX is no method":           {[]byte("GETX / HTTP/1.1"), ""},
		"SSH banner":                  {[]byte("SSH-2.0-OpenSSH"), ""},
		"short":                       {[]byte{0x16, 0x03}, ""},
	} {
		if got := classifyStreamStart(tc.start); got != tc.want {
			t.Errorf("%s: classified %q, want %q", name, got, tc.want)
		}
	}
}

func TestTCPProtocolProbeReadsTheFirstBytesAndLeavesThem(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	conn := N.NewBufferedConn(server)
	hello := []byte{0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0xaa, 0xbb, 0xcc, 0xdd}
	go func() { _, _ = client.Write(hello) }()
	var peek sync.Mutex
	if got := tcpProtocolProbe(conn, &peek, &C.Metadata{NetWork: C.TCP, DstPort: 443})(); got != RC.ProtocolHTTPS {
		t.Fatalf("probe read %q, want HTTPS", got)
	}
	got := make([]byte, len(hello))
	if _, err := conn.Read(got); err != nil || !bytes.Equal(got, hello) {
		t.Fatalf("after the probe the connection reads %x (%v), want the client's bytes %x", got, err, hello)
	}
}

func TestTCPProtocolProbeGivesUpOnASilentClient(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	var peek sync.Mutex
	start := time.Now()
	if got := tcpProtocolProbe(N.NewBufferedConn(server), &peek, &C.Metadata{NetWork: C.TCP, DstPort: 443})(); got != "" {
		t.Fatalf("a silent client was classified %q", got)
	}
	if waited := time.Since(start); waited < protocolProbeTimeout/2 || waited > 3*protocolProbeTimeout {
		t.Fatalf("waited %s for a silent client, want about %s", waited, protocolProbeTimeout)
	}
}

func protocolRules(t *testing.T, lines ...[2]string) []C.Rule {
	t.Helper()
	var rules []C.Rule
	for _, line := range lines {
		rule, err := R.ParseRule("PROTOCOL", line[0], line[1], nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		rules = append(rules, rule)
	}
	return rules
}

func TestAProtocolRuleReadsTheFlowOnceAndOnlyOnItsNetwork(t *testing.T) {
	withDoorTestTunnel(t, "DIRECT")
	UpdateProxiesAndRules(waitTestProxies("web", "tls", "quic", "stun", "tcp"), nil, protocolRules(t,
		[2]string{"STUN", "stun"}, [2]string{"QUIC", "quic"}, [2]string{"HTTP", "web"}, [2]string{"TLS", "tls"}, [2]string{"TCP", "tcp"},
	), nil, nil)
	for name, tc := range map[string]struct {
		network   C.NetWork
		read      string
		want      string
		wantReads int32
	}{
		"TLS over TCP":         {C.TCP, RC.ProtocolHTTPS, "tls", 1},
		"HTTP over TCP":        {C.TCP, RC.ProtocolHTTP, "web", 1},
		"other TCP":            {C.TCP, "", "tcp", 1},
		"QUIC over UDP":        {C.UDP, RC.ProtocolQUIC, "quic", 1},
		"STUN over UDP":        {C.UDP, RC.ProtocolSTUN, "stun", 1},
		"other UDP to DIRECT":  {C.UDP, "", "DIRECT", 1},
		"TCP reading QUIC yet": {C.TCP, RC.ProtocolQUIC, "tcp", 1},
	} {
		var reads atomic.Int32
		probe := func() string { reads.Add(1); return tc.read }
		metadata := &C.Metadata{NetWork: tc.network, Type: C.TUN, DstIP: testAddr("192.0.2.9"), DstPort: 443}
		proxy, _, err := resolveMetadataContext(withProtocolProbe(context.Background(), probe), metadata)
		if err != nil || proxy == nil || proxy.Name() != tc.want {
			t.Errorf("%s: matched %v (%v), want %s", name, proxy, err, tc.want)
		}
		if got := reads.Load(); got != tc.wantReads {
			t.Errorf("%s: the flow was read %d times, want %d", name, got, tc.wantReads)
		}
	}
}

func TestAProtocolRuleWithNothingToReadMatchesByNetworkOnly(t *testing.T) {
	withDoorTestTunnel(t, "DIRECT")
	UpdateProxiesAndRules(waitTestProxies("tls", "tcp"), nil, protocolRules(t, [2]string{"HTTPS", "tls"}, [2]string{"TCP", "tcp"}), nil, nil)
	if proxy, _, err := resolveMetadata(&C.Metadata{NetWork: C.TCP, Type: C.TUN, DstIP: testAddr("192.0.2.9"), DstPort: 443}); err != nil || proxy.Name() != "tcp" {
		t.Errorf("with no reader matched %v (%v), want tcp", proxy, err)
	}
	var reads atomic.Int32
	probe := func() string { reads.Add(1); return RC.ProtocolHTTPS }
	inner := &C.Metadata{NetWork: C.TCP, Type: C.INNER, DstIP: testAddr("192.0.2.9"), DstPort: 443}
	if proxy, _, err := resolveMetadataContext(withProtocolProbe(context.Background(), probe), inner); err != nil || proxy.Name() != "tcp" || reads.Load() != 0 {
		t.Errorf("the kernel's own flow matched %v (%v) after %d reads, want tcp and none", proxy, err, reads.Load())
	}
}

func TestProtocolMTProtoIsTheBuiltInServersConnections(t *testing.T) {
	withDoorTestTunnel(t, "DIRECT")
	UpdateProxiesAndRules(waitTestProxies("tg", "tls"), nil, protocolRules(t, [2]string{"HTTPS", "tls"}, [2]string{"MTProto", "tg"}), nil, nil)
	var reads atomic.Int32
	probe := func() string { reads.Add(1); return RC.ProtocolHTTPS }
	for typ, want := range map[C.Type]string{C.MTPROTO: "tg", C.TUN: "tls"} {
		metadata := &C.Metadata{NetWork: C.TCP, Type: typ, DstIP: testAddr("149.154.167.51"), DstPort: 443}
		if proxy, _, err := resolveMetadataContext(withProtocolProbe(context.Background(), probe), metadata); err != nil || proxy.Name() != want {
			t.Errorf("a %s connection matched %v (%v), want %s", typ, proxy, err, want)
		}
	}
	if reads.Load() != 1 {
		t.Errorf("read %d flows, want only the TUN one", reads.Load())
	}
}

func TestTheProtocolReaderDoesNotWaitOnAServerFirstPort(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	var peek sync.Mutex
	start := time.Now()
	if got := tcpProtocolProbe(N.NewBufferedConn(server), &peek, &C.Metadata{NetWork: C.TCP, DstPort: 22})(); got != "" {
		t.Fatalf("an SSH flow read as %q", got)
	}
	if waited := time.Since(start); waited > protocolProbeTimeout/4 {
		t.Fatalf("waited %s on port 22, where the server speaks first", waited)
	}
}

func TestTheProtocolReaderLeavesAHeldBackIPv6FlowUnanswered(t *testing.T) {
	withDoorTestTunnel(t, "DIRECT")
	held := newVerdictConn(true)
	defer held.Close()
	var peek sync.Mutex
	metadata := &C.Metadata{NetWork: C.TCP, Type: C.TUN, DstIP: testAddr("2001:db8::1"), DstPort: 443}
	if got := tcpProtocolProbe(N.NewBufferedConn(held), &peek, metadata)(); got != "" {
		t.Fatalf("read %q", got)
	}
	if !held.HandshakeDeferred() {
		t.Fatal("the reader answered the held-back handshake")
	}
}

func TestNoReaderIsInstalledBeforeAReadingRuleIsParsed(t *testing.T) {
	if _, err := R.ParseRule("PROTOCOL", "TCP", "DIRECT", nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := R.ParseRule("PROTOCOL", "STUN", "DIRECT", nil, nil); err != nil || !RC.ProtocolReadersParsed() {
		t.Fatalf("after PROTOCOL,STUN the readers are not in use (%v)", err)
	}
}

func TestAMatchAllocatesNothingForProtocolUntilAReadingRuleIsParsed(t *testing.T) {
	withDoorTestTunnel(t, "DIRECT")
	UpdateProxiesAndRules(waitTestProxies("p"), nil, []C.Rule{routingTestRule(t, "DOMAIN", "a.example", "p")}, nil, nil)
	previous := RC.SetProtocolReadersParsedForTest(false)
	t.Cleanup(func() { RC.SetProtocolReadersParsedForTest(previous) })
	flow := &C.Metadata{NetWork: C.TCP, Type: C.TUN, Host: "b.example", DstPort: 443}
	allocs := func() float64 {
		return testing.AllocsPerRun(200, func() { _, _, _ = resolveMetadataContext(context.Background(), flow) })
	}
	without := allocs()
	RC.SetProtocolReadersParsedForTest(true)
	with := allocs()
	if without >= with {
		t.Fatalf("a match makes %v allocations with no reading rule and %v with one, want fewer without", without, with)
	}
}
