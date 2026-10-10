//go:build darwin

package clash

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/dns"

	D "github.com/miekg/dns"
)

func TestMDNSHeaderFraming(t *testing.T) {
	header := appendMDNSHeader(nil, mdnsOpQuery, 42, 7, mdnsIPCFlagNoErrorSocket)
	if len(header) != mdnsHeaderLength {
		t.Fatalf("header is %d bytes, the protocol says %d", len(header), mdnsHeaderLength)
	}
	for _, field := range []struct {
		name string
		at   int
		want uint32
	}{
		{"version", 0, mdnsVersion},
		{"data length", 4, 42},
		{"ipc flags", 8, mdnsIPCFlagNoErrorSocket},
		{"operation", 12, mdnsOpQuery},
		{"reg_index", 24, 0},
	} {
		got := uint32(header[field.at])<<24 | uint32(header[field.at+1])<<16 |
			uint32(header[field.at+2])<<8 | uint32(header[field.at+3])
		if got != field.want {
			t.Fatalf("%s = %d, want %d", field.name, got, field.want)
		}
	}
	if header[23] != 7 {
		t.Fatalf("client context low byte = %d, want 7", header[23])
	}
}

func TestMDNSQueryPayload(t *testing.T) {
	query := buildMDNSQuery("nas.local.", D.TypeA, D.ClassINET)
	payload := query[mdnsHeaderLength:]
	flags := uint32(payload[0])<<24 | uint32(payload[1])<<16 | uint32(payload[2])<<8 | uint32(payload[3])
	for name, flag := range map[string]uint32{
		"share connection":     mdnsFlagShareConnection,
		"return intermediates": mdnsFlagReturnIntermediates,
		"timeout":              mdnsFlagTimeout,
	} {
		if flags&flag == 0 {
			t.Fatalf("the %s flag must be set", name)
		}
	}
	name := string(payload[8 : 8+len("nas.local.")])
	if name != "nas.local." {
		t.Fatalf("name on the wire = %q", name)
	}
	if payload[8+len("nas.local.")] != 0 {
		t.Fatal("the name must be NUL terminated")
	}
}

func TestMDNSReplyParserRefusesTruncation(t *testing.T) {
	if _, err := parseMDNSReply([]byte{0, 0, 0}); err == nil {
		t.Fatal("a reply shorter than its first field must be refused")
	}
	if _, err := parseMDNSReply(nil); err == nil {
		t.Fatal("an empty reply must be refused")
	}
}

func TestMDNSRecordIsBuiltFromRawData(t *testing.T) {
	record, err := buildMDNSRecord(mdnsReply{
		name:    "nas.local",
		rrtype:  D.TypeA,
		rrclass: D.ClassINET,
		ttl:     120,
		rdata:   []byte{192, 168, 1, 42},
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	a, ok := record.(*D.A)
	if !ok {
		t.Fatalf("record is %T, want *dns.A", record)
	}
	if a.A.String() != "192.168.1.42" || a.Hdr.Name != "nas.local." || a.Hdr.Ttl != 120 {
		t.Fatalf("record = %v", a)
	}
}

func TestMDNSNoSuchRecordIsNotNameError(t *testing.T) {
	if !errors.Is(mdnsError("nas.local.", mdnsErrNoSuchRecord), errMDNSNoSuchRecord) {
		t.Fatal("no-such-record must be distinguishable, so it can answer empty NOERROR")
	}
	if errors.Is(mdnsError("nas.local.", mdnsErrNoSuchName), errMDNSNoSuchRecord) {
		t.Fatal("no-such-name is a different answer from no-such-record")
	}
}

func TestMDNSFailsFastAgainstAnUnresponsiveSocket(t *testing.T) {
	file, err := os.CreateTemp("/tmp", "clash-mdns-*.sock")
	if err != nil {
		t.Skipf("no temp path available: %v", err)
	}
	path := file.Name()
	file.Close()
	_ = os.Remove(path)
	t.Cleanup(func() { _ = os.Remove(path) })
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Skipf("no unix socket available: %v", err)
	}
	defer listener.Close()
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		<-time.After(30 * time.Second)
		conn.Close()
	}()
	t.Setenv(mdnsSocketEnv, path)

	m := new(D.Msg)
	m.SetQuestion("nas.local.", D.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := exchangeMulticastDNS(ctx, m); err == nil {
		t.Fatal("a daemon that never answers must produce an error")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the query hung for %v instead of honouring its context", elapsed)
	}
}

func TestMDNSResolvesThisMachineThroughTheDaemon(t *testing.T) {
	if _, err := os.Stat(mdnsSocketPath); err != nil {
		t.Skipf("no mDNSResponder socket on this host: %v", err)
	}
	hostname, err := os.Hostname()
	if err != nil {
		t.Skipf("hostname: %v", err)
	}
	if !strings.HasSuffix(hostname, ".local") {
		hostname = strings.TrimSuffix(hostname, ".") + ".local"
	}

	m := new(D.Msg)
	m.SetQuestion(D.Fqdn(hostname), D.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	reply, err := exchangeMulticastDNS(ctx, m)
	if err != nil {
		t.Skipf("this host did not answer for %s through the daemon: %v", hostname, err)
	}
	if reply == nil {
		t.Fatal("a successful exchange must return a message")
	}
	var addresses []string
	for _, answer := range reply.Answer {
		if a, ok := answer.(*D.A); ok {
			addresses = append(addresses, a.A.String())
		}
	}
	if len(addresses) == 0 {
		t.Skipf("no A record for %s; answers = %v", hostname, reply.Answer)
	}
	t.Logf("mDNSResponder resolved %s to %v", hostname, addresses)
}

func TestInstallLocalZoneResolverPublishesAndClears(t *testing.T) {
	t.Cleanup(func() { dns.SetLocalZoneExchanger(nil) })
	installLocalZoneResolver(true)
	if !dns.IsLocalZone("nas.local.") {
		t.Fatal("precondition: .local is a multicast-DNS zone")
	}
	installLocalZoneResolver(false)
}

func TestMDNSDeadlineIsReportedAsATimeout(t *testing.T) {
	if _, err := os.Stat(mdnsSocketPath); err != nil {
		t.Skipf("no mDNSResponder socket on this host: %v", err)
	}
	m := new(D.Msg)
	m.SetQuestion("clash-nothere-8f3a.local.", D.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), 900*time.Millisecond)
	defer cancel()

	_, err := exchangeMulticastDNS(ctx, m)
	if err == nil {
		t.Skip("this link answered for a name that should not exist")
	}
	message := err.Error()
	if strings.Contains(message, "use of closed network connection") {
		t.Fatalf("our own deadline must not be reported as a broken connection: %q", message)
	}
	if !strings.Contains(message, "timeout") {
		t.Fatalf("a query that ran out of time must say so: %q", message)
	}
}

func TestMDNSConcurrencyCapRefusesWithoutDialing(t *testing.T) {
	file, err := os.CreateTemp("/tmp", "clash-mdns-cap-*.sock")
	if err != nil {
		t.Skipf("no temp path available: %v", err)
	}
	path := file.Name()
	file.Close()
	_ = os.Remove(path)
	t.Setenv(mdnsSocketEnv, path)

	held := 0
	defer func() {
		for ; held > 0; held-- {
			<-mdnsConcurrency
		}
	}()
	for held < cap(mdnsConcurrency) {
		select {
		case mdnsConcurrency <- struct{}{}:
			held++
		default:
			t.Fatalf("could not fill the cap: held %d of %d", held, cap(mdnsConcurrency))
		}
	}

	m := new(D.Msg)
	m.SetQuestion("nas.local.", D.TypeA)
	start := time.Now()
	_, err = exchangeMulticastDNS(context.Background(), m)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("a query past the cap must be refused")
	}
	if !strings.Contains(err.Error(), "too many queries in flight") {
		t.Fatalf("the refusal must say why: %q", err)
	}
	if elapsed > time.Second {
		t.Fatalf("the refusal took %v; it must not dial or wait", elapsed)
	}

	<-mdnsConcurrency
	held--
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	if _, err := exchangeMulticastDNS(ctx, m); err == nil {
		t.Fatal("the socket does not exist, so this must fail for a different reason")
	} else if strings.Contains(err.Error(), "too many queries in flight") {
		t.Fatalf("a freed slot must admit the next query, got %q", err)
	}
}
