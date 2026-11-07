package sniffer

import (
	"net/netip"
	"testing"

	"github.com/ProjectClash/Clash/common/utils"
	C "github.com/ProjectClash/Clash/constant"
	CS "github.com/ProjectClash/Clash/constant/sniffer"
)

type exactDomain string

func (d exactDomain) MatchDomain(domain string) bool { return string(d) == domain }

type exactIP netip.Addr

func (a exactIP) MatchIp(ip netip.Addr) bool { return netip.Addr(a) == ip }

func TestReadsPastDnsMappingIsForceDnsMappingAlone(t *testing.T) {
	ports, err := utils.NewUnsignedRanges[uint16]("443")
	if err != nil {
		t.Fatal(err)
	}
	mapped := func() *C.Metadata {
		return &C.Metadata{NetWork: C.TCP, Host: "pay.example.com", DNSMode: C.DNSMapping,
			DstIP: netip.MustParseAddr("2001:db8::10"), DstPort: 443, SrcIP: netip.MustParseAddr("fd00::2")}
	}
	dispatcher := func(config Config) *Dispatcher {
		config.Enable = true
		config.Sniffers = map[CS.Type]SnifferConfig{CS.TLS: {Ports: ports}}
		d, err := NewDispatcher(&config)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	on := Config{ForceDnsMapping: true}
	for _, tc := range []struct {
		name     string
		config   Config
		metadata func(*C.Metadata)
		want     bool
	}{
		{"force-dns-mapping on", on, nil, true},
		{"force-dns-mapping off", Config{}, nil, false},
		{"force-domain names it", Config{ForceDnsMapping: true, ForceDomain: []C.DomainMatcher{exactDomain("pay.example.com")}}, nil, false},
		{"skip-dst-address excludes it", Config{ForceDnsMapping: true, SkipDstAddress: []C.IpMatcher{exactIP(netip.MustParseAddr("2001:db8::10"))}}, nil, false},
		{"no sniffer takes its port", on, func(m *C.Metadata) { m.DstPort = 22 }, false},
		{"a bare address", on, func(m *C.Metadata) { m.Host = "" }, false},
		{"a fake-ip name", on, func(m *C.Metadata) { m.DNSMode = C.DNSFakeIP }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			metadata := mapped()
			if tc.metadata != nil {
				tc.metadata(metadata)
			}
			if got := dispatcher(tc.config).ReadsPastDnsMapping(metadata); got != tc.want {
				t.Fatalf("ReadsPastDnsMapping = %v, want %v", got, tc.want)
			}
		})
	}
	d := dispatcher(on)
	metadata := mapped()
	for i := 0; i < 6; i++ {
		d.cacheSniffFailed(metadata)
	}
	if d.ReadsPastDnsMapping(metadata) {
		t.Fatal("ReadsPastDnsMapping is true for a destination TCPSniff skips for its failed reads")
	}
	if (*Dispatcher)(nil).ReadsPastDnsMapping(mapped()) {
		t.Fatal("no sniffer reads past a DNS mapping")
	}
}
