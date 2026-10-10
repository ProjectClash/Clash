package clash

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/common/orderedmap"
	"github.com/ProjectClash/Clash/config"
)

func policyTableOf(entries map[string]any) *orderedmap.OrderedMap[string, any] {
	table := orderedmap.New[string, any]()
	for key, value := range entries {
		table.Set(key, value)
	}
	return table
}

func TestLoopbackResolverEntriesAreJudgedByHostAndByTheListener(t *testing.T) {
	cases := []struct {
		entry  string
		listen string
		strip  bool
		why    string
	}{
		{"udp://127.0.0.1:7874", "", true, "the reported shape: udp to a loopback port nobody listens on"},
		{"127.0.0.1:7874", "", true, "bare host:port"},
		{"127.0.0.1", "", true, "bare host, port 53 by default"},
		{"127.0.0.1:7874", "0.0.0.0:7874", false, "dns.listen on the same port, on every address"},
		{"udp://127.0.0.1:7874", ":7874", false, "dns.listen with no host is every address"},
		{"tcp://127.0.0.1:7874", "127.0.0.1:7874", false, "dns.listen on loopback itself"},
		{"udp://127.0.0.1:7874", "[::]:7874", false, "dns.listen on the v6 wildcard"},
		{"udp://127.0.0.1:7874", "0.0.0.0:53", true, "dns.listen on another port"},
		{"udp://127.0.0.1:7874", "198.18.0.2:7874", true, "dns.listen on an address that is not this device's loopback"},
		{"udp://127.0.0.1#DIRECT", "", true, "a fragment is stripped before the host is read"},
		{"udp://127.0.0.1:7874#h3=true&ecs=1.1.1.1", "0.0.0.0:7874", false, "fragment with params, listener present"},
		{"[::1]:7874", "", true, "bracketed v6 loopback"},
		{"::1", "", true, "bare v6 loopback, no brackets"},
		{"udp://[::1]:7874", "[::1]:7874", false, "v6 loopback with its listener"},
		{"::ffff:127.0.0.1", "", true, "v4-mapped loopback"},
		{"localhost:7874", "", true, "the name localhost"},
		{"udp://localhost:7874", "0.0.0.0:7874", false, "localhost with the listener"},
		{"0.0.0.0:53", "", true, "the unspecified address is this device too"},
		{"udp://[::]:53", "", true, "v6 unspecified"},
		{"::ffff:0.0.0.0", "", true, "v4-mapped unspecified"},
		{"tls://127.0.0.1:853", "0.0.0.0:853", true, "dns.listen answers plain UDP/TCP only: tls to loopback is always dead"},
		{"quic://[::1]:853", "[::]:853", true, "quic likewise"},
		{"https://127.0.0.1/dns-query", "0.0.0.0:443", true, "https likewise"},
		{"http://localhost:8053/dns-query", "0.0.0.0:8053", true, "http likewise"},
		{"tls://127.0.0.1", "", true, "tls with its default port 853"},
		{"223.5.5.5", "", false, "a public resolver is not this device"},
		{"udp://10.0.0.1:53", "", false, "a LAN resolver is reachable from the tunnel"},
		{"https://dns.alidns.com/dns-query", "", false, "a named resolver"},
		{"tls://1.1.1.1", "", false, "a public DoT resolver"},
		{"system", "", false, "system is another rule's business"},
		{"dhcp://en0", "", false, "dhcp likewise"},
		{"rcode://name_error", "", false, "an rcode entry has no host"},
		{"127.0.0.1:7874", "0.0.0.0:7874", false, "listener covers even when dns.enable is false: the packet tunnel forces it on"},
	}
	for _, tc := range cases {
		t.Run(tc.entry+" listen="+tc.listen, func(t *testing.T) {
			raw := config.DefaultRawConfig()
			raw.DNS.Listen = tc.listen
			raw.DNS.NameServer = []string{"223.5.5.5", tc.entry}
			stripped := stripLoopbackResolvers(raw)
			if got := len(stripped) == 1; got != tc.strip {
				t.Fatalf("%s: stripped=%v want %v (%v)", tc.why, got, tc.strip, stripped)
			}
			if tc.strip {
				if !strings.HasPrefix(stripped[0], "nameserver "+tc.entry+" (loopback, no dns.listen on port ") {
					t.Fatalf("the stripped line names the field, the entry as written and the port: %q", stripped[0])
				}
				if !reflect.DeepEqual(raw.DNS.NameServer, []string{"223.5.5.5"}) {
					t.Fatalf("the entry must be gone and its neighbour kept: %v", raw.DNS.NameServer)
				}
			} else if !reflect.DeepEqual(raw.DNS.NameServer, []string{"223.5.5.5", tc.entry}) {
				t.Fatalf("an entry that is kept is kept as written: %v", raw.DNS.NameServer)
			}
		})
	}
}

func TestLoopbackResolversAreStrippedFromEveryListAndPolicy(t *testing.T) {
	raw := config.DefaultRawConfig()
	raw.DNS.NameServer = []string{"127.0.0.1:5353", "223.5.5.5"}
	raw.DNS.Fallback = []string{"8.8.8.8", "udp://[::1]:5353"}
	raw.DNS.ProxyServerNameserver = []string{"udp://127.0.0.1:7874"}
	raw.DNS.DirectNameServer = []string{"localhost"}
	raw.DNS.DefaultNameserver = []string{"127.0.0.1:5353", "223.5.5.5"}
	raw.DNS.NameServerPolicy = policyTableOf(map[string]any{"+.lan": "127.0.0.1:5353", "+.corp": []any{"127.0.0.1:5353", "10.0.0.53"}})
	raw.DNS.ProxyServerNameserverPolicy = policyTableOf(map[string]any{"+.example": []any{"udp://127.0.0.1:7874"}})

	stripped := stripLoopbackResolvers(raw)

	if len(stripped) != 8 {
		t.Fatalf("eight entries strip (five lists, three policy resolvers), got %d: %v", len(stripped), stripped)
	}
	if !reflect.DeepEqual(raw.DNS.NameServer, []string{"223.5.5.5"}) || !reflect.DeepEqual(raw.DNS.Fallback, []string{"8.8.8.8"}) ||
		len(raw.DNS.ProxyServerNameserver) != 0 || len(raw.DNS.DirectNameServer) != 0 || !reflect.DeepEqual(raw.DNS.DefaultNameserver, []string{"223.5.5.5"}) {
		t.Fatalf("lists after the strip: ns=%v fb=%v psn=%v dn=%v dfl=%v", raw.DNS.NameServer, raw.DNS.Fallback, raw.DNS.ProxyServerNameserver, raw.DNS.DirectNameServer, raw.DNS.DefaultNameserver)
	}
	if v, _ := raw.DNS.NameServerPolicy.Get("+.lan"); !reflect.DeepEqual(v, []any{"rcode://name_error"}) {
		t.Fatalf("a policy whose only resolver strips fails closed, got %v", v)
	}
	if v, _ := raw.DNS.NameServerPolicy.Get("+.corp"); !reflect.DeepEqual(v, []any{"10.0.0.53"}) {
		t.Fatalf("a policy keeps its reachable resolvers, got %v", v)
	}
	if v, _ := raw.DNS.ProxyServerNameserverPolicy.Get("+.example"); !reflect.DeepEqual(v, []any{"rcode://name_error"}) {
		t.Fatalf("proxy-server-nameserver-policy likewise, got %v", v)
	}
}

func TestABootstrapOfOnlyLoopbackEntriesIsEmptiedForTheRepairToRefill(t *testing.T) {
	raw := config.DefaultRawConfig()
	raw.DNS.Enable = true
	raw.DNS.NameServer = []string{"223.5.5.5"}
	raw.DNS.DefaultNameserver = []string{"127.0.0.1:5353"}
	normalizeRawConfigForIOS(raw, true)
	if len(raw.DNS.DefaultNameserver) == 0 || raw.DNS.DefaultNameserver[0] == "127.0.0.1:5353" {
		t.Fatalf("the repair refills the bootstrap with core defaults, got %v", raw.DNS.DefaultNameserver)
	}
}

func TestLoopbackResolversAreLeftAloneOnMacOS(t *testing.T) {
	for _, profile := range []runtimeProfile{runtimeProfileMacOSPacketTunnel, runtimeProfileMacOSApplication} {
		raw := config.DefaultRawConfig()
		raw.DNS.Enable = true
		raw.DNS.NameServer = []string{"223.5.5.5"}
		raw.DNS.ProxyServerNameserver = []string{"udp://127.0.0.1:7874"}
		normalizeRawConfigForApple(raw, runtimePolicyFor(profile, true))
		if !reflect.DeepEqual(raw.DNS.ProxyServerNameserver, []string{"udp://127.0.0.1:7874"}) {
			t.Fatalf("%v: macOS must not strip a loopback resolver, got %v", profile, raw.DNS.ProxyServerNameserver)
		}
	}
	for _, profile := range []runtimeProfile{runtimeProfileIOSPacketTunnel, runtimeProfileTVOSPacketTunnel} {
		raw := config.DefaultRawConfig()
		raw.DNS.Enable = true
		raw.DNS.NameServer = []string{"223.5.5.5"}
		raw.DNS.ProxyServerNameserver = []string{"udp://127.0.0.1:7874"}
		normalizeRawConfigForApple(raw, runtimePolicyFor(profile, true))
		if len(raw.DNS.ProxyServerNameserver) != 0 {
			t.Fatalf("%v: a packet tunnel strips it, got %v", profile, raw.DNS.ProxyServerNameserver)
		}
	}
}

func TestPlanReportsEachLoopbackResolverItWillStrip(t *testing.T) {
	r := planOf(t, `
tun:
  enable: true
dns:
  enable: true
  listen: 0.0.0.0:5353
  nameserver: ['223.5.5.5', '127.0.0.1:5353']
  proxy-server-nameserver: ['udp://127.0.0.1:7874']
  nameserver-policy:
    '+.lan': ['udp://[::1]:7874']
`)
	mustNotRefuse(t, r, "a configuration with a dead loopback resolver still starts")
	if got, want := noticeFieldsOfKind(r, planNoticeDNSLoopbackResolverStripped), []string{"dns.nameserver-policy", "dns.proxy-server-nameserver"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("notices on %v, want %v (127.0.0.1:5353 has its listener and is not reported)", got, want)
	}
	for _, n := range r.StructuredNotices {
		if n.Kind != planNoticeDNSLoopbackResolverStripped {
			continue
		}
		for _, want := range []string{"port 7874", "dns.listen", "this device"} {
			if !strings.Contains(n.Text, want) {
				t.Fatalf("the notice must say %q: %q", want, n.Text)
			}
		}
	}
}
