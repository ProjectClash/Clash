package outbound

import (
	"fmt"
	"io"
	"net/netip"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/constant/features"
)

func clashTestIPStackModes() []string {
	modes := []string{ipStackAuto, ipStackMips}
	if features.WithGVisor {
		modes = append(modes, ipStackGVisor)
	}
	return modes
}

func clashStackError(t *testing.T, mode string, prefixes []netip.Prefix, mtu uint32) string {
	t.Helper()
	option := IPStackOption{Mode: mode}
	option.normalize()
	stack, err := newIPStack(option, prefixes, mtu)
	if err != nil {
		return err.Error()
	}
	_ = stack.Close()
	return ""
}

var clashStackPrefixes = []string{
	"10.0.0.2/32", "10.0.0.2/24", "10.0.0.255/24", "10.0.0.0/24", "10.0.0.1/31", "10.0.0.1/30",
	"10.0.0.3/30", "255.255.255.255/32", "0.0.0.0/32", "224.0.0.1/32", "127.0.0.1/8",
	"fd00::2/128", "fd00::2/64", "::/128", "ff02::1/128", "::ffff:10.0.0.2/128",
	"::ffff:10.0.0.255/120", "::ffff:10.0.0.2/96",
}

func TestEveryStackRefusalIsFlaggedAtParse(t *testing.T) {
	var refused, flaggedOnly int
	check := func(prefixes []netip.Prefix, mtu uint32) {
		flagged := clashIPStackMayRefuse(prefixes, mtu)
		failedSomewhere := false
		for _, mode := range clashTestIPStackModes() {
			if message := clashStackError(t, mode, prefixes, mtu); message != "" {
				failedSomewhere = true
				refused++
				if !flagged {
					t.Errorf("mode %s refuses %v at MTU %d (%s), and the parser would not see it", mode, prefixes, mtu, message)
				}
			}
		}
		if flagged && !failedSomewhere {
			flaggedOnly++
		}
	}
	for i, first := range clashStackPrefixes {
		check([]netip.Prefix{netip.MustParsePrefix(first)}, 1408)
		for _, second := range clashStackPrefixes[i:] {
			check([]netip.Prefix{netip.MustParsePrefix(first), netip.MustParsePrefix(second)}, 1408)
		}
	}
	for _, mtu := range []uint32{0, 20, 67, 68, 1280, 1408, 65535, 65536, ^uint32(0)} {
		check([]netip.Prefix{netip.MustParsePrefix("10.0.0.2/32")}, mtu)
	}
	check([]netip.Prefix{netip.MustParsePrefix("10.0.0.1/24"), netip.MustParsePrefix("::ffff:10.0.0.255/128")}, 1408)
	check([]netip.Prefix{netip.MustParsePrefix("::ffff:10.0.0.255/128"), netip.MustParsePrefix("10.0.0.1/24")}, 1408)
	if refused == 0 {
		t.Fatal("no setting was refused by any stack; the table no longer exercises the refusals")
	}
	t.Logf("%d refusals, all flagged; %d settings flagged that every stack builds (built at parse, as before)", refused, flaggedOnly)
}

func TestOrdinaryStackSettingsAreNotFlagged(t *testing.T) {
	for _, prefixes := range [][]string{
		{"10.0.0.2/32"}, {"172.16.0.2/32", "fd01:5ca1:ab1e::2/128"}, {"10.8.0.5/24"}, {"fd00::2/64"},
	} {
		var parsed []netip.Prefix
		for _, prefix := range prefixes {
			parsed = append(parsed, netip.MustParsePrefix(prefix))
		}
		for _, mtu := range []uint32{0, 1280, 1408, 1420} {
			if clashIPStackMayRefuse(parsed, mtu) {
				t.Errorf("%v at MTU %d is flagged; such a node would build its stack at parse", parsed, mtu)
			}
		}
	}
}

func TestStackRefusalsStayParseErrors(t *testing.T) {
	cases := []struct {
		ip, ipv6 string
		mtu      int
	}{
		{"10.0.0.2/32", "", 20},
		{"10.0.0.2/32", "", 70000},
		{"10.0.0.255/24", "", 0},
		{"0.0.0.0/32", "", 0},
		{"224.0.0.1/32", "", 0},
		{"10.0.0.2/32", "10.0.0.2/24", 0},
		{"fd00::2/128", "fd00::2/64", 0},
		{"10.0.0.2/32", "fd00::2/128", 0},
	}
	masqueOption := clashMasqueOption(t)
	for _, tc := range cases {
		for _, mode := range clashTestIPStackModes() {
			name := fmt.Sprintf("%s %s mtu %d %s", tc.ip, tc.ipv6, tc.mtu, mode)
			t.Run(name, func(t *testing.T) {
				var prefixes []netip.Prefix
				for _, address := range []string{tc.ip, tc.ipv6} {
					if address != "" {
						prefixes = append(prefixes, netip.MustParsePrefix(address))
					}
				}

				wireGuard := clashWireGuardOption()
				wireGuard.Ip, wireGuard.Ipv6, wireGuard.MTU, wireGuard.IPStack.Mode = tc.ip, tc.ipv6, tc.mtu, mode
				wireGuardMTU := uint32(tc.mtu)
				if tc.mtu == 0 {
					wireGuardMTU = 1408
				}
				clashRequireParseOutcome(t, "wireguard", "create WireGuard stack: ", clashStackError(t, mode, prefixes, wireGuardMTU), func() (io.Closer, error) {
					return NewWireGuard(wireGuard)
				})

				masque := masqueOption
				masque.Ip, masque.Ipv6, masque.MTU, masque.IPStack.Mode = tc.ip, tc.ipv6, tc.mtu, mode
				masqueMTU := uint32(tc.mtu)
				if tc.mtu == 0 {
					masqueMTU = 1280
				}
				clashRequireParseOutcome(t, "masque", "create device: ", clashStackError(t, mode, prefixes, masqueMTU), func() (io.Closer, error) {
					return NewMasque(masque)
				})
			})
		}
	}
}

func clashRequireParseOutcome(t *testing.T, protocol string, prefix string, stackError string, parse func() (io.Closer, error)) {
	t.Helper()
	node, err := parse()
	if stackError == "" {
		if err != nil {
			t.Errorf("%s: the stack builds these settings, and parse refused them: %v", protocol, err)
			return
		}
		_ = node.Close()
		return
	}
	if err == nil {
		_ = node.Close()
		t.Errorf("%s: upstream refuses these settings at parse (%s), and parse accepted them", protocol, stackError)
		return
	}
	if want := prefix + stackError; err.Error() != want && !strings.HasSuffix(err.Error(), want) {
		t.Errorf("%s: parse refused with %q, upstream with %q", protocol, err.Error(), want)
	}
}
