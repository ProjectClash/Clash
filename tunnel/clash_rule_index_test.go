package tunnel

import (
	"bytes"
	"context"
	"fmt"
	"hash/fnv"
	"math/rand"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	C "github.com/ProjectClash/Clash/constant"
	R "github.com/ProjectClash/Clash/rules"
	"github.com/ProjectClash/Clash/rules/clashindex"
	RC "github.com/ProjectClash/Clash/rules/common"
	RW "github.com/ProjectClash/Clash/rules/wrapper"
)


type indexNoUDPProxy struct{ doorProxy }

func (indexNoUDPProxy) SupportUDP() bool { return false }

type indexRematchProxy struct {
	doorProxy
	subRule string
}

func (p indexRematchProxy) DialContext(_ context.Context, metadata *C.Metadata) (C.Conn, error) {
	metadata.SpecialRules = p.subRule
	return nil, nil
}

func ruleIndexTestProxies(t *testing.T) map[string]C.Proxy {
	t.Helper()
	rematch := indexRematchProxy{doorProxy{name: "R", typ: C.Rematch}, "s1"}
	hk := doorProxy{name: "HK", typ: C.Shadowsocks}
	return map[string]C.Proxy{
		"DIRECT": doorProxy{name: "DIRECT", typ: C.Direct},
		"REJECT": doorProxy{name: "REJECT", typ: C.Reject},
		"A":      indexNoUDPProxy{doorProxy{name: "A", typ: C.Shadowsocks}},
		"B":      hk,
		"G":      chainProxy{doorProxy{name: "G", typ: C.Selector}, hk},
		"PASSX":  chainProxy{doorProxy{name: "PASSX", typ: C.Selector}, doorProxy{name: "PASS", typ: C.Pass}},
		"R":      rematch,
	}
}

func installCountryDatabase(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	data, err := os.ReadFile(filepath.Join("..", "component", "mmdb", "testdata", "country-b.mmdb"))
	if err != nil {
		t.Skip("no test country database:", err)
	}
	if err := os.WriteFile(filepath.Join(home, "Country.mmdb"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	previous := C.Path.HomeDir()
	C.SetHomeDir(home)
	t.Cleanup(func() { C.SetHomeDir(previous) })
}

func ruleIndexTestLines(rnd *rand.Rand, n int) (lines, names, suffixes []string, prefixes []netip.Prefix) {
	targets := []string{"DIRECT", "REJECT", "A", "B", "G", "PASSX", "R"}
	target := func() string {
		if rnd.Intn(40) == 0 {
			return "R"
		}
		return targets[rnd.Intn(len(targets)-1)]
	}
	label := func() string {
		const letters = "abcdefghij0123"
		b := make([]byte, 1+rnd.Intn(4))
		for i := range b {
			b[i] = letters[rnd.Intn(len(letters))]
		}
		return string(b)
	}
	bases := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("1.0.0.0/8"), netip.MustParsePrefix("2001:db8::/32")}
	for len(lines) < n {
		switch r := rnd.Intn(100); {
		case r < 25:
			name := label() + "." + label() + ".com"
			names = append(names, name)
			lines = append(lines, "DOMAIN,"+name+","+target())
		case r < 50:
			name := label() + ".net"
			suffixes = append(suffixes, name)
			lines = append(lines, "DOMAIN-SUFFIX,"+name+","+target())
		case r < 55:
			lines = append(lines, "DOMAIN-KEYWORD,"+label()+","+target())
		case r < 78:
			base := bases[rnd.Intn(len(bases))]
			a := base.Addr().AsSlice()
			for i := base.Bits() / 8; i < len(a); i++ {
				a[i] = byte(rnd.Intn(3))
			}
			addr, _ := netip.AddrFromSlice(a)
			p := netip.PrefixFrom(addr, base.Bits()+rnd.Intn(addr.BitLen()-base.Bits()+1))
			prefixes = append(prefixes, p)
			line := "IP-CIDR," + p.String() + "," + target()
			if rnd.Intn(15) != 0 {
				line += ",no-resolve"
			}
			lines = append(lines, line)
		default:
			switch rnd.Intn(8) {
			case 0:
				lines = append(lines, "GEOIP,LAN,"+target()+[]string{"", ",no-resolve"}[rnd.Intn(2)])
			case 1:
				lines = append(lines, "GEOIP,CN,"+target()+",no-resolve")
			case 2:
				lines = append(lines, "SUB-RULE,(DST-PORT,443),s1")
			case 3:
				lines = append(lines, "NETWORK,udp,"+target())
			case 4:
				lines = append(lines, "DST-PORT,80,"+target())
			case 5:
				lines = append(lines, "AND,((DOMAIN-KEYWORD,"+label()[:1]+"),(IP-CIDR,10.0.0.0/9)),"+target())
			case 6:
				lines = append(lines, "PROCESS-NAME,proc1,"+target())
			case 7:
				lines = append(lines, "DOMAIN-REGEX,^a.*\\.net$,"+target())
			}
		}
	}
	return
}

type matchOutcome struct {
	proxy, rule, payload, special string
	dst                           netip.Addr
	err                           error
	dns, lookups                  int
}

func TestMatchOnARuleIndexIsMatchOnTheRules(t *testing.T) {
	installCountryDatabase(t)
	proxies := ruleIndexTestProxies(t)
	parse := func(line string, subRules map[string][]C.Rule) C.Rule {
		tp, payload, target, params := RC.ParseRulePayload(line, true)
		rule, err := R.ParseRule(tp, payload, target, params, subRules)
		if err != nil {
			t.Fatalf("%s: %v", line, err)
		}
		return rule
	}
	subRules := map[string][]C.Rule{}
	for _, line := range []string{"DOMAIN-SUFFIX,a.net,B", "IP-CIDR,10.1.0.0/16,PASSX", "GEOIP,LAN,G", "NETWORK,udp,A", "MATCH,REJECT"} {
		subRules["s1"] = append(subRules["s1"], parse(line, nil))
	}
	seen := map[string]int{}
	for _, seed := range []int64{1, 2, 3} {
		t.Run(strconv.FormatInt(seed, 10), func(t *testing.T) {
			rnd := rand.New(rand.NewSource(seed))
			lines, names, suffixes, prefixes := ruleIndexTestLines(rnd, 4000)
			if seed != 2 {
				lines = append(lines, "MATCH,G")
			}
			var list C.RuleList
			compiler := clashindex.NewCompiler()
			for _, line := range lines {
				rule := parse(line, subRules)
				list = append(list, RW.NewRuleWrapper(rule))
				if err := compiler.Add(line, rule); err != nil {
					t.Fatal(err)
				}
			}
			var buffer bytes.Buffer
			if _, _, err := compiler.Write(&buffer); err != nil {
				t.Fatal(err)
			}
			index, err := clashindex.Decode(buffer.Bytes())
			if err != nil {
				t.Fatal(err)
			}
			var others []C.Rule
			index.Others(func(_ int, line string) bool {
				others = append(others, RW.NewRuleWrapper(parse(line, subRules)))
				return true
			})
			table, err := index.Table(others)
			if err != nil {
				t.Fatal(err)
			}
			slice := &runtimeVersion{mode: Rule, proxies: proxies, rules: list, subRules: subRules}
			compiled := &runtimeVersion{mode: Rule, proxies: proxies, rules: table, subRules: subRules}

			outcome := func(version *runtimeVersion, m C.Metadata) matchOutcome {
				var o matchOutcome
				resolved, found := false, false
				helper := C.RuleMatchHelper{
					ResolveIP: func() {
						if !resolved && m.Host != "" && !m.Resolved() {
							resolved = true
							o.dns++
							f := fnv.New32a()
							f.Write([]byte(m.Host))
							h := f.Sum32()
							if h%4 != 0 && len(prefixes) > 0 {
								p := prefixes[int(h>>2)%len(prefixes)].Masked()
								a := p.Addr().AsSlice()
								if p.Bits() <= 8*len(a)-8 {
									a[len(a)-1] = byte(h)
								}
								m.DstIP, _ = netip.AddrFromSlice(a)
							}
						}
					},
					FindProcess: func() {
						if !found {
							found = true
							o.lookups++
							m.Process = "proc" + strconv.Itoa(len(m.Host)%3)
						}
					},
				}
				proxy, rule, err := match(&m, helper, version)
				if proxy != nil {
					o.proxy = proxy.Name()
				}
				if rule != nil {
					o.rule, o.payload = rule.RuleType().String(), rule.Payload()
				}
				o.err, o.dst, o.special = err, m.DstIP, m.SpecialRules
				return o
			}

			for q := 0; q < 20000; q++ {
				m := C.Metadata{NetWork: C.TCP, DstPort: uint16([]int{443, 80, 8080}[rnd.Intn(3)])}
				if rnd.Intn(3) == 0 {
					m.NetWork = C.UDP
				}
				switch rnd.Intn(6) {
				case 0:
					m.Host = names[rnd.Intn(len(names))]
				case 1:
					m.Host = "x." + suffixes[rnd.Intn(len(suffixes))]
				case 2:
					m.Host = "a" + strings.Repeat("b", rnd.Intn(3)) + ".net"
				case 3:
					m.Host = "zz" + strconv.Itoa(rnd.Intn(1000)) + ".org"
				case 4:
					p := prefixes[rnd.Intn(len(prefixes))].Masked()
					m.DstIP = p.Addr()
				case 5:
					m.Host = names[rnd.Intn(len(names))]
					m.DstIP = prefixes[rnd.Intn(len(prefixes))].Masked().Addr()
				}
				want, got := outcome(slice, m), outcome(compiled, m)
				if fmt.Sprint(want) != fmt.Sprint(got) {
					t.Fatalf("query %d %+v:\nslice    %+v\ncompiled %+v", q, m, want, got)
				}
				seen["rule "+want.rule]++
				if want.special != "" {
					seen["rematched"]++
				}
				if want.dns > 0 {
					seen["resolved"]++
				}
				if want.lookups > 0 {
					seen["process"]++
				}
			}
		})
	}
	for _, path := range []string{"rule DomainSuffix", "rule Domain", "rule DomainKeyword", "rule IPCIDR", "rule GeoIP", "rule SubRules", "rule Match", "rematched", "resolved", "process"} {
		if seen[path] == 0 {
			t.Errorf("no flow took the path %q: %v", path, seen)
		}
	}
}
