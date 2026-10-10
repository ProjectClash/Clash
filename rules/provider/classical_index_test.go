package provider_test

import (
	"fmt"
	"math/rand"
	"net/netip"
	"testing"

	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	"github.com/ProjectClash/Clash/rules"
	"github.com/ProjectClash/Clash/rules/common"
	RP "github.com/ProjectClash/Clash/rules/provider"
)


type classicalMatcher interface {
	Insert(string)
	FinishInsert()
	Match(*C.Metadata, C.RuleMatchHelper) bool
	Count() int
}

func loadClassical(lines []string, index bool) classicalMatcher {
	if !index {
		return loadUpstreamClassical(lines)
	}
	s := RP.NewClassicalStrategy(rules.ParseRule)
	for _, line := range lines {
		s.Insert(line)
	}
	s.FinishInsert()
	return s
}

func loadUnbuilt(lines []string) classicalMatcher {
	s := RP.NewClassicalStrategy(rules.ParseRule)
	for _, line := range lines {
		s.Insert(line)
	}
	return s
}

type upstreamClassical struct{ rules []C.Rule }

func loadUpstreamClassical(lines []string) *upstreamClassical {
	u := &upstreamClassical{}
	for _, line := range lines {
		u.Insert(line)
	}
	return u
}

func (u *upstreamClassical) Insert(line string) {
	tp, payload, target, params := common.ParseRulePayload(line, false)
	switch tp {
	case "MATCH", "RULE-SET", "SUB-RULE":
		return
	}
	if rule, err := rules.ParseRule(tp, payload, target, params, nil); err == nil {
		u.rules = append(u.rules, rule)
	}
}

func (u *upstreamClassical) FinishInsert() {}

func (u *upstreamClassical) Match(metadata *C.Metadata, helper C.RuleMatchHelper) bool {
	for _, rule := range u.rules {
		if matched, _ := rule.Match(metadata, helper); matched {
			return true
		}
	}
	return false
}

func (u *upstreamClassical) Count() int { return len(u.rules) }

type resolver struct {
	table   map[string]netip.Addr
	calls   int
	lookups int
}

func (r *resolver) helper(m *C.Metadata) C.RuleMatchHelper {
	return C.RuleMatchHelper{
		ResolveIP: func() {
			r.calls++
			if !m.DstIP.IsValid() {
				if ip, ok := r.table[m.Host]; ok {
					m.DstIP = ip
				}
			}
		},
		FindProcess: func() { r.lookups++ },
	}
}

func randomClassicalCorpus(rng *rand.Rand, n int) (lines []string, hosts []string, ips []netip.Addr) {
	labels := []string{"a", "b", "cdn", "example", "google", "apple", "中文", "x-y", "com", "net", "cn", "io"}
	host := func() string {
		parts := 1 + rng.Intn(4)
		h := labels[rng.Intn(len(labels))]
		for i := 1; i < parts; i++ {
			h = labels[rng.Intn(len(labels))] + "." + h
		}
		return h
	}
	v4 := func() netip.Addr {
		return netip.AddrFrom4([4]byte{byte(10 + rng.Intn(3)), byte(rng.Intn(4)), byte(rng.Intn(4)), byte(rng.Intn(256))})
	}
	v6 := func() netip.Addr {
		var b [16]byte
		b[0], b[1], b[2] = 0x20, 0x01, byte(rng.Intn(4))
		b[15] = byte(rng.Intn(256))
		return netip.AddrFrom16(b)
	}
	sub := func() string {
		switch rng.Intn(4) {
		case 0:
			return "(DOMAIN," + host() + ")"
		case 1:
			return "(DOMAIN-SUFFIX," + host() + ")"
		case 2:
			return "(PROCESS-NAME,Telegram)"
		default:
			return fmt.Sprintf("(DST-PORT,%d)", 440+rng.Intn(8))
		}
	}
	for i := 0; i < n; i++ {
		switch rng.Intn(13) {
		case 0, 1, 2:
			lines = append(lines, "DOMAIN,"+host())
		case 3, 4, 5:
			lines = append(lines, "DOMAIN-SUFFIX,"+host())
		case 6:
			lines = append(lines, "DOMAIN-KEYWORD,"+labels[rng.Intn(len(labels))])
		case 7:
			p, _ := v4().Prefix(16 + rng.Intn(17))
			lines = append(lines, "IP-CIDR,"+p.String()+",no-resolve")
		case 8:
			p, _ := v4().Prefix(16 + rng.Intn(17))
			lines = append(lines, "IP-CIDR,"+p.String())
		case 9:
			p, _ := v6().Prefix(24 + rng.Intn(105))
			if rng.Intn(2) == 0 {
				lines = append(lines, "IP-CIDR6,"+p.String()+",no-resolve")
			} else {
				lines = append(lines, "IP-CIDR6,"+p.String())
			}
		case 10:
			p, _ := v4().Prefix(24)
			lines = append(lines, "SRC-IP-CIDR,"+p.String())
		case 11:
			lines = append(lines, fmt.Sprintf("DST-PORT,%d", 440+rng.Intn(8)), "PROCESS-NAME,Telegram")
		case 12:
			switch rng.Intn(3) {
			case 0:
				lines = append(lines, "AND,("+sub()+","+sub()+")")
			case 1:
				lines = append(lines, "OR,("+sub()+","+sub()+")")
			default:
				lines = append(lines, "NOT,("+sub()+")")
			}
		}
	}
	for i := 0; i < 64; i++ {
		hosts = append(hosts, host())
		ips = append(ips, v4(), v6())
	}
	return
}

func TestClassicalIndexAnswersWhatTheLinearScanAnswers(t *testing.T) {
	for seed := int64(1); seed <= 40; seed++ {
		rng := rand.New(rand.NewSource(seed))
		lines, hosts, ips := randomClassicalCorpus(rng, 5+rng.Intn(300))
		indexed, linear := loadClassical(lines, true), loadClassical(lines, false)
		if indexed.Count() != linear.Count() || indexed.Count() != len(lines) {
			t.Fatalf("seed %d: count %d, linear %d, lines %d", seed, indexed.Count(), linear.Count(), len(lines))
		}
		table := map[string]netip.Addr{}
		for i, h := range hosts {
			table[h] = ips[i*2+rng.Intn(2)]
		}
		for trial := 0; trial < 400; trial++ {
			base := C.Metadata{DstPort: uint16(440 + rng.Intn(8)), SrcIP: ips[rng.Intn(len(ips))]}
			switch rng.Intn(4) {
			case 0:
				base.Host = hosts[rng.Intn(len(hosts))]
			case 1:
				base.DstIP = ips[rng.Intn(len(ips))]
			case 2:
				base.Host = hosts[rng.Intn(len(hosts))]
				base.SniffHost = hosts[rng.Intn(len(hosts))]
			case 3:
				base.Host = hosts[rng.Intn(len(hosts))]
				base.Process = "telegram"
			}
			withResolver := rng.Intn(3) != 0
			a, b := base, base
			ra, rb := &resolver{table: table}, &resolver{table: table}
			ha, hb := ra.helper(&a), rb.helper(&b)
			if !withResolver {
				ha.ResolveIP, hb.ResolveIP = nil, nil
			}
			got, want := indexed.Match(&a, ha), linear.Match(&b, hb)
			if got != want {
				t.Fatalf("seed %d trial %d: indexed %v, linear %v for %+v", seed, trial, got, want, base)
			}
			if (ra.calls > 0) != (rb.calls > 0) || a.DstIP != b.DstIP || (ra.lookups > 0) != (rb.lookups > 0) {
				t.Fatalf("seed %d trial %d: resolved %d/%d, dst %v/%v, process lookups %d/%d for %+v",
					seed, trial, ra.calls, rb.calls, a.DstIP, b.DstIP, ra.lookups, rb.lookups, base)
			}
		}
	}
}

func TestClassicalIndexKeepsResolveOrderBetweenIPRuns(t *testing.T) {
	table := map[string]netip.Addr{"a.test": netip.MustParseAddr("10.0.0.5")}
	for _, c := range []struct {
		lines []string
		want  bool
	}{
		{[]string{"IP-CIDR,10.0.0.0/24,no-resolve", "DOMAIN,z.test", "IP-CIDR,192.0.2.0/24"}, false},
		{[]string{"IP-CIDR,192.0.2.0/24", "DOMAIN,z.test", "IP-CIDR,10.0.0.0/24,no-resolve"}, true},
	} {
		for _, index := range []bool{false, true} {
			m := C.Metadata{Host: "a.test"}
			r := &resolver{table: table}
			if got := loadClassical(c.lines, index).Match(&m, r.helper(&m)); got != c.want {
				t.Errorf("%v (indexed %v): got %v, want %v", c.lines, index, got, c.want)
			}
		}
	}
	for _, lines := range [][]string{
		{"IP-CIDR,192.0.2.0/24", "DOMAIN,a.test"},
		{"PROCESS-NAME,Other", "DOMAIN-SUFFIX,test"},
	} {
		m := C.Metadata{Host: "a.test"}
		r := &resolver{table: table}
		if !loadClassical(lines, true).Match(&m, r.helper(&m)) {
			t.Fatalf("%v does not match a.test", lines)
		}
		if lines[0][0] == 'I' && (r.calls == 0 || m.DstIP != table["a.test"]) {
			t.Errorf("%v: the resolve before the domain line did not happen", lines)
		}
		if lines[0][0] == 'P' && r.lookups == 0 {
			t.Errorf("%v: the process lookup before the domain line did not happen", lines)
		}
	}
}

func TestClassicalIndexKeepsNameCountAndProcessLines(t *testing.T) {
	payload := []string{"DOMAIN-SUFFIX,example.com", "PROCESS-NAME,Telegram", "IP-CIDR,192.0.2.0/24,no-resolve", "DOMAIN,a.test"}
	provider := RP.NewInlineProvider("Mixed", P.Classical, payload, rules.ParseRule)
	if provider.Name() != "Mixed" || provider.Behavior() != P.Classical || provider.Count() != len(payload) {
		t.Fatalf("name %q behavior %v count %d", provider.Name(), provider.Behavior(), provider.Count())
	}
	set, err := rules.ParseRule("RULE-SET", "Mixed", "Proxy", nil, nil)
	if err != nil {
		t.Fatalf("RULE-SET: %v", err)
	}
	if set.Payload() != "Mixed" {
		t.Fatalf("RULE-SET payload %q", set.Payload())
	}
	if names := set.ProviderNames(); len(names) != 1 || names[0] != "Mixed" {
		t.Fatalf("RULE-SET provider names %v", names)
	}
	found := false
	m := C.Metadata{Host: "other.test", Process: "Telegram"}
	if ok := provider.Match(&m, C.RuleMatchHelper{FindProcess: func() { found = true }}); !ok || !found {
		t.Fatalf("PROCESS-NAME line in a mixed set: match %v, looked up %v", ok, found)
	}
	for host, want := range map[string]bool{"example.com": true, "x.example.com": true, "xexample.com": false, "a.test": true, "b.a.test": false} {
		m := C.Metadata{Host: host}
		if got := provider.Match(&m, C.RuleMatchHelper{}); got != want {
			t.Errorf("%s: got %v, want %v", host, got, want)
		}
	}
}

func BenchmarkClassicalMissIndexed(b *testing.B) { benchmarkClassicalMiss(b, true) }
func BenchmarkClassicalMissLinear(b *testing.B)  { benchmarkClassicalMiss(b, false) }

func benchmarkClassicalMiss(b *testing.B, index bool) {
	var lines []string
	for i := 0; i < 35000; i++ {
		if i%2 == 0 {
			lines = append(lines, fmt.Sprintf("DOMAIN-SUFFIX,site%d.example", i))
		} else {
			lines = append(lines, fmt.Sprintf("DOMAIN,host%d.example", i))
		}
	}
	lines = append(lines, "DOMAIN-KEYWORD,tracker", "IP-CIDR,198.51.100.0/24,no-resolve")
	s := loadClassical(lines, index)
	m := C.Metadata{Host: "www.unlisted.example.org"}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Match(&m, C.RuleMatchHelper{})
	}
}

func TestClassicalIndexToleratesLateInsertsAndASecondFinish(t *testing.T) {
	s := loadClassical([]string{"DOMAIN,a.test"}, true)
	s.Insert("DOMAIN,b.test")
	s.FinishInsert()
	for host, want := range map[string]bool{"a.test": true, "b.test": false} {
		m := C.Metadata{Host: host}
		if got := s.Match(&m, C.RuleMatchHelper{}); got != want {
			t.Errorf("%s: got %v, want %v", host, got, want)
		}
	}
	if s.Count() != 1 {
		t.Errorf("count %d", s.Count())
	}
}

func TestClassicalNameLinesAnswerAsUpstreamRules(t *testing.T) {
	edges := []string{
		"DOMAIN-SUFFIX,Google.COM", "DOMAIN,CDN.Example", "DOMAIN-SUFFIX,apple.com,no-resolve",
		" DOMAIN-SUFFIX , cn ", "DOMAIN,", "DOMAIN-SUFFIX,", "DOMAIN-SUFFIX,.example",
		"domain-suffix,google", "DOMAIN-SUFFIX,中文", "DOMAIN,a.b..cdn", "DOMAIN-SUFFIX,io",
	}
	for seed := int64(1); seed <= 40; seed++ {
		rng := rand.New(rand.NewSource(seed))
		lines, hosts, ips := randomClassicalCorpus(rng, 5+rng.Intn(300))
		for _, edge := range edges {
			at := rng.Intn(len(lines) + 1)
			lines = append(lines[:at], append([]string{edge}, lines[at:]...)...)
		}
		hosts = append(hosts, "google.com", "www.google.com", "cdn.example", "x.cn", "a.b..cdn", ".example", "中文", "b.中文", "IO", "io")
		reference, built, unbuilt := loadUpstreamClassical(lines), loadClassical(lines, true), loadUnbuilt(lines)
		if built.Count() != reference.Count() || unbuilt.Count() != reference.Count() {
			t.Fatalf("seed %d: count %d / %d, upstream %d", seed, built.Count(), unbuilt.Count(), reference.Count())
		}
		for trial := 0; trial < 300; trial++ {
			base := C.Metadata{DstPort: uint16(440 + rng.Intn(8)), SrcIP: ips[rng.Intn(len(ips))], Host: hosts[rng.Intn(len(hosts))]}
			if rng.Intn(3) == 0 {
				base.DstIP = ips[rng.Intn(len(ips))]
			}
			for name, matcher := range map[string]classicalMatcher{"built": built, "unbuilt": unbuilt} {
				a, b := base, base
				ra, rb := &resolver{}, &resolver{}
				got, want := matcher.Match(&a, ra.helper(&a)), reference.Match(&b, rb.helper(&b))
				if got != want || (ra.calls > 0) != (rb.calls > 0) || (ra.lookups > 0) != (rb.lookups > 0) {
					t.Fatalf("seed %d trial %d: %s answered %v (resolved %d, looked up %d), upstream %v (%d, %d) for %+v",
						seed, trial, name, got, ra.calls, ra.lookups, want, rb.calls, rb.lookups, base)
				}
			}
		}
	}
}
