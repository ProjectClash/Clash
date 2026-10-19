package clashindex_test

import (
	"bytes"
	"crypto/sha256"
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

type corpus struct {
	lines    []string
	subRules map[string][]C.Rule
	names    []string
	suffixes []string
	keywords []string
	prefixes []netip.Prefix
}

var targets = []string{"DIRECT", "REJECT", "A", "B", "C", "PASSX", "D", "E"}

func label(rnd *rand.Rand) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	n := 1 + rnd.Intn(6)
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rnd.Intn(len(letters))]
	}
	return string(b)
}

func newCorpus(t testing.TB, seed int64, n int, resolveEvery int, quietUntil int) *corpus {
	rnd := rand.New(rand.NewSource(seed))
	c := &corpus{subRules: map[string][]C.Rule{}}
	sub := []string{"DOMAIN-SUFFIX,sub.example,A", "IP-CIDR,10.1.0.0/16,B", "DOMAIN-KEYWORD,zz,PASSX", "DST-PORT,8443,C"}
	for _, line := range sub {
		tp, payload, target, params := RC.ParseRulePayload(line, true)
		r, err := R.ParseRule(tp, payload, target, params, nil)
		if err != nil {
			t.Fatal(err)
		}
		c.subRules["s1"] = append(c.subRules["s1"], r)
	}
	tlds := []string{"com", "net", "io", "cn", "org"}
	bases := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12"), netip.MustParsePrefix("1.0.0.0/8"), netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("::ffff:0:0/96")}
	target := func() string { return targets[rnd.Intn(len(targets))] }
	for len(c.lines) < n {
		r := rnd.Intn(100)
		switch {
		case r < 25:
			name := label(rnd) + "." + label(rnd) + "." + tlds[rnd.Intn(len(tlds))]
			c.names = append(c.names, name)
			if rnd.Intn(20) == 0 {
				name = strings.ToUpper(name)
			}
			c.lines = append(c.lines, "DOMAIN,"+name+","+target())
		case r < 50:
			name := label(rnd) + "." + tlds[rnd.Intn(len(tlds))]
			if rnd.Intn(30) == 0 {
				name = "." + name
			}
			c.suffixes = append(c.suffixes, strings.TrimPrefix(name, "."))
			c.lines = append(c.lines, "DOMAIN-SUFFIX,"+name+","+target())
		case r < 55:
			kw := label(rnd)
			c.keywords = append(c.keywords, kw)
			c.lines = append(c.lines, "DOMAIN-KEYWORD,"+kw+","+target())
		case r < 75:
			base := bases[rnd.Intn(len(bases))]
			bits := base.Bits() + rnd.Intn(base.Addr().BitLen()-base.Bits()+1)
			a := base.Addr().AsSlice()
			for i := base.Bits() / 8; i < len(a); i++ {
				a[i] = byte(rnd.Intn(4))
			}
			addr, _ := netip.AddrFromSlice(a)
			p := netip.PrefixFrom(addr, bits)
			if !base.Contains(addr) {
				p = base
			}
			c.prefixes = append(c.prefixes, p)
			kind := "IP-CIDR"
			if addr.Is6() {
				kind = "IP-CIDR6"
			}
			line := kind + "," + p.String() + "," + target()
			if resolveEvery == 0 || rnd.Intn(resolveEvery) != 0 {
				line += ",no-resolve"
			}
			c.lines = append(c.lines, line)
		case r < 80 && len(c.lines) > 10:
			prev := c.lines[rnd.Intn(len(c.lines))]
			if tp, payload, _, params := RC.ParseRulePayload(prev, true); tp != "MATCH" && !strings.ContainsAny(payload, "()") && tp != "SUB-RULE" {
				line := tp + "," + payload + "," + target()
				if len(params) > 0 {
					line += "," + strings.Join(params, ",")
				}
				c.lines = append(c.lines, line)
			}
		default:
			switch rnd.Intn(11) {
			case 0:
				c.lines = append(c.lines, "DST-PORT,"+[]string{"443", "80", "8000-9000"}[rnd.Intn(3)]+","+target())
			case 1:
				c.lines = append(c.lines, "NETWORK,udp,"+target())
			case 2:
				c.lines = append(c.lines, "PROCESS-NAME,proc"+strconv.Itoa(rnd.Intn(4))+","+target())
			case 3:
				c.lines = append(c.lines, `DOMAIN-REGEX,^[a-c].*\.io$,`+target())
			case 4:
				c.lines = append(c.lines, "DOMAIN-WILDCARD,*.a?.com,"+target())
			case 5:
				c.lines = append(c.lines, "SRC-IP-CIDR,192.168."+strconv.Itoa(rnd.Intn(3))+".0/24,"+target())
			case 6:
				if len(c.lines) >= quietUntil {
					c.lines = append(c.lines, "AND,((DOMAIN-KEYWORD,"+label(rnd)[:1]+"),(IP-CIDR,10.0.0.0/9)),"+target())
				}
			case 7:
				c.lines = append(c.lines, "NOT,((IP-CIDR,1.0.0.0/9,no-resolve)),"+target())
			case 8:
				c.lines = append(c.lines, "OR,((DST-PORT,53),(DOMAIN-SUFFIX,cn)),"+target())
			case 9:
				c.lines = append(c.lines, "SUB-RULE,(NETWORK,tcp),s1")
			case 10:
				if len(c.lines) >= quietUntil {
					c.lines = append(c.lines, "IP-SUFFIX,0.0.0.1/8,"+target())
				} else {
					c.lines = append(c.lines, "IP-SUFFIX,0.0.0.1/8,"+target()+",no-resolve")
				}
			}
		}
	}
	if rnd.Intn(2) == 0 {
		c.lines = append(c.lines, "MATCH,"+target())
	}
	return c
}

func (c *corpus) parse(t testing.TB, wrap bool) []C.Rule {
	rules := make([]C.Rule, 0, len(c.lines))
	for _, line := range c.lines {
		tp, payload, target, params := RC.ParseRulePayload(line, true)
		r, err := R.ParseRule(tp, payload, target, params, c.subRules)
		if err != nil {
			t.Fatalf("%s: %v", line, err)
		}
		if wrap {
			r = RW.NewRuleWrapper(r)
		}
		rules = append(rules, r)
	}
	return rules
}

func (c *corpus) compile(t testing.TB, wrap bool) (*clashindex.Table, []byte) {
	compiler := clashindex.NewCompiler()
	for i, rule := range c.parse(t, false) {
		if err := compiler.Add(c.lines[i], rule); err != nil {
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
		tp, payload, target, params := RC.ParseRulePayload(line, true)
		r, err := R.ParseRule(tp, payload, target, params, c.subRules)
		if err != nil {
			t.Fatal(err)
		}
		if wrap {
			r = RW.NewRuleWrapper(r)
		}
		others = append(others, r)
		return true
	})
	table, err := index.Table(others)
	if err != nil {
		t.Fatal(err)
	}
	return table, buffer.Bytes()
}

func h32(s string) uint32 {
	f := fnv.New32a()
	f.Write([]byte(s))
	return f.Sum32()
}

type flow struct {
	metadata *C.Metadata
	resolved bool
	process  bool
	dns      int
	lookups  int
	prefixes []netip.Prefix
}

func (f *flow) helper() C.RuleMatchHelper {
	return C.RuleMatchHelper{
		ResolveIP: func() {
			m := f.metadata
			if !f.resolved && m.Host != "" && !m.Resolved() {
				h := h32(m.Host)
				if h%5 != 0 {
					if h%3 == 0 || len(f.prefixes) == 0 {
						m.DstIP = netip.AddrFrom4([4]byte{byte(h >> 24), byte(h >> 16), byte(h >> 8), byte(h)})
					} else {
						m.DstIP = inside(f.prefixes[int(h>>3)%len(f.prefixes)], h)
					}
				}
				f.resolved = true
				f.dns++
			}
		},
		FindProcess: func() {
			if !f.process {
				f.process = true
				f.metadata.Process = "proc" + strconv.Itoa(int(h32(f.metadata.Host)%4))
				f.lookups++
			}
		},
	}
}

func inside(p netip.Prefix, seed uint32) netip.Addr {
	a := p.Masked().Addr().AsSlice()
	for i := len(a) - 1; i >= 0 && i*8 >= p.Bits(); i-- {
		a[i] = byte(seed >> (uint(i%4) * 8))
	}
	if r := p.Bits() % 8; r != 0 && p.Bits()/8 < len(a) {
		i := p.Bits() / 8
		mask := byte(0xff >> r)
		a[i] = a[i]&^mask | byte(seed)&mask
	}
	addr, _ := netip.AddrFromSlice(a)
	return addr
}

func (c *corpus) queries(seed int64, n int) []C.Metadata {
	rnd := rand.New(rand.NewSource(seed))
	pick := func(s []string) string {
		if len(s) == 0 {
			return "x.invalid"
		}
		return s[rnd.Intn(len(s))]
	}
	out := make([]C.Metadata, 0, n)
	for i := 0; i < n; i++ {
		m := C.Metadata{NetWork: C.TCP, DstPort: uint16([]int{443, 80, 8443, 53, 8500, rnd.Intn(65535)}[rnd.Intn(6)])}
		if rnd.Intn(4) == 0 {
			m.NetWork = C.UDP
		}
		m.SrcIP = netip.AddrFrom4([4]byte{192, 168, byte(rnd.Intn(4)), byte(rnd.Intn(255))})
		switch rnd.Intn(10) {
		case 0:
			m.Host = pick(c.names)
		case 1:
			m.Host = pick(c.suffixes)
		case 2:
			m.Host = label(rnd) + "." + pick(c.suffixes)
		case 3:
			m.Host = "x" + pick(c.keywords) + "y.com"
		case 4:
			m.Host = label(rnd) + "." + label(rnd) + ".example"
		case 5:
			m.Host = strings.ToUpper(pick(c.names))
		case 6:
			m.Host = "a" + strconv.Itoa(rnd.Intn(3)) + "." + label(rnd) + ".io"
		case 7, 8:
			if len(c.prefixes) > 0 {
				m.DstIP = inside(c.prefixes[rnd.Intn(len(c.prefixes))], rnd.Uint32())
			}
		case 9:
			m.Host = pick(c.names)
			if len(c.prefixes) > 0 {
				m.DstIP = inside(c.prefixes[rnd.Intn(len(c.prefixes))], rnd.Uint32())
			}
		}
		if rnd.Intn(10) == 0 {
			m.SniffHost = pick(c.names)
		}
		out = append(out, m)
	}
	return out
}

type walkResult struct {
	matches  []string
	before   []int
	dns      int
	lookups  int
	dstIP    netip.Addr
	process  string
	resolved bool
}

func walk(table C.RuleTable, m C.Metadata, prefixes []netip.Prefix, stopOn func(index int, adapter string) bool, otherIndex func(int) bool) walkResult {
	f := &flow{metadata: &m, prefixes: prefixes}
	var res walkResult
	table.Walk(&m, f.helper(), func(index int, _ C.Rule) {
		if otherIndex(index) {
			res.before = append(res.before, index)
		}
	}, func(index int, rule C.Rule, adapter string) bool {
		res.matches = append(res.matches, fmt.Sprintf("%d:%s:%s:%s", index, rule.RuleType(), rule.Payload(), adapter))
		return stopOn(index, adapter)
	})
	res.dns, res.lookups, res.dstIP, res.process, res.resolved = f.dns, f.lookups, m.DstIP, m.Process, f.resolved
	return res
}

func (r walkResult) String() string {
	return fmt.Sprintf("matches=%v before=%v dns=%d lookups=%d dst=%v process=%q", r.matches, r.before, r.dns, r.lookups, r.dstIP, r.process)
}

func equal(a, b walkResult) bool {
	return fmt.Sprint(a) == fmt.Sprint(b)
}

func TestTheIndexWalksAsTheLoop(t *testing.T) {
	for _, variant := range []struct {
		name         string
		seed         int64
		rules        int
		resolveEvery int
		quietUntil   int
		queries      int
		mapped, other bool
	}{
		{"most IP rules resolve", 1, 3000, 2, 0, 20000, false, false},
		{"a few resolve, other rules resolve late", 2, 3000, 50, 2000, 20000, true, true},
		{"a few resolve, other rules resolve anywhere", 6, 3000, 50, 0, 20000, false, true},
		{"none resolve, only other rules do", 3, 3000, 0, 0, 20000, false, true},
		{"no other rule resolves", 7, 3000, 30, 1 << 30, 20000, true, false},
		{"small", 4, 40, 3, 20, 20000, false, false},
		{"large", 5, 30000, 200, 20000, 2000, true, true},
	} {
		t.Run(variant.name, func(t *testing.T) {
			c := newCorpus(t, variant.seed, variant.rules, variant.resolveEvery, variant.quietUntil)
			list := C.RuleList(c.parse(t, false))
			table, _ := c.compile(t, false)
			isOther := func(i int) bool {
				switch table.At(i).(type) {
				case *RC.Domain, *RC.DomainSuffix, *RC.DomainKeyword:
					return false
				case *RC.IPCIDR:
					return table.At(i).RuleType() != C.IPCIDR
				}
				return true
			}
			for i := 0; i < list.Len(); i++ {
				a, b := list.At(i), table.At(i)
				if a.RuleType() != b.RuleType() || a.Payload() != b.Payload() || a.Adapter() != b.Adapter() {
					t.Fatalf("rule %d: loop %s,%s,%s, index %s,%s,%s", i, a.RuleType(), a.Payload(), a.Adapter(), b.RuleType(), b.Payload(), b.Adapter())
				}
			}
			stops := []struct {
				name string
				stop func(int, string) bool
			}{
				{"every match", func(int, string) bool { return false }},
				{"first not passed over", func(_ int, adapter string) bool { return adapter != "PASSX" && adapter != "C" }},
			}
			if mapped, other := c.paths(list, c.queries(variant.seed*7+1, variant.queries)); (variant.mapped && mapped == 0) || (variant.other && other == 0) {
				t.Fatalf("the corpus does not take the paths it is for: %d flows resolved by an IP rule past a no-resolve one holding the address, %d by an other rule", mapped, other)
			}
			for _, s := range stops {
				for qi, q := range c.queries(variant.seed*7+1, variant.queries) {
					want := walk(list, q, c.prefixes, s.stop, isOther)
					got := walk(table, q, c.prefixes, s.stop, isOther)
					if !equal(want, got) {
						t.Fatalf("%s, query %d %+v:\nloop  %s\nindex %s", s.name, qi, q, want, got)
					}
				}
			}
		})
	}
}

func (c *corpus) paths(list C.RuleList, queries []C.Metadata) (mapped, other int) {
	for _, q := range queries {
		if q.DstIP.IsValid() || q.Host == "" {
			continue
		}
		m := q
		f := &flow{metadata: &m, prefixes: c.prefixes}
		h := f.helper()
		for i := 0; i < list.Len(); i++ {
			before := m.DstIP
			list.At(i).Match(&m, h)
			if m.DstIP == before {
				continue
			}
			if r, ok := list.At(i).(*RC.IPCIDR); ok && r.ClashResolvesIP() {
				for j := 0; j < i; j++ {
					if r, ok := list.At(j).(*RC.IPCIDR); ok && !r.ClashResolvesIP() && r.ClashPrefix().Contains(m.DstIP) {
						mapped++
						break
					}
				}
			} else {
				other++
			}
			break
		}
	}
	return mapped, other
}

func TestTheIndexCountsAsRuleWrappers(t *testing.T) {
	c := newCorpus(t, 11, 2000, 10, 1000)
	list := C.RuleList(c.parse(t, true))
	table, _ := c.compile(t, true)
	stop := func(_ int, adapter string) bool { return adapter != "PASSX" }
	never := func(int) bool { return false }
	queries := c.queries(13, 6000)
	rnd := rand.New(rand.NewSource(17))
	for qi, q := range queries {
		if qi%500 == 250 {
			for k := 0; k < 20; k++ {
				i := rnd.Intn(list.Len())
				disabled := rnd.Intn(3) != 0
				if !table.SetDisabled(i, disabled) {
					table.At(i).(C.RuleWrapper).SetDisabled(disabled)
				}
				list.At(i).(C.RuleWrapper).SetDisabled(disabled)
			}
		}
		walk(list, q, c.prefixes, stop, never)
		walk(table, q, c.prefixes, stop, never)
	}
	all := map[int]C.RuleStatistics{}
	table.RangeStatistics(func(i int, s C.RuleStatistics, ok bool) bool {
		if ok {
			all[i] = s
		}
		return true
	})
	checked := 0
	for i := 0; i < list.Len(); i++ {
		w := list.At(i).(C.RuleWrapper)
		want := C.RuleStatistics{Disabled: w.IsDisabled(), HitCount: w.HitCount(), HitAt: w.HitAt(), MissCount: w.MissCount(), MissAt: w.MissAt()}
		got, ok := table.Statistics(i)
		if !ok {
			o := table.At(i).(C.RuleWrapper)
			got = C.RuleStatistics{Disabled: o.IsDisabled(), HitCount: o.HitCount(), HitAt: o.HitAt(), MissCount: o.MissCount(), MissAt: o.MissAt()}
		} else {
			if bulk := all[i]; bulk.HitCount != got.HitCount || bulk.MissCount != got.MissCount || bulk.Disabled != got.Disabled || !bulk.MissAt.Equal(got.MissAt) || !bulk.HitAt.Equal(got.HitAt) {
				t.Fatalf("rule %d: one by one %+v, all at once %+v", i, got, bulk)
			}
			checked++
		}
		if want.Disabled != got.Disabled || want.HitCount != got.HitCount || want.MissCount != got.MissCount ||
			(want.HitAt.UnixNano() == 0) != (got.HitAt.UnixNano() == 0) || (want.MissAt.UnixNano() == 0) != (got.MissAt.UnixNano() == 0) {
			t.Fatalf("rule %d (%s): wrapper %+v, index %+v", i, c.lines[i], want, got)
		}
	}
	if checked < list.Len()/2 {
		t.Fatalf("only %d of %d rules mapped", checked, list.Len())
	}
}

func TestAnIndexIsTheSameBytesForTheSameRulesAndChecksItself(t *testing.T) {
	c := newCorpus(t, 21, 5000, 5, 0)
	_, first := c.compile(t, false)
	_, second := c.compile(t, false)
	if !bytes.Equal(first, second) {
		t.Fatal("two compiles of the same rules differ")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "rules.index")
	if err := os.WriteFile(path, first, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := [32]byte(first[len(first)-32:])
	if sha256.Sum256(first[:len(first)-32]) != sum {
		t.Fatal("the trailer is not the SHA-256 of the index")
	}
	index, err := clashindex.Open(path, sum)
	if err != nil {
		t.Fatal(err)
	}
	if index.Len() != len(c.lines) {
		t.Fatalf("%d rules, want %d", index.Len(), len(c.lines))
	}
	var other [32]byte
	if _, err := clashindex.Open(path, other); err == nil {
		t.Fatal("an index opened for a checksum it does not have")
	}
	for _, at := range []int{0, 30, len(first) / 2, len(first) - 40} {
		damaged := append([]byte(nil), first...)
		damaged[at] ^= 0x40
		if _, err := clashindex.Decode(damaged); err == nil {
			t.Fatalf("an index damaged at %d decoded", at)
		}
	}
	link := filepath.Join(dir, "link.index")
	if err := os.Symlink(path, link); err == nil {
		if _, err := clashindex.Open(link, sum); err == nil {
			t.Fatal("a link opened as an index")
		}
	}
}

func TestATableIsWalkedFromManyFlowsAtOnce(t *testing.T) {
	c := newCorpus(t, 31, 2000, 10, 1000)
	table, _ := c.compile(t, true)
	queries := c.queries(33, 4000)
	done := make(chan struct{})
	for g := 0; g < 8; g++ {
		go func(g int) {
			defer func() { done <- struct{}{} }()
			for i := g; i < len(queries); i += 8 {
				walk(table, queries[i], c.prefixes, func(_ int, adapter string) bool { return adapter != "PASSX" }, func(int) bool { return false })
				if i%97 == 0 {
					table.SetDisabled(i%table.Len(), i%2 == 0)
				}
				if i%301 == 0 {
					table.RangeStatistics(func(int, C.RuleStatistics, bool) bool { return true })
					table.Statistics(i % table.Len())
				}
			}
		}(g)
	}
	for g := 0; g < 8; g++ {
		<-done
	}
}

func TestTheIndexWalksAsTheLoopWithRulesDisabled(t *testing.T) {
	for _, seed := range []int64{41, 42, 43} {
		c := newCorpus(t, seed, 3000, 3, 1500)
		list := C.RuleList(c.parse(t, true))
		table, _ := c.compile(t, true)
		rnd := rand.New(rand.NewSource(seed))
		for k := 0; k < 300; k++ {
			i := rnd.Intn(list.Len())
			if !table.SetDisabled(i, true) {
				table.At(i).(C.RuleWrapper).SetDisabled(true)
			}
			list.At(i).(C.RuleWrapper).SetDisabled(true)
		}
		isOther := func(int) bool { return false }
		for qi, q := range c.queries(seed, 10000) {
			for _, stop := range []func(int, string) bool{
				func(int, string) bool { return false },
				func(_ int, adapter string) bool { return adapter != "PASSX" },
			} {
				want := walk(list, q, c.prefixes, stop, isOther)
				got := walk(table, q, c.prefixes, stop, isOther)
				if !equal(want, got) {
					t.Fatalf("seed %d query %d %+v:\nloop  %s\nindex %s", seed, qi, q, want, got)
				}
			}
		}
	}
}
