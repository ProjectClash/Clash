package clashindex_test

import (
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/rules/clashindex"
)


const sectionsAt = 8 + 4*4 + 32

func section(data []byte, i int) (int, int) {
	return int(binary.LittleEndian.Uint32(data[sectionsAt+8*i:])), int(binary.LittleEndian.Uint32(data[sectionsAt+4+8*i:]))
}

func resum(data []byte) {
	sum := sha256.Sum256(data[:len(data)-32])
	copy(data[len(data)-32:], sum[:])
}

func TestADisabledResolvingRuleResolvesNothing(t *testing.T) {
	c := &corpus{lines: []string{"IP-CIDR,10.0.0.0/8,REJECT", "IP-CIDR,1.2.3.4/32,REJECT,no-resolve", "MATCH,DIRECT"}, subRules: map[string][]C.Rule{}}
	table, _ := c.compile(t, true)
	list := C.RuleList(c.parse(t, true))
	table.SetDisabled(0, true)
	list[0].(C.RuleWrapper).SetDisabled(true)
	for _, rules := range []C.RuleTable{list, table} {
		m := &C.Metadata{Host: "example.org", NetWork: C.TCP, DstPort: 443}
		dns := 0
		var decided string
		rules.Walk(m, C.RuleMatchHelper{ResolveIP: func() { dns++; m.DstIP = netip.MustParseAddr("1.2.3.4") }}, nil, func(_ int, _ C.Rule, adapter string) bool {
			decided = adapter
			return true
		})
		if decided != "DIRECT" || dns != 0 || m.DstIP.IsValid() {
			t.Fatalf("%T: %s, %d lookups, %v", rules, decided, dns, m.DstIP)
		}
	}
}

func TestAWalkHoldsNothingOfTheRulesItReads(t *testing.T) {
	c := &corpus{lines: make([]string, 200000), subRules: map[string][]C.Rule{}}
	for i := range c.lines {
		c.lines[i] = "DOMAIN-KEYWORD,a,DIRECT"
	}
	table, _ := c.compile(t, true)
	walk := func(matches int) uint64 {
		m := &C.Metadata{Host: strings.Repeat("a", 63) + ".example"}
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		n := 0
		table.Walk(m, C.RuleMatchHelper{}, nil, func(int, C.Rule, string) bool { n++; return n == matches })
		runtime.ReadMemStats(&after)
		if n != matches {
			t.Fatalf("%d matches", n)
		}
		return after.TotalAlloc - before.TotalAlloc
	}
	if grown := walk(1); grown > 64<<10 {
		t.Fatalf("the first match took %d bytes", grown)
	}
	if grown := walk(1000); grown > 1<<20 {
		t.Fatalf("a thousand matches took %d bytes", grown)
	}
}

func TestTheStatisticsStayBounded(t *testing.T) {
	c := &corpus{subRules: map[string][]C.Rule{}}
	for i := 0; i < 200000; i++ {
		c.lines = append(c.lines, "IP-CIDR,"+netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}).String()+"/32,DIRECT,no-resolve")
	}
	table, _ := c.compile(t, true)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := 0; i < 200000; i++ {
		m := C.Metadata{DstIP: netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)})}
		table.Walk(&m, C.RuleMatchHelper{}, nil, func(int, C.Rule, string) bool { return true })
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(table)
	if grown := int64(after.HeapAlloc) - int64(before.HeapAlloc); grown > 8<<20 {
		t.Fatalf("the statistics hold %d bytes", grown)
	}
	if table.DroppedStatistics() == 0 {
		t.Fatal("no record left out past the bound")
	}
}

func TestAnIndexWithAPayloadTheParserRefusesIsRefused(t *testing.T) {
	c := &corpus{lines: []string{"IP-CIDR,1.2.3.4/32,DIRECT,no-resolve"}, subRules: map[string][]C.Rule{}}
	_, data := c.compile(t, true)
	pool, _ := section(data, 3)
	data[pool] = 'z'
	resum(data)
	if _, err := clashindex.Decode(data); err == nil {
		t.Fatal("decoded")
	}
}

func TestAnIndexWhoseTableIsNotTheCompilersIsRefused(t *testing.T) {
	c := &corpus{lines: []string{"DOMAIN,a.example,DIRECT", "DOMAIN,b.example,REJECT"}, subRules: map[string][]C.Rule{}}
	_, data := c.compile(t, true)
	full := append([]byte(nil), data...)
	off, _ := section(full, 4)
	slots := int(binary.LittleEndian.Uint32(full[off:]))
	for i := 0; i < slots; i++ {
		binary.LittleEndian.PutUint32(full[off+12+4*i:], 1)
	}
	resum(full)
	if _, err := clashindex.Decode(full); err == nil {
		t.Error("a full table decoded")
	}
	wrong := append([]byte(nil), data...)
	keys := off + 12 + 4*slots
	first, second := binary.LittleEndian.Uint32(wrong[keys+8:]), binary.LittleEndian.Uint32(wrong[keys+12+8:])
	binary.LittleEndian.PutUint32(wrong[keys+8:], second)
	binary.LittleEndian.PutUint32(wrong[keys+12+8:], first)
	resum(wrong)
	if _, err := clashindex.Decode(wrong); err == nil {
		t.Error("an index whose keys name each other's rules decoded")
	}
}

func TestAWalkCountsAsTheRulesWereWhenItPassedThem(t *testing.T) {
	for _, startDisabled := range []bool{false, true} {
		c := &corpus{lines: []string{"DOMAIN,miss.example,DIRECT", "MATCH,DIRECT"}, subRules: map[string][]C.Rule{}}
		table, _ := c.compile(t, true)
		list := C.RuleList(c.parse(t, true))
		if startDisabled {
			table.SetDisabled(0, true)
			list[0].(C.RuleWrapper).SetDisabled(true)
		}
		for _, rules := range []C.RuleTable{list, table} {
			entered, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
			go func() {
				rules.Walk(&C.Metadata{Host: "other.example"}, C.RuleMatchHelper{}, nil, func(int, C.Rule, string) bool {
					close(entered)
					<-release
					return true
				})
				close(done)
			}()
			<-entered
			if r, ok := rules.(*clashindex.Table); ok {
				r.SetDisabled(0, !startDisabled)
			} else {
				rules.At(0).(C.RuleWrapper).SetDisabled(!startDisabled)
			}
			close(release)
			<-done
		}
		want := list[0].(C.RuleWrapper).MissCount()
		got, _ := table.Statistics(0)
		if got.MissCount != want {
			t.Errorf("started disabled %v: %d misses, the wrapper %d", startDisabled, got.MissCount, want)
		}
	}
	c := &corpus{lines: []string{"DOMAIN,a.example,DIRECT"}, subRules: map[string][]C.Rule{}}
	table, _ := c.compile(t, true)
	var yieldAt time.Time
	table.Walk(&C.Metadata{Host: "a.example"}, C.RuleMatchHelper{}, nil, func(int, C.Rule, string) bool {
		yieldAt = time.Now()
		time.Sleep(20 * time.Millisecond)
		return true
	})
	if st, _ := table.Statistics(0); st.HitAt.After(yieldAt) {
		t.Fatalf("the hit is %v after the match", st.HitAt.Sub(yieldAt))
	}
}

func TestTheTunnelsOpenRefusesWhatWouldBreakAWalk(t *testing.T) {
	dir := t.TempDir()
	open := func(data []byte) (*clashindex.Index, error) {
		path := dir + "/x.index"
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		return clashindex.Open(path, [32]byte(data[len(data)-32:]))
	}
	c := &corpus{lines: []string{"IP-CIDR,1.2.3.4/32,DIRECT,no-resolve", "DOMAIN,a.example,DIRECT"}, subRules: map[string][]C.Rule{}}
	_, data := c.compile(t, true)
	if _, err := open(data); err != nil {
		t.Fatal(err)
	}
	bad := append([]byte(nil), data...)
	pool, _ := section(bad, 3)
	bad[pool] = 'z'
	resum(bad)
	if _, err := open(bad); err == nil {
		t.Error("an IP payload that is not a prefix opened")
	}
	full := append([]byte(nil), data...)
	off, _ := section(full, 4)
	slots := int(binary.LittleEndian.Uint32(full[off:]))
	for i := 0; i < slots; i++ {
		binary.LittleEndian.PutUint32(full[off+12+4*i:], 1)
	}
	resum(full)
	if index, err := open(full); err == nil {
		table, _ := index.Table(nil)
		done := make(chan struct{})
		go func() {
			table.Walk(&C.Metadata{Host: "missing.example"}, C.RuleMatchHelper{}, nil, func(int, C.Rule, string) bool { return true })
			close(done)
		}()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("a walk over a full table did not return")
		}
	}
}
