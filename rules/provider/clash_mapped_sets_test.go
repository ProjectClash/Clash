package provider_test

import (
	"errors"
	"fmt"
	"math/rand"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	"github.com/ProjectClash/Clash/rules"
	RP "github.com/ProjectClash/Clash/rules/provider"
)

type setMatcher interface {
	Match(*C.Metadata, C.RuleMatchHelper) bool
	Count() int
}

func loadSetStub(s interface {
	setMatcher
	Insert(string)
	FinishInsert()
}, stub string) setMatcher {
	s.Insert(stub)
	s.FinishInsert()
	return s
}

func TestAMappedDomainSetAnswersAsTheTextSet(t *testing.T) {
	random := rand.New(rand.NewSource(7))
	var lines []string
	for i := 0; i < 3000; i++ {
		name := fmt.Sprintf("h%d.example%d.com", random.Intn(500), random.Intn(20))
		switch i % 3 {
		case 0:
			lines = append(lines, "+."+name)
		case 1:
			lines = append(lines, "."+name)
		default:
			lines = append(lines, name)
		}
	}
	compiled, err := RP.ClashCompileMappedDomainSet(lines)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "set.cds"), compiled.Bytes, 0o644); err != nil {
		t.Fatal(err)
	}
	mapped := loadSetStub(RP.NewDomainStrategyInStubDirectory(dir), RP.ClashMappedSetStub(RP.ClashDomainSetStubType, "set.cds", compiled.SHA256, compiled.Count))
	reference := RP.NewDomainStrategy()
	for _, line := range lines {
		reference.Insert(line)
	}
	reference.FinishInsert()
	if mapped.Count() != reference.Count() || mapped.Count() == 0 {
		t.Fatalf("count %d, the text set's %d", mapped.Count(), reference.Count())
	}
	for i := 0; i < 20000; i++ {
		host := fmt.Sprintf("%sh%d.example%d.com", []string{"", "a.", "b.c."}[i%3], random.Intn(600), random.Intn(25))
		m := &C.Metadata{Host: host}
		if got, want := mapped.Match(m, C.RuleMatchHelper{}), reference.Match(m, C.RuleMatchHelper{}); got != want {
			t.Fatalf("%s: mapped %v, text %v", host, got, want)
		}
	}
	damaged := append([]byte(nil), compiled.Bytes...)
	damaged[len(damaged)/2] ^= 1
	_ = os.WriteFile(filepath.Join(dir, "bad.cds"), damaged, 0o644)
	bad := loadSetStub(RP.NewDomainStrategyInStubDirectory(dir), RP.ClashMappedSetStub(RP.ClashDomainSetStubType, "bad.cds", compiled.SHA256, compiled.Count))
	if bad.Count() != 0 || bad.Match(&C.Metadata{Host: strings.TrimPrefix(lines[2], "+.")}, C.RuleMatchHelper{}) {
		t.Fatal("a damaged set was used")
	}
	outside := loadSetStub(RP.NewDomainStrategy(), RP.ClashMappedSetStub(RP.ClashDomainSetStubType, "set.cds", compiled.SHA256, compiled.Count))
	if outside.Match(&C.Metadata{Host: lines[2]}, C.RuleMatchHelper{}) {
		t.Fatal("a stub was honoured outside a stub file")
	}
}

func TestAMappedIPCidrSetAnswersAsTheTextSet(t *testing.T) {
	random := rand.New(rand.NewSource(11))
	var lines []string
	for i := 0; i < 3000; i++ {
		if i%4 == 0 {
			lines = append(lines, fmt.Sprintf("2001:db8:%x::/%d", random.Intn(4096), 32+random.Intn(33)))
		} else {
			lines = append(lines, fmt.Sprintf("10.%d.%d.0/%d", random.Intn(256), random.Intn(256), 16+random.Intn(17)))
		}
	}
	compiled, err := RP.ClashCompileMappedIPCidrSet(lines)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "set.cip"), compiled.Bytes, 0o644); err != nil {
		t.Fatal(err)
	}
	mapped := loadSetStub(RP.NewIPCidrStrategyInStubDirectory(dir), RP.ClashMappedSetStub(RP.ClashIPCidrSetStubType, "set.cip", compiled.SHA256, compiled.Count))
	reference := RP.NewIPCidrStrategy()
	reference.Reset()
	for _, line := range lines {
		reference.Insert(line)
	}
	reference.FinishInsert()
	if mapped.Count() != reference.Count() || mapped.Count() == 0 {
		t.Fatalf("count %d, the text set's %d", mapped.Count(), reference.Count())
	}
	for i := 0; i < 20000; i++ {
		var ip netip.Addr
		switch i % 3 {
		case 0:
			ip = netip.AddrFrom4([4]byte{10, byte(random.Intn(256)), byte(random.Intn(256)), byte(random.Intn(256))})
		case 1:
			ip = netip.MustParseAddr(fmt.Sprintf("2001:db8:%x::%x", random.Intn(4096), random.Intn(65536)))
		default:
			ip = netip.AddrFrom16(netip.AddrFrom4([4]byte{10, byte(random.Intn(256)), 1, 1}).As16())
		}
		m := &C.Metadata{DstIP: ip}
		if got, want := mapped.Match(m, C.RuleMatchHelper{}), reference.Match(m, C.RuleMatchHelper{}); got != want {
			t.Fatalf("%s: mapped %v, text %v", ip, got, want)
		}
	}
}

func TestACompiledClassicalSetHoldsItsIPRunsInTheMapping(t *testing.T) {
	var lines []string
	for i := 0; i < 50000; i++ {
		lines = append(lines, fmt.Sprintf("DOMAIN-SUFFIX,s%d.example.net", i))
		lines = append(lines, fmt.Sprintf("IP-CIDR,10.%d.%d.0/25,no-resolve", i/256%256, i%256))
		if i%1000 == 0 {
			lines = append(lines, fmt.Sprintf("IP-CIDR6,2001:db8:%x::/48", i))
		}
	}
	dir := t.TempDir()
	indexPath, sourcePath := stageCompiled(t, dir, lines, P.TextRule)
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	matcher := loadStaged(indexPath, sourcePath, P.TextRule)
	runtime.GC()
	runtime.ReadMemStats(&after)
	held := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	if matcher.Count() != len(lines) {
		t.Fatalf("count %d of %d", matcher.Count(), len(lines))
	}
	if held > 1<<20 {
		t.Fatalf("the loaded set holds %d KiB of heap", held>>10)
	}
	for ip, want := range map[string]bool{"10.0.5.9": true, "10.195.79.1": true, "10.0.5.200": false, "11.0.0.1": false, "2001:db8:3e8::1": true} {
		m := &C.Metadata{DstIP: netip.MustParseAddr(ip)}
		if got := matcher.Match(m, C.RuleMatchHelper{}); got != want {
			t.Fatalf("%s: matched %v", ip, got)
		}
	}
	runtime.KeepAlive(matcher)
}

func TestAClassicalSetPastTheHeapLimitLoadsNoRules(t *testing.T) {
	for _, c := range []struct {
		kind  string
		limit int
		line  func(int) string
	}{
		{"DOMAIN-KEYWORD", RP.ClashClassicalKeywordLimit, func(i int) string { return fmt.Sprintf("DOMAIN-KEYWORD,kw%d", i) }},
		{"DOMAIN-REGEX", RP.ClashClassicalRegexLimit, func(i int) string { return fmt.Sprintf(`DOMAIN-REGEX,^a%d\.example$`, i) }},
	} {
		lines := []string{"DOMAIN-SUFFIX,kept.example"}
		for i := 0; i <= c.limit; i++ {
			lines = append(lines, c.line(i))
		}
		if _, err := RP.ClashCompileClassicalIndex(lines, rules.ParseRule); !errors.Is(err, RP.ErrClassicalTooHeavy) {
			t.Fatalf("%s: the compile took %d lines: %v", c.kind, c.limit+1, err)
		}
		s := RP.NewClassicalStrategy(rules.ParseRule)
		for _, line := range lines {
			s.Insert(line)
		}
		s.FinishInsert()
		if s.Count() != 0 || s.Match(&C.Metadata{Host: "a.kept.example"}, C.RuleMatchHelper{}) {
			t.Fatalf("%s: the text load holds %d rules", c.kind, s.Count())
		}
		if _, err := RP.ClashCompileClassicalIndex(lines[:len(lines)-1], rules.ParseRule); err != nil {
			t.Fatalf("%s: a set at the limit was refused: %v", c.kind, err)
		}
	}
}
