package provider_test

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/component/resource"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	"github.com/ProjectClash/Clash/rules"
	RP "github.com/ProjectClash/Clash/rules/provider"
	"github.com/sirupsen/logrus"
)


func stageCompiled(t *testing.T, dir string, lines []string, format P.RuleFormat) (indexPath, sourcePath string) {
	t.Helper()
	index, err := RP.ClashCompileClassicalIndex(lines, rules.ParseRule)
	if err != nil {
		t.Fatal(err)
	}
	if want := loadUpstreamClassical(lines).Count(); index.Rules != want {
		t.Fatalf("compiled count %d, upstream %d", index.Rules, want)
	}
	indexPath, sourcePath = filepath.Join(dir, "set,one.idx"), filepath.Join(dir, "set,one.src")
	compiledChecksums[indexPath] = index.Checksum
	if err := os.WriteFile(indexPath, index.Bytes, 0o644); err != nil {
		t.Fatal(err)
	}
	var source string
	if format == P.YamlRule {
		source = "payload:\n"
		for _, line := range lines {
			source += "  - '" + strings.ReplaceAll(line, "'", "''") + "'\n"
		}
	} else {
		source = strings.Join(lines, "\n") + "\n"
	}
	if err := os.WriteFile(sourcePath, []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
	return indexPath, sourcePath
}

func loadStaged(indexPath, sourcePath string, format P.RuleFormat) classicalMatcher {
	return loadStub(filepath.Dir(indexPath), stubFor(indexPath, sourcePath, format))
}

func stubFor(indexPath, sourcePath string, format P.RuleFormat) string {
	checksum, ok := compiledChecksums[indexPath]
	if !ok {
		panic("no index was compiled at " + indexPath)
	}
	return RP.ClashClassicalIndexStub(filepath.Base(indexPath), checksum, filepath.Base(sourcePath), format) + "\n"
}

var compiledChecksums = map[string]uint32{}

func withoutCatchAlls(lines []string) (kept []string) {
	for _, line := range lines {
		if !strings.Contains(line, "KEYWORD,") && !strings.Contains(line, "DST-PORT,") && !strings.HasPrefix(line, "NOT,") {
			kept = append(kept, line)
		}
	}
	return kept
}

func probeHosts(lines, hosts []string) []string {
	probes := append([]string{"nomatch.invalid", "zz", ""}, hosts...)
	for _, line := range lines {
		kind, rest, _ := strings.Cut(line, ",")
		if kind = strings.ToUpper(strings.TrimSpace(kind)); kind != "DOMAIN" && kind != "DOMAIN-SUFFIX" {
			continue
		}
		name, _, _ := strings.Cut(rest, ",")
		name = strings.ToLower(strings.TrimSpace(name))
		probes = append(probes, name, "zz."+name, strings.ToUpper(name))
		if _, parent, ok := strings.Cut(name, "."); ok {
			probes = append(probes, parent)
		}
	}
	return probes
}

func loadStub(directory, stub string) classicalMatcher {
	s := RP.NewClassicalStrategyInIndexDirectory(rules.ParseRule, directory)
	for _, line := range strings.Split(strings.TrimSpace(stub), "\n") {
		s.Insert(line)
	}
	s.FinishInsert()
	return s
}

func sameAsUpstream(t *testing.T, name string, seed int64, matcher, reference classicalMatcher, hosts []string, ips []C.Metadata) {
	t.Helper()
	if matcher.Count() != reference.Count() {
		t.Fatalf("%s seed %d: count %d, upstream %d", name, seed, matcher.Count(), reference.Count())
	}
	for _, base := range ips {
		for _, host := range hosts {
			base.Host = host
			a, b := base, base
			ra, rb := &resolver{}, &resolver{}
			got, want := matcher.Match(&a, ra.helper(&a)), reference.Match(&b, rb.helper(&b))
			if got != want || (ra.calls > 0) != (rb.calls > 0) || (ra.lookups > 0) != (rb.lookups > 0) {
				t.Fatalf("%s seed %d: answered %v (resolved %d, looked up %d), upstream %v (%d, %d) for %+v",
					name, seed, got, ra.calls, ra.lookups, want, rb.calls, rb.lookups, base)
			}
		}
	}
}

func TestCompiledClassicalIndexAnswersAsUpstream(t *testing.T) {
	edges := []string{
		"DOMAIN-SUFFIX,Google.COM", "DOMAIN,CDN.Example", "DOMAIN-SUFFIX,apple.com,no-resolve",
		" DOMAIN-SUFFIX , cn ", "DOMAIN,", "DOMAIN-SUFFIX,", "DOMAIN-SUFFIX,.example",
		"domain-suffix,google", "DOMAIN-SUFFIX,中文", "DOMAIN,a.b..cdn", "DOMAIN-SUFFIX,io",
		"AND,((DOMAIN-SUFFIX,cdn),(PROCESS-NAME,Telegram))", "OR,((DOMAIN,apple.io),(SRC-IP-CIDR,10.0.0.0/8))",
		"OR,((AND,((DOMAIN-SUFFIX,net),(PROCESS-NAME,Telegram))),(DOMAIN,x-y.com))",
		"AND,((DOMAIN,", "NOT,((DOMAIN,google.com))",
	}
	for seed := int64(1); seed <= 30; seed++ {
		rng := rand.New(rand.NewSource(seed))
		lines, hosts, ips := randomClassicalCorpus(rng, 5+rng.Intn(400))
		for _, edge := range edges {
			at := rng.Intn(len(lines) + 1)
			lines = append(lines[:at], append([]string{edge}, lines[at:]...)...)
		}
		hosts = append(hosts, "google.com", "www.google.com", "cdn.example", "x.cn", "a.b..cdn", ".example", "中文", "b.中文", "io", "")
		var metas []C.Metadata
		for i := 0; i < 24; i++ {
			m := C.Metadata{DstPort: uint16(440 + rng.Intn(8)), SrcIP: ips[rng.Intn(len(ips))]}
			if rng.Intn(3) == 0 {
				m.DstIP = ips[rng.Intn(len(ips))]
			}
			if rng.Intn(5) == 0 {
				m.Process = "telegram"
			}
			metas = append(metas, m)
		}
		for _, corpus := range []struct {
			name   string
			lines  []string
			probes []string
		}{
			{"every kind", lines, hosts},
			{"no catch-all", withoutCatchAlls(lines), probeHosts(withoutCatchAlls(lines), hosts)},
		} {
			reference := loadUpstreamClassical(corpus.lines)
			for _, format := range []P.RuleFormat{P.TextRule, P.YamlRule} {
				indexPath, sourcePath := stageCompiled(t, t.TempDir(), corpus.lines, format)
				_ = os.Remove(sourcePath)
				compiled := loadStaged(indexPath, sourcePath, format)
				sameAsUpstream(t, corpus.name+" "+format.String(), seed, compiled, reference, corpus.probes, metas)
			}
		}
	}
}

func TestCompiledClassicalIndexFallsBackToItsSource(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	lines, hosts, ips := randomClassicalCorpus(rng, 300)
	lines = withoutCatchAlls(append(lines, "DOMAIN,spoilme.zzq", "IP-CIDR,198.18.7.0/24,no-resolve"))
	reference := loadUpstreamClassical(lines)
	probes := probeHosts(lines, hosts)
	metas := []C.Metadata{{}, {DstIP: ips[0]}, {DstIP: ips[1], SrcIP: ips[2]}, {DstIP: netip.MustParseAddr("198.18.7.9")}}
	flip := func(path, text string, at int) {
		data, _ := os.ReadFile(path)
		found := bytes.Index(data, []byte(text))
		if found < 0 {
			t.Fatalf("%q is not in the index", text)
		}
		data[found+at] ^= 0x01
		_ = os.WriteFile(path, data, 0o644)
	}
	for name, spoil := range map[string]func(path string){
		"missing":   func(path string) { _ = os.Remove(path) },
		"truncated": func(path string) { data, _ := os.ReadFile(path); _ = os.WriteFile(path, data[:len(data)/2], 0o644) },
		"changed": func(path string) {
			data, _ := os.ReadFile(path)
			data[len(data)-3] ^= 0x55
			_ = os.WriteFile(path, data, 0o644)
		},
		"changed in the middle": func(path string) {
			data, _ := os.ReadFile(path)
			data[len(data)/2] ^= 0x55
			_ = os.WriteFile(path, data, 0o644)
		},
		"version": func(path string) {
			data, _ := os.ReadFile(path)
			data[8] = 9
			_ = os.WriteFile(path, data, 0o644)
		},
		"a name changed": func(path string) { flip(path, "spoilme.zzq", 0) },
		"a rule changed": func(path string) { flip(path, "CIP1", 40) },
	} {
		for _, format := range []P.RuleFormat{P.TextRule, P.YamlRule} {
			indexPath, sourcePath := stageCompiled(t, t.TempDir(), lines, format)
			spoil(indexPath)
			sameAsUpstream(t, name+" "+format.String(), 7, loadStaged(indexPath, sourcePath, format), reference, probes, metas)
		}
	}
	indexPath, sourcePath := stageCompiled(t, t.TempDir(), lines, P.TextRule)
	_ = os.Remove(indexPath)
	_ = os.Remove(sourcePath)
	if matcher := loadStaged(indexPath, sourcePath, P.TextRule); matcher.Count() != 0 {
		t.Errorf("count %d with nothing to read", matcher.Count())
	}
	link := func(path string) {
		if err := os.Rename(path, path+".real"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(path+".real", path); err != nil {
			t.Fatal(err)
		}
	}
	indexPath, sourcePath = stageCompiled(t, t.TempDir(), lines, P.TextRule)
	link(indexPath)
	sameAsUpstream(t, "a linked index", 7, loadStaged(indexPath, sourcePath, P.TextRule), reference, probes, metas)
	_ = os.Remove(sourcePath)
	if matcher := loadStaged(indexPath, sourcePath, P.TextRule); matcher.Count() != 0 {
		t.Errorf("count %d through a linked index", matcher.Count())
	}
	indexPath, sourcePath = stageCompiled(t, t.TempDir(), lines, P.TextRule)
	_ = os.Remove(indexPath)
	link(sourcePath)
	if matcher := loadStaged(indexPath, sourcePath, P.TextRule); matcher.Count() != 0 {
		t.Errorf("count %d through a linked source", matcher.Count())
	}
}

func TestCompiledClassicalIndexStubIsHonouredOnlyInItsPlace(t *testing.T) {
	dir := t.TempDir()
	lines := []string{"DOMAIN-SUFFIX,example.com", "IP-CIDR,10.0.0.0/8"}
	indexPath, sourcePath := stageCompiled(t, dir, lines, P.TextRule)
	stub := stubFor(indexPath, sourcePath, P.TextRule)

	t.Chdir(dir)
	plain := RP.NewClassicalStrategy(rules.ParseRule)
	plain.Insert(strings.TrimSpace(stub))
	plain.FinishInsert()
	if plain.Count() != 0 {
		t.Errorf("a stub outside a stub file loaded %d rules", plain.Count())
	}
	if loaded := loadStub(dir, stub); loaded.Count() != 2 {
		t.Errorf("the stub in its place loaded %d rules", loaded.Count())
	}
	elsewhere := t.TempDir()
	outsideIndex, outsideSource := stageCompiled(t, elsewhere, lines, P.TextRule)
	for _, names := range [][2]string{
		{"../" + filepath.Base(elsewhere) + "/" + filepath.Base(outsideIndex), filepath.Base(sourcePath)},
		{filepath.Base(indexPath), "../" + filepath.Base(elsewhere) + "/" + filepath.Base(outsideSource)},
		{outsideIndex, outsideSource},
		{"..", filepath.Base(sourcePath)},
		{"", filepath.Base(sourcePath)},
	} {
		line := RP.ClashClassicalIndexStub(names[0], compiledChecksums[indexPath], names[1], P.TextRule)
		if loaded := loadStub(dir, line); loaded.Count() != 0 {
			t.Errorf("stub %q loaded %d rules", line, loaded.Count())
		}
	}
}

func TestCompiledClassicalIndexThroughAFileProvider(t *testing.T) {
	RP.UseTestTunnel(t)
	dir := t.TempDir()
	lines := []string{"DOMAIN-SUFFIX,example.com", "AND,((DOMAIN,a.example.org),(PROCESS-NAME,Telegram))", "IP-CIDR,10.0.0.0/8,no-resolve"}
	indexPath, sourcePath := stageCompiled(t, dir, lines, P.TextRule)
	stub := stubFor(indexPath, sourcePath, P.TextRule)
	for name, want := range map[string]int{"set" + RP.ClashClassicalIndexStubSuffix: 3, "set.provider": 0, "set.stub.txt": 0} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(stub), 0o644); err != nil {
			t.Fatal(err)
		}
		provider := RP.NewRuleSetProvider(name, P.Classical, P.TextRule, 0, resource.NewFileVehicle(path), nil, nil, rules.ParseRule)
		if err := provider.Initial(); err != nil && want != 0 {
			t.Fatalf("%s: %v", name, err)
		}
		if got := provider.Count(); got != want {
			t.Errorf("%s: %d rules, want %d", name, got, want)
		}
		helper := C.RuleMatchHelper{ResolveIP: func() {}, FindProcess: func() {}}
		if matched := provider.Match(&C.Metadata{Host: "www.example.com"}, helper); matched != (want != 0) {
			t.Errorf("%s: matched %v", name, matched)
		}
		if closer, ok := provider.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
	}
}

func TestCompiledClassicalIndexStubStandsAlone(t *testing.T) {
	lines := []string{"DOMAIN-SUFFIX,example.com", "DOMAIN-KEYWORD,ads"}
	indexPath, sourcePath := stageCompiled(t, t.TempDir(), lines, P.TextRule)
	_ = os.Remove(sourcePath)
	matcher := loadStub(filepath.Dir(indexPath), stubFor(indexPath, sourcePath, P.TextRule)+"DOMAIN,extra.test\n")
	if matcher.Count() != 2 {
		t.Errorf("count %d", matcher.Count())
	}
	helper := C.RuleMatchHelper{ResolveIP: func() {}, FindProcess: func() {}}
	if matcher.Match(&C.Metadata{Host: "extra.test"}, helper) {
		t.Error("a line after the stub was matched")
	}
	if !matcher.Match(&C.Metadata{Host: "www.example.com"}, helper) || !matcher.Match(&C.Metadata{Host: "x.ads.y"}, helper) {
		t.Error("the compiled set does not answer")
	}
}

func TestCompiledClassicalIndexWarnsWhereItLoads(t *testing.T) {
	var logged bytes.Buffer
	logrus.SetOutput(&logged)
	t.Cleanup(func() { logrus.SetOutput(os.Stderr) })
	lines := []string{"DOMAIN-SUFFIX,example.com", "INVALID_RULE,x", "DOMAIN,", "IP-CIDR,10.0.0.0/8"}
	indexPath, sourcePath := stageCompiled(t, t.TempDir(), lines, P.TextRule)
	if compiled := logged.String(); strings.Contains(compiled, "parse classical rule") {
		t.Errorf("compiling warned:\n%s", compiled)
	}
	logged.Reset()
	_ = os.Remove(sourcePath)
	if matcher := loadStaged(indexPath, sourcePath, P.TextRule); matcher.Count() != 2 {
		t.Errorf("count %d", matcher.Count())
	}
	for _, want := range []string{"parse classical rule [INVALID_RULE,x] error", "parse classical rule [DOMAIN,] error"} {
		if !strings.Contains(logged.String(), want) {
			t.Errorf("loading did not warn %q:\n%s", want, logged.String())
		}
	}
}

func TestCompiledClassicalIndexOfAnotherSetIsNotUsed(t *testing.T) {
	rng := rand.New(rand.NewSource(11))
	lines, hosts, ips := randomClassicalCorpus(rng, 200)
	lines = withoutCatchAlls(append(lines, "DOMAIN,own.example"))
	indexPath, sourcePath := stageCompiled(t, t.TempDir(), lines, P.TextRule)
	other, err := RP.ClashCompileClassicalIndex([]string{"DOMAIN,foreign.zzq", "DOMAIN-SUFFIX,foreign-zzq.test"}, rules.ParseRule)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(indexPath, other.Bytes, 0o644); err != nil {
		t.Fatal(err)
	}
	matcher := loadStaged(indexPath, sourcePath, P.TextRule)
	sameAsUpstream(t, "another set's index", 11, matcher, loadUpstreamClassical(lines), probeHosts(lines, hosts), []C.Metadata{{}, {DstIP: ips[0]}})
	helper := C.RuleMatchHelper{ResolveIP: func() {}, FindProcess: func() {}}
	if matcher.Match(&C.Metadata{Host: "foreign.zzq"}, helper) {
		t.Error("the other set's rules were loaded")
	}
}

func TestCompiledClassicalIndexChecksumReadsAsAsked(t *testing.T) {
	indexPath, _ := stageCompiled(t, t.TempDir(), []string{"DOMAIN,a.example", "IP-CIDR,10.0.0.0/8"}, P.TextRule)
	want := compiledChecksums[indexPath]
	for _, whole := range []bool{false, true} {
		if got, ok := RP.ClashClassicalIndexChecksumOf(indexPath, whole); !ok || got != want {
			t.Errorf("whole %v: %08x %v, want %08x", whole, got, ok, want)
		}
	}
	data, _ := os.ReadFile(indexPath)
	data[len(data)-2] ^= 0x10
	if err := os.WriteFile(indexPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if got, ok := RP.ClashClassicalIndexChecksumOf(indexPath, false); !ok || got != want {
		t.Errorf("header of a changed index: %08x %v", got, ok)
	}
	if _, ok := RP.ClashClassicalIndexChecksumOf(indexPath, true); ok {
		t.Error("a changed index checked out whole")
	}
	link := indexPath + ".link"
	if err := os.Symlink(indexPath, link); err != nil {
		t.Fatal(err)
	}
	if _, ok := RP.ClashClassicalIndexChecksumOf(link, false); ok {
		t.Error("an index was read through a link")
	}
}

func TestAClassicalSourcePastTheLimitIsNotReadInTheIndexsPlace(t *testing.T) {
	lines := []string{"DOMAIN,a.example", "IP-CIDR,10.0.0.0/8,no-resolve"}
	indexPath, sourcePath := stageCompiled(t, t.TempDir(), lines, P.TextRule)
	_ = os.Remove(indexPath)
	if matcher := loadStaged(indexPath, sourcePath, P.TextRule); matcher.Count() != 2 {
		t.Fatalf("a source within the limit is read: count %d", matcher.Count())
	}
	previous := RP.ClashClassicalSourceFallbackLimit
	RP.ClashClassicalSourceFallbackLimit = 8
	t.Cleanup(func() { RP.ClashClassicalSourceFallbackLimit = previous })
	if matcher := loadStaged(indexPath, sourcePath, P.TextRule); matcher.Count() != 0 {
		t.Fatalf("a source past the limit was read: count %d", matcher.Count())
	}
}

func TestAClassicalIndexRefusesWhatWouldStayOnTheHeap(t *testing.T) {
	var alternating, others, grouped []string
	alternating = append(alternating, "DOMAIN,example.org")
	for i := 0; i <= RP.ClashClassicalIPRunLimit; i++ {
		line := fmt.Sprintf("IP-CIDR,10.%d.%d.0/24", (i>>8)&255, i&255)
		if i%2 == 1 {
			line += ",no-resolve"
		}
		alternating = append(alternating, line)
	}
	for i := 0; i <= RP.ClashClassicalOthersLimit; i++ {
		others = append(others, fmt.Sprintf("DST-PORT,%d", 1+i%60000))
	}
	for i := 0; i < 50000; i++ {
		grouped = append(grouped, fmt.Sprintf("IP-CIDR,11.%d.%d.0/24,no-resolve", (i>>8)&255, i&255))
	}
	for name, lines := range map[string][]string{"alternating IP kinds": alternating, "lines parsed at load": others} {
		if _, err := RP.ClashCompileClassicalIndex(lines, rules.ParseRule); !errors.Is(err, RP.ErrClassicalTooHeavy) {
			t.Fatalf("%s: compiled (%v)", name, err)
		}
	}
	index, err := RP.ClashCompileClassicalIndex(grouped, rules.ParseRule)
	if err != nil || index.IPRules != 50000 || index.Names != 0 {
		t.Fatalf("grouped IP ranges: %+v (%v)", index.Rules, err)
	}
}

func TestRulesInsideLogicRulesCountAgainstTheLimits(t *testing.T) {
	lines := []string{"DOMAIN,example.org"}
	for i := 0; i <= RP.ClashClassicalRegexLimit; i++ {
		lines = append(lines, fmt.Sprintf("AND,((DOMAIN-REGEX,^n%d\\.example$),(NETWORK,tcp))", i))
	}
	if _, err := RP.ClashCompileClassicalIndex(lines, rules.ParseRule); !errors.Is(err, RP.ErrClassicalTooHeavy) {
		t.Fatalf("1,001 wrapped expressions compiled (%v)", err)
	}
	if index, err := RP.ClashCompileClassicalIndex(lines[:RP.ClashClassicalRegexLimit], rules.ParseRule); err != nil || index.Rules != RP.ClashClassicalRegexLimit {
		t.Fatalf("999 wrapped expressions: %v", err)
	}
	for name, shape := range map[string]string{
		"lower case": "AND,((domain-regex,^n%d\\.example$),(NETWORK,tcp))",
		"spaces":     "AND,(( DOMAIN-REGEX ,^n%d\\.example$),(NETWORK,tcp))",
		"mixed case": "AND,((Domain-Regex,^n%d\\.example$),(NETWORK,tcp))",
		"dotless i":  "AND,((domaın-regex,^n%d\\.example$),(NETWORK,tcp))",
		"nested":     "OR,((AND,((DOMAIN-REGEX,^n%d\\.example$),(NETWORK,tcp))),(NETWORK,udp))",
	} {
		lines := []string{"DOMAIN,example.org"}
		for i := 0; i <= RP.ClashClassicalRegexLimit; i++ {
			lines = append(lines, fmt.Sprintf(shape, i))
		}
		if loadUpstreamClassical(lines[:2]).Count() != 2 {
			t.Fatalf("%s: upstream does not parse %q", name, lines[1])
		}
		if _, err := RP.ClashCompileClassicalIndex(lines, rules.ParseRule); !errors.Is(err, RP.ErrClassicalTooHeavy) {
			t.Fatalf("%s: 1,001 wrapped expressions compiled (%v)", name, err)
		}
		s := RP.NewClassicalStrategy(rules.ParseRule)
		for _, line := range lines {
			s.Insert(line)
		}
		s.FinishInsert()
		if s.Count() != 0 {
			t.Fatalf("%s: the text load holds %d rules", name, s.Count())
		}
	}
}

func TestRulesInsideLogicRulesCountAgainstTheParsedLines(t *testing.T) {
	lines := []string{"DOMAIN,example.org"}
	for i := 0; i <= RP.ClashClassicalOthersLimit/3; i++ {
		lines = append(lines, fmt.Sprintf("AND,((NETWORK,tcp),(DST-PORT,%d))", 1+i%60000))
	}
	if _, err := RP.ClashCompileClassicalIndex(lines, rules.ParseRule); !errors.Is(err, RP.ErrClassicalTooHeavy) {
		t.Fatalf("%d lines holding %d rules compiled (%v)", len(lines)-1, 2*(len(lines)-1), err)
	}
	if index, err := RP.ClashCompileClassicalIndex(lines[:len(lines)-1], rules.ParseRule); err != nil || index.Rules != len(lines)-1 {
		t.Fatalf("%d lines holding %d rules: %v", len(lines)-2, 2*(len(lines)-2), err)
	}
}
