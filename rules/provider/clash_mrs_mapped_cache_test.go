package provider_test

import (
	"bytes"
	"fmt"
	"math/rand"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	RP "github.com/ProjectClash/Clash/rules/provider"

	"github.com/klauspost/compress/zstd"
)

func mrsOf(t *testing.T, behavior P.RuleBehavior, lines []string) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := RP.ConvertToMrs([]byte(strings.Join(lines, "\n")), behavior, P.TextRule, &b); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func useMrsMappedCache(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	RP.ClashSetMrsMappedCacheDirectory(root, "test-core")
	t.Cleanup(func() { RP.ClashSetMrsMappedCacheDirectory("", "") })
	dir := filepath.Join(root, RP.MrsMappedCacheGenerationForTest())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func cacheFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

func randomDomains(seed int64, n int) []string {
	random := rand.New(rand.NewSource(seed))
	var lines []string
	for i := 0; i < n; i++ {
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
	return lines
}

func TestAnMrsDomainSetIsServedFromTheMappedCache(t *testing.T) {
	mrs := mrsOf(t, P.Domain, randomDomains(7, 3000))
	reference, err := RP.ParseMrsDomainForTest("p", mrs)
	if err != nil || reference.MappedForTest() || reference.Count() == 0 {
		t.Fatalf("without a cache the set is read onto the heap: mapped=%v count=%d err=%v", reference.MappedForTest(), reference.Count(), err)
	}
	dir := useMrsMappedCache(t)
	writes := RP.MrsMappedCacheWritesForTest()
	first, err := RP.ParseMrsDomainForTest("p", mrs)
	if err != nil || !first.MappedForTest() || first.Count() != reference.Count() {
		t.Fatalf("first read: mapped=%v count=%d (want %d) err=%v", first.MappedForTest(), first.Count(), reference.Count(), err)
	}
	if n := len(cacheFiles(t, dir)); n != 1 || RP.MrsMappedCacheWritesForTest() != writes+1 {
		t.Fatalf("first read wrote %d sets into %d files", RP.MrsMappedCacheWritesForTest()-writes, n)
	}
	second, err := RP.ParseMrsDomainForTest("p", mrs)
	if err != nil || !second.MappedForTest() || second.Count() != reference.Count() {
		t.Fatalf("second read: mapped=%v count=%d err=%v", second.MappedForTest(), second.Count(), err)
	}
	if RP.MrsMappedCacheWritesForTest() != writes+1 {
		t.Fatal("a second read of the same content wrote the set again")
	}
	random := rand.New(rand.NewSource(9))
	for i := 0; i < 20000; i++ {
		host := fmt.Sprintf("%sh%d.example%d.com", []string{"", "a.", "b.c."}[i%3], random.Intn(600), random.Intn(25))
		m := &C.Metadata{Host: host}
		want := reference.Match(m, C.RuleMatchHelper{})
		if first.Match(m, C.RuleMatchHelper{}) != want || second.Match(m, C.RuleMatchHelper{}) != want {
			t.Fatalf("%s: mapped answers differ from the heap set's %v", host, want)
		}
	}
	name := filepath.Join(dir, cacheFiles(t, dir)[0])
	damaged, _ := os.ReadFile(name)
	damaged[len(damaged)/2] ^= 1
	if err := os.WriteFile(name, damaged, 0o600); err != nil {
		t.Fatal(err)
	}
	third, err := RP.ParseMrsDomainForTest("p", mrs)
	if err != nil || !third.MappedForTest() || third.Count() != reference.Count() {
		t.Fatalf("after damage: mapped=%v count=%d err=%v", third.MappedForTest(), third.Count(), err)
	}
	if RP.MrsMappedCacheWritesForTest() != writes+2 || len(cacheFiles(t, dir)) != 1 {
		t.Fatalf("a damaged file was not replaced: %d writes, files %v", RP.MrsMappedCacheWritesForTest()-writes, cacheFiles(t, dir))
	}
	if _, err := RP.ParseMrsDomainForTest("other", mrsOf(t, P.Domain, randomDomains(8, 50))); err != nil || len(cacheFiles(t, dir)) != 2 {
		t.Fatalf("another set: err=%v files %v", err, cacheFiles(t, dir))
	}
	if _, err := RP.ParseMrsDomainForTest("garbage", []byte("not an mrs")); err == nil || len(cacheFiles(t, dir)) != 2 {
		t.Fatalf("garbage: err=%v files %v", err, cacheFiles(t, dir))
	}
}

func TestAnMrsIPSetIsServedFromTheMappedCache(t *testing.T) {
	random := rand.New(rand.NewSource(3))
	var lines []string
	for i := 0; i < 2000; i++ {
		if i%4 == 0 {
			lines = append(lines, fmt.Sprintf("2001:db8:%x::/48", random.Intn(4096)))
		} else {
			lines = append(lines, fmt.Sprintf("%d.%d.%d.0/24", 1+random.Intn(200), random.Intn(256), random.Intn(256)))
		}
	}
	mrs := mrsOf(t, P.IPCIDR, lines)
	reference, err := RP.ParseMrsIPCidrForTest("p", mrs)
	if err != nil || reference.MappedForTest() {
		t.Fatalf("without a cache: mapped=%v err=%v", reference.MappedForTest(), err)
	}
	useMrsMappedCache(t)
	for round := 0; round < 2; round++ {
		mapped, err := RP.ParseMrsIPCidrForTest("p", mrs)
		if err != nil || !mapped.MappedForTest() || mapped.Count() != reference.Count() {
			t.Fatalf("round %d: mapped=%v count=%d (want %d) err=%v", round, mapped.MappedForTest(), mapped.Count(), reference.Count(), err)
		}
		for i := 0; i < 20000; i++ {
			var ip netip.Addr
			if i%4 == 0 {
				ip = netip.MustParseAddr(fmt.Sprintf("2001:db8:%x::1", random.Intn(4096)))
			} else {
				ip = netip.AddrFrom4([4]byte{byte(1 + random.Intn(200)), byte(random.Intn(256)), byte(random.Intn(256)), 9})
			}
			m := &C.Metadata{DstIP: ip}
			if got, want := mapped.Match(m, C.RuleMatchHelper{}), reference.Match(m, C.RuleMatchHelper{}); got != want {
				t.Fatalf("%s: mapped %v, heap %v", ip, got, want)
			}
		}
		if got, want := mapped.ToIpCidr().Prefixes(), reference.ToIpCidr().Prefixes(); fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("route set differs: %d prefixes, heap %d", len(got), len(want))
		}
	}
}

func TestTheMrsMappedCacheSweepRemovesOnlyOldUnusedSets(t *testing.T) {
	dir := useMrsMappedCache(t)
	if _, err := RP.ParseMrsDomainForTest("p", mrsOf(t, P.Domain, randomDomains(1, 100))); err != nil {
		t.Fatal(err)
	}
	used := cacheFiles(t, dir)[0]
	old := time.Now().Add(-30 * 24 * time.Hour)
	_ = os.Chtimes(filepath.Join(dir, used), old, old)
	stale := strings.Repeat("ab", 32) + ".domain.5"
	recent := strings.Repeat("cd", 32) + ".ipcidr.7"
	foreign := "notes.txt"
	for _, name := range []string{stale, recent, foreign} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.Chtimes(filepath.Join(dir, stale), old, old)
	_ = os.Chtimes(filepath.Join(dir, foreign), old, old)
	orphan := ".mrs-mapped-123"
	if err := os.WriteFile(filepath.Join(dir, orphan), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(filepath.Join(dir, orphan), old, old)
	otherCore := filepath.Join(filepath.Dir(dir), "0123456789abcdef")
	if err := os.MkdirAll(otherCore, 0o700); err != nil {
		t.Fatal(err)
	}
	RP.ClashSweepMrsMappedCache(7 * 24 * time.Hour)
	if _, err := os.Stat(otherCore); !os.IsNotExist(err) {
		t.Fatalf("another core's mappings stayed: %v", err)
	}
	got := strings.Join(cacheFiles(t, dir), " ")
	if strings.Contains(got, orphan) {
		t.Fatalf("the orphaned temporary file stayed: %s", got)
	}
	for _, keep := range []string{used, recent, foreign} {
		if !strings.Contains(got, keep) {
			t.Fatalf("%s was removed: %s", keep, got)
		}
	}
	if strings.Contains(got, stale) {
		t.Fatalf("the stale set stayed: %s", got)
	}
}

func TestAnUnreadableCachedSetIsKept(t *testing.T) {
	dir := useMrsMappedCache(t)
	mrs := mrsOf(t, P.Domain, randomDomains(4, 200))
	if _, err := RP.ParseMrsDomainForTest("p", mrs); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(dir, cacheFiles(t, dir)[0])
	if err := os.Chmod(name, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(name, 0o600) })
	RP.ClashSetMrsMappedCacheDirectory(filepath.Dir(dir), "test-core")
	writes := RP.MrsMappedCacheWritesForTest()
	s, err := RP.ParseMrsDomainForTest("p", mrs)
	if err != nil || s.MappedForTest() || s.Count() == 0 {
		t.Fatalf("unreadable cache: mapped=%v count=%d err=%v", s.MappedForTest(), s.Count(), err)
	}
	if _, err := os.Lstat(name); err != nil || RP.MrsMappedCacheWritesForTest() != writes {
		t.Fatalf("the unreadable file was replaced or removed: %v", err)
	}
}

func TestConcurrentReadsOfTheMrsMappedCacheAgree(t *testing.T) {
	dir := useMrsMappedCache(t)
	contents := [][]byte{mrsOf(t, P.Domain, randomDomains(11, 800)), mrsOf(t, P.Domain, randomDomains(12, 800))}
	type result struct {
		which, count int
		mapped       bool
		err          error
	}
	results := make(chan result, 32)
	for i := 0; i < 32; i++ {
		go func(i int) {
			s, err := RP.ParseMrsDomainForTest(fmt.Sprintf("p%d", i), contents[i%2])
			results <- result{i % 2, s.Count(), s.MappedForTest(), err}
		}(i)
	}
	counts := map[int]int{}
	for i := 0; i < 32; i++ {
		r := <-results
		if r.err != nil || !r.mapped {
			t.Fatalf("read of content %d: mapped=%v err=%v", r.which, r.mapped, r.err)
		}
		if c, ok := counts[r.which]; ok && c != r.count {
			t.Fatalf("content %d counted %d and %d", r.which, c, r.count)
		}
		counts[r.which] = r.count
	}
	if names := cacheFiles(t, dir); len(names) != 2 {
		t.Fatalf("files %v, want one per content", names)
	}
}

func TestTheSharedMrsHelpersDoNotUseTheCache(t *testing.T) {
	dir := useMrsMappedCache(t)
	mrs := mrsOf(t, P.Domain, randomDomains(5, 300))
	s, err := RP.HelperParseMrsDomainForTest(mrs)
	if err != nil || s.MappedForTest() || len(cacheFiles(t, dir)) != 0 {
		t.Fatalf("a helper's parse: mapped=%v files %v err=%v", s.MappedForTest(), cacheFiles(t, dir), err)
	}
	compiled, err := RP.ClashMappedFromMrs(mrs, P.Domain)
	if err != nil || compiled.Count != s.Count() || len(compiled.Bytes) <= 32 {
		t.Fatalf("ClashMappedFromMrs with the cache on: count %d (want %d), %d bytes, err=%v", compiled.Count, s.Count(), len(compiled.Bytes), err)
	}
	var text bytes.Buffer
	if err := RP.ConvertToMrs(mrs, P.Domain, P.MrsRule, &text); err != nil || text.Len() == 0 {
		t.Fatalf("MRS to text with the cache on: %d bytes, err=%v", text.Len(), err)
	}
}

func TestAnMrsWithNoPositiveCountIsNotCached(t *testing.T) {
	dir := useMrsMappedCache(t)
	decoder, err := zstd.NewReader(bytes.NewReader(mrsOf(t, P.Domain, randomDomains(6, 100))))
	if err != nil {
		t.Fatal(err)
	}
	var plain bytes.Buffer
	if _, err := plain.ReadFrom(decoder); err != nil {
		t.Fatal(err)
	}
	decoder.Close()
	raw := plain.Bytes()
	copy(raw[5:13], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfb})
	var patched bytes.Buffer
	encoder, _ := zstd.NewWriter(&patched)
	_, _ = encoder.Write(raw)
	_ = encoder.Close()
	s, err := RP.ParseMrsDomainForTest("p", patched.Bytes())
	if err != nil || s.MappedForTest() {
		t.Fatalf("mapped=%v err=%v", s.MappedForTest(), err)
	}
	if files := cacheFiles(t, dir); len(files) != 0 {
		t.Fatalf("wrote %v", files)
	}
}

func TestANewerContentReplacesTheProvidersMapping(t *testing.T) {
	dir := useMrsMappedCache(t)
	a, b, c := mrsOf(t, P.Domain, randomDomains(21, 100)), mrsOf(t, P.Domain, randomDomains(22, 100)), mrsOf(t, P.Domain, randomDomains(23, 100))
	if _, err := RP.ParseMrsDomainForTest("p", a); err != nil {
		t.Fatal(err)
	}
	first := cacheFiles(t, dir)
	if _, err := RP.ParseMrsDomainForTest("p", b); err != nil {
		t.Fatal(err)
	}
	second := cacheFiles(t, dir)
	if len(second) != 1 || second[0] == first[0] {
		t.Fatalf("after p's newer content: %v (before %v)", second, first)
	}
	if _, err := RP.ParseMrsDomainForTest("q", b); err != nil {
		t.Fatal(err)
	}
	if _, err := RP.ParseMrsDomainForTest("p", c); err != nil {
		t.Fatal(err)
	}
	if got := cacheFiles(t, dir); len(got) != 2 || !strings.Contains(strings.Join(got, " "), second[0]) {
		t.Fatalf("q still reads %s, files %v", second[0], got)
	}
}

func TestTheSweepKeepsASetReadNow(t *testing.T) {
	dir := useMrsMappedCache(t)
	if _, err := RP.ParseMrsDomainForTest("p", mrsOf(t, P.Domain, randomDomains(31, 100))); err != nil {
		t.Fatal(err)
	}
	name := cacheFiles(t, dir)[0]
	old := time.Now().Add(-30 * 24 * time.Hour)
	_ = os.Chtimes(filepath.Join(dir, name), old, old)
	RP.ClashSweepMrsMappedCache(-time.Hour)
	if got := cacheFiles(t, dir); len(got) != 1 {
		t.Fatalf("the set read now was swept: %v", got)
	}
}

func TestAMissingCachedFileIsWrittenAgain(t *testing.T) {
	dir := useMrsMappedCache(t)
	mrs := mrsOf(t, P.Domain, randomDomains(41, 100))
	if _, err := RP.ParseMrsDomainForTest("p", mrs); err != nil {
		t.Fatal(err)
	}
	name := cacheFiles(t, dir)[0]
	if err := os.Remove(filepath.Join(dir, name)); err != nil {
		t.Fatal(err)
	}
	writes := RP.MrsMappedCacheWritesForTest()
	s, err := RP.ParseMrsDomainForTest("q", mrs)
	if err != nil || !s.MappedForTest() || RP.MrsMappedCacheWritesForTest() != writes+1 {
		t.Fatalf("after the file went: mapped=%v writes=%d err=%v", s.MappedForTest(), RP.MrsMappedCacheWritesForTest()-writes, err)
	}
	if got := cacheFiles(t, dir); len(got) != 1 || got[0] != name {
		t.Fatalf("files %v, want %s again", got, name)
	}
}

func TestTheSweepRemovesSetsBesideTheGenerations(t *testing.T) {
	dir := useMrsMappedCache(t)
	root := filepath.Dir(dir)
	stray := strings.Repeat("ef", 32) + ".domain.9"
	if err := os.WriteFile(filepath.Join(root, stray), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	keep := "README"
	if err := os.WriteFile(filepath.Join(root, keep), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	RP.ClashSweepMrsMappedCache(time.Hour)
	if _, err := os.Stat(filepath.Join(root, stray)); !os.IsNotExist(err) {
		t.Fatalf("the stray set stayed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, keep)); err != nil {
		t.Fatalf("a file that is not the cache's was removed: %v", err)
	}
}
