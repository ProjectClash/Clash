package geodata

import (
	"fmt"
	"net/netip"
	"os"
	"sync"
	"testing"

	"github.com/ProjectClash/Clash/component/cidr"
	"github.com/ProjectClash/Clash/component/geodata/compiled"
	"github.com/ProjectClash/Clash/component/geodata/router"
	C "github.com/ProjectClash/Clash/constant"
)

type countingIPLoader struct {
	reads *int
	list  []*router.CIDR
}

func (l countingIPLoader) LoadSiteByPath(_, _ string) ([]*router.Domain, error) {
	return nil, fmt.Errorf("not used")
}

func (l countingIPLoader) LoadSiteByBytes([]byte, string) ([]*router.Domain, error) {
	return nil, fmt.Errorf("not used")
}

func (l countingIPLoader) LoadIPByPath(_, _ string) ([]*router.CIDR, error) {
	*l.reads++
	return l.list, nil
}

func (l countingIPLoader) LoadIPByBytes([]byte, string) ([]*router.CIDR, error) {
	return nil, fmt.Errorf("not used")
}

func stageCountingIPLoader(t *testing.T, name string) *int {
	t.Helper()
	reads := 0
	list := []*router.CIDR{{Ip: netip.MustParseAddr("203.0.113.0").AsSlice(), Prefix: 24}}
	RegisterGeoDataLoaderImplementationCreator(name, func() LoaderImplementation {
		return countingIPLoader{reads: &reads, list: list}
	})
	previousLoader := geoLoaderName
	previousMode := geoMode.Load()
	SetLoader(name)
	SetGeodataMode(true)
	t.Cleanup(func() {
		geoLoaderName = previousLoader
		geoMode.Store(previousMode)
		delete(loaders, name)
	})
	return &reads
}

func stageCompiledGeoIPHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	previous := C.Path.HomeDir()
	C.SetHomeDir(home)
	previousOnly := CompiledGeoIPOnly()
	t.Cleanup(func() {
		C.SetHomeDir(previous)
		SetCompiledGeoIPOnly(previousOnly)
	})
	ClearGeoIPCache()
	t.Cleanup(ClearGeoIPCache)
	return CompiledGeoIPDir()
}

func writeCompiledCountry(t *testing.T, directory, country string, prefixes ...string) {
	t.Helper()
	set := cidr.NewIpCidrSet()
	for _, prefix := range prefixes {
		if err := set.AddIpCidr(netip.MustParsePrefix(prefix)); err != nil {
			t.Fatal(err)
		}
	}
	if err := set.Merge(); err != nil {
		t.Fatal(err)
	}
	if err := compiled.StoreIPCIDR(directory, country, set, len(prefixes)); err != nil {
		t.Fatal(err)
	}
}

func TestCompiledCountryIsPreferredOverSource(t *testing.T) {
	directory := stageCompiledGeoIPHome(t)
	reads := stageCountingIPLoader(t, "compiled-geoip-preference-probe")
	writeCompiledCountry(t, directory, "cn", "1.1.1.0/24")

	matcher, err := LoadGeoIPMatcher("cn")
	if err != nil {
		t.Fatal(err)
	}
	if *reads != 0 {
		t.Fatalf("source was decoded %d times despite a compiled artifact", *reads)
	}
	if !matcher.Match(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("the compiled country does not answer for what it holds")
	}
	if matcher.Match(netip.MustParseAddr("203.0.113.1")) {
		t.Fatal("the matcher holds the source loader's addresses, so the artifact lost")
	}
}

func TestCompiledOnlyGeoIPDegradesInsteadOfDecoding(t *testing.T) {
	stageCompiledGeoIPHome(t)
	reads := stageCountingIPLoader(t, "compiled-geoip-degrade-probe")
	SetCompiledGeoIPOnly(true)

	matcher, err := LoadGeoIPMatcher("us")
	if err != nil {
		t.Fatalf("an uncompiled country failed instead of matching nothing: %v", err)
	}
	if *reads != 0 {
		t.Fatalf("the compiled-only runtime decoded source %d times", *reads)
	}
	if matcher.Match(netip.MustParseAddr("203.0.113.1")) {
		t.Fatal("an uncompiled country matched an address")
	}
	if matcher.Count() != 0 {
		t.Fatalf("an uncompiled country reports %d records", matcher.Count())
	}
}

func TestGeoIPStillDecodesWhereItIsAffordable(t *testing.T) {
	stageCompiledGeoIPHome(t)
	reads := stageCountingIPLoader(t, "compiled-geoip-app-probe")
	SetCompiledGeoIPOnly(false)

	matcher, err := LoadGeoIPMatcher("us")
	if err != nil {
		t.Fatal(err)
	}
	if *reads != 1 {
		t.Fatalf("source was decoded %d times, want exactly 1", *reads)
	}
	if !matcher.Match(netip.MustParseAddr("203.0.113.1")) {
		t.Fatal("the decoded matcher does not hold the source addresses")
	}
}

func TestCompiledCountryHonoursNegation(t *testing.T) {
	directory := stageCompiledGeoIPHome(t)
	stageCountingIPLoader(t, "compiled-geoip-negation-probe")
	writeCompiledCountry(t, directory, "cn", "1.1.1.0/24")

	matcher, err := LoadGeoIPMatcher("!cn")
	if err != nil {
		t.Fatal(err)
	}
	if matcher.Match(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("!cn matched an address cn holds")
	}
	if !matcher.Match(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("!cn did not match an address cn does not hold")
	}
}

func TestCorruptCompiledCountryFallsBackToSource(t *testing.T) {
	directory := stageCompiledGeoIPHome(t)
	reads := stageCountingIPLoader(t, "compiled-geoip-corrupt-probe")
	SetCompiledGeoIPOnly(false)

	path, err := compiled.IPCIDRPath(directory, "us")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("this is not a compiled rule set"), 0o644); err != nil {
		t.Fatal(err)
	}

	matcher, err := LoadGeoIPMatcher("us")
	if err != nil {
		t.Fatalf("a corrupt artifact failed the load instead of falling back: %v", err)
	}
	if *reads != 1 {
		t.Fatalf("source was decoded %d times after a corrupt artifact, want 1", *reads)
	}
	if !matcher.Match(netip.MustParseAddr("203.0.113.1")) {
		t.Fatal("the fallback decode did not produce a working matcher")
	}
}

func TestAnUnavailableCountryStaysInertUnderNegation(t *testing.T) {
	stageCompiledGeoIPHome(t)
	stageCountingIPLoader(t, "compiled-geoip-negation-inert-probe")
	SetCompiledGeoIPOnly(true)

	matcher, err := LoadGeoIPMatcher("!us")
	if err != nil {
		t.Fatalf("an uncompiled negated country failed instead of degrading: %v", err)
	}
	for _, address := range []string{"1.1.1.1", "114.114.114.114", "8.8.8.8", "2400:3200::1"} {
		if matcher.Match(netip.MustParseAddr(address)) {
			t.Fatalf("!us with us unavailable matched %s: the negation inverted the "+
				"degradation, so every rule below this one is dead", address)
		}
	}
}

func TestAnUnavailableCategoryStaysInertUnderNegation(t *testing.T) {
	stageCompiledGeoIPHome(t)
	previous := CompiledGeoSiteOnly()
	SetCompiledGeoSiteOnly(true)
	t.Cleanup(func() { SetCompiledGeoSiteOnly(previous) })
	ClearGeoSiteCache()

	matcher, err := LoadGeoSiteMatcher("!nonexistent-category")
	if err != nil {
		t.Fatalf("an uncompiled negated category failed instead of degrading: %v", err)
	}
	for _, domain := range []string{"example.com", "www.baidu.com", "github.com"} {
		if matcher.ApplyDomain(domain) {
			t.Fatalf("!nonexistent with it unavailable matched %s: the negation inverted "+
				"the degradation", domain)
		}
	}
}

func TestReloadingWhileMatchingIsNotARace(t *testing.T) {
	stageCompiledGeoIPHome(t)
	stageCountingIPLoader(t, "compiled-geoip-race-probe")
	t.Cleanup(func() { SetGeodataProgressReporter(nil) })

	done := make(chan struct{})
	var writers, readers sync.WaitGroup

	writers.Add(1)
	go func() {
		defer writers.Done()
		noop := func(string) {}
		for index := 0; ; index++ {
			select {
			case <-done:
				return
			default:
			}
			SetCompiledGeoIPOnly(index%2 == 0)
			SetCompiledGeoSiteOnly(index%2 == 1)
			if index%2 == 0 {
				SetGeodataProgressReporter(noop)
			} else {
				SetGeodataProgressReporter(nil)
			}
		}
	}()

	for worker := 0; worker < 4; worker++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for index := 0; index < 500; index++ {
				_, _ = LoadGeoIPMatcher("cn")
				_ = CompiledGeoIPOnly()
				_ = CompiledGeoSiteOnly()
			}
		}()
	}
	readers.Wait()
	close(done)
	writers.Wait()
}
