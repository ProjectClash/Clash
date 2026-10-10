package geodata

import (
	"fmt"
	"testing"

	"github.com/ProjectClash/Clash/component/geodata/router"
)

type countingLoader struct {
	reads *int
	list  []*router.Domain
}

func (l countingLoader) LoadSiteByPath(_, _ string) ([]*router.Domain, error) {
	*l.reads++
	return l.list, nil
}

func (l countingLoader) LoadSiteByBytes([]byte, string) ([]*router.Domain, error) {
	return nil, fmt.Errorf("not used")
}

func (l countingLoader) LoadIPByPath(string, string) ([]*router.CIDR, error) {
	return nil, fmt.Errorf("not used")
}

func (l countingLoader) LoadIPByBytes([]byte, string) ([]*router.CIDR, error) {
	return nil, fmt.Errorf("not used")
}

func stageCountingLoader(t *testing.T, name string) *int {
	t.Helper()
	reads := 0
	domains := make([]*router.Domain, 0, 64)
	for index := 0; index < 64; index++ {
		domains = append(domains, &router.Domain{
			Type:  router.Domain_Domain,
			Value: fmt.Sprintf("host%d.example.com", index),
		})
	}
	RegisterGeoDataLoaderImplementationCreator(name, func() LoaderImplementation {
		return countingLoader{reads: &reads, list: domains}
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

func TestMemConservativeDoesNotRetainTheDecodedList(t *testing.T) {
	reads := stageCountingLoader(t, "memconservative")

	if _, err := LoadGeoSiteMatcher("retention-cn"); err != nil {
		t.Fatal(err)
	}
	if *reads != 1 {
		t.Fatalf("first build read the list %d times, want 1", *reads)
	}
	if _, err := LoadGeoSiteMatcher("retention-cn@ads"); err != nil {
		t.Fatal(err)
	}
	if *reads != 2 {
		t.Fatalf("the decoded list was still cached: reads=%d, want a second read", *reads)
	}
}

func TestStandardLoaderKeepsTheDecodedList(t *testing.T) {
	reads := stageCountingLoader(t, "standard-retention-probe")

	if _, err := LoadGeoSiteMatcher("kept-cn"); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadGeoSiteMatcher("kept-cn@ads"); err != nil {
		t.Fatal(err)
	}
	if *reads != 1 {
		t.Fatalf("reads=%d, want the list read once and reused", *reads)
	}
}
