package geodata

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/component/geodata/router"
	C "github.com/ProjectClash/Clash/constant"
)

func TestADatDownloadOnlyReplacesTheFileOnAWholeGoodBody(t *testing.T) {
	previous := []byte("the .dat that is already here, and is longer than what follows")

	t.Run("a bad status leaves the file alone", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadGateway)
			w.Write([]byte("<html><body>502 Bad Gateway</body></html>"))
		}))
		defer server.Close()

		dir := t.TempDir()
		path := filepath.Join(dir, "GeoSite.dat")
		if err := os.WriteFile(path, previous, 0o644); err != nil {
			t.Fatal(err)
		}
		err := downloadToPath(server.URL, path)
		if err == nil || !strings.Contains(err.Error(), "502") {
			t.Fatalf("a 502 must be refused by its status, got %v", err)
		}
		assertUnchanged(t, path, previous)
		assertNoLeftovers(t, dir, "GeoSite.dat")
	})

	t.Run("a body that never ends leaves the file alone", func(t *testing.T) {
		const chunk = 1 << 20
		block := make([]byte, chunk)
		done := make(chan struct{})
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for {
				select {
				case <-done:
					return
				default:
				}
				if _, err := w.Write(block); err != nil {
					return
				}
			}
		}))
		defer server.Close()
		defer close(done)

		dir := t.TempDir()
		path := filepath.Join(dir, "GeoSite.dat")
		if err := os.WriteFile(path, previous, 0o644); err != nil {
			t.Fatal(err)
		}
		err := downloadToPath(server.URL, path)
		if err == nil || !strings.Contains(err.Error(), "larger than") {
			t.Fatalf("an oversized body must be refused by its size, got %v", err)
		}
		assertUnchanged(t, path, previous)
		assertNoLeftovers(t, dir, "GeoSite.dat")
	})

	t.Run("a good body replaces the file whole", func(t *testing.T) {
		fresh := []byte("shorter")
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(fresh)
		}))
		defer server.Close()

		dir := t.TempDir()
		path := filepath.Join(dir, "GeoSite.dat")
		if err := os.WriteFile(path, previous, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := downloadToPath(server.URL, path); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(path)
		if err != nil || string(got) != string(fresh) {
			t.Fatalf("read back %q, want %q (%v)", got, fresh, err)
		}
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != 0o644 {
			t.Fatalf("mode %v, want 0644 (%v)", info.Mode().Perm(), err)
		}
		assertNoLeftovers(t, dir, "GeoSite.dat")
	})
}

func assertUnchanged(t *testing.T, path string, want []byte) {
	t.Helper()
	got, err := os.ReadFile(path)
	if err != nil || string(got) != string(want) {
		t.Fatalf("the file on disk must be untouched, read %q (%v)", got, err)
	}
}

func assertNoLeftovers(t *testing.T, dir, expected string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() != expected {
			t.Fatalf("left behind %q beside the destination", e.Name())
		}
	}
}

type contentsLoader struct{}

func (contentsLoader) LoadSiteByPath(filename, list string) ([]*router.Domain, error) {
	if filename == C.GeositeName {
		filename = C.Path.GeoSite()
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return contentsLoader{}.LoadSiteByBytes(data, list)
}

func (contentsLoader) LoadSiteByBytes(geositeBytes []byte, list string) ([]*router.Domain, error) {
	if !strings.HasPrefix(string(geositeBytes), "GOOD") {
		return nil, fmt.Errorf("not a geosite file")
	}
	return []*router.Domain{{Type: router.Domain_Domain, Value: "example.com"}}, nil
}

func (contentsLoader) LoadIPByPath(filename, country string) ([]*router.CIDR, error) {
	return nil, fmt.Errorf("not used")
}

func (contentsLoader) LoadIPByBytes(geoipBytes []byte, country string) ([]*router.CIDR, error) {
	return nil, fmt.Errorf("not used")
}

func TestASecondDownloadIsVerifiedBeforeItCountsAsInitialised(t *testing.T) {
	previousLoader := geoLoaderName
	previousURL := GeoSiteUrl()
	previousHome := C.Path.HomeDir()
	t.Cleanup(func() {
		geoLoaderName = previousLoader
		SetGeoSiteUrl(previousURL)
		C.SetHomeDir(previousHome)
		initGeoSite = false
	})
	RegisterGeoDataLoaderImplementationCreator("test-contents", func() LoaderImplementation { return contentsLoader{} })
	geoLoaderName = "test-contents"

	body := "NOT A GEOSITE FILE"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(body))
	}))
	defer server.Close()
	SetGeoSiteUrl(server.URL)

	C.SetHomeDir(t.TempDir())
	initGeoSite = false
	ClearGeoSiteCache()

	if err := InitGeoSite(); err == nil {
		t.Fatal("an endpoint serving a file that does not load must not initialise")
	} else if !strings.Contains(err.Error(), "invalid") {
		t.Fatalf("the error must say what is wrong with the download, got %v", err)
	}
	if initGeoSite {
		t.Fatal("a file that does not load must not be marked initialised")
	}

	body = "GOOD geosite"
	C.SetHomeDir(t.TempDir())
	initGeoSite = false
	ClearGeoSiteCache()
	if err := InitGeoSite(); err != nil {
		t.Fatalf("a file that loads must initialise: %v", err)
	}
	if !initGeoSite {
		t.Fatal("a file that loads must be marked initialised")
	}
}

func TestADatDownloadFollowsASymlinkToItsTarget(t *testing.T) {
	fresh := []byte("GOOD geosite")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(fresh)
	}))
	defer server.Close()

	shared := t.TempDir()
	home := t.TempDir()
	target := filepath.Join(shared, "GeoSite.dat")
	link := filepath.Join(home, "GeoSite.dat")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if err := downloadToPath(server.URL, link); err != nil {
		t.Fatal(err)
	}

	info, err := os.Lstat(link)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the link must still be a link, got %v (%v)", info.Mode(), err)
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != string(fresh) {
		t.Fatalf("the target must hold the download, read %q (%v)", got, err)
	}
	assertNoLeftovers(t, shared, "GeoSite.dat")
	assertNoLeftovers(t, home, "GeoSite.dat")
}

func TestReplacingAnInvalidDatKeepsTheSymlink(t *testing.T) {
	previousLoader := geoLoaderName
	previousURL := GeoSiteUrl()
	previousHome := C.Path.HomeDir()
	t.Cleanup(func() {
		geoLoaderName = previousLoader
		SetGeoSiteUrl(previousURL)
		C.SetHomeDir(previousHome)
		initGeoSite = false
	})
	RegisterGeoDataLoaderImplementationCreator("test-contents", func() LoaderImplementation { return contentsLoader{} })
	geoLoaderName = "test-contents"

	fresh := []byte("GOOD geosite, freshly downloaded")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(fresh)
	}))
	defer server.Close()
	SetGeoSiteUrl(server.URL)

	shared := t.TempDir()
	home := t.TempDir()
	target := filepath.Join(shared, "GeoSite.dat")
	if err := os.WriteFile(target, []byte("NOT A GEOSITE FILE"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(home, "GeoSite.dat")); err != nil {
		t.Fatal(err)
	}
	C.SetHomeDir(home)
	initGeoSite = false
	ClearGeoSiteCache()

	if err := InitGeoSite(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Lstat(filepath.Join(home, "GeoSite.dat"))
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the link must still be a link, got %v (%v)", info.Mode(), err)
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != string(fresh) {
		t.Fatalf("the shared target must hold the replacement, read %q (%v)", got, err)
	}
	assertNoLeftovers(t, home, "GeoSite.dat")
	assertNoLeftovers(t, shared, "GeoSite.dat")
}
