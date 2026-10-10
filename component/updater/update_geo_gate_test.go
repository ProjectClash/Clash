package updater

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ProjectClash/Clash/common/utils"
	"github.com/ProjectClash/Clash/component/geodata"
)

func TestOnlyOneGeoUpdateRunsAtATime(t *testing.T) {
	previous := updateGeoDatabases
	t.Cleanup(func() { updateGeoDatabases = previous })
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	updateGeoDatabases = func() error {
		once.Do(func() { close(entered) })
		<-release
		return nil
	}
	first := make(chan error, 1)
	go func() { first <- UpdateGeoDatabases() }()
	<-entered
	if err := UpdateGeoDatabases(); !errors.Is(err, ErrGetDatabaseUpdateSkip) {
		t.Fatalf("a concurrent update must be skipped, got %v", err)
	}
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	updateGeoDatabases = func() error { return nil }
	if err := UpdateGeoDatabases(); err != nil {
		t.Fatalf("after the first update returned, the next must run: %v", err)
	}
}

func TestStagedWriteReplacesThroughARename(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "GeoSite.dat")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := stagedWrite(path, []byte("new contents")); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || string(got) != "new contents" {
		t.Fatalf("read back %q, %v", got, err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o, want the previous file's 0600", info.Mode().Perm())
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if strings.Contains(e.Name(), ".staging") {
			t.Fatalf("a staging file survived: %s", e.Name())
		}
	}
	nested := filepath.Join(dir, "sub", "dir", "GeoIP.dat")
	if err := stagedWrite(nested, []byte("x")); err != nil {
		t.Fatal(err)
	}
}

func TestADownloadPastTheCeilingIsRefusedAndLeavesTheFileAlone(t *testing.T) {
	const chunk = 1 << 20
	body := make([]byte, chunk)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		for sent := int64(0); sent <= geodata.MaxMMDBBytes; sent += chunk {
			if _, err := w.Write(body); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	dir := t.TempDir()
	path := filepath.Join(dir, "Country.mmdb")
	if err := os.WriteFile(path, []byte("the database that is already here"), 0o600); err != nil {
		t.Fatal(err)
	}

	data, changed, err := downloadGeoDatabase(testDatabase(server.URL, path, geodata.MaxMMDBBytes))
	if err == nil {
		t.Fatalf("an oversized body must be refused, got %d bytes changed=%v", len(data), changed)
	}
	if !strings.Contains(err.Error(), "larger than the") {
		t.Fatalf("the refusal must name the ceiling, got %v", err)
	}
	if changed || data != nil {
		t.Fatalf("a refused download hands back nothing, got %d bytes changed=%v", len(data), changed)
	}
	got, readErr := os.ReadFile(path)
	if readErr != nil || string(got) != "the database that is already here" {
		t.Fatalf("the file on disk must be untouched, read %q %v", got, readErr)
	}
}

func TestADownloadUnderTheCeilingIsHandedBackWhole(t *testing.T) {
	payload := bytes.Repeat([]byte("mmdb"), 4096)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "Country.mmdb")
	data, changed, err := downloadGeoDatabase(testDatabase(server.URL, path, geodata.MaxMMDBBytes))
	if err != nil {
		t.Fatal(err)
	}
	if !changed || !bytes.Equal(data, payload) {
		t.Fatalf("got %d bytes changed=%v, want the %d that were sent", len(data), changed, len(payload))
	}
}

func TestADownloadThatMatchesTheFileOnDiskIsNotAChange(t *testing.T) {
	payload := bytes.Repeat([]byte("mmdb"), 4096)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "Country.mmdb")
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	data, changed, err := downloadGeoDatabase(testDatabase(server.URL, path, geodata.MaxMMDBBytes))
	if err != nil || changed || data != nil {
		t.Fatalf("same bytes must be no change, got %d bytes changed=%v err=%v", len(data), changed, err)
	}
}

func TestTheGeoVehicleStopsReadingAtTheCeiling(t *testing.T) {
	const chunk = 1 << 20
	const slack = 4 * chunk
	body := make([]byte, chunk)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for sent := int64(0); sent < geodata.MaxMMDBBytes+slack; sent += chunk {
			if _, err := w.Write(body); err != nil {
				return
			}
		}
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "Country.mmdb")
	data, _, err := geoVehicle(server.URL, path, geodata.MaxMMDBBytes).Read(context.Background(), utils.HashType{})
	if err != nil {
		t.Fatal(err)
	}
	if int64(len(data)) != geodata.MaxMMDBBytes+1 {
		t.Fatalf("read %d bytes, want it to stop at the ceiling+1 (%d) -- the vehicle has no limit", len(data), geodata.MaxMMDBBytes+1)
	}
}

func TestTheFileOnDiskIsHashedOnlyUpToTheCeiling(t *testing.T) {
	dir := t.TempDir()

	ordinary := filepath.Join(dir, "Country.mmdb")
	contents := []byte("a database that is a reasonable size")
	if err := os.WriteFile(ordinary, contents, 0o600); err != nil {
		t.Fatal(err)
	}
	if got, want := hashExistingDatabase(ordinary, geodata.MaxMMDBBytes), utils.MakeHash(contents); !got.Equal(want) {
		t.Fatalf("an ordinary file must hash to its contents, got %v want %v", got, want)
	}

	over := filepath.Join(dir, "Huge.mmdb")
	f, err := os.Create(over)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(geodata.MaxMMDBBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if hash := hashExistingDatabase(over, geodata.MaxMMDBBytes); !hash.Equal(utils.HashType{}) {
		t.Fatalf("a file past the ceiling must not be hashed, got %v", hash)
	}

	if hash := hashExistingDatabase(filepath.Join(dir, "absent.mmdb"), geodata.MaxMMDBBytes); !hash.Equal(utils.HashType{}) {
		t.Fatalf("a missing file has no hash, got %v", hash)
	}
}

func TestAnOversizedFileOnDiskIsStillReplacedByTheNextDownload(t *testing.T) {
	payload := bytes.Repeat([]byte("mmdb"), 4096)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(payload)
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "Country.mmdb")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(geodata.MaxMMDBBytes + 1); err != nil {
		t.Fatal(err)
	}
	f.Close()

	data, changed, err := downloadGeoDatabase(testDatabase(server.URL, path, geodata.MaxMMDBBytes))
	if err != nil || !changed || !bytes.Equal(data, payload) {
		t.Fatalf("the download must count as a change, got %d bytes changed=%v err=%v", len(data), changed, err)
	}
}

func testDatabase(url, path string, ceiling int64) geoDatabase {
	return geoDatabase{
		name:    "MMDB",
		url:     func() string { return url },
		path:    func() string { return path },
		ceiling: ceiling,
	}
}

func TestEachGeoDownloadCarriesItsFormatsCeiling(t *testing.T) {
	for _, c := range []struct {
		db   geoDatabase
		name string
		want int64
	}{
		{mmdbDatabase, "MMDB", geodata.MaxMMDBBytes},
		{asnDatabase, "ASN", geodata.MaxMMDBBytes},
		{geoIPDatabase, "GeoIP", geodata.MaxDatFileBytes},
		{geoSiteDatabase, "GeoSite", geodata.MaxDatFileBytes},
	} {
		if c.db.name != c.name {
			t.Fatalf("entry named %q, want %q", c.db.name, c.name)
		}
		if c.db.ceiling != c.want {
			t.Fatalf("%s carries ceiling %d, want %d", c.name, c.db.ceiling, c.want)
		}
		if c.db.url == nil || c.db.path == nil {
			t.Fatalf("%s has no url or no path", c.name)
		}
	}
	if geodata.MaxDatFileBytes == geodata.MaxMMDBBytes {
		t.Fatal("the two ceilings are the same number again -- this test would then prove nothing")
	}
}
