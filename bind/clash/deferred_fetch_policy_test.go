package clash

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/ProjectClash/Clash/component/resource"
)

func TestSetupTurnsTheDeferredFetchKnobsTogether(t *testing.T) {
	if err := Setup(testOptions(t)); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if !resource.DeferRemoteInitialFetch {
		t.Fatal("the first fetch of a remote provider must not sit on the Start path")
	}
	if got, want := resource.DefaultRemoteSizeLimit, int64(maximumProviderResourceBytes); got != want {
		t.Fatalf("DefaultRemoteSizeLimit = %d, want the provider ceiling %d", got, want)
	}
	if got := resource.FirstLoadConcurrency(); got != 5 {
		t.Fatalf("FirstLoadConcurrency = %d, want the executor's five", got)
	}
}

func TestSetupEnablesCompleteTVCacheGenerations(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(options.WorkingPath, "tv-rule-cache", "rules.yaml")
	vehicle := resource.NewHTTPVehicle("https://example.invalid/rules", path, "", nil, 0, 0)
	if err := vehicle.Write([]byte("previous")); err != nil {
		t.Fatal(err)
	}
	reader, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	if err := vehicle.Write([]byte("replacement")); err != nil {
		t.Fatal(err)
	}
	previous, err := io.ReadAll(reader)
	if err != nil || string(previous) != "previous" {
		t.Fatalf("existing reader = %q, %v", previous, err)
	}
}
