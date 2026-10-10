package resource

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAFileProviderWaitsForAFileInTheDeferredDirectory(t *testing.T) {
	directory := t.TempDir()
	SetDeferredFileDirectory(directory)
	t.Cleanup(func() { SetDeferredFileDirectory("") })
	path := filepath.Join(directory, "cache", "product")
	fetcher := NewFetcher[string]("waiting", 0, NewFileVehicle(path), nil,
		func(buf []byte) (string, error) { return string(buf), nil }, nil)
	if _, err := fetcher.Initial(); !errors.Is(err, ErrRemoteFetchDeferred) {
		t.Fatalf("a missing file the refresher will write is deferred, not an error: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("loaded"), 0o600); err != nil {
		t.Fatal(err)
	}
	if contents, _, err := fetcher.Update(); err != nil || contents != "loaded" {
		t.Fatalf("the provider reads the file once it is written: %q, %v", contents, err)
	}
	elsewhere := NewFetcher[string]("missing", 0, NewFileVehicle(filepath.Join(t.TempDir(), "absent")), nil,
		func(buf []byte) (string, error) { return string(buf), nil }, nil)
	if _, err := elsewhere.Initial(); err == nil || errors.Is(err, ErrRemoteFetchDeferred) {
		t.Fatalf("a missing file elsewhere is an error, as upstream: %v", err)
	}
}
