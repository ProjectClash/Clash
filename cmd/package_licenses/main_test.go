package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDiscoverLicenseFiles(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"LICENSE", "NOTICE.md", "copying.txt", "README.md"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte(name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	files, err := discoverLicenseFiles(directory)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, file := range files {
		names = append(names, filepath.Base(file))
	}
	want := []string{"LICENSE", "NOTICE.md", "copying.txt"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("license files = %v, want %v", names, want)
	}
}

func TestDiscoverLicenseFilesFallsBackToPackageLicenses(t *testing.T) {
	directory := t.TempDir()
	if err := os.MkdirAll(filepath.Join(directory, "crypto"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "crypto", "LICENSE"), []byte("license"), 0o644); err != nil {
		t.Fatal(err)
	}
	files, err := discoverLicenseFiles(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || filepath.Base(files[0]) != "LICENSE" {
		t.Fatalf("fallback license files = %v", files)
	}
}

func TestSafeModuleDirectory(t *testing.T) {
	if got, want := safeModuleDirectory("github.com/example/module/v2"), "github.com__example__module__v2"; got != want {
		t.Fatalf("safeModuleDirectory = %q, want %q", got, want)
	}
}

func TestLinkedModulesCoverEverySlice(t *testing.T) {
	if testing.Short() {
		t.Skip("lists the binding's dependencies for every slice")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	modules, err := linkedModules(filepath.Join(root, "bind", "clash"))
	if err != nil {
		t.Fatal(err)
	}
	linked := map[string]bool{}
	for _, module := range modules {
		linked[module.Path] = true
	}
	for _, path := range []string{"github.com/google/pprof", "github.com/easytier/easytier/easytier-go"} {
		if !linked[path] {
			t.Errorf("%s ships in the macOS slice but is missing from the inventory", path)
		}
	}
}
