package clash

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStagingRefusesASymlinkedRuntimeDirectory(t *testing.T) {
	home := compileStagingHome(t)
	elsewhere := t.TempDir()
	bystander := filepath.Join(elsewhere, "important.txt")
	if err := os.WriteFile(bystander, []byte("not ours"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(home, providerRuntimeDirectoryName)); err != nil {
		t.Fatal(err)
	}

	source := writeRuleSource(t, "rules.yaml", "payload:\n  - DOMAIN,example.com\n")
	raw := stagingRawWithProviderPath(t, "rule", source)
	runtime, err := stageProviderRuntime(raw, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), false)
	if runtime != nil {
		runtime.close()
	}
	if err == nil {
		t.Fatal("staging accepted a symlinked runtime directory; every staged write and the sweep would land outside the container")
	}
	if _, statErr := os.Stat(bystander); statErr != nil {
		t.Fatalf("the sweep deleted a file outside the container: %v", statErr)
	}
}

func TestCompileRuleProviderRefusesPathsOutsideTheContainer(t *testing.T) {
	home := compileStagingHome(t)
	inside := filepath.Join(home, "rules.txt")
	if err := os.WriteFile(inside, []byte("example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outsideDir := t.TempDir()

	if _, err := CompileRuleProvider(inside, "domain", "text", filepath.Join(outsideDir, "artifact.mrs")); err == nil {
		t.Fatal("an output path outside the container was accepted")
	}
	if _, err := CompileRuleProvider(filepath.Join(outsideDir, "elsewhere.txt"), "domain", "text",
		filepath.Join(home, "artifact.mrs")); err == nil {
		t.Fatal("a source path outside the container was accepted")
	}

	result, err := CompileRuleProvider(inside, "domain", "text", filepath.Join(home, "artifact.mrs"))
	if err != nil {
		t.Fatalf("an in-container compile must work: %v", err)
	}
	if !result.Compiled {
		t.Fatalf("compile reported no artifact: %s", result.Reason)
	}
}

func TestCompileRuleProviderDoesNotFollowASymlinkedOutput(t *testing.T) {
	home := compileStagingHome(t)
	inside := filepath.Join(home, "rules.txt")
	if err := os.WriteFile(inside, []byte("example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "victim.txt")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(home, "artifact.mrs")
	if err := os.Symlink(target, output); err != nil {
		t.Fatal(err)
	}

	_, err := CompileRuleProvider(inside, "domain", "text", output)
	victim, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(victim) != "original" {
		t.Fatalf("the compile wrote through a symlink to a file outside the container (err=%v)", err)
	}
}

func TestCompileRuleProviderBoundsTheSourceRead(t *testing.T) {
	home := compileStagingHome(t)
	huge := filepath.Join(home, "huge.txt")
	if err := os.WriteFile(huge, []byte(strings.Repeat("example.com\n", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(home, "empty.txt")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := CompileRuleProvider(empty, "domain", "text", filepath.Join(home, "out.mrs")); err == nil {
		t.Fatal("an unbounded read accepted a zero-byte source; the bounded reader is not in the path")
	}
}
