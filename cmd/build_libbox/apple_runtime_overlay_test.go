package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)


func appleRuntimeOverlayForTest(t *testing.T) (goBinary, goroot, overlayJSON string) {
	t.Helper()
	goBinary, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go not on PATH")
	}
	goroot = strings.TrimSpace(runOutput(t, goBinary, "env", "GOROOT"))
	dir := t.TempDir()
	replace, err := writeAppleRuntimeOverlay(repoRoot(t), goroot, dir)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(map[string]map[string]string{"Replace": replace})
	if err != nil {
		t.Fatal(err)
	}
	overlayJSON = filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(overlayJSON, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return goBinary, goroot, overlayJSON
}

func TestAppleRuntimeOverlayAppliesToTheToolchainAndCompilesForEverySlice(t *testing.T) {
	goBinary, _, overlayJSON := appleRuntimeOverlayForTest(t)
	for _, target := range []struct{ goos, goarch, tags string }{
		{"ios", "arm64", ""},
		{"ios", "amd64", ""},
		{"darwin", "arm64", "ios,tvos"},
		{"darwin", "arm64", ""},
		{"darwin", "amd64", ""},
	} {
		args := []string{"build", "-overlay=" + overlayJSON}
		if target.tags != "" {
			args = append(args, "-tags", target.tags)
		}
		cmd := exec.Command(goBinary, append(args, "runtime")...)
		cmd.Env = append(os.Environ(), "GOOS="+target.goos, "GOARCH="+target.goarch, "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s/%s tags=%q with the runtime overlay: %v\n%s", target.goos, target.goarch, target.tags, err, out)
		}
	}
}

func TestAppleRuntimeEditsRefuseAToolchainThatChangedTheirText(t *testing.T) {
	edits := []appleRuntimeEdit{{old: "keep the stack\n", new: "free the stack\n"}}
	if got, err := applyAppleRuntimeEdits("proc.go", "a\nkeep the stack\nb\n", edits); err != nil || got != "a\nfree the stack\nb\n" {
		t.Fatalf("the text that is there once must be replaced: %q, %v", got, err)
	}
	if _, err := applyAppleRuntimeEdits("proc.go", "a\nb\n", edits); err == nil {
		t.Fatal("an edit whose text the toolchain no longer has must fail the build, not vanish")
	}
	if _, err := applyAppleRuntimeEdits("proc.go", "keep the stack\nkeep the stack\n", edits); err == nil {
		t.Fatal("an edit whose text the toolchain has twice must fail the build, not pick one")
	}
}

func writeRuntimeFilesForOverlay(t *testing.T, goroot string) string {
	t.Helper()
	runtimeDir := filepath.Join(goroot, "src", "runtime")
	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, edits := range appleRuntimeOverlayEdits {
		var text strings.Builder
		for _, edit := range edits {
			text.WriteString(edit.old)
		}
		if err := os.WriteFile(filepath.Join(runtimeDir, name), []byte(text.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return runtimeDir
}

func TestAppleRuntimeOverlayAddsFilesTheToolchainDoesNotHave(t *testing.T) {
	goroot := t.TempDir()
	runtimeDir := writeRuntimeFilesForOverlay(t, goroot)
	if _, err := writeAppleRuntimeOverlay(repoRoot(t), goroot, t.TempDir()); err != nil {
		t.Fatalf("a toolchain with every edited text once: %v", err)
	}
	if err := os.WriteFile(filepath.Join(runtimeDir, "clash_apple_tunnel.go"), []byte("package runtime\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := writeAppleRuntimeOverlay(repoRoot(t), goroot, t.TempDir()); err == nil {
		t.Fatal("a toolchain that already has a file the overlay adds would have it replaced in silence")
	}
}

func TestAppleRuntimeOverlayMarkerVerdict(t *testing.T) {
	withMarker := "0000000000001000 t _runtime." + appleRuntimeOverlayMarkerSymbol + "\n0000000000002000 t _runtime.schedinit\n"
	without := "0000000000002000 t _runtime.schedinit\n"
	for _, slice := range []string{"ios-arm64", "ios-arm64_x86_64-simulator", "tvos-arm64", "tvos-arm64_x86_64-simulator"} {
		if err := verifyAppleRuntimeOverlayMarker(slice, withMarker); err != nil {
			t.Errorf("%s with the marker must pass: %v", slice, err)
		}
		if err := verifyAppleRuntimeOverlayMarker(slice, without); err == nil {
			t.Errorf("%s without the marker was built past the overlay and must fail", slice)
		}
	}
	if err := verifyAppleRuntimeOverlayMarker("macos-arm64_x86_64", without); err != nil {
		t.Errorf("macOS keeps upstream's runtime: %v", err)
	}
	if err := verifyAppleRuntimeOverlayMarker("macos-arm64_x86_64", withMarker); err == nil {
		t.Error("a macOS slice carrying the iOS-family marker means the constraint leaked and must fail")
	}
}

func TestAppleRuntimeOverlayGivesBackDeadStacksAndSpanSetBlocks(t *testing.T) {
	if runtime.GOOS != "darwin" || runtime.GOARCH != "arm64" {
		t.Skip("the probe is built for darwin/arm64 and run here")
	}
	goBinary, goroot, overlayJSON := appleRuntimeOverlayForTest(t)
	const probeTag = "clash_runtime_overlay_probe"
	data, err := os.ReadFile(overlayJSON)
	if err != nil {
		t.Fatal(err)
	}
	var overlay map[string]map[string]string
	if err := json.Unmarshal(data, &overlay); err != nil {
		t.Fatal(err)
	}
	for name, source := range appleRuntimeOverlayAddedFiles {
		text, err := os.ReadFile(filepath.Join(repoRoot(t), filepath.FromSlash(source)))
		if err != nil {
			t.Fatal(err)
		}
		retagged := strings.Replace(string(text), "//go:build ios\n", "//go:build "+probeTag+"\n", 1)
		retagged = strings.Replace(retagged, "//go:build !ios\n", "//go:build !"+probeTag+"\n", 1)
		if retagged == string(text) {
			t.Fatalf("%s: no ios constraint to retag", source)
		}
		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, []byte(retagged), 0o644); err != nil {
			t.Fatal(err)
		}
		overlay["Replace"][filepath.Join(goroot, "src", "runtime", name)] = path
	}
	if data, err = json.Marshal(overlay); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(overlayJSON, data, 0o644); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	program := `package main

import (
	"fmt"
	"runtime"
	"runtime/metrics"
	"sync"
)

var keep [][]byte

func main() {
	runtime.GOMAXPROCS(4)
	for size := 8; size <= 32<<10; size += size / 8 {
		for i := 0; i < 64; i++ {
			keep = append(keep, make([]byte, size))
		}
	}
	var wg sync.WaitGroup
	for round := 0; round < 8; round++ {
		for i := 0; i < 256; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); var pad [512]byte; _ = pad }()
		}
		wg.Wait()
	}
	runtime.GC()
	runtime.GC()
	samples := []metrics.Sample{{Name: "/memory/classes/heap/stacks:bytes"}, {Name: "/memory/classes/metadata/other:bytes"}}
	metrics.Read(samples)
	fmt.Println(samples[0].Value.Uint64(), samples[1].Value.Uint64(), len(keep))
}
`
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(program), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module probe\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	measure := func(overlay bool) (stacks, metadata uint64) {
		args := []string{"run"}
		if overlay {
			args = append(args, "-overlay="+overlayJSON)
		}
		cmd := exec.Command(goBinary, append(args, "-tags", probeTag, ".")...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GOOS=darwin", "GOARCH=arm64", "CGO_ENABLED=0", "GOFLAGS=", "GOTOOLCHAIN=local")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("run overlay=%v: %v\n%s", overlay, err, out)
		}
		fields := strings.Fields(string(out))
		if len(fields) != 3 {
			t.Fatalf("unexpected output: %s", out)
		}
		stacks, _ = strconv.ParseUint(fields[0], 10, 64)
		metadata, _ = strconv.ParseUint(fields[1], 10, 64)
		return stacks, metadata
	}
	upstreamStacks, upstreamMetadata := measure(false)
	stacks, metadata := measure(true)
	t.Logf("stacks %d -> %d bytes, metadata/other %d -> %d bytes", upstreamStacks, stacks, upstreamMetadata, metadata)
	if stacks >= upstreamStacks {
		t.Errorf("dead goroutines' stacks: %d bytes with the overlay, %d upstream", stacks, upstreamStacks)
	}
	if metadata*10 > upstreamMetadata*7 {
		t.Errorf("span-set metadata: %d bytes with the overlay, %d upstream; expected at most 70%%", metadata, upstreamMetadata)
	}
}
