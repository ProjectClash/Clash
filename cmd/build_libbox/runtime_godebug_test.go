package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestTheStackStartIsAddedAfterTheDefaults(t *testing.T) {
	if got := withStackStartGODEBUG(""); got != "adaptivestackstart=0" {
		t.Fatalf("no defaults: %q", got)
	}
	if got := withStackStartGODEBUG("asynctimerchan=1,x509sha1=1"); got != "asynctimerchan=1,x509sha1=1,adaptivestackstart=0" {
		t.Fatalf("with defaults: %q", got)
	}
}

func TestTheFrameworkLinksTheStackStartOverTheMainPackageDefaults(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	defaults, err := gomobileMainDefaultGODEBUG(root)
	if err != nil {
		t.Fatal(err)
	}
	godebug, err := appleRuntimeGODEBUG(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("gomobile main default GODEBUG %q; linked %q", defaults, godebug)
	if godebug != withStackStartGODEBUG(defaults) {
		t.Fatalf("linked %q, want the defaults %q then the stack start", godebug, defaults)
	}
	ldflags := appleLdflags("1.19.32", true, godebug)
	if !strings.Contains(ldflags, " -X runtime.godebugDefault="+godebug) {
		t.Fatalf("ldflags %q do not link the runtime GODEBUG", ldflags)
	}
}

func TestALinkedStackStartKeepsGoroutinesStartingAtTwoKiB(t *testing.T) {
	if testing.Short() {
		t.Skip("builds two programs")
	}
	dir := t.TempDir()
	program := `package main

import (
	"fmt"
	"runtime"
	"runtime/metrics"
	"sync"
)

//go:noinline
func deep(n int, release <-chan struct{}) byte {
	var pad [512]byte
	if n == 0 {
		<-release
		return pad[0]
	}
	return deep(n-1, release) + pad[n%len(pad)]
}

func main() {
	release := make(chan struct{})
	var started, done sync.WaitGroup
	for i := 0; i < 64; i++ {
		started.Add(1)
		done.Add(1)
		go func() {
			defer done.Done()
			started.Done()
			deep(24, release)
		}()
	}
	started.Wait()
	runtime.Gosched()
	runtime.GC()
	sample := []metrics.Sample{{Name: "/gc/stack/starting-size:bytes"}}
	metrics.Read(sample)
	close(release)
	done.Wait()
	fmt.Print(sample[0].Value.Uint64())
}
`
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module stackstart\n\ngo 1.26\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(program), 0o644); err != nil {
		t.Fatal(err)
	}
	startingSize := func(ldflags string) string {
		t.Helper()
		binary := filepath.Join(dir, "probe")
		build := exec.Command("go", "build", "-ldflags", ldflags, "-o", binary, ".")
		build.Dir = dir
		build.Env = append(os.Environ(), "GOFLAGS=")
		if output, err := build.CombinedOutput(); err != nil {
			t.Fatalf("build: %v\n%s", err, output)
		}
		run := exec.Command(binary)
		run.Env = append(os.Environ(), "GODEBUG=")
		output, err := run.Output()
		if err != nil {
			t.Fatalf("run: %v", err)
		}
		return string(output)
	}
	adaptive := startingSize("-s -w")
	fixed := startingSize("-s -w -X runtime.godebugDefault=" + withStackStartGODEBUG(""))
	t.Logf("starting stack after deep goroutines were scanned: %s B by default, %s B linked", adaptive, fixed)
	if adaptive == "2048" {
		t.Fatalf("the default runtime did not adapt (%s B); the program does not exercise the setting", adaptive)
	}
	if fixed != "2048" {
		t.Fatalf("with the linked GODEBUG goroutines start at %s B, want 2048", fixed)
	}
}

func TestASliceWithoutTheLinkedGODEBUGFailsTheBuild(t *testing.T) {
	godebug := withStackStartGODEBUG("")
	if err := runtimeGODEBUGVerdict("ios-arm64", []byte("...\x00"+godebug+"\x00..."), godebug); err != nil {
		t.Fatalf("a slice carrying it: %v", err)
	}
	if err := runtimeGODEBUGVerdict("ios-arm64", []byte("...adaptivestackstart\x00..."), godebug); err == nil {
		t.Fatal("a slice with only the runtime's own setting name passed")
	}
}
