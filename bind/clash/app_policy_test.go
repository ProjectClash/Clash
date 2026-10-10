package clash

import (
	"math"
	"os"
	"path/filepath"
	"reflect"
	"runtime/debug"
	"testing"
)

func TestUpdateAppPolicyChangesOnlyThePolicy(t *testing.T) {
	previousResolvers := systemDNSSubstitutes.Load()
	previousStack := currentIPStackSettings()
	t.Cleanup(func() {
		systemDNSSubstitutes.Store(previousResolvers)
		setIPStackSettings(previousStack)
	})
	base := t.TempDir()
	if err := Setup(&SetupOptions{BasePath: base, WorkingPath: filepath.Join(base, "working"), TempPath: filepath.Join(base, "temp")}); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	t.Cleanup(func() { _ = disarmGoCrashOutput() })
	liveName, _ := goCrashReportFileNames(setupGoCrashReportRole)
	before, err := os.Stat(filepath.Join(base, liveName))
	if err != nil {
		t.Fatal(err)
	}

	policy := &AppPolicyOptions{IPQueryMode: "ipv4-only", TunIPv6Mode: "automatic", SystemDNSServerLines: "119.29.29.29\n"}
	if err := UpdateAppPolicy(policy); err != nil {
		t.Fatalf("UpdateAppPolicy: %v", err)
	}
	want, _ := parseIPStackSettings("ipv4-only", "automatic")
	if got := currentIPStackSettings(); got != want {
		t.Fatalf("IP Stack = %+v, want %+v", got, want)
	}
	if got := systemDNSSubstitutes.Load(); got == nil || !reflect.DeepEqual(*got, []string{"119.29.29.29"}) {
		t.Fatalf("system resolvers = %v", got)
	}
	after, err := os.Stat(filepath.Join(base, liveName))
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("a policy update must not touch the process setup (crash output re-armed: %v)", err)
	}

	if err := UpdateAppPolicy(&AppPolicyOptions{IPQueryMode: "bogus"}); err == nil {
		t.Fatal("an unknown IP query mode must be refused")
	}
	if err := UpdateAppPolicy(&AppPolicyOptions{IPQueryMode: "ipv4-only", TunIPv6Mode: "automatic", SystemDNSServerLines: "not an address\n"}); err == nil {
		t.Fatal("a resolver line that is not an address must be refused")
	}
	if got := currentIPStackSettings(); got != want {
		t.Fatal("a refused update must leave the IP Stack as it was")
	}
	if got := systemDNSSubstitutes.Load(); !reflect.DeepEqual(*got, []string{"119.29.29.29"}) {
		t.Fatal("a refused update must leave the resolvers as they were")
	}
	if err := UpdateAppPolicy(nil); err == nil {
		t.Fatal("nil options must be refused")
	}
}

func TestSetupWithoutAMemoryLimitRestoresTheDefaultGC(t *testing.T) {
	base := t.TempDir()
	options := func(limit int64) *SetupOptions {
		return &SetupOptions{BasePath: base, WorkingPath: filepath.Join(base, "working"), TempPath: filepath.Join(base, "temp"), MemoryLimit: limit}
	}
	t.Cleanup(func() { _ = disarmGoCrashOutput(); debug.SetGCPercent(100); debug.SetMemoryLimit(math.MaxInt64) })
	if err := Setup(options(50 << 20)); err != nil {
		t.Fatal(err)
	}
	if during := debug.SetGCPercent(10); during != 10 {
		t.Fatalf("GOGC after a budgeted Setup = %d, want 10", during)
	}
	if err := Setup(options(0)); err != nil {
		t.Fatal(err)
	}
	if previous := debug.SetGCPercent(100); previous != 100 {
		t.Fatalf("GOGC after a Setup without a limit = %d, want the default 100", previous)
	}
	if currentRuntimeSetup.gcPercent != 0 {
		t.Fatalf("the diagnostics mirror still reports GOGC %d", currentRuntimeSetup.gcPercent)
	}
}
