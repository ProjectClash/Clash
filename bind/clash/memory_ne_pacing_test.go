package clash

import (
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strings"
	"testing"
	"time"
)

func TestThresholdFixtureRestoresRuntimeTuning(t *testing.T) {
	priorState := runtimeSetupSnapshot()
	priorLimit := debug.SetMemoryLimit(-1)
	priorProcs := runtime.GOMAXPROCS(0)
	samples := []metrics.Sample{{Name: "/gc/gogc:percent"}}
	metrics.Read(samples)
	priorGC := int(samples[0].Value.Uint64())
	t.Cleanup(func() {
		debug.SetMemoryLimit(priorLimit)
		debug.SetGCPercent(priorGC)
		runtime.GOMAXPROCS(priorProcs)
	})
	t.Run("limited session", func(t *testing.T) {
		disarmThresholdMonitor(t, pressureThresholdShedEnabled.Load())
		options := testOptions(t)
		options.MemoryLimit = 48 * 1024 * 1024
		options.MaxProcs = 1
		if err := Setup(options); err != nil {
			t.Fatal(err)
		}
		if got := debug.SetMemoryLimit(-1); got != 36*1024*1024 {
			t.Fatalf("fixture did not apply the memory limit: %d", got)
		}
	})
	if got := debug.SetMemoryLimit(-1); got != priorLimit {
		t.Errorf("fixture leaked memory limit: %d, want %d", got, priorLimit)
	}
	metrics.Read(samples)
	if got := int(samples[0].Value.Uint64()); got != priorGC {
		t.Errorf("fixture leaked GC percent: %d, want %d", got, priorGC)
	}
	if got := runtime.GOMAXPROCS(0); got != priorProcs {
		t.Errorf("fixture leaked processor limit: %d, want %d", got, priorProcs)
	}
	if got := runtimeSetupSnapshot(); got != priorState {
		t.Errorf("fixture leaked runtime setup metadata: %+v, want %+v", got, priorState)
	}
}

func TestNEPacingSoftLimitDecision(t *testing.T) {
	cases := []struct {
		name     string
		budgeted bool
		underNE  bool
		existing int64
		want     int64
	}{
		{"a budgeted-platform NE without a limit gets the pacing", true, true, 0, nePacingSoftLimitBytes},
		{"an explicit limit is never overridden", true, true, 12345678, 0},
		{"macOS keeps runtime defaults on purpose", false, true, 0, 0},
		{"an app process is not on the NE budget", true, false, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := nePacingSoftLimit(tc.budgeted, tc.underNE, tc.existing); got != tc.want {
				t.Fatalf("nePacingSoftLimit(%v, %v, %d) = %d, want %d",
					tc.budgeted, tc.underNE, tc.existing, got, tc.want)
			}
		})
	}
}

func disarmThresholdMonitor(t *testing.T, priorShed bool) {
	priorLimit := debug.SetMemoryLimit(-1)
	priorProcs := runtime.GOMAXPROCS(0)
	samples := []metrics.Sample{{Name: "/gc/gogc:percent"}}
	metrics.Read(samples)
	priorGC := int(samples[0].Value.Uint64())
	setupMu.Lock()
	priorState := currentRuntimeSetup
	setupMu.Unlock()
	t.Cleanup(func() {
		setupMu.Lock()
		currentRuntimeSetup = priorState
		setupMu.Unlock()
		startPressureThresholdMonitor(0, priorShed)
		pressureThresholdShedEnabled.Store(priorShed)
		debug.SetMemoryLimit(priorLimit)
		debug.SetGCPercent(priorGC)
		runtime.GOMAXPROCS(priorProcs)
	})
}

func TestSetupArmsShedByDefault(t *testing.T) {
	prior := pressureThresholdShedEnabled.Load()
	disarmThresholdMonitor(t, prior)
	if err := Setup(testOptions(t)); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if !pressureThresholdShedEnabled.Load() {
		t.Fatal("shedding is still report-only by default; the enabling criterion that mode " +
			"declared for itself has been met on real devices (19 triggers, 3 process deaths)")
	}
}

func TestNewServiceArmsNEPacingAndRelogsTheMonitor(t *testing.T) {
	priorBudgeted := pacingBudgetedPlatform
	priorLimit := debug.SetMemoryLimit(-1)
	t.Cleanup(func() {
		pacingBudgetedPlatform = priorBudgeted
		debug.SetMemoryLimit(priorLimit)
	})
	pacingBudgetedPlatform = true
	disarmThresholdMonitor(t, pressureThresholdShedEnabled.Load())

	if err := Setup(testOptions(t)); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	platform := newRecordingPlatform()
	platform.underNetworkExtension = true
	svc, err := NewService(platform)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	defer stopLogRedirect(svc.logWriter)

	if got := runtimeSetupSnapshot().softMemoryLimit; got != nePacingSoftLimitBytes {
		t.Fatalf("softMemoryLimit = %d, want %d; the pacing never armed", got, nePacingSoftLimitBytes)
	}
	if got := debug.SetMemoryLimit(-1); got != nePacingSoftLimitBytes {
		t.Fatalf("GOMEMLIMIT = %d, want %d", got, nePacingSoftLimitBytes)
	}

	deadline := time.After(2 * time.Second)
	for {
		select {
		case line := <-platform.lines:
			if strings.Contains(line, "threshold monitor armed") {
				if !strings.Contains(line, "mode=limit") || !strings.Contains(line, "limit=52428800") || !strings.Contains(line, "shed=true") {
					t.Fatalf("armed line = %q, want mode=limit limit=52428800 shed=true", line)
				}
				return
			}
		case <-deadline:
			t.Fatal("the armed line never reached the platform log; it is still logged into the void")
		}
	}
}

func TestNewServiceLeavesExplicitLimitsAlone(t *testing.T) {
	priorBudgeted := pacingBudgetedPlatform
	priorLimit := debug.SetMemoryLimit(-1)
	t.Cleanup(func() {
		pacingBudgetedPlatform = priorBudgeted
		debug.SetMemoryLimit(priorLimit)
	})
	pacingBudgetedPlatform = true
	disarmThresholdMonitor(t, pressureThresholdShedEnabled.Load())

	options := testOptions(t)
	options.MemoryLimit = 48 * 1024 * 1024
	if err := Setup(options); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	want := runtimeSetupSnapshot().softMemoryLimit
	if want == 0 {
		t.Fatal("fixture broke: an explicit MemoryLimit produced no soft limit")
	}
	platform := newRecordingPlatform()
	platform.underNetworkExtension = true
	svc, err := NewService(platform)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	defer stopLogRedirect(svc.logWriter)
	if got := runtimeSetupSnapshot().softMemoryLimit; got != want {
		t.Fatalf("softMemoryLimit = %d, want the explicit %d untouched", got, want)
	}
}

func TestSecondNewServiceKeepsTheMachineOnTheFullBudget(t *testing.T) {
	priorBudgeted := pacingBudgetedPlatform
	priorLimit := debug.SetMemoryLimit(-1)
	t.Cleanup(func() {
		pacingBudgetedPlatform = priorBudgeted
		debug.SetMemoryLimit(priorLimit)
	})
	pacingBudgetedPlatform = true
	disarmThresholdMonitor(t, pressureThresholdShedEnabled.Load())

	if err := Setup(testOptions(t)); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	platform := newRecordingPlatform()
	platform.underNetworkExtension = true
	first, err := NewService(platform)
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	stopLogRedirect(first.logWriter)

	second := newRecordingPlatform()
	second.underNetworkExtension = true
	svc, err := NewService(second)
	if err != nil {
		t.Fatalf("second NewService: %v", err)
	}
	defer stopLogRedirect(svc.logWriter)

	deadline := time.After(2 * time.Second)
	for {
		select {
		case line := <-second.lines:
			if strings.Contains(line, "threshold monitor armed") {
				if !strings.Contains(line, "limit=52428800") {
					t.Fatalf("second service armed %q; the derived pacing value resurrected the unit error", line)
				}
				return
			}
		case <-deadline:
			t.Fatal("no armed line from the second service")
		}
	}
}

func TestExplicitReloadSoftLimitRearmsTheMachine(t *testing.T) {
	priorLimit := debug.SetMemoryLimit(-1)
	t.Cleanup(func() { debug.SetMemoryLimit(priorLimit) })
	disarmThresholdMonitor(t, pressureThresholdShedEnabled.Load())

	if err := Setup(testOptions(t)); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	options := &RuntimeSetupOptions{SoftMemoryLimit: 32 * 1024 * 1024}
	if err := ReloadSetupOptions(options); err != nil {
		t.Fatalf("ReloadSetupOptions: %v", err)
	}
	pressureThresholdMu.Lock()
	machine := pressureThresholdMachine
	pressureThresholdMu.Unlock()
	if machine == nil || machine.mode != thresholdModeLimit || machine.limit != uint64(machineBudgetForPacing(32*1024*1024)) {
		t.Fatalf("machine not re-armed on the pacing value's budget: %+v", machine)
	}
	if got := runtimeSetupSnapshot(); got.softMemoryLimitIsPacingDefault {
		t.Fatal("an explicit limit must clear the pacing-default provenance")
	}
}

func TestPredictorHonoursTheEdgeDuringASustainedGrowingEpisode(t *testing.T) {
	machine := newPressureMachine(thresholdModeLimit, 50*1024*1024)
	machine.notifyPressure()
	now := time.Now()
	usage := uint64(20 * 1024 * 1024)
	triggers := 0
	for i := 0; i < 20; i++ {
		now = now.Add(100 * time.Millisecond)
		usage += 3 * 1024 * 1024
		if usage >= 49*1024*1024 {
			usage = 49 * 1024 * 1024
		}
		decision := machine.step(pressureSample{usage: usage}, now)
		if decision.triggered {
			triggers++
		}
	}
	if triggers != 1 {
		t.Fatalf("a sustained growing episode raised the trigger %d times; the decision "+
			"documents an edge, and the driver sheds on every raise", triggers)
	}
}

func TestSetupArmsTheMachineOnTheFullConfiguredBudget(t *testing.T) {
	disarmThresholdMonitor(t, pressureThresholdShedEnabled.Load())
	options := testOptions(t)
	options.MemoryLimit = 48 * 1024 * 1024
	if err := Setup(options); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	pressureThresholdMu.Lock()
	machine := pressureThresholdMachine
	pressureThresholdMu.Unlock()
	if machine == nil || machine.limit != 48*1024*1024 {
		t.Fatalf("machine limit = %+v, want the full 48 MiB budget, not its 3/4 pacing", machine)
	}
}
