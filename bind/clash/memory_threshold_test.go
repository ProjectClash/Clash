package clash

import (
	"testing"
	"time"
)

const testLimit = 50 << 20

func atUsage(usage uint64) pressureSample {
	return pressureSample{usage: usage}
}

func atAvailable(usage, available uint64) pressureSample {
	return pressureSample{usage: usage, available: available, availableKnown: true}
}

func TestLimitThresholdsAreOrderedAndClampToSmallLimits(t *testing.T) {
	thresholds := computeLimitThresholds(testLimit, pressureSafetyMargin)
	if !(thresholds.resume < thresholds.armed && thresholds.armed < thresholds.trigger) {
		t.Fatalf("thresholds out of order: resume=%d armed=%d trigger=%d; hysteresis needs resume "+
			"strictly below trigger or it cannot stop flapping",
			thresholds.resume, thresholds.armed, thresholds.trigger)
	}
	if thresholds.trigger != testLimit-pressureSafetyMargin {
		t.Fatalf("trigger = %d, want one margin below the limit", thresholds.trigger)
	}

	tiny := computeLimitThresholds(4<<20, pressureSafetyMargin)
	if tiny.trigger > 4<<20 {
		t.Fatalf("trigger = %d for a 4 MiB limit; the margin underflowed and the machine would "+
			"never fire", tiny.trigger)
	}
}

func TestHysteresisDoesNotFlapAtTheTriggerLine(t *testing.T) {
	machine := newPressureMachine(thresholdModeLimit, testLimit)
	thresholds := computeLimitThresholds(testLimit, pressureSafetyMargin)
	now := time.Unix(1_800_000_000, 0)

	first := machine.step(atUsage(thresholds.trigger+1), now)
	if !first.triggered || first.state != pressureStateTriggered {
		t.Fatalf("crossing the trigger line did not trigger: %+v", first)
	}

	for i := 0; i < 6; i++ {
		now = now.Add(pressureMinInterval)
		step := machine.step(atUsage(thresholds.trigger-1), now)
		if step.triggered {
			t.Fatalf("re-fired on poll %d while hovering below the trigger; every fire closes "+
				"every connection, so flapping here is worse than not acting at all", i)
		}
		if step.state != pressureStateTriggered {
			t.Fatalf("left the triggered state at usage above resume (%d > %d) on poll %d; the "+
				"separate resume threshold is what prevents oscillation",
				thresholds.trigger-1, thresholds.resume, i)
		}
	}

	now = now.Add(pressureMinInterval)
	recovered := machine.step(atUsage(thresholds.resume-1), now)
	if recovered.state != pressureStateNormal {
		t.Fatalf("state = %v after dropping below resume, want normal", recovered.state)
	}
	if recovered.triggered {
		t.Fatal("recovery reported a trigger")
	}
}

func TestPredictorFiresBeforeTheLimitIsReached(t *testing.T) {
	machine := newPressureMachine(thresholdModeLimit, testLimit)
	now := time.Unix(1_800_000_000, 0)

	thresholds := computeLimitThresholds(testLimit, pressureSafetyMargin)
	start := uint64(20 << 20)
	if start >= thresholds.armed {
		t.Fatalf("test baseline %d is not below the armed threshold %d", start, thresholds.armed)
	}

	machine.notifyPressure()
	baseline := machine.step(atUsage(start), now)
	if baseline.triggered {
		t.Fatal("the baseline poll triggered")
	}

	now = now.Add(pressureMinInterval)
	grown := machine.step(atUsage(39<<20), now)

	if !grown.triggered {
		t.Fatalf("a footprint growing at ~190 MiB/s with ~11 MiB of headroom did not trigger: "+
			"%+v. Reaching the limit on iOS is a jetsam kill, so reacting only after the "+
			"threshold is the same as not reacting", grown)
	}
	if !grown.predicted {
		t.Fatal("triggered, but not reported as a prediction; the distinction is what tells a " +
			"device report apart from an ordinary threshold crossing")
	}
	if grown.state != pressureStateTriggered {
		t.Fatalf("state = %v, want triggered", grown.state)
	}
}

func TestPredictorIgnoresSlowGrowth(t *testing.T) {
	machine := newPressureMachine(thresholdModeLimit, testLimit)
	now := time.Unix(1_800_000_000, 0)

	machine.notifyPressure()
	machine.step(atUsage(18<<20), now)

	now = now.Add(time.Second)
	step := machine.step(atUsage(19<<20), now)
	if step.triggered {
		t.Fatalf("slow growth triggered: %+v. Twenty-six seconds of headroom is not an emergency", step)
	}
}

func TestAvailableModeThresholdsAreInverted(t *testing.T) {
	machine := newPressureMachine(thresholdModeAvailable, 0)
	now := time.Unix(1_800_000_000, 0)

	plenty := machine.step(atAvailable(200<<20, 8<<30), now)
	if plenty.state != pressureStateNormal {
		t.Fatalf("8 GiB free read as %v; the comparison is inverted", plenty.state)
	}

	now = now.Add(pressureMaxInterval)
	scarce := machine.step(atAvailable(200<<20, 8<<20), now)
	if scarce.state != pressureStateTriggered || !scarce.triggered {
		t.Fatalf("8 MiB free read as %v (triggered=%v); this is the case the mode exists for",
			scarce.state, scarce.triggered)
	}
}

func TestAvailableModeStaysQuietWithoutAReading(t *testing.T) {
	machine := newPressureMachine(thresholdModeAvailable, 0)
	now := time.Unix(1_800_000_000, 0)
	for i := 0; i < 4; i++ {
		step := machine.step(atUsage(200<<20), now)
		if step.state != pressureStateNormal || step.triggered {
			t.Fatalf("an unknown available reading produced %v (triggered=%v) on poll %d",
				step.state, step.triggered, i)
		}
		now = now.Add(pressureMaxInterval)
	}
}

func TestModeResolutionMatchesUpstreamPrecedence(t *testing.T) {
	cases := []struct {
		name      string
		softLimit int64
		available int64
		want      thresholdMode
		why       string
	}{
		{
			name: "a configured limit wins", softLimit: 50 << 20, available: 8 << 30,
			want: thresholdModeLimit,
			why:  "the iOS profiles carry the jetsam-derived budget and must threshold on their own footprint",
		},
		{
			name: "no limit but a readable machine", softLimit: 0, available: 8 << 30,
			want: thresholdModeAvailable,
			why:  "the macOS profiles never set a soft limit, exactly as upstream reaches for its NE regime only under C.IsIos",
		},
		{
			name: "neither", softLimit: 0, available: -1,
			want: thresholdModeNone,
			why:  "nothing measurable; guessing would be worse than idling",
		},
		{
			name: "a negative limit is not a limit", softLimit: -1, available: -1,
			want: thresholdModeNone,
			why:  "an unset int64 must not be read as a one-byte budget",
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := resolveThresholdMode(testCase.softLimit, testCase.available); got != testCase.want {
				t.Fatalf("mode = %v, want %v — %s", got, testCase.want, testCase.why)
			}
		})
	}
}

func TestIntervalBacksOffAndSnapsBack(t *testing.T) {
	machine := newPressureMachine(thresholdModeLimit, testLimit)
	now := time.Unix(1_800_000_000, 0)

	var interval time.Duration
	for i := 0; i < 8; i++ {
		interval = machine.step(atUsage(10<<20), now).interval
		now = now.Add(interval)
	}
	if interval != pressureMaxInterval {
		t.Fatalf("quiet interval settled at %v, want %v", interval, pressureMaxInterval)
	}

	thresholds := computeLimitThresholds(testLimit, pressureSafetyMargin)
	armed := machine.step(atUsage(thresholds.armed+1), now)
	if armed.state != pressureStateArmed {
		t.Fatalf("state = %v, want armed", armed.state)
	}
	if armed.interval != pressureArmedInterval {
		t.Fatalf("armed interval = %v, want %v", armed.interval, pressureArmedInterval)
	}

	now = now.Add(armed.interval)
	triggered := machine.step(atUsage(thresholds.trigger+1), now)
	if triggered.interval != pressureMinInterval {
		t.Fatalf("triggered interval = %v, want %v", triggered.interval, pressureMinInterval)
	}

	machine.notifyPressure()
	now = now.Add(pressureMinInterval)
	quiet := machine.step(atUsage(10<<20), now)
	if quiet.state != pressureStateNormal {
		t.Fatalf("state = %v after a quiet reading, want normal", quiet.state)
	}
	if quiet.interval == pressureMinInterval {
		t.Fatal("held the fast rate on a quiet reading after a notification; upstream clears the " +
			"force flag as soon as the state resolves to normal, so this would poll ten times " +
			"faster than upstream for as long as notifications keep arriving")
	}

	machine.notifyPressure()
	now = now.Add(quiet.interval)
	hinted := machine.step(atUsage(thresholds.armed+1), now)
	if hinted.state != pressureStateArmed {
		t.Fatalf("state = %v, want armed", hinted.state)
	}
	if hinted.interval != pressureMinInterval {
		t.Fatalf("interval = %v on an armed reading after a notification, want %v — this is the "+
			"only case where the force flag changes anything", hinted.interval, pressureMinInterval)
	}
}

func TestNoneModeIsInert(t *testing.T) {
	machine := newPressureMachine(thresholdModeNone, 0)
	step := machine.step(atUsage(1<<30), time.Unix(1_800_000_000, 0))
	if step.triggered || step.state != pressureStateNormal {
		t.Fatalf("none mode acted: %+v", step)
	}
	if step.interval != pressureMaxInterval {
		t.Fatalf("none mode interval = %v, want the slowest rate", step.interval)
	}
}

func TestZeroHeadroomIsNotAReading(t *testing.T) {
	if got := resolveThresholdMode(0, 0); got != thresholdModeNone {
		t.Fatalf("mode for a zero headroom reading = %v, want none. Zero means 'no limit' from "+
			"os_proc_available_memory, and treating it as a reading fires the trigger permanently", got)
	}
	if got := resolveThresholdMode(0, -1); got != thresholdModeNone {
		t.Fatalf("mode for an unavailable reading = %v, want none", got)
	}
	if got := resolveThresholdMode(0, 1); got != thresholdModeAvailable {
		t.Fatalf("mode for a positive headroom reading = %v, want available", got)
	}

	machine := newPressureMachine(thresholdModeAvailable, 0)
	step := machine.step(pressureSample{usage: 200 << 20, available: 0, availableKnown: false}, timeUnix())
	if step.triggered || step.state != pressureStateNormal {
		t.Fatalf("an unknown headroom produced %+v; the available mode must stay quiet without a "+
			"reading rather than treating absence as exhaustion", step)
	}
}

func timeUnix() time.Time { return time.Unix(1_800_000_000, 0) }

func TestPredictorPreservesFractionalSeconds(t *testing.T) {
	for _, elapsed := range []time.Duration{50 * time.Millisecond, 99 * time.Millisecond, 100 * time.Millisecond, 101 * time.Millisecond, 500 * time.Millisecond, 999 * time.Millisecond, time.Second, 1500 * time.Millisecond} {
		t.Run(elapsed.String(), func(t *testing.T) {
			machine := newPressureMachine(thresholdModeLimit, 50<<20)
			now := time.Unix(1_800_000_000, 0)
			machine.notifyPressure()
			machine.step(atUsage(30<<20), now)
			decision := machine.step(atUsage(40<<20), now.Add(elapsed))
			want := elapsed < pressureMinInterval
			if decision.predicted != want || decision.triggered != want {
				t.Fatalf("time-to-limit=%v minimum interval=%v: decision=%+v, want trigger=%t", elapsed, pressureMinInterval, decision, want)
			}
		})
	}
}
