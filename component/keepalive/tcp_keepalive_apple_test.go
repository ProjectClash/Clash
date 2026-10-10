package keepalive

import (
	"runtime"
	"testing"
	"time"
)


func TestUnconfiguredKeepAliveUsesAppleFriendlyDefaults(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "ios" {
		t.Skipf("the carve-out is darwin-only by design; %s keeps upstream behaviour", runtime.GOOS)
	}
	restore := saveKeepAlive()
	defer restore()

	SetKeepAliveIdle(0)
	SetKeepAliveInterval(0)

	if got, want := KeepAliveIdle(), 5*time.Minute; got != want {
		t.Fatalf("unconfigured KeepAliveIdle() = %v, want %v; zero would reach Go and become 15s", got, want)
	}
	if got, want := KeepAliveInterval(), 75*time.Second; got != want {
		t.Fatalf("unconfigured KeepAliveInterval() = %v, want %v", got, want)
	}
}

func TestExplicitConfigurationStillWins(t *testing.T) {
	restore := saveKeepAlive()
	defer restore()

	SetKeepAliveIdle(42 * time.Second)
	SetKeepAliveInterval(7 * time.Second)

	if got, want := KeepAliveIdle(), 42*time.Second; got != want {
		t.Fatalf("KeepAliveIdle() = %v, want the configured %v; a default must not shadow config", got, want)
	}
	if got, want := KeepAliveInterval(), 7*time.Second; got != want {
		t.Fatalf("KeepAliveInterval() = %v, want the configured %v", got, want)
	}
}

func TestNonAppleKeepsUpstreamZero(t *testing.T) {
	if runtime.GOOS == "darwin" || runtime.GOOS == "ios" {
		t.Skip("darwin has the carve-out; this asserts the absence of one elsewhere")
	}
	restore := saveKeepAlive()
	defer restore()

	SetKeepAliveIdle(0)
	SetKeepAliveInterval(0)

	if got := KeepAliveIdle(); got != 0 {
		t.Fatalf("KeepAliveIdle() = %v on %s, want 0 so Go's own default applies", got, runtime.GOOS)
	}
}

func saveKeepAlive() func() {
	idle, interval, disabled := KeepAliveIdle(), KeepAliveInterval(), DisableKeepAlive()
	rawIdle, rawInterval := keepAliveIdle.Load(), keepAliveInterval.Load()
	_ = idle
	_ = interval
	return func() {
		keepAliveIdle.Store(rawIdle)
		keepAliveInterval.Store(rawInterval)
		setDisableKeepAlive(disabled)
	}
}
