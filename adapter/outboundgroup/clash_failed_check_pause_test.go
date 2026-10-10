package outboundgroup

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/component/pause"
	C "github.com/ProjectClash/Clash/constant"
)

func TestAFailureStormStartsNoHealthCheckWhileTheNetworkIsPaused(t *testing.T) {
	gb := NewGroupBase(GroupBaseOption{Name: "AUTO", Type: C.URLTest, MaxFailedTimes: 3, TestTimeout: 5000})
	var checks atomic.Int32
	check := func() { checks.Add(1) }
	timeout := errors.New("connect error: context deadline exceeded")

	pause.NetworkPause()
	t.Cleanup(pause.NetworkWake)
	for i := 0; i < 6; i++ {
		gb.onDialFailed(C.Vmess, timeout, check)
	}
	time.Sleep(200 * time.Millisecond)
	if got := checks.Load(); got != 0 {
		t.Fatalf("%d health checks started into a paused network, want none", got)
	}

	pause.NetworkWake()
	for i := 0; i < 6; i++ {
		gb.onDialFailed(C.Vmess, timeout, check)
	}
	deadline := time.Now().Add(2 * time.Second)
	for checks.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if checks.Load() == 0 {
		t.Fatal("once the network delivers again the failure trigger must work as before")
	}
}

func TestAFailureStormStartsNoHealthCheckWhileTheDeviceSleeps(t *testing.T) {
	gb := NewGroupBase(GroupBaseOption{Name: "AUTO", Type: C.URLTest, MaxFailedTimes: 3, TestTimeout: 5000})
	var checks atomic.Int32
	pause.DevicePause()
	t.Cleanup(pause.DeviceWake)
	for i := 0; i < 6; i++ {
		gb.onDialFailed(C.Vmess, errors.New("connect error: context deadline exceeded"), func() { checks.Add(1) })
	}
	time.Sleep(200 * time.Millisecond)
	if got := checks.Load(); got != 0 {
		t.Fatalf("%d health checks while the device sleeps, want none", got)
	}
}
