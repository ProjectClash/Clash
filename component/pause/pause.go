package pause

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/metacubex/sing/service"
	singpause "github.com/metacubex/sing/service/pause"
)

type Callback = singpause.Callback

const (
	EventDevicePaused = singpause.EventDevicePaused
	EventDeviceWake   = singpause.EventDeviceWake
	EventNetworkPause = singpause.EventNetworkPause
	EventNetworkWake  = singpause.EventNetworkWake
)

var manager = service.FromContext[singpause.Manager](
	singpause.WithDefaultManager(context.Background()),
)

var outstanding atomic.Int64

func Outstanding() int64 { return outstanding.Load() }

func release(unregister func()) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			unregister()
			outstanding.Add(-1)
		})
	}
}

func DevicePause() { manager.DevicePause() }

func DeviceWake() { manager.DeviceWake() }

func NetworkPause() { manager.NetworkPause() }

func NetworkWake() { manager.NetworkWake() }

func IsNetworkPaused() bool { return manager.IsNetworkPaused() }

func IsDevicePaused() bool { return manager.IsDevicePaused() }

func RegisterTicker(ticker *time.Ticker, duration time.Duration, resume func()) func() {
	element := singpause.RegisterTicker(manager, ticker, duration, resume)
	outstanding.Add(1)
	return release(func() { manager.UnregisterCallback(element) })
}

func RegisterTickerResumingOnDeviceWake(ticker *time.Ticker, duration time.Duration, resume func()) func() {
	if manager.IsPaused() {
		ticker.Stop()
	}
	element := manager.RegisterCallback(func(event int) {
		switch event {
		case EventDevicePaused, EventNetworkPause:
			ticker.Stop()
		case EventDeviceWake, EventNetworkWake:
			if event == EventDeviceWake && resume != nil {
				resume()
			}
			ticker.Reset(duration)
		}
	})
	outstanding.Add(1)
	return release(func() { manager.UnregisterCallback(element) })
}

func RegisterCallback(callback Callback) func() {
	element := manager.RegisterCallback(callback)
	outstanding.Add(1)
	return release(func() { manager.UnregisterCallback(element) })
}
