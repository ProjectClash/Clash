//go:build !no_easytier

package outbound

import (
	"context"
	"reflect"
	"runtime"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	corehost "github.com/easytier/easytier/easytier-go"
)

func runningEasyTierInstance(t *testing.T) *corehost.Instance {
	t.Helper()
	instance := new(corehost.Instance)
	engineField := reflect.ValueOf(instance).Elem().FieldByName("engine")
	if !engineField.IsValid() {
		t.Fatal("easytier-go no longer keeps its state where this fixture writes it; update the fixture, do not drop the test")
	}
	engine := reflect.New(engineField.Type().Elem())
	reflect.NewAt(engineField.Type(), unsafe.Pointer(engineField.UnsafeAddr())).Elem().Set(engine)
	stateField := engine.Elem().FieldByName("state")
	if !stateField.IsValid() {
		t.Fatal("easytier-go no longer keeps its state where this fixture writes it; update the fixture, do not drop the test")
	}
	state, ok := reflect.NewAt(stateField.Type(), unsafe.Pointer(stateField.UnsafeAddr())).Interface().(*atomic.Int32)
	if !ok {
		t.Fatal("easytier-go no longer keeps its state where this fixture writes it; update the fixture, do not drop the test")
	}
	state.Store(int32(corehost.StateRunning))
	if instance.State() != corehost.StateRunning {
		t.Fatal("fixture instance is not running")
	}
	return instance
}

func TestEasyTierReadinessBetweenCheckAndSubscriptionIsNotLost(t *testing.T) {
	previous := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(previous)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e := &EasyTier{ctx: ctx, cancel: cancel}
	e.loopOnce.Do(func() {})
	running := runningEasyTierInstance(t)
	request, cancelRequest := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancelRequest()
	done := make(chan error, 1)

	e.mu.Lock()
	go func() { done <- e.ensureStarted(request) }()
	runtime.Gosched()
	e.startMu.Lock()
	e.mu.Unlock()
	runtime.Gosched()
	e.mu.Lock()
	e.instance = running
	e.mu.Unlock()
	e.startMu.Unlock()
	e.signalReady()
	if err := <-done; err != nil {
		t.Fatalf("a running EasyTier was never observed after signalReady: %v", err)
	}
}
