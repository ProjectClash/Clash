//go:build !no_easytier

package outbound

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	C "github.com/ProjectClash/Clash/constant"
	D "github.com/miekg/dns"
)

func easyTierPlatformFixture(t *testing.T) EasyTierOption {
	t.Helper()
	home := t.TempDir()
	previous := C.Path.HomeDir()
	C.SetHomeDir(home)
	t.Cleanup(func() { C.SetHomeDir(previous) })
	if err := os.WriteFile(filepath.Join(home, "blocked"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	return EasyTierOption{
		Name: t.Name(), NetworkName: "platform-fixture",
		Peers: []string{"tcp://127.0.0.1:1"}, StateDir: "blocked/state", UDP: true,
	}
}

func TestEasyTierMobileRejectsEveryEngineEntry(t *testing.T) {
	e, err := newEasyTier(easyTierPlatformFixture(t), "ios")
	if err != nil {
		t.Fatalf("a valid unsupported node must still parse: %v", err)
	}
	t.Cleanup(func() { _ = e.Close() })
	if e.Type() != C.EasyTier || !e.SupportUDP() {
		t.Fatal("platform policy must preserve configured node metadata")
	}
	query := new(D.Msg)
	query.SetQuestion("node.easytier.", D.TypeA)
	entries := map[string]func() error{
		"tcp-and-urltest": func() error { _, err := e.DialContext(context.Background(), &C.Metadata{}); return err },
		"udp":             func() error { _, err := e.ListenPacketContext(context.Background(), &C.Metadata{}); return err },
		"overlay-dns": func() error {
			_, err := (easyTierDNSTransport{easytier: e}).ExchangeContext(context.Background(), query)
			return err
		},
	}
	for name, entry := range entries {
		t.Run(name, func(t *testing.T) {
			for attempt := 0; attempt < 2; attempt++ {
				if err := entry(); !errors.Is(err, C.ErrNotSupport) || !strings.Contains(err.Error(), "iOS/tvOS") {
					t.Errorf("got %v, want explicit iOS/tvOS unsupported error", err)
				}
			}
		})
	}
	unused := false
	e.loopOnce.Do(func() { unused = true })
	if !unused || e.host != nil || e.instance != nil {
		t.Fatal("unsupported calls reached the engine initialization path")
	}
}

func TestEasyTierMobileConcurrentProbesDoNotStartEngine(t *testing.T) {
	e, err := newEasyTier(easyTierPlatformFixture(t), "ios")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.Close() })
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Go(func() {
			if err := e.ensureStarted(context.Background()); !errors.Is(err, C.ErrNotSupport) {
				t.Errorf("probe error = %v", err)
			}
		})
	}
	wg.Wait()
	unused := false
	e.loopOnce.Do(func() { unused = true })
	if !unused || e.host != nil || e.instance != nil {
		t.Fatal("probes started the engine")
	}
}

func TestEasyTierOtherPlatformsRetainInitialization(t *testing.T) {
	option := easyTierPlatformFixture(t)
	for _, goos := range []string{"darwin", "linux", "android", "windows"} {
		t.Run(goos, func(t *testing.T) {
			e, err := newEasyTier(option, goos)
			if err != nil {
				t.Fatal(err)
			}
			defer e.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
			defer cancel()
			if err = e.ensureStarted(ctx); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("supported platform should wait on the engine, got %v", err)
			}
			unused := false
			e.loopOnce.Do(func() { unused = true })
			if unused {
				t.Fatal("supported platform never started the engine loop")
			}
			if err = e.init(); err == nil || errors.Is(err, C.ErrNotSupport) || !strings.Contains(err.Error(), "create state-dir") {
				t.Fatalf("supported platform did not reach original initialization: %v", err)
			}
		})
	}
}

func TestEasyTierProductionConstructorUsesActualPlatform(t *testing.T) {
	e, err := NewEasyTier(easyTierPlatformFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	err = e.ensureStarted(ctx)
	if got, want := errors.Is(err, C.ErrNotSupport), runtime.GOOS == "ios"; got != want {
		t.Fatalf("platform %s: unsupported=%t, want %t; error=%v", runtime.GOOS, got, want, err)
	}
}
