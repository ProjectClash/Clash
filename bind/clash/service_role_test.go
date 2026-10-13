package clash

import "testing"

func TestARefusedServiceLeavesTheProcessTheApp(t *testing.T) {
	setupMu.Lock()
	wasDone, wasDisabled := setupDone, setupCacheDisabled
	setupDone, setupCacheDisabled = true, true
	setupMu.Unlock()
	wasTunnel := tunnelProcess.Load()
	tunnelProcess.Store(false)
	t.Cleanup(func() {
		setupMu.Lock()
		setupDone, setupCacheDisabled = wasDone, wasDisabled
		setupMu.Unlock()
		tunnelProcess.Store(wasTunnel)
	})
	if _, err := NewService(newRecordingPlatform()); err == nil {
		t.Fatal("NewService ran after an App-only Setup")
	}
	if tunnelProcess.Load() {
		t.Fatal("a refused NewService marked the process the tunnel's")
	}
	if got := providerContentBytes(); got != maximumPendingCompileBytes {
		t.Fatalf("the App reads providers up to %d, want %d", got, maximumPendingCompileBytes)
	}
}
