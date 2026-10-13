package clash

import (
	"strings"
	"testing"
)

func asTunnelProcess(t *testing.T) { t.Helper(); withTunnelProcess(t, true) }
func asAppProcess(t *testing.T)    { t.Helper(); withTunnelProcess(t, false) }

func withTunnelProcess(t *testing.T, tunnel bool) {
	t.Helper()
	previous := tunnelProcess.Load()
	tunnelProcess.Store(tunnel)
	t.Cleanup(func() { tunnelProcess.Store(previous) })
}

func TestTheProviderCeilingIsTheProcesss(t *testing.T) {
	asAppProcess(t)
	if providerContentBytes() != maximumPendingCompileBytes {
		t.Fatalf("the App reads %d bytes", providerContentBytes())
	}
	big := make([]byte, maximumProviderResourceBytes+1)
	if _, err := inspectProxyPayloadForIOSUnguarded(big, "", false); err != nil && containsLimit(err.Error()) {
		t.Fatalf("the App refused a payload past 16 MiB: %v", err)
	}
	asTunnelProcess(t)
	if providerContentBytes() != maximumProviderResourceBytes {
		t.Fatalf("the tunnel reads %d bytes", providerContentBytes())
	}
	if _, err := inspectProxyPayloadForIOSUnguarded(big, "", false); err == nil || !containsLimit(err.Error()) {
		t.Fatalf("the tunnel took a payload past 16 MiB: %v", err)
	}
}

func containsLimit(message string) bool { return strings.Contains(message, "byte limit") }
