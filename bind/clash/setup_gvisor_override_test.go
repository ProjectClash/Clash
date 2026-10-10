package clash

import (
	"os"
	"path/filepath"
	"testing"

	tun "github.com/metacubex/sing-tun"
)

func TestApplyGVisorTCPBufferOverride(t *testing.T) {
	original := tun.GVisorTCPBufferBytes
	t.Cleanup(func() { tun.GVisorTCPBufferBytes = original })

	base := t.TempDir()
	overridePath := filepath.Join(base, gVisorTCPBufferOverrideFile)

	tun.GVisorTCPBufferBytes = 20 * 1024
	applyGVisorTCPBufferOverride(base)
	if tun.GVisorTCPBufferBytes != 20*1024 {
		t.Fatalf("absent override changed the window: %d", tun.GVisorTCPBufferBytes)
	}

	if err := os.WriteFile(overridePath, []byte("131072\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	applyGVisorTCPBufferOverride(base)
	if tun.GVisorTCPBufferBytes != 131072 {
		t.Fatalf("valid override not applied: %d", tun.GVisorTCPBufferBytes)
	}

	for _, bad := range []string{"0", "-5", "not-a-number", ""} {
		tun.GVisorTCPBufferBytes = 20 * 1024
		if err := os.WriteFile(overridePath, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		applyGVisorTCPBufferOverride(base)
		if tun.GVisorTCPBufferBytes != 20*1024 {
			t.Fatalf("invalid override %q changed the window: %d", bad, tun.GVisorTCPBufferBytes)
		}
	}
}
