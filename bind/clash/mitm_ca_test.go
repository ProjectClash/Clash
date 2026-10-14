package clash

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/ProjectClash/Clash/component/mitm"
)

// startMITM installs a dispatcher with a live engine for the duration of the
// test and restores the disabled state afterwards.
func startMITM(t *testing.T) {
	t.Helper()
	cfg := &mitm.Config{Enable: true, HostGates: []string{"example.com"}}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	dispatcher, err := mitm.NewDispatcher(cfg)
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}
	mitm.UpdateMITM(dispatcher)
	t.Cleanup(func() { mitm.UpdateMITM(nil) })
}

// TestExportMITMCaFingerprintMatchesMITMState pins the contract that both
// surfaces report the SAME fingerprint — SHA-256 of the certificate DER.
// ExportMITMCa used to hash the PEM bytes, which can never equal the
// DER-based fingerprint MITMState shows the user.
func TestExportMITMCaFingerprintMatchesMITMState(t *testing.T) {
	startMITM(t)
	state, err := MITMState()
	if err != nil {
		t.Fatalf("MITMState: %v", err)
	}
	if !state.Enabled || state.Fingerprint == "" {
		t.Fatalf("MITMState = %+v, want enabled with a fingerprint", state)
	}

	path := filepath.Join(t.TempDir(), "export", "ca.pem")
	exportFp, err := ExportMITMCa(path)
	if err != nil {
		t.Fatalf("ExportMITMCa: %v", err)
	}
	if exportFp != state.Fingerprint {
		t.Fatalf("fingerprint mismatch: ExportMITMCa=%s MITMState=%s", exportFp, state.Fingerprint)
	}

	// Independent check: the fingerprint is SHA-256 of the DER in the file.
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("exported file is not PEM")
	}
	sum := sha256.Sum256(block.Bytes)
	if hex.EncodeToString(sum[:]) != exportFp {
		t.Fatalf("ExportMITMCa fingerprint is not SHA-256 of the DER: %s vs %s", exportFp, hex.EncodeToString(sum[:]))
	}

	// The export parent dir must not be world-readable (0700, consistent
	// with the mitm state dir).
	info, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Fatalf("export dir perms = %v, want 0700", got)
	}
}

func TestMITMStateDisabledWhenNoDispatcher(t *testing.T) {
	mitm.UpdateMITM(nil)
	t.Cleanup(func() { mitm.UpdateMITM(nil) })
	state, err := MITMState()
	if err != nil {
		t.Fatalf("MITMState: %v", err)
	}
	if state.Enabled {
		t.Fatalf("MITMState = %+v with no dispatcher, want enabled=false", state)
	}
	if _, err := ExportMITMCa(filepath.Join(t.TempDir(), "ca.pem")); err == nil {
		t.Fatal("ExportMITMCa must fail when MITM is off")
	}
}
