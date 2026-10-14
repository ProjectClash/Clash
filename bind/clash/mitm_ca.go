package clash

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ProjectClash/Clash/component/mitm"
)

// MITMCaInfo describes the active MITM root certificate so the App can show
// what it is asking the user to install and trust.
type MITMCaInfo struct {
	Enabled     bool   `json:"enabled"`
	Fingerprint string `json:"fingerprint,omitempty"`
	NotAfter    string `json:"notAfter,omitempty"`
	StoreDir    string `json:"storeDir,omitempty"`
}

// MITMState reports whether MITM is active and describes its CA. When MITM
// is off the answer carries Enabled=false and nothing else; the App treats
// that as "no profile to install".
func MITMState() (*MITMCaInfo, error) {
	info, err := recoverAppCall("MITMState", func() (*MITMCaInfo, error) {
		return mitmStateUnguarded()
	})
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return info, nil
}

func mitmStateUnguarded() (*MITMCaInfo, error) {
	dispatcher := mitm.ActiveDispatcher()
	if dispatcher == nil || !dispatcher.Enable() {
		return &MITMCaInfo{Enabled: false}, nil
	}
	engine := dispatcher.Engine()
	if engine == nil {
		return &MITMCaInfo{Enabled: false}, nil
	}
	fingerprint, err := engine.CaFingerprintHex()
	if err != nil {
		return nil, err
	}
	info := &MITMCaInfo{Enabled: true, Fingerprint: fingerprint}
	if notAfter, err := engine.CaNotAfter(); err == nil {
		info.NotAfter = notAfter.UTC().Format("2006-01-02T15:04:05Z")
	}
	return info, nil
}

// ExportMITMCa writes the active MITM root certificate to caPath in PEM form
// and returns the SHA-256 fingerprint hex of the DER. The App passes a path
// inside its own container; the core only writes that one file.
func ExportMITMCa(caPath string) (string, error) {
	fingerprint, err := recoverAppCall("ExportMITMCa", func() (string, error) {
		return exportMITMCaUnguarded(caPath)
	})
	if err != nil {
		return "", bridgeSafeError(err)
	}
	return fingerprint, nil
}

func exportMITMCaUnguarded(caPath string) (string, error) {
	if strings.TrimSpace(caPath) == "" {
		return "", fmt.Errorf("clash: mitm: empty CA export path")
	}
	dispatcher := mitm.ActiveDispatcher()
	if dispatcher == nil || !dispatcher.Enable() {
		return "", fmt.Errorf("clash: mitm is not enabled")
	}
	pemBytes, err := dispatcher.CaCertificatePEM()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(caPath), 0o755); err != nil {
		return "", fmt.Errorf("clash: mitm: create CA directory: %w", err)
	}
	if err := os.WriteFile(caPath, pemBytes, 0o644); err != nil {
		return "", fmt.Errorf("clash: mitm: write CA file: %w", err)
	}
	sum := sha256.Sum256(pemBytes)
	return hex.EncodeToString(sum[:]), nil
}

// ResetMITMCa regenerates the root certificate. Installed trust profiles
// stop working until the user reinstalls, so only the App's explicit reset
// action calls this.
func ResetMITMCa() error {
	_, err := recoverAppCall("ResetMITMCa", func() (struct{}, error) {
		dispatcher := mitm.ActiveDispatcher()
		if dispatcher == nil || !dispatcher.Enable() {
			return struct{}{}, fmt.Errorf("clash: mitm is not enabled")
		}
		engine := dispatcher.Engine()
		if engine == nil {
			return struct{}{}, fmt.Errorf("clash: mitm is not enabled")
		}
		if err := engine.Regenerate(); err != nil {
			return struct{}{}, err
		}
		if dir := dispatcher.StoreDir(); dir != "" {
			if err := mitm.SaveState(engine, dir); err != nil {
				return struct{}{}, err
			}
		}
		return struct{}{}, nil
	})
	if err != nil {
		return bridgeSafeError(err)
	}
	return nil
}
