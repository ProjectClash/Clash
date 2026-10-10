package clash

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/ProjectClash/Clash/component/ca"
	"github.com/ProjectClash/Clash/hub/route"
	"github.com/ProjectClash/Clash/log"
)

const (
	remoteControlConfig = "config"
	remoteControlLocal  = "local"
	remoteControlLAN    = "lan"
)

const (
	remoteControlMinimumPort = 1024
	remoteControlMaximumPort = 65535
	remoteControlSecretBytes = 256
)

var remoteControlLANHost = "0.0.0.0"

type remoteControlSettings struct {
	Mode           string `json:"mode"`
	HTTPPort       int    `json:"httpPort"`
	TLSPort        int    `json:"tlsPort"`
	Secret         string `json:"secret"`
	CertificatePEM string `json:"certificatePEM"`
	PrivateKeyPEM  string `json:"privateKeyPEM"`
	Fingerprint    string `json:"fingerprint"`
	Generation     int64  `json:"generation"`
}

func (s remoteControlSettings) takesOver() bool {
	return s.Mode == remoteControlLocal || s.Mode == remoteControlLAN
}

func (s remoteControlSettings) takesOverOn(profile runtimeProfile) bool {
	return s.takesOver() && !(s.Mode == remoteControlLocal && profile == runtimeProfileTVOSPacketTunnel)
}

func (s remoteControlSettings) sameListeners(other remoteControlSettings) bool {
	if s.Mode != other.Mode {
		return false
	}
	if !s.takesOver() {
		return true
	}
	if s.HTTPPort != other.HTTPPort || s.Secret != other.Secret {
		return false
	}
	return s.Mode != remoteControlLAN || (s.TLSPort == other.TLSPort &&
		s.CertificatePEM == other.CertificatePEM && s.PrivateKeyPEM == other.PrivateKeyPEM)
}

func parseRemoteControlSettings(text string, profile runtimeProfile) (remoteControlSettings, error) {
	var settings remoteControlSettings
	if err := json.Unmarshal([]byte(text), &settings); err != nil {
		return settings, fmt.Errorf("external controller settings are not JSON: %w", err)
	}
	switch settings.Mode {
	case remoteControlConfig:
		return settings, nil
	case remoteControlLocal:
		if profile == runtimeProfileTVOSPacketTunnel {
			return settings, errors.New("external controller mode local is not offered on tvOS; use lan")
		}
	case remoteControlLAN:
	default:
		return settings, fmt.Errorf("external controller mode %q is not one of config, local, lan", settings.Mode)
	}
	if !validRemoteControlPort(settings.HTTPPort) {
		return settings, fmt.Errorf("external controller HTTP port %d is outside %d-%d", settings.HTTPPort, remoteControlMinimumPort, remoteControlMaximumPort)
	}
	if err := validateRemoteControlSecret(settings.Secret); err != nil {
		return settings, err
	}
	if settings.Mode == remoteControlLocal {
		return settings, nil
	}
	if !validRemoteControlPort(settings.TLSPort) {
		return settings, fmt.Errorf("external controller TLS port %d is outside %d-%d", settings.TLSPort, remoteControlMinimumPort, remoteControlMaximumPort)
	}
	if settings.TLSPort == settings.HTTPPort {
		return settings, fmt.Errorf("external controller HTTP and TLS port are both %d", settings.TLSPort)
	}
	if _, err := controllerCertificateFingerprint(settings.CertificatePEM, settings.PrivateKeyPEM); err != nil {
		return settings, err
	}
	return settings, nil
}

func validRemoteControlPort(port int) bool {
	return port >= remoteControlMinimumPort && port <= remoteControlMaximumPort
}

func validateRemoteControlSecret(secret string) error {
	if secret == "" {
		return errors.New("external controller secret is empty")
	}
	if len(secret) > remoteControlSecretBytes {
		return fmt.Errorf("external controller secret is longer than %d bytes", remoteControlSecretBytes)
	}
	for _, r := range secret {
		if r <= ' ' || r > '~' {
			return errors.New("external controller secret must be printable ASCII without spaces")
		}
	}
	return nil
}

func controllerCertificateFingerprint(certificatePEM, privateKeyPEM string) (string, error) {
	if _, err := tls.X509KeyPair([]byte(certificatePEM), []byte(privateKeyPEM)); err != nil {
		return "", fmt.Errorf("external controller certificate does not load: %w", err)
	}
	block, _ := pem.Decode([]byte(certificatePEM))
	if block == nil {
		return "", errors.New("external controller certificate is not PEM")
	}
	sum := sha256.Sum256(block.Bytes)
	return formatControllerFingerprint(sum[:]), nil
}

func formatControllerFingerprint(sum []byte) string {
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return "sha256:" + strings.Join(parts, ":")
}

func mergeRemoteControl(base *route.Config, settings remoteControlSettings, profile runtimeProfile) *route.Config {
	merged := *base
	if !settings.takesOverOn(profile) {
		return &merged
	}
	merged.Managed = true
	merged.Secret = settings.Secret
	merged.Addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(settings.HTTPPort))
	merged.TLSAddr = ""
	merged.Certificate, merged.PrivateKey = "", ""
	merged.ClientAuthType, merged.ClientAuthCert, merged.EchKey = "", "", ""
	merged.DohServer = ""
	merged.AcceptFilter = nil
	if settings.Mode == remoteControlLAN {
		merged.TLSAddr = net.JoinHostPort(remoteControlLANHost, strconv.Itoa(settings.TLSPort))
		merged.Certificate, merged.PrivateKey = settings.CertificatePEM, settings.PrivateKeyPEM
		merged.AcceptFilter = proxyShareRemoteAllowed
		if profile == runtimeProfileTVOSPacketTunnel {
			merged.Addr = ""
		}
	}
	return &merged
}

var remoteControl struct {
	tx       sync.Mutex
	mu       sync.Mutex
	settings remoteControlSettings
	base     *route.Config
	applied  remoteControlSettings
}

func resetRemoteControlState() {
	remoteControl.tx.Lock()
	defer remoteControl.tx.Unlock()
	remoteControl.mu.Lock()
	defer remoteControl.mu.Unlock()
	remoteControl.settings = remoteControlSettings{Mode: remoteControlConfig}
	remoteControl.base = nil
	remoteControl.applied = remoteControlSettings{}
}

func currentRemoteControlSettings() remoteControlSettings {
	remoteControl.mu.Lock()
	defer remoteControl.mu.Unlock()
	return remoteControl.settings
}

func ApplyRemoteControl(settingsJSON string) string {
	return bridgeSafeString(recoverAppCallValueOr("ApplyRemoteControl", `{"error":"external controller settings could not be applied"}`, func() string {
		data, err := json.Marshal(applyRemoteControl(settingsJSON))
		if err != nil {
			return `{"error":"external controller status could not be encoded"}`
		}
		return string(data)
	}))
}

func applyRemoteControl(settingsJSON string) remoteControlStatus {
	profile := currentRuntimeProfile()
	settings, parseErr := parseRemoteControlSettings(settingsJSON, profile)
	if service := currentCoreService(); service != nil {
		service.mu.Lock()
		defer service.mu.Unlock()
	}
	remoteControl.tx.Lock()
	defer remoteControl.tx.Unlock()

	remoteControl.mu.Lock()
	previous := remoteControl.settings
	if parseErr == nil && settings.Generation < previous.Generation {
		parseErr = fmt.Errorf("external controller settings generation %d is older than %d", settings.Generation, previous.Generation)
	}
	if parseErr != nil {
		remoteControl.mu.Unlock()
		status := currentRemoteControlStatusLocked()
		status.Error = parseErr.Error()
		return status
	}
	remoteControl.settings = settings
	base, applied := remoteControl.base, remoteControl.applied
	remoteControl.mu.Unlock()

	if base != nil {
		changed := !settings.sameListeners(applied) || settings.Generation != applied.Generation
		network := route.CurrentNetworkStatus()
		if changed || network.HTTP.Err != nil || network.TLS.Err != nil {
			merged := mergeRemoteControl(base, settings, profile)
			network = route.ReCreateNetworkServers(merged, changed)
			userControllerLive.Store(merged.Addr != "" || merged.TLSAddr != "")
			remoteControl.mu.Lock()
			remoteControl.applied = settings
			remoteControl.mu.Unlock()
			log.Infoln("[Apple] external controller is now %s: http=%q tls=%q", settings.Mode, network.HTTP.Address, network.TLS.Address)
		}
	}
	return currentRemoteControlStatusLocked()
}

type remoteControlListenerStatus struct {
	Address     string `json:"address"`
	Error       string `json:"error"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

type remoteControlStatus struct {
	Generation int64                       `json:"generation"`
	Mode       string                      `json:"mode"`
	Running    bool                        `json:"running"`
	Error      string                      `json:"error,omitempty"`
	HTTP       remoteControlListenerStatus `json:"http"`
	TLS        remoteControlListenerStatus `json:"tls"`
}

func currentRemoteControlStatus() remoteControlStatus {
	remoteControl.tx.Lock()
	defer remoteControl.tx.Unlock()
	return currentRemoteControlStatusLocked()
}

func currentRemoteControlStatusLocked() remoteControlStatus {
	remoteControl.mu.Lock()
	settings, running := remoteControl.settings, remoteControl.base != nil
	remoteControl.mu.Unlock()
	status := remoteControlStatus{Generation: settings.Generation, Mode: settings.Mode, Running: running}
	if status.Mode == "" {
		status.Mode = remoteControlConfig
	}
	if running {
		network := route.CurrentNetworkStatus()
		status.HTTP = remoteControlListenerStatus{Address: network.HTTP.Address, Error: listenerErrorText(network.HTTP.Err)}
		status.TLS = remoteControlListenerStatus{Address: network.TLS.Address, Error: listenerErrorText(network.TLS.Err)}
	}
	if settings.Mode == remoteControlLAN {
		status.TLS.Fingerprint, _ = controllerCertificateFingerprint(settings.CertificatePEM, settings.PrivateKeyPEM)
	}
	if settings.takesOver() && !settings.takesOverOn(currentRuntimeProfile()) {
		status.Error = "external controller mode local is not offered on tvOS; the configuration's controller is served"
	}
	return status
}

func listenerErrorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func GenerateControllerCertificate() string {
	return bridgeSafeString(recoverAppCallValueOr("GenerateControllerCertificate",
		`{"error":"the certificate could not be generated"}`, generateControllerCertificate))
}

func generateControllerCertificate() string {
	type reply struct {
		CertificatePEM string `json:"certificatePEM,omitempty"`
		PrivateKeyPEM  string `json:"privateKeyPEM,omitempty"`
		Fingerprint    string `json:"fingerprint,omitempty"`
		Error          string `json:"error,omitempty"`
	}
	encode := func(r reply) string {
		data, _ := json.Marshal(r)
		return string(data)
	}
	certificate, key, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		return encode(reply{Error: err.Error()})
	}
	fingerprint, err := controllerCertificateFingerprint(certificate, key)
	if err != nil {
		return encode(reply{Error: err.Error()})
	}
	return encode(reply{CertificatePEM: certificate, PrivateKeyPEM: key, Fingerprint: fingerprint})
}
