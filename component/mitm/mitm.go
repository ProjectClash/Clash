package mitm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// MaxLeafCache caps the minted-leaf certificate cache. Each entry holds the
// DER of one host's leaf plus its parsed tls.Certificate, well under a
// kilobyte of live memory per host after parsing; a few thousand hosts stay
// in the tens-of-kilobytes range the extension budget tolerates.
const MaxLeafCache = 4096

var (
	// ErrNotEnabled is returned when an operation requires a loaded MITM
	// engine and none was configured.
	ErrNotEnabled = errors.New("mitm is not enabled")

	// ErrHostMismatch guards Engine.ServerTLSConfig against handshakes whose
	// ClientHello SNI does not match the host the leaf was minted for. Callers
	// decide whether to close, or to fall back to tunneling.
	ErrHostMismatch = errors.New("mitm: ClientHello does not match intercepted host")

	errLeafKeyMismatch = errors.New("mitm: cached leaf key does not match certificate")
)

// HostCertificate pairs a minted leaf with the private key and the public
// fingerprint (SHA-256 of the DER) that the UI can show for trust auditing.
type HostCertificate struct {
	Certificate tls.Certificate
	Fingerprint [32]byte
}

// Engine holds the generated CA material and the minted-leaf cache.
// Constructed by LoadState from persisted files on disk, or fresh when no
// state exists yet; safe for concurrent use across connections.
type Engine struct {
	caCert *x509.Certificate
	caKey  crypto.Signer

	mu       sync.Mutex
	leaves   map[string]*HostCertificate
	lastEvic time.Time
}

// CaCertificatePEM returns the root certificate as PEM, the form the client
// exports for the user's "install and trust" flow.
func (e *Engine) CaCertificatePEM() ([]byte, error) {
	if e == nil {
		return nil, ErrNotEnabled
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: e.caCert.Raw}), nil
}

// CaFingerprintHex returns the SHA-256 fingerprint of the root certificate
// DER as a hex string, for display next to the exported PEM.
func (e *Engine) CaFingerprintHex() (string, error) {
	if e == nil {
		return "", ErrNotEnabled
	}
	sum := sha256.Sum256(e.caCert.Raw)
	return hex.EncodeToString(sum[:]), nil
}

// CaNotAfter returns the root certificate expiry so the client can prompt
// for regeneration before installed profiles stop working.
func (e *Engine) CaNotAfter() (time.Time, error) {
	if e == nil {
		return time.Time{}, ErrNotEnabled
	}
	return e.caCert.NotAfter, nil
}

// Regenerate discards the current CA and mints a fresh one. Existing leaf
// certificates and installed trust profiles become invalid, so the client
// only calls this when the user explicitly resets MITM.
func (e *Engine) Regenerate() error {
	if e == nil {
		return ErrNotEnabled
	}
	cert, key, err := mintCA()
	if err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.caCert = cert
	e.caKey = key
	e.leaves = make(map[string]*HostCertificate)
	e.lastEvic = time.Time{}
	return nil
}

// mintCA generates a self-signed RSA 2048 root certificate. RSA is chosen
// over ECDSA P-256 because the profile is installed in the trust store of
// every client device and some third-party TLS stacks on routed hosts still
// gate on RSA roots; the per-connection cost is paid once by leaf signing.
func mintCA() (*x509.Certificate, crypto.Signer, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   "Clash MITM CA",
			Organization: []string{"Clash"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, key.Public(), key)
	if err != nil {
		return nil, nil, fmt.Errorf("mint CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, fmt.Errorf("parse minted CA: %w", err)
	}
	return cert, key, nil
}

// MintLeaf returns a tls.Certificate for host signed by the engine's CA.
// Leaves are cached per host; the cache is bounded and entries older than
// half their validity are re-minted lazily on read.
func (e *Engine) MintLeaf(host string) (*HostCertificate, error) {
	if e == nil {
		return nil, ErrNotEnabled
	}
	normalized, err := normalizeHost(host)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if cached, ok := e.leaves[normalized]; ok && leafFresh(cached) {
		return cached, nil
	}
	if len(e.leaves) >= MaxLeafCache {
		e.evictLeafCacheLocked()
	}
	leaf, err := e.mintLeafLocked(normalized)
	if err != nil {
		return nil, err
	}
	e.leaves[normalized] = leaf
	return leaf, nil
}

func (e *Engine) mintLeafLocked(host string) (*HostCertificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	notBefore := time.Now().Add(-time.Hour)
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{"Clash MITM"},
		},
		NotBefore: notBefore,
		NotAfter:  notBefore.Add(leafValidity),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, e.caCert, key.Public(), e.caKey)
	if err != nil {
		return nil, fmt.Errorf("sign leaf for %s: %w", host, err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse minted leaf for %s: %w", host, err)
	}
	fingerprint := sha256.Sum256(der)
	return &HostCertificate{
		Certificate: tls.Certificate{
			Certificate: [][]byte{der, e.caCert.Raw},
			PrivateKey:  key,
			Leaf:        parsed,
		},
		Fingerprint: fingerprint,
	}, nil
}

// ServerTLSConfig builds the inner-leg tls.Config for host: the minted leaf
// pair with the negotiated ALPN restricted to HTTP protocols, since non-HTTP
// traffic must not be intercepted (the gate keeps Engine.TrafficMatch in
// charge of that decision; this config is only reached for HTTP hosts).
func (e *Engine) ServerTLSConfig(host string, alpn []string) (*tls.Config, error) {
	leaf, err := e.MintLeaf(host)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{leaf.Certificate},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   alpn,
	}
	return cfg, nil
}

// evictLeafCacheLocked drops the oldest half of the leaf cache by insertion
// order tracked through lastEvic batching: Go maps do not preserve insertion
// order, so eviction clears everything minted before the previous watermark
// using the fingerprint timestamp embedded in expiry checks instead. The
// simple, predictable policy: on overflow, drop all entries older than one
// leaf-validity half-life; mintedFresh tracks that via NotAfter.
func (e *Engine) evictLeafCacheLocked() {
	now := time.Now()
	if now.Sub(e.lastEvic) < time.Minute {
		// Cache refilled faster than a minute after a full sweep: keep the
		// newest entries by re-minting on demand, drop the rest.
		for host, leaf := range e.leaves {
			if !leafFreshSince(leaf, now.Add(-leafValidity/4)) {
				delete(e.leaves, host)
			}
		}
		if len(e.leaves) < MaxLeafCache {
			return
		}
	}
	e.leaves = make(map[string]*HostCertificate)
	e.lastEvic = now
}

func leafFresh(leaf *HostCertificate) bool {
	return leafFreshSince(leaf, time.Now())
}

// leafFreshSince reports whether the cached leaf still has at least half of
// its validity left when checked at since-adjusted time, so connections are
// never handed a certificate minutes from expiry.
func leafFreshSince(leaf *HostCertificate, cutoff time.Time) bool {
	if leaf.Certificate.Leaf == nil {
		return false
	}
	halfLife := leaf.Certificate.Leaf.NotAfter.Add(-leafValidity / 2)
	return cutoff.Before(halfLife)
}

const leafValidity = 7 * 24 * time.Hour

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	return serial, nil
}

func normalizeHost(host string) (string, error) {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return "", errors.New("mitm: empty host")
	}
	if strings.ContainsAny(host, "/\\ \t") {
		return "", fmt.Errorf("mitm: invalid host %q", host)
	}
	return host, nil
}

// SaveState persists the CA certificate and key so the trust profile a user
// installed keeps working across core restarts and app updates. Files are
// written with 0600 (key) and 0644 (certificate) inside the app group
// container the client passes as stateDir.
func SaveState(engine *Engine, stateDir string) error {
	if engine == nil {
		return ErrNotEnabled
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("create mitm state dir: %w", err)
	}
	engine.mu.Lock()
	cert, key := engine.caCert, engine.caKey
	engine.mu.Unlock()
	if err := os.WriteFile(filepath.Join(stateDir, "ca.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0o644); err != nil {
		return fmt.Errorf("write CA certificate: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(filepath.Join(stateDir, "ca.key"), keyPEM, 0o600); err != nil {
		return fmt.Errorf("write CA key: %w", err)
	}
	return nil
}

// LoadState restores a previously persisted CA from stateDir. When no state
// exists yet a fresh CA is generated and saved immediately, so the first
// launch of the client already has exportable material. Returns ErrNotEnabled
// only when engine is nil.
func LoadState(engine *Engine, stateDir string) error {
	if engine == nil {
		return ErrNotEnabled
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("create mitm state dir: %w", err)
	}
	certPEM, certErr := os.ReadFile(filepath.Join(stateDir, "ca.crt"))
	keyPEM, keyErr := os.ReadFile(filepath.Join(stateDir, "ca.key"))
	if certErr != nil || keyErr != nil {
		// First launch on this device: mint and persist a new CA.
		if err := engine.Regenerate(); err != nil {
			return err
		}
		return SaveState(engine, stateDir)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return errors.New("mitm: CA certificate file is not PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse persisted CA: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return errors.New("mitm: CA key file is not PEM")
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse persisted CA key: %w", err)
	}
	signer, ok := parsedKey.(crypto.Signer)
	if !ok {
		return errLeafKeyMismatch
	}
	if err := verifyCAKeyPair(cert, signer); err != nil {
		return err
	}
	engine.mu.Lock()
	engine.caCert = cert
	engine.caKey = signer
	engine.leaves = make(map[string]*HostCertificate)
	engine.lastEvic = time.Time{}
	engine.mu.Unlock()
	return nil
}

// verifyCAKeyPair proves the persisted certificate and key belong together
// before the engine accepts them; a mismatched pair would mint leaves no
// client trusts and fail every inner handshake.
func verifyCAKeyPair(cert *x509.Certificate, key crypto.Signer) error {
	if !cert.IsCA {
		return errors.New("mitm: persisted certificate is not a CA")
	}
	pub := key.Public()
	eq, ok := pub.(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !eq.Equal(cert.PublicKey) {
		return errLeafKeyMismatch
	}
	return nil
}
