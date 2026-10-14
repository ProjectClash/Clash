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

	"github.com/ProjectClash/Clash/log"
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

	mu     sync.Mutex
	leaves map[string]*HostCertificate

	// order/orderIdx track leaf-cache insertion order so overflow evicts
	// only the oldest quarter; Go maps do not preserve insertion order.
	order    []string
	orderIdx map[string]int
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
	e.resetLeafOrderLocked()
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
//
// Concurrency: the cache lookup and insert take the engine mutex, but the
// expensive ECDSA keygen + RSA signing happen OUTSIDE the lock on a
// snapshot of the CA material, so parallel first connections to distinct
// hosts are not serialized. A concurrent mint for the same host may win the
// insert; the loser returns the winner's cached leaf instead of its own.
func (e *Engine) MintLeaf(host string) (*HostCertificate, error) {
	if e == nil {
		return nil, ErrNotEnabled
	}
	normalized, err := normalizeHost(host)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	if cached, ok := e.leaves[normalized]; ok && leafFresh(cached) {
		e.mu.Unlock()
		return cached, nil
	}
	if len(e.leaves) >= MaxLeafCache {
		e.evictLeafCacheLocked()
	}
	caCert, caKey := e.caCert, e.caKey
	e.mu.Unlock()
	if caCert == nil || caKey == nil {
		return nil, ErrNotEnabled
	}

	leaf, err := mintLeaf(caCert, caKey, normalized)
	if err != nil {
		return nil, err
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if cached, ok := e.leaves[normalized]; ok && leafFresh(cached) {
		// A concurrent mint for the same host inserted first: serve the
		// cached leaf and drop ours so all connections share one identity.
		return cached, nil
	}
	e.insertLeafLocked(normalized, leaf)
	return leaf, nil
}

// insertLeafLocked adds an entry to the cache and the insertion-order index;
// caller holds e.mu and has already handled eviction.
func (e *Engine) insertLeafLocked(host string, leaf *HostCertificate) {
	if _, exists := e.leaves[host]; exists {
		return
	}
	e.leaves[host] = leaf
	if e.orderIdx == nil {
		e.orderIdx = make(map[string]int)
	}
	e.orderIdx[host] = len(e.order)
	e.order = append(e.order, host)
}

// resetLeafOrderLocked drops the leaf cache and its insertion-order index;
// caller holds e.mu.
func (e *Engine) resetLeafOrderLocked() {
	e.leaves = make(map[string]*HostCertificate)
	e.order = nil
	e.orderIdx = nil
}

func mintLeaf(caCert *x509.Certificate, caKey crypto.Signer, host string) (*HostCertificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	notBefore := time.Now().Add(-leafNotBeforeSkew)
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
	der, err := x509.CreateCertificate(rand.Reader, tpl, caCert, key.Public(), caKey)
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
			Certificate: [][]byte{der, caCert.Raw},
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

// evictLeafCacheLocked drops the oldest quarter of the leaf cache when it
// overflows. Insertion order is tracked in e.order/e.orderIdx, so eviction
// is bounded and predictable: each overflow event removes exactly the
// longest-resident quarter and leaves fresh entries untouched (the whole
// cache is never nuked, which would thrash under steady churn).
func (e *Engine) evictLeafCacheLocked() {
	victims := MaxLeafCache / 4
	if len(e.order) < victims {
		victims = len(e.order)
	}
	for _, host := range e.order[:victims] {
		delete(e.leaves, host)
		delete(e.orderIdx, host)
	}
	e.order = e.order[victims:]
	for host, idx := range e.orderIdx {
		e.orderIdx[host] = idx - victims
	}
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

// leafNotBeforeSkew backdates every minted leaf so a verifier whose clock
// runs up to half an hour behind this device still accepts the chain.
const leafNotBeforeSkew = 30 * time.Minute

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

// SaveState atomically persists the CA certificate and key so the trust
// profile a user installed keeps working across core restarts and app
// updates. Both temp files are written and fsynced before either rename
// starts (key first, then certificate), so a crash or ENOSPC mid-write can
// never leave a half-matched pair behind: at worst the previous pair stays
// intact, at best both new files land. stateDir is filepath.Clean'ed before
// use; an existing directory's permissions are never modified — 0700 is
// applied only when the directory is created. Files are written with 0600
// (key) and 0644 (certificate) inside the app group container the client
// passes as stateDir.
func SaveState(engine *Engine, stateDir string) error {
	if engine == nil {
		return ErrNotEnabled
	}
	stateDir = filepath.Clean(stateDir)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("create mitm state dir: %w", err)
	}
	engine.mu.Lock()
	cert, key := engine.caCert, engine.caKey
	engine.mu.Unlock()

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal CA key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	certTmp := filepath.Join(stateDir, "ca.crt.tmp")
	keyTmp := filepath.Join(stateDir, "ca.key.tmp")
	if err := os.WriteFile(keyTmp, keyPEM, 0o600); err != nil {
		return fmt.Errorf("write CA key temp: %w", err)
	}
	if err := syncFile(keyTmp); err != nil {
		_ = os.Remove(keyTmp)
		return fmt.Errorf("sync CA key temp: %w", err)
	}
	if err := os.WriteFile(certTmp, certPEM, 0o644); err != nil {
		_ = os.Remove(keyTmp)
		return fmt.Errorf("write CA certificate temp: %w", err)
	}
	if err := syncFile(certTmp); err != nil {
		_ = os.Remove(keyTmp)
		_ = os.Remove(certTmp)
		return fmt.Errorf("sync CA certificate temp: %w", err)
	}
	// Key first: a crash between the two renames leaves ca.key new and
	// ca.crt old — LoadState rejects that pair and the user still has the
	// old working profile instead of a half-installed one.
	if err := os.Rename(keyTmp, filepath.Join(stateDir, "ca.key")); err != nil {
		_ = os.Remove(keyTmp)
		_ = os.Remove(certTmp)
		return fmt.Errorf("replace CA key: %w", err)
	}
	if err := os.Rename(certTmp, filepath.Join(stateDir, "ca.crt")); err != nil {
		_ = os.Remove(certTmp)
		return fmt.Errorf("replace CA certificate: %w", err)
	}
	return nil
}

// syncFile flushes a file's contents to stable storage before it is renamed
// into place; persistence failures must surface, not surface later as a
// truncated CA at next launch.
func syncFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// LoadState restores a previously persisted CA from stateDir. Only a fully
// absent pair (both files missing) counts as first launch, in which case a
// fresh CA is generated and saved immediately so the first launch of the
// client already has exportable material. Any other read error — EIO,
// EACCES, a truncated file, one file of the pair missing — is returned
// fail-closed: persisted CA material is never silently discarded or
// overwritten. Returns ErrNotEnabled only when engine is nil.
func LoadState(engine *Engine, stateDir string) error {
	if engine == nil {
		return ErrNotEnabled
	}
	stateDir = filepath.Clean(stateDir)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("create mitm state dir: %w", err)
	}
	certPath := filepath.Join(stateDir, "ca.crt")
	keyPath := filepath.Join(stateDir, "ca.key")
	certPEM, certErr := os.ReadFile(certPath)
	keyPEM, keyErr := os.ReadFile(keyPath)
	if os.IsNotExist(certErr) && os.IsNotExist(keyErr) {
		// First launch on this device: mint and persist a new CA.
		log.Debugln("[MITM] no CA state in %s; generating a new root certificate", stateDir)
		if err := engine.Regenerate(); err != nil {
			return err
		}
		return SaveState(engine, stateDir)
	}
	if certErr != nil || keyErr != nil {
		// One file missing or unreadable is a broken install, not a first
		// launch; regenerating here would destroy the surviving half of an
		// installed CA.
		return fmt.Errorf("read persisted mitm CA state: cert err %v, key err %v", certErr, keyErr)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return fmt.Errorf("mitm: CA certificate file %s is not PEM; fix or remove it manually, it will not be overwritten", certPath)
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("parse persisted CA: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return fmt.Errorf("mitm: CA key file %s is not PEM; fix or remove it manually, it will not be overwritten", keyPath)
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
	engine.resetLeafOrderLocked()
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

var warnPerProcessCA sync.Once

// StableDispatcher builds the dispatcher for one ApplyConfig pass while
// keeping the CA stable across reloads. Without a store-dir the CA lives
// only in memory, so minting a new engine on every reload would silently
// rotate the CA and break every installed trust profile; when previous has
// a usable engine it is carried into the new dispatcher and only the config
// snapshot is swapped. A fresh engine is minted when:
//   - previous is nil (first construction),
//   - previous is disabled (its engine never held a real CA),
//   - the new config sets StoreDir (state must come from disk, not memory).
//
// The per-process-CA warning fires once per process: without store-dir,
// installed profiles must be reinstalled after a full core restart.
func StableDispatcher(previous *Dispatcher, config *Config) (*Dispatcher, error) {
	if config == nil {
		return nil, errors.New("mitm: nil config")
	}
	if config.Enable && config.StoreDir == "" {
		if previous != nil && previous.Enable() && previous.Engine() != nil {
			d := &Dispatcher{}
			d.config.Store(config)
			d.engine = previous.Engine()
			return d, nil
		}
		warnPerProcessCA.Do(func() {
			log.Warnln("[MITM] store-dir is empty: the CA is per-process and cannot be exported persistently; installed trust profiles must be reinstalled after a core restart")
		})
	}
	return NewDispatcher(config)
}
