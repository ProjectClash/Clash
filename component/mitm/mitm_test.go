package mitm

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/common/utils"
)

// --- F5: value-prefix semantics (applyHeaderRules in dispatcher.go) ---

func TestApplyHeaderRulesValuePrefixPrependsToClientValue(t *testing.T) {
	buildReq := func(headers map[string]string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "https://gated.test/", nil)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		return req
	}
	cases := []struct {
		name    string
		rule    HeaderRule
		in      map[string]string
		wantGet string // Header.Get after the rule ("" = absent)
		wantAll []string
	}{
		{
			name:    "set+prefix on existing client value",
			rule:    HeaderRule{Action: "set", Name: "Authorization", ValuePrefix: "Bearer "},
			in:      map[string]string{"Authorization": "tok123"},
			wantGet: "Bearer tok123",
		},
		{
			name:    "set+prefix with missing client header yields just the prefix",
			rule:    HeaderRule{Action: "set", Name: "Authorization", ValuePrefix: "Bearer "},
			in:      nil,
			wantGet: "Bearer ",
		},
		{
			name:    "set+prefix with empty client value yields just the prefix",
			rule:    HeaderRule{Action: "set", Name: "Authorization", ValuePrefix: "Bearer "},
			in:      map[string]string{"Authorization": ""},
			wantGet: "Bearer ",
		},
		{
			name:    "add+prefix appends prefix+original",
			rule:    HeaderRule{Action: "add", Name: "X-Chain", ValuePrefix: "p;"},
			in:      map[string]string{"X-Chain": "orig"},
			wantGet: "orig",
			wantAll: []string{"orig", "p;orig"},
		},
		{
			name:    "set with static value replaces verbatim",
			rule:    HeaderRule{Action: "set", Name: "User-Agent", Value: "agent/1"},
			in:      map[string]string{"User-Agent": "old"},
			wantGet: "agent/1",
		},
		{
			name:    "remove drops the header",
			rule:    HeaderRule{Action: "remove", Name: "X-Drop"},
			in:      map[string]string{"X-Drop": "v"},
			wantGet: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := buildReq(tc.in)
			applyHeaderRules(req, []HeaderRule{tc.rule})
			if got := req.Header.Get(tc.rule.Name); got != tc.wantGet {
				t.Fatalf("Get(%q) = %q, want %q", tc.rule.Name, got, tc.wantGet)
			}
			if tc.wantAll != nil {
				got := req.Header.Values(tc.rule.Name)
				if len(got) != len(tc.wantAll) {
					t.Fatalf("Values = %v, want %v", got, tc.wantAll)
				}
				for i := range tc.wantAll {
					if got[i] != tc.wantAll[i] {
						t.Fatalf("Values = %v, want %v", got, tc.wantAll)
					}
				}
			}
		})
	}
}

func TestNormalizeAllowsPrefixOnlyHeaderRule(t *testing.T) {
	cfg := &Config{
		Enable:          true,
		HostGates:       []string{"a.com"},
		RewritePolicies: []RewritePolicy{{URLPattern: "a.com/", HeaderRules: []HeaderRule{{Action: "set", Name: "Authorization", ValuePrefix: "Bearer "}}}},
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("value-prefix without value must be valid: %v", err)
	}
	cfg = &Config{
		Enable:          true,
		HostGates:       []string{"a.com"},
		RewritePolicies: []RewritePolicy{{URLPattern: "a.com/", HeaderRules: []HeaderRule{{Action: "set", Name: "X", Value: "a", ValuePrefix: "b"}}}},
	}
	if err := cfg.Normalize(); err == nil {
		t.Fatal("value and value-prefix together must be rejected")
	}
}

// --- F4: CA stability across reloads (StableDispatcher) ---

func TestStableDispatcherReusesEngineOnReloadWithoutStoreDir(t *testing.T) {
	cfg := &Config{Enable: true, HostGates: []string{"reload.example.com"}}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	first, err := NewDispatcher(cfg)
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}
	if !first.Enable() {
		t.Fatal("sanity: first dispatcher must be enabled")
	}
	enginePEM, err := first.CaCertificatePEM()
	if err != nil {
		t.Fatalf("CaCertificatePEM: %v", err)
	}

	// Reload with a new config snapshot (e.g. gates changed), still no
	// store-dir: the engine — and therefore the CA the user installed —
	// must be reused, not rotated.
	reloadedCfg := &Config{Enable: true, HostGates: []string{"other.example.com"}}
	if err := reloadedCfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	second, err := StableDispatcher(first, reloadedCfg)
	if err != nil {
		t.Fatalf("StableDispatcher: %v", err)
	}
	if second.Engine() != first.Engine() {
		t.Fatal("reload without store-dir must reuse the engine, not mint a new CA")
	}
	if second.Config() != reloadedCfg {
		t.Fatal("reloaded dispatcher must carry the new config snapshot")
	}
	secondPEM, _ := second.CaCertificatePEM()
	if string(secondPEM) != string(enginePEM) {
		t.Fatal("reloaded dispatcher serves a different CA")
	}
}

func TestStableDispatcherMintsFreshWhenRequired(t *testing.T) {
	cfg := &Config{Enable: true, HostGates: []string{"fresh.example.com"}}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	// No previous dispatcher (first construction): fresh engine.
	first, err := StableDispatcher(nil, cfg)
	if err != nil {
		t.Fatalf("StableDispatcher(nil): %v", err)
	}
	if first.Engine() == nil {
		t.Fatal("first construction must produce an engine")
	}

	// A configured store-dir must always go through LoadState, never reuse
	// the previous in-memory engine.
	persistent := &Config{Enable: true, HostGates: []string{"fresh.example.com"}, StoreDir: t.TempDir()}
	if err := persistent.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	withStore, err := StableDispatcher(first, persistent)
	if err != nil {
		t.Fatalf("StableDispatcher(store-dir): %v", err)
	}
	if withStore.Engine() == first.Engine() {
		t.Fatal("store-dir config must not reuse the previous in-memory engine")
	}
	inMemoryPEM, _ := first.CaCertificatePEM()
	persistedPEM, _ := withStore.CaCertificatePEM()
	if string(inMemoryPEM) == string(persistedPEM) {
		t.Fatal("store-dir config must load or mint a distinct CA")
	}
}

func TestStableDispatcherDisabledPreviousMintsFresh(t *testing.T) {
	disabledCfg := &Config{Enable: false, HostGates: []string{"x.example.com"}}
	disabled, err := NewDispatcher(disabledCfg)
	if err != nil {
		t.Fatalf("NewDispatcher(disabled): %v", err)
	}
	if disabled.Enable() {
		t.Fatal("sanity: dispatcher with Enable=false must be disabled")
	}
	cfg := &Config{Enable: true, HostGates: []string{"y.example.com"}}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	fresh, err := StableDispatcher(disabled, cfg)
	if err != nil {
		t.Fatalf("StableDispatcher: %v", err)
	}
	if fresh.Engine() != nil && fresh.Engine() == disabled.Engine() {
		t.Fatal("must not reuse the engine of a disabled dispatcher")
	}
	if !fresh.Enable() {
		t.Fatal("result must be enabled")
	}
}

func TestMintCAThenLeafVerifiesAgainstCA(t *testing.T) {
	engine := &Engine{leaves: make(map[string]*HostCertificate)}
	if err := engine.Regenerate(); err != nil {
		t.Fatalf("Regenerate: %v", err)
	}
	leaf, err := engine.MintLeaf("api.example.com")
	if err != nil {
		t.Fatalf("MintLeaf: %v", err)
	}
	if len(leaf.Certificate.Certificate) != 2 {
		t.Fatalf("leaf chain must be [leaf, ca], got %d certs", len(leaf.Certificate.Certificate))
	}
	pool := tlsCertPool(t, engine)
	if err := verifyLeafChain(leaf.Certificate.Certificate, pool, "api.example.com"); err != nil {
		t.Fatalf("minted leaf does not verify against own CA: %v", err)
	}
}

func TestMintLeafCacheReturnsSameCert(t *testing.T) {
	engine := &Engine{leaves: make(map[string]*HostCertificate)}
	if err := engine.Regenerate(); err != nil {
		t.Fatalf("Regenerate: %v", err)
	}
	first, err := engine.MintLeaf("a.example.com")
	if err != nil {
		t.Fatalf("first MintLeaf: %v", err)
	}
	second, err := engine.MintLeaf("a.example.com")
	if err != nil {
		t.Fatalf("second MintLeaf: %v", err)
	}
	if hex.EncodeToString(first.Fingerprint[:]) != hex.EncodeToString(second.Fingerprint[:]) {
		t.Fatal("cached leaf changed identity between calls")
	}
}

func TestSaveLoadStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	engine := &Engine{leaves: make(map[string]*HostCertificate)}
	if err := engine.Regenerate(); err != nil {
		t.Fatalf("Regenerate: %v", err)
	}
	if err := SaveState(engine, dir); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	for _, name := range []string{"ca.crt", "ca.key"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("state file %s missing: %v", name, err)
		}
		if name == "ca.key" && info.Mode().Perm() != 0o600 {
			t.Fatalf("ca.key must be 0600, got %v", info.Mode().Perm())
		}
	}

	restored := &Engine{leaves: make(map[string]*HostCertificate)}
	if err := LoadState(restored, dir); err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	originalPEM, _ := engine.CaCertificatePEM()
	restoredPEM, _ := restored.CaCertificatePEM()
	if string(originalPEM) != string(restoredPEM) {
		t.Fatal("restored CA differs from saved CA")
	}
	leaf, err := restored.MintLeaf("b.example.com")
	if err != nil {
		t.Fatalf("MintLeaf on restored engine: %v", err)
	}
	if err := verifyLeafChain(leaf.Certificate.Certificate, tlsCertPool(t, restored), "b.example.com"); err != nil {
		t.Fatalf("restored engine cannot mint valid leaves: %v", err)
	}
}

func TestLoadStateRejectsKeyMismatch(t *testing.T) {
	dir := t.TempDir()
	engine := &Engine{leaves: make(map[string]*HostCertificate)}
	_ = engine.Regenerate()
	_ = SaveState(engine, dir)

	other := &Engine{leaves: make(map[string]*HostCertificate)}
	_ = other.Regenerate()
	otherPEM, _ := other.CaCertificatePEM()
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), otherPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	// ca.key on disk belongs to the first engine; the certificate now belongs
	// to another CA. LoadState must refuse the pair.
	if err := LoadState(&Engine{leaves: make(map[string]*HostCertificate)}, dir); err == nil {
		t.Fatal("LoadState accepted a certificate/key mismatch")
	}
}

func TestLoadStateRegeneratesOnlyWhenBothFilesMissing(t *testing.T) {
	dir := t.TempDir()
	engine := &Engine{leaves: make(map[string]*HostCertificate)}
	if err := LoadState(engine, dir); err != nil {
		t.Fatalf("first launch LoadState: %v", err)
	}
	for _, name := range []string{"ca.crt", "ca.key"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("regenerate path must persist %s: %v", name, err)
		}
	}
}

// TestLoadStateReadErrorsFailClosed covers the durability contract: any read
// error other than both-files-missing must be returned, and the on-disk bytes
// must be left untouched — a flaky filesystem must never destroy an
// installed CA by silently regenerating.
func TestLoadStateReadErrorsFailClosed(t *testing.T) {
	build := func(t *testing.T) (string, []byte, []byte) {
		t.Helper()
		dir := t.TempDir()
		engine := &Engine{leaves: make(map[string]*HostCertificate)}
		if err := engine.Regenerate(); err != nil {
			t.Fatalf("Regenerate: %v", err)
		}
		if err := SaveState(engine, dir); err != nil {
			t.Fatalf("SaveState: %v", err)
		}
		cert, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
		if err != nil {
			t.Fatal(err)
		}
		key, err := os.ReadFile(filepath.Join(dir, "ca.key"))
		if err != nil {
			t.Fatal(err)
		}
		return dir, cert, key
	}
	assertUnchanged := func(t *testing.T, dir string, cert, key []byte) {
		t.Helper()
		gotCert, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
		gotKey, _ := os.ReadFile(filepath.Join(dir, "ca.key"))
		if string(gotCert) != string(cert) || string(gotKey) != string(key) {
			t.Fatal("failed LoadState must not modify the persisted files")
		}
	}

	t.Run("cert not PEM", func(t *testing.T) {
		dir, _, key := build(t)
		if err := os.WriteFile(filepath.Join(dir, "ca.crt"), []byte("this is not pem\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := LoadState(&Engine{leaves: make(map[string]*HostCertificate)}, dir); err == nil {
			t.Fatal("LoadState accepted a non-PEM certificate")
		}
		// The corrupt file itself is user data: LoadState must not rewrite it.
		gotCert, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
		if string(gotCert) != "this is not pem\n" {
			t.Fatal("LoadState rewrote the corrupt certificate file")
		}
		if string(key) == "" {
			t.Fatal("sanity: key was read")
		}
	})

	t.Run("key truncated mid-DER", func(t *testing.T) {
		dir, cert, key := build(t)
		block, _ := pem.Decode(key)
		if block == nil {
			t.Fatal("sanity: saved key is PEM")
		}
		truncated := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: block.Bytes[:len(block.Bytes)/2]})
		if err := os.WriteFile(filepath.Join(dir, "ca.key"), truncated, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := LoadState(&Engine{leaves: make(map[string]*HostCertificate)}, dir); err == nil {
			t.Fatal("LoadState accepted a truncated key")
		}
		gotKey, _ := os.ReadFile(filepath.Join(dir, "ca.key"))
		if string(gotKey) != string(truncated) {
			t.Fatal("LoadState rewrote the truncated key file")
		}
		_ = cert
	})

	t.Run("both corrupt", func(t *testing.T) {
		dir, _, _ := build(t)
		if err := os.WriteFile(filepath.Join(dir, "ca.crt"), []byte("garbage\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "ca.key"), []byte("garbage\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := LoadState(&Engine{leaves: make(map[string]*HostCertificate)}, dir); err == nil {
			t.Fatal("LoadState accepted a corrupt pair")
		}
		assertUnchanged(t, dir, []byte("garbage\n"), []byte("garbage\n"))
	})

	t.Run("only cert missing", func(t *testing.T) {
		dir, _, key := build(t)
		if err := os.Remove(filepath.Join(dir, "ca.crt")); err != nil {
			t.Fatal(err)
		}
		// One file missing is a broken state, not a first launch: fail closed
		// instead of minting a new CA over the surviving key.
		if err := LoadState(&Engine{leaves: make(map[string]*HostCertificate)}, dir); err == nil {
			t.Fatal("LoadState treated a half-missing pair as first launch")
		}
		gotKey, _ := os.ReadFile(filepath.Join(dir, "ca.key"))
		if string(gotKey) != string(key) {
			t.Fatal("LoadState rewrote the surviving key")
		}
	})

	t.Run("cert unreadable", func(t *testing.T) {
		dir, _, key := build(t)
		// os.ReadFile on a directory errors with EISDIR — not IsNotExist —
		// even as root, so this exercises the generic read-error branch.
		if err := os.Remove(filepath.Join(dir, "ca.crt")); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(filepath.Join(dir, "ca.crt"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := LoadState(&Engine{leaves: make(map[string]*HostCertificate)}, dir); err == nil {
			t.Fatal("LoadState swallowed a read error")
		}
		gotKey, _ := os.ReadFile(filepath.Join(dir, "ca.key"))
		if string(gotKey) != string(key) {
			t.Fatal("LoadState rewrote the persisted key")
		}
	})
}

// TestSaveStateAtomicReplacement: a failed SaveState must leave the previous
// pair intact, and a successful one must leave no temp files behind.
func TestSaveStateAtomicReplacement(t *testing.T) {
	dir := t.TempDir()
	engine := &Engine{leaves: make(map[string]*HostCertificate)}
	if err := engine.Regenerate(); err != nil {
		t.Fatalf("Regenerate: %v", err)
	}
	if err := SaveState(engine, dir); err != nil {
		t.Fatalf("first SaveState: %v", err)
	}
	originalCert, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	originalKey, _ := os.ReadFile(filepath.Join(dir, "ca.key"))

	// Second SaveState fails at the final rename: a directory sits at the
	// destination filename, which even root cannot replace with a file. Both
	// temps are already written at that point, so this probes the failure
	// window — nothing may be left behind and any pre-existing pair survives.
	other := &Engine{leaves: make(map[string]*HostCertificate)}
	if err := other.Regenerate(); err != nil {
		t.Fatalf("Regenerate: %v", err)
	}
	failing := filepath.Join(dir, "sub")
	if err := os.Mkdir(failing, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(failing, "ca.key"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := SaveState(other, failing); err == nil {
		t.Fatal("SaveState onto a directory-shaped ca.key should fail")
	}
	entries, err := os.ReadDir(failing)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "ca.key" || !entries[0].IsDir() {
		names := make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("failed SaveState littered the state dir: %v", names)
	}

	// Successful re-save of the same engine: round-trips and no temp litter.
	if err := SaveState(engine, dir); err != nil {
		t.Fatalf("re-save: %v", err)
	}
	entries, err = os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if name := entry.Name(); name != "ca.crt" && name != "ca.key" && name != "sub" {
			t.Fatalf("SaveState left %q behind", name)
		}
	}
	gotCert, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	gotKey, _ := os.ReadFile(filepath.Join(dir, "ca.key"))
	if string(gotCert) != string(originalCert) || string(gotKey) != string(originalKey) {
		t.Fatal("re-saving the same engine changed the persisted CA")
	}
}

func TestRegenerateInvalidatesLeaves(t *testing.T) {
	engine := &Engine{leaves: make(map[string]*HostCertificate)}
	_ = engine.Regenerate()
	first, _ := engine.MintLeaf("c.example.com")
	if err := engine.Regenerate(); err != nil {
		t.Fatalf("Regenerate: %v", err)
	}
	second, _ := engine.MintLeaf("c.example.com")
	if hex.EncodeToString(first.Fingerprint[:]) == hex.EncodeToString(second.Fingerprint[:]) {
		t.Fatal("leaf survived CA regeneration")
	}
}

func TestFingerprintMatchesCertDER(t *testing.T) {
	engine := &Engine{leaves: make(map[string]*HostCertificate)}
	_ = engine.Regenerate()
	leaf, _ := engine.MintLeaf("d.example.com")
	der := leaf.Certificate.Certificate[0]
	sum := sha256.Sum256(der)
	if hex.EncodeToString(sum[:]) != hex.EncodeToString(leaf.Fingerprint[:]) {
		t.Fatal("fingerprint is not SHA-256 of leaf DER")
	}
}

func TestMatchHostSemantics(t *testing.T) {
	cfg := &Config{
		Enable:    true,
		HostGates: []string{".example.com", "sub.other.org"},
	}
	cases := []struct {
		host string
		want bool
	}{
		{"example.com", true},
		{"www.example.com", true},
		{"deep.www.example.com", true},
		{"notexample.com", false},
		{"example.com.evil.test", false},
		{"sub.other.org", true},
		{"x.sub.other.org", true},
		{"other.org", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := cfg.MatchHost(tc.host); got != tc.want {
			t.Errorf("MatchHost(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

func TestSkipDomainBeatsGate(t *testing.T) {
	cfg := &Config{
		Enable:      true,
		HostGates:   []string{".example.com"},
		SkipDomains: []string{"auth.example.com"},
	}
	if !cfg.MatchHost("api.example.com") {
		t.Fatal("gate should match api.example.com")
	}
	if cfg.MatchHost("auth.example.com") {
		t.Fatal("skip-domain must win over the gate")
	}
}

func TestSkipDstAddress(t *testing.T) {
	prefix := netip.MustParsePrefix("10.0.0.0/8")
	if !prefix.Contains(netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("sanity: prefix must contain its own address")
	}
	cfg := &Config{
		Enable:         true,
		HostGates:      []string{".example.com"},
		SkipDstAddress: []netip.Prefix{prefix},
	}
	if len(cfg.SkipDstAddress) != 1 || !cfg.SkipDstAddress[0].Contains(netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("skip-dst-address not stored")
	}
}

func TestNormalizeRejectsBadHosts(t *testing.T) {
	bad := []string{"", "*.example.com", "ex..com", "-a.example.com", "example.com/path", "exa mple.com", "user@example.com", "192.168.1.1"}
	for _, host := range bad {
		cfg := &Config{Enable: true, HostGates: []string{host}}
		if err := cfg.Normalize(); err == nil {
			t.Errorf("Normalize accepted bad host gate %q", host)
		}
	}
	good := &Config{Enable: true, HostGates: []string{"example.com", ".example.org"}}
	if err := good.Normalize(); err != nil {
		t.Fatalf("Normalize rejected valid gates: %v", err)
	}
}

func TestNormalizeRejectsBadRewrites(t *testing.T) {
	cases := []Config{
		{Enable: true, HostGates: []string{"a.com"}, RewritePolicies: []RewritePolicy{{URLPattern: ""}}},
		{Enable: true, HostGates: []string{"a.com"}, RewritePolicies: []RewritePolicy{{URLPattern: "a.com/", Reject: 302}}},
		{Enable: true, HostGates: []string{"a.com"}, RewritePolicies: []RewritePolicy{{URLPattern: "a.com/", Redirect: "javascript:alert(1)"}}},
		{Enable: true, HostGates: []string{"a.com"}, RewritePolicies: []RewritePolicy{{URLPattern: "a.com/", HeaderRules: []HeaderRule{{Action: "delete", Name: "X"}}}}},
		{Enable: true, HostGates: []string{"a.com"}, RewritePolicies: []RewritePolicy{{URLPattern: "a.com/", HeaderRules: []HeaderRule{{Action: "set"}}}}},
	}
	for i, cfg := range cases {
		if err := cfg.Normalize(); err == nil {
			t.Errorf("case %d: Normalize accepted invalid rewrite policy", i)
		}
	}
}

func TestNormalizeRejectsTooManyPolicies(t *testing.T) {
	cfg := &Config{Enable: true, HostGates: []string{"a.com"}}
	for i := 0; i <= MaxPolicyCount; i++ {
		cfg.RewritePolicies = append(cfg.RewritePolicies, RewritePolicy{URLPattern: "a.com/x"})
	}
	if err := cfg.Normalize(); err == nil {
		t.Fatal("Normalize accepted more than MaxPolicyCount policies")
	}
}

func TestTrafficMatchFirstWins(t *testing.T) {
	cfg := &Config{
		Enable:    true,
		HostGates: []string{".example.com"},
		RewritePolicies: []RewritePolicy{
			{URLPattern: "api.example.com/v1/", Reject: 404},
			{URLPattern: "api.example.com/", Redirect: "https://mirror.example.net"},
		},
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	policy, ok := cfg.TrafficMatch("api.example.com", "https", 443, "/v1/x")
	if !ok || policy.Reject != 404 {
		t.Fatalf("first-match must win: got %+v ok=%v", policy, ok)
	}
	if _, ok := cfg.TrafficMatch("api.example.com", "https", 8443, "/v1/x"); ok {
		t.Fatal("port outside default 443 must not match with empty port list")
	}
	if _, ok := cfg.TrafficMatch("www.example.com", "https", 443, "/v1/x"); ok {
		t.Fatal("host without a matching policy block must not be intercepted")
	}
}

func TestMatchPortRanges(t *testing.T) {
	cfg := &Config{
		Enable:     true,
		HostGates:  []string{"a.com"},
		HTTPSPorts: portRanges(t, "443,8443-8444"),
	}
	if !cfg.MatchPort("https", 443) || !cfg.MatchPort("https", 8443) || !cfg.MatchPort("https", 8444) {
		t.Fatal("range syntax must match 443, 8443, 8444")
	}
	if cfg.MatchPort("https", 8080) {
		t.Fatal("8080 must not match")
	}
}

func TestLeafCacheEviction(t *testing.T) {
	engine := &Engine{leaves: make(map[string]*HostCertificate)}
	_ = engine.Regenerate()
	for i := 0; i < MaxLeafCache+64; i++ {
		host := "h" + itoa(i) + ".example.com"
		if _, err := engine.MintLeaf(host); err != nil {
			t.Fatalf("MintLeaf(%s): %v", host, err)
		}
	}
	engine.mu.Lock()
	size := len(engine.leaves)
	engine.mu.Unlock()
	if size > MaxLeafCache {
		t.Fatalf("leaf cache grew past MaxLeafCache: %d", size)
	}
}

// helpers

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}

func portRanges(t *testing.T, spec string) utils.IntRanges[uint16] {
	t.Helper()
	ranges, err := utils.NewUnsignedRangesFromList[uint16](strings.Split(spec, ","))
	if err != nil {
		t.Fatalf("parsePortRanges(%q): %v", spec, err)
	}
	return ranges
}

func tlsCertPool(t *testing.T, engine *Engine) *x509.CertPool {
	t.Helper()
	pemBytes, err := engine.CaCertificatePEM()
	if err != nil {
		t.Fatalf("CaCertificatePEM: %v", err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("CA PEM did not decode")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		t.Fatal("could not add CA to pool")
	}
	return pool
}

func verifyLeafChain(chain [][]byte, roots *x509.CertPool, host string) error {
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return err
	}
	intermediates := x509.NewCertPool()
	for _, der := range chain[1:] {
		intermediates.AddCert(&x509.Certificate{Raw: der})
	}
	opts := x509.VerifyOptions{
		DNSName:       host,
		Roots:         roots,
		Intermediates: intermediates,
	}
	_, err = leaf.Verify(opts)
	return err
}

// --- config gate normalization (F2) ---

func TestNormalizeCanonicalizesHostGates(t *testing.T) {
	cfg := &Config{
		Enable:    true,
		HostGates: []string{"EXAMPLE.com.", "Example.COM", "xn--bcher-kva.example.COM."},
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	want := []string{"example.com", "example.com", "xn--bcher-kva.example.com"}
	for i, gate := range cfg.HostGates {
		if gate != want[i] {
			t.Errorf("gate %d normalized to %q, want %q", i, gate, want[i])
		}
	}
	// Uppercase or trailing-dot SNI from the wire must still match.
	for _, host := range []string{"example.com", "EXAMPLE.com.", "sub.EXAMPLE.com"} {
		if !cfg.MatchHost(host) {
			t.Errorf("MatchHost(%q) = false after normalization", host)
		}
	}
	if !cfg.MatchHost("xn--bcher-kva.example.com") {
		t.Error("punycode gate must match punycode SNI")
	}
}

func TestNormalizeRejectsNonASCIIGates(t *testing.T) {
	for _, gate := range []string{"bücher.example.com", "例え.jp", ".münchen.de"} {
		cfg := &Config{Enable: true, HostGates: []string{gate}}
		err := cfg.Normalize()
		if err == nil {
			t.Errorf("Normalize accepted non-ASCII gate %q (clients send punycode)", gate)
			continue
		}
		if !strings.Contains(err.Error(), "xn--") {
			t.Errorf("error for %q should point at the xn-- punycode form, got: %v", gate, err)
		}
	}
}

// --- skip-domain semantics (F3) ---

func TestSkipDomainsCoverSubdomains(t *testing.T) {
	cfg := &Config{
		Enable:      true,
		HostGates:   []string{".example.com"},
		SkipDomains: []string{"example.com"},
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	for _, host := range []string{"example.com", "a.example.com", "deep.a.example.com"} {
		if cfg.MatchHost(host) {
			t.Errorf("bare skip-domain %q must cover %q (host+subdomains)", "example.com", host)
		}
	}
	if cfg.MatchHost("other.org") {
		t.Error("sanity: other.org is not gated and must stay interceptable=false (MatchHost true means intercept)")
	}
}

func TestSkipDomainLeadingDotCoversSubdomainsOnlyOfBase(t *testing.T) {
	cfg := &Config{
		Enable:      true,
		HostGates:   []string{".example.com"},
		SkipDomains: []string{".auth.example.com"},
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	for _, host := range []string{"auth.example.com", "api.auth.example.com"} {
		if cfg.MatchHost(host) {
			t.Errorf("skip %q must cover %q", ".auth.example.com", host)
		}
	}
	if !cfg.MatchHost("example.com") || !cfg.MatchHost("shop.example.com") {
		t.Error("skip of auth.example.com must not swallow the rest of example.com")
	}
}

// --- url-pattern host validation (F6) ---

func TestNormalizeRejectsBadURLPatternHosts(t *testing.T) {
	cases := []string{
		"*.example.com/",    // wildcard host
		"example.com:443/",  // port in host part
		"exa mple.com/",     // space
		"user@example.com/", // userinfo
		"*.example.com",     // wildcard, host-only pattern
		"bad..host.com/x",   // empty label
	}
	for _, pattern := range cases {
		cfg := &Config{
			Enable:          true,
			HostGates:       []string{"example.com"},
			RewritePolicies: []RewritePolicy{{URLPattern: pattern}},
		}
		if pattern == "example.com/../x/" {
			continue // path-only concern, enforced by the hot path, not the host check
		}
		if err := cfg.Normalize(); err == nil {
			t.Errorf("Normalize accepted bad url-pattern host %q", pattern)
		}
	}
	valid := []string{"example.com/", "api.example.com/v2/", "/api/", "example.com", "EXAMPLE.com/V2/"}
	for _, pattern := range valid {
		cfg := &Config{
			Enable:          true,
			HostGates:       []string{"example.com"},
			RewritePolicies: []RewritePolicy{{URLPattern: pattern}},
		}
		if err := cfg.Normalize(); err != nil {
			t.Errorf("Normalize rejected valid url-pattern %q: %v", pattern, err)
		}
	}
}

// --- header field-name validation (F7) ---

func TestNormalizeRejectsInvalidHeaderNames(t *testing.T) {
	bad := []string{"X Bad", "X-Bad:", "X\r\nInjected: 1", "X	Tab", "X=Bad", "X\"Quote", "X,(Comma"}
	for _, name := range bad {
		cfg := &Config{
			Enable:          true,
			HostGates:       []string{"a.com"},
			RewritePolicies: []RewritePolicy{{URLPattern: "a.com/", HeaderRules: []HeaderRule{{Action: "set", Name: name, Value: "v"}}}},
		}
		if err := cfg.Normalize(); err == nil {
			t.Errorf("Normalize accepted invalid header field name %q", name)
		}
	}
	good := []string{"X-Custom", "x_custom", "X2-Header_3", "User-Agent"}
	for _, name := range good {
		cfg := &Config{
			Enable:          true,
			HostGates:       []string{"a.com"},
			RewritePolicies: []RewritePolicy{{URLPattern: "a.com/", HeaderRules: []HeaderRule{{Action: "set", Name: name, Value: "v"}}}},
		}
		if err := cfg.Normalize(); err != nil {
			t.Errorf("Normalize rejected valid header field name %q: %v", name, err)
		}
	}
}

// --- list caps (F8) ---

func TestNormalizeCapsHostAndSkipLists(t *testing.T) {
	filler := func(n int) []string {
		out := make([]string, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, "h"+itoa(i)+".example.com")
		}
		return out
	}
	prefixes := func(n int) []netip.Prefix {
		out := make([]netip.Prefix, 0, n)
		for i := 0; i < n; i++ {
			out = append(out, netip.MustParsePrefix("10."+itoa(i%256)+".0.0/16"))
		}
		return out
	}
	tooMany := filler(257)
	cases := []struct {
		name string
		make func() *Config
	}{
		{"host gates", func() *Config { return &Config{Enable: true, HostGates: tooMany} }},
		{"skip domains", func() *Config { return &Config{Enable: true, HostGates: []string{"a.com"}, SkipDomains: tooMany} }},
		{"skip dst addresses", func() *Config {
			return &Config{Enable: true, HostGates: []string{"a.com"}, SkipDstAddress: prefixes(257)}
		}},
	}
	for _, tc := range cases {
		if err := tc.make().Normalize(); err == nil {
			t.Errorf("Normalize accepted unbounded %s (cap is 256)", tc.name)
		}
	}
	// Exactly at the cap must still load.
	ok := &Config{Enable: true, HostGates: filler(256)}
	if err := ok.Normalize(); err != nil {
		t.Fatalf("Normalize rejected exactly 256 gates: %v", err)
	}
}

// TestHostsWithoutPoliciesStillParse pins that gating hosts with no rewrite
// block is a valid (warn-only at the executor) configuration, and that
// TrafficMatch declines it — interception needs a policy.
func TestHostsWithoutPoliciesStillParse(t *testing.T) {
	cfg := &Config{Enable: true, HostGates: []string{".example.com"}, SkipDomains: []string{"auth.example.com"}}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("hosts without rewrite policies must parse: %v", err)
	}
	if cfg.MatchHost("auth.example.com") {
		t.Fatal("skip-domain auth.example.com must cover auth.example.com")
	}
	if !cfg.MatchHost("api.example.com") {
		t.Fatal("sanity: gate should match api.example.com")
	}
	if _, ok := cfg.TrafficMatch("example.com", "https", 443, "/"); ok {
		t.Fatal("no policies configured: nothing may be intercepted")
	}
}

// --- leaf NotBefore skew ---

func TestMintedLeafAcceptedWithClockBehind(t *testing.T) {
	engine := &Engine{leaves: make(map[string]*HostCertificate)}
	if err := engine.Regenerate(); err != nil {
		t.Fatalf("Regenerate: %v", err)
	}
	leaf, err := engine.MintLeaf("skew.example.com")
	if err != nil {
		t.Fatalf("MintLeaf: %v", err)
	}
	// A verifier with a clock 30 minutes behind mint time must accept the
	// chain: NotBefore is backdated by leafNotBeforeSkew.
	verifierNow := time.Now().Add(-30 * time.Minute)
	leafCert := leaf.Certificate.Leaf
	if verifierNow.Before(leafCert.NotBefore) {
		t.Fatalf("NotBefore %v is not at least 30min in the past", leafCert.NotBefore)
	}
	if !verifierNow.Before(leafCert.NotAfter) {
		t.Fatal("sanity: verifier clock must also be inside validity")
	}
	if err := verifyLeafChain(leaf.Certificate.Certificate, tlsCertPool(t, engine), "skew.example.com"); err != nil {
		t.Fatalf("chain must verify: %v", err)
	}
}

// --- leaf cache eviction keeps fresh entries (F10a) ---

func TestLeafCacheEvictionPreservesNewestEntries(t *testing.T) {
	engine := &Engine{leaves: make(map[string]*HostCertificate)}
	if err := engine.Regenerate(); err != nil {
		t.Fatalf("Regenerate: %v", err)
	}
	for i := 0; i < MaxLeafCache; i++ {
		if _, err := engine.MintLeaf("old" + itoa(i) + ".example.com"); err != nil {
			t.Fatalf("MintLeaf: %v", err)
		}
	}
	// Overflow by one: exactly the oldest quarter goes, the newest
	// three-quarters survive.
	if _, err := engine.MintLeaf("trigger.example.com"); err != nil {
		t.Fatalf("MintLeaf(trigger): %v", err)
	}
	engine.mu.Lock()
	_, oldSurvivor := engine.leaves["old0.example.com"]
	_, newSurvivor := engine.leaves["old"+itoa(MaxLeafCache-1)+".example.com"]
	orderLen := len(engine.order)
	engine.mu.Unlock()
	if oldSurvivor {
		t.Error("oldest entry survived eviction")
	}
	if !newSurvivor {
		t.Error("newest pre-overflow entry was evicted (cache was nuked, not quartered)")
	}
	if orderLen != len(engine.leaves) {
		t.Fatalf("order index out of sync: order=%d leaves=%d", orderLen, len(engine.leaves))
	}
}

// --- H2: path-aware url-pattern matching (segment boundaries) ---

func TestMatchURLPatternSegmentBoundaries(t *testing.T) {
	cfg := &Config{
		Enable:    true,
		HostGates: []string{"api.example.com"},
		RewritePolicies: []RewritePolicy{
			{URLPattern: "api.example.com/v2", Reject: 403},
		},
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	match := func(path string) bool {
		_, ok := cfg.TrafficMatch("api.example.com", "https", 443, path)
		return ok
	}
	for _, path := range []string{"/v2", "/v2/", "/v2/x", "/v2/users"} {
		if !match(path) {
			t.Errorf("pattern v2 must match %s", path)
		}
	}
	for _, path := range []string{"/v2x", "/v22", "/other", "/", "/v"} {
		if match(path) {
			t.Errorf("pattern v2 must NOT match %s", path)
		}
	}
	// Host suffix semantics still hold at any matched path.
	if _, ok := cfg.TrafficMatch("sub.api.example.com", "https", 443, "/v2/x"); !ok {
		t.Error("subdomain of pattern host must match")
	}
	if _, ok := cfg.TrafficMatch("api.example.org", "https", 443, "/v2"); ok {
		t.Error("different host must not match")
	}
}

func TestMatchURLPatternHostWideAndPathOnly(t *testing.T) {
	hostWide := &Config{
		Enable:          true,
		HostGates:       []string{"api.example.com"},
		RewritePolicies: []RewritePolicy{{URLPattern: "api.example.com", Reject: 404}},
	}
	if err := hostWide.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	// Bare host pattern covers every path.
	for _, path := range []string{"/", "/anything", "/deep/path"} {
		if _, ok := hostWide.TrafficMatch("api.example.com", "https", 443, path); !ok {
			t.Errorf("host-wide pattern must match %s", path)
		}
	}
	pathOnly := &Config{
		Enable:          true,
		HostGates:       []string{"a.com", "b.com"},
		RewritePolicies: []RewritePolicy{{URLPattern: "/api/", Reject: 404}},
	}
	if err := pathOnly.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if _, ok := pathOnly.TrafficMatch("a.com", "https", 443, "/api/x"); !ok {
		t.Error("path-only pattern must match at any gated host")
	}
	if _, ok := pathOnly.TrafficMatch("b.com", "https", 443, "/other"); ok {
		t.Error("path-only pattern must not match other paths")
	}
	// "host/" (empty path part) is host-wide too.
	trailing := &Config{
		Enable:          true,
		HostGates:       []string{"a.com"},
		RewritePolicies: []RewritePolicy{{URLPattern: "a.com/", Reject: 404}},
	}
	if err := trailing.Normalize(); err != nil {
		t.Fatalf("Normalize: %v", err)
	}
	if _, ok := trailing.TrafficMatch("a.com", "https", 443, "/anything"); !ok {
		t.Error("empty path part must cover every path")
	}
}

// --- H3: bare-host redirect preserves path+query ---

func TestComposeRedirectBareHost(t *testing.T) {
	got := composeRedirect("mirror.example.com", "/v2/x", "q=1", "https")
	if got != "https://mirror.example.com/v2/x?q=1" {
		t.Fatalf("bare host: %q", got)
	}
	if got := composeRedirect("mirror.example.com", "/a", "", "http"); got != "http://mirror.example.com/a" {
		t.Fatalf("bare host no query: %q", got)
	}
	// Full URLs pass through verbatim.
	if got := composeRedirect("https://other.test/new", "/old", "q=1", "https"); got != "https://other.test/new" {
		t.Fatalf("full URL: %q", got)
	}
	// A bare host is NOT misdetected as one when it carries a scheme.
	if isBareHostTarget("https://x.test") {
		t.Fatal("schemed target misread as bare host")
	}
	if isBareHostTarget("/path") || isBareHostTarget("") {
		t.Fatal("path/empty misread as bare host")
	}
}

// --- H4: overlapping port lists rejected at load ---

func TestNormalizeRejectsPortOverlap(t *testing.T) {
	cfg := &Config{
		Enable:     true,
		HostGates:  []string{"a.com"},
		HTTPSPorts: portRanges(t, "443,8080"),
		HTTPPorts:  portRanges(t, "80,8080"),
		RewritePolicies: []RewritePolicy{
			{URLPattern: "a.com/"},
		},
	}
	if err := cfg.Normalize(); err == nil {
		t.Fatal("Normalize accepted a port in both http-ports and https-ports")
	}
	disjoint := &Config{
		Enable:     true,
		HostGates:  []string{"a.com"},
		HTTPSPorts: portRanges(t, "443"),
		HTTPPorts:  portRanges(t, "80"),
		RewritePolicies: []RewritePolicy{
			{URLPattern: "a.com/"},
		},
	}
	if err := disjoint.Normalize(); err != nil {
		t.Fatalf("disjoint port lists must parse: %v", err)
	}
}
