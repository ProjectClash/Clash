package mitm

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/common/utils"
)

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
	policy, ok := cfg.TrafficMatch("api.example.com", "https", 443)
	if !ok || policy.Reject != 404 {
		t.Fatalf("first-match must win: got %+v ok=%v", policy, ok)
	}
	if _, ok := cfg.TrafficMatch("api.example.com", "https", 8443); ok {
		t.Fatal("port outside default 443 must not match with empty port list")
	}
	if _, ok := cfg.TrafficMatch("www.example.com", "https", 443); ok {
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
