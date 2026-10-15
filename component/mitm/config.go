package mitm

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"

	"github.com/ProjectClash/Clash/common/utils"
)

// Config is the declarative MITM rewrite policy. It is static for the life
// of a Dispatcher, so no locking is needed on the hot path; hot reload swaps
// the whole Dispatcher via the existing sniffer/mode pattern.
type Config struct {
	// Enable is the master switch. Gate fails closed when false.
	Enable bool

	// StoreDir is the directory the CA certificate and key persist to. When
	// empty the CA is generated in memory only and is not exportable.
	StoreDir string

	// PortGates restricts interception to a set of destination ports, in the
	// same range syntax as the sniffer ("443", "80,8080-8880"). Empty means
	// all ports. Sourced from sniffer.sniff.ports for HTTPS and
	// sniffer.sniff.HTTP.ports for plain HTTP.
	HTTPSPorts utils.IntRanges[uint16]
	HTTPPorts  utils.IntRanges[uint16]

	// HostGates are the intercept prefixes. Both accepted forms —
	// "sub.example.com" and ".example.com" — cover the bare domain AND its
	// subdomains (suffix semantics, like the rule engine's DOMAIN-SUFFIX);
	// Normalize lowercases and strips any trailing dot, and rejects
	// non-ASCII values (use the punycode xn-- form).
	HostGates []string

	// SkipDomains keep tunnel-sensitive hosts out of interception entirely,
	// taking priority over HostGates. Like HostGates, a bare entry covers
	// the domain and its subdomains; the "+." config form (stored with a
	// leading dot) is accepted and behaves identically. SkipDstAddress
	// keeps IP-only destinations out at gate time.
	SkipDomains    []string
	SkipDstAddress []netip.Prefix

	// RewritePolicies are ordered; the first match wins and stops the scan,
	// mirroring Clash's first-match rule semantics.
	RewritePolicies []RewritePolicy

	// UpstreamRoots verifies the outer-leg TLS handshake. It is an internal
	// field seeded from tls.custom-trust-cert by the config layer; nil means
	// the system pool.
	UpstreamRoots *x509.CertPool
}

// RewritePolicy rewrites requests within one gate block.
type RewritePolicy struct {
	// URLPattern gates the policy on the request path. The host part uses
	// suffix semantics: "api.example.com/v2/" matches api.example.com AND
	// its subdomains (a leading-dot form behaves the same); "/api/" matches
	// the path prefix at any gated host. The host part is validated at load
	// like a gate: no wildcards, ports, or spaces.
	URLPattern string

	// Redirect returns an immediate 302 without contacting the upstream when
	// set. A bare-host value rewrites the authority and keeps the request
	// path+query; a full URL replaces the location verbatim.
	Redirect string

	// Reject answers with a status and no upstream dial when set. Use 403
	// or 404; reject ranges from 400 to 499.
	Reject int

	// HeaderRules are applied in order to the request before it leaves for
	// the upstream. Response-side rewriting is intentionally not in this
	// first cut: request headers carry the auth/geo state MITM exists for.
	HeaderRules []HeaderRule
}

// HeaderRule is one declarative header edit on the request side.
type HeaderRule struct {
	Action      string // set | add | remove
	Name        string
	Value       string
	ValuePrefix string
}

// MaxPolicyCount bounds one config so a pathological subscription cannot
// balloon the gate into a per-connection linear scan over thousands of
// entries.
const MaxPolicyCount = 64

// MaxHostGates caps the host/skip lists so MatchHost's linear scans stay
// bounded no matter what a subscription feeds in.
const MaxHostGates = 256

// validHeaderFieldName reports whether name is a valid RFC 7230 header field
// name: a token of ! and 0x23-0x7E characters excluding separators. This
// keeps CRLF, colons, and spaces out of the wire at load time instead of at
// request time.
func validHeaderFieldName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c <= ' ' || c >= 0x7f {
			return false
		}
		switch c {
		case '(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '/', '[', ']', '?', '=', '{', '}':
			return false
		}
	}
	return true
}

// Normalize validates and fills defaults. It is called by the config layer
// after decoding; errors are configuration errors, not runtime states.
// Gates and skip domains are canonicalized to lowercase without a trailing
// dot so wire-form SNI always matches, and non-ASCII values are rejected:
// TLS SNI on the wire is punycode (xn--), so an IDN gate would load fine
// and then never match.
func (c *Config) Normalize() error {
	if !c.Enable {
		return nil
	}
	if len(c.HostGates) == 0 {
		return errors.New("mitm: enable requires at least one host gate")
	}
	if len(c.HostGates) > MaxHostGates {
		return fmt.Errorf("mitm: too many host gates (max %d)", MaxHostGates)
	}
	for i := range c.HostGates {
		gate, err := normalizeGate(c.HostGates[i], "host gate")
		if err != nil {
			return err
		}
		c.HostGates[i] = gate
	}
	if len(c.SkipDomains) > MaxHostGates {
		return fmt.Errorf("mitm: too many skip domains (max %d)", MaxHostGates)
	}
	for i := range c.SkipDomains {
		gate, err := normalizeGate(c.SkipDomains[i], "skip domain")
		if err != nil {
			return err
		}
		c.SkipDomains[i] = gate
	}
	if len(c.SkipDstAddress) > MaxHostGates {
		return fmt.Errorf("mitm: too many skip-dst-address entries (max %d)", MaxHostGates)
	}
	if len(c.RewritePolicies) > MaxPolicyCount {
		return fmt.Errorf("mitm: too many rewrite policies (max %d)", MaxPolicyCount)
	}
	// A port in both lists is ambiguous: the gate cannot know whether the
	// conn is cleartext or TLS, and the dialer picks TLS-vs-plain from the
	// scheme the gate chose. Reject at load instead of guessing at runtime.
	// The comparison uses the EFFECTIVE sets: an empty list means "standard
	// port only" (443 https / 80 http), so https-ports:["80"] with no
	// http-ports must collide exactly like an explicit http-ports:["80"] —
	// otherwise every plaintext :80 conn would fail a TLS handshake.
	httpsAny := len(c.HTTPSPorts) == 0
	httpAny := len(c.HTTPPorts) == 0
	var overlap uint16
	if !httpsAny && !httpAny {
		c.HTTPPorts.Range(func(p uint16) bool {
			if c.HTTPSPorts.Check(p) {
				overlap = p
				return false
			}
			return true
		})
	} else if !httpsAny && httpAny {
		// http is standard-port-only (80): collide if 80 is claimed for TLS.
		if c.HTTPSPorts.Check(80) {
			overlap = 80
		}
	} else if httpsAny && !httpAny {
		// https is standard-port-only (443): collide if 443 is claimed for
		// cleartext.
		c.HTTPPorts.Range(func(p uint16) bool {
			if p == 443 {
				overlap = p
				return false
			}
			return true
		})
	}
	if overlap != 0 {
		return fmt.Errorf("mitm: port %d is in both http-ports and https-ports; a port must carry exactly one protocol", overlap)
	}
	for i := range c.RewritePolicies {
		if err := c.RewritePolicies[i].normalize(i); err != nil {
			return err
		}
	}
	return nil
}

// normalizeGate canonicalizes one host gate / skip domain: trimmed,
// lowercased, trailing dot stripped, ASCII-only, and host-valid. The bare
// and leading-dot forms both carry suffix (host+subdomains) semantics — the
// form distinction is kept only for readability.
func normalizeGate(raw, what string) (string, error) {
	gate := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if gate == "" {
		return "", fmt.Errorf("mitm: empty %s", what)
	}
	host := strings.TrimPrefix(gate, ".")
	if err := validateHost(host); err != nil {
		return "", fmt.Errorf("mitm: %s %q: %w", what, raw, err)
	}
	for i := 0; i < len(host); i++ {
		if host[i] >= 0x80 {
			return "", fmt.Errorf("mitm: %s %q contains non-ASCII characters; use the punycode (xn--) form of the IDN, e.g. xn--bcher-kva.example.com", what, raw)
		}
	}
	return gate, nil
}

func (p *RewritePolicy) normalize(idx int) error {
	prefix := fmt.Sprintf("mitm: rewrite[%d]", idx)
	if p.URLPattern == "" {
		return fmt.Errorf("%s: url-pattern is required", prefix)
	}
	if err := validateURLPatternHost(p.URLPattern); err != nil {
		return fmt.Errorf("%s: %w", prefix, err)
	}
	if p.Reject != 0 && (p.Reject < 400 || p.Reject > 499) {
		return fmt.Errorf("%s: reject must be a 4xx status", prefix)
	}
	if p.Redirect != "" {
		u, err := url.Parse(p.Redirect)
		// Bare-host rewrites ("mirror.example.com") parse as a path with no
		// scheme/host; only reject values with an explicit foreign scheme.
		if err != nil {
			return fmt.Errorf("%s: invalid redirect %q", prefix, p.Redirect)
		}
		if u.Scheme != "" && u.Scheme != "https" && u.Scheme != "http" {
			return fmt.Errorf("%s: redirect scheme must be http(s)", prefix)
		}
		if u.Host != "" {
			if err := validateHost(u.Hostname()); err != nil {
				return fmt.Errorf("%s: redirect host: %w", prefix, err)
			}
		}
	}
	for j := range p.HeaderRules {
		r := &p.HeaderRules[j]
		switch strings.ToLower(r.Action) {
		case "set", "add", "remove":
			r.Action = strings.ToLower(r.Action)
		default:
			return fmt.Errorf("%s: header action %q must be set, add or remove", prefix, r.Action)
		}
		if !validHeaderFieldName(r.Name) {
			return fmt.Errorf("%s: header rule name %q is not a valid HTTP field name (RFC 7230 token)", prefix, r.Name)
		}
		if r.Value != "" && r.ValuePrefix != "" {
			return fmt.Errorf("%s: value and value-prefix are exclusive; value-prefix prepends to the client's header value", prefix)
		}
		if r.ValuePrefix != "" && r.Action == "remove" {
			return fmt.Errorf("%s: value-prefix only applies to header set/add", prefix)
		}
	}
	return nil
}

// validateURLPatternHost validates the host part of a policy's url-pattern
// with the same rules as host gates (no wildcards, ports, spaces, or
// non-ASCII), so a typo cannot install a policy that silently never
// matches. The path part is enforced on the hot path; a leading-dot host
// form is accepted and behaves like the bare form.
func validateURLPatternHost(pattern string) error {
	host, _, _ := strings.Cut(pattern, "/")
	if host == "" {
		return nil // path-only pattern: applies at any gated host
	}
	host = strings.TrimPrefix(host, ".")
	if err := validateHost(host); err != nil {
		return fmt.Errorf("url-pattern host: %w", err)
	}
	for i := 0; i < len(host); i++ {
		if host[i] >= 0x80 {
			return fmt.Errorf("url-pattern host %q contains non-ASCII characters; use the punycode (xn--) form of the IDN", host)
		}
	}
	return nil
}

// validateHost rejects values that would let a host field escape into a URL
// or match more than the intended domain: no scheme separators, whitespace,
// wildcards, userinfo, or embedded credentials.
func validateHost(host string) error {
	if host == "" {
		return errors.New("empty host")
	}
	if strings.ContainsAny(host, "/\\ \t\r\n@?#:") {
		return fmt.Errorf("invalid characters in host %q", host)
	}
	if strings.Contains(host, "*") {
		return errors.New("wildcards are not supported; use a leading-dot suffix form")
	}
	if strings.Contains(host, "..") {
		return errors.New("empty label in host")
	}
	for _, label := range strings.Split(host, ".") {
		if label == "" {
			return errors.New("empty label in host")
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return errors.New("label may not start or end with a hyphen")
		}
	}
	if ip := net.ParseIP(host); ip != nil {
		return errors.New("bare IP hosts are not interceptable; gate on the fake-ip domain instead")
	}
	return nil
}

// MatchHost reports whether host is covered by the gate list. Both gate
// forms carry suffix semantics: a leading-dot gate (".example.com") and a
// bare gate ("sub.example.com") each cover that domain AND every subdomain,
// mirroring the rule engine's DOMAIN-SUFFIX. Gates are stored normalized
// (lowercase, no trailing dot), and the incoming host is canonicalized the
// same way before comparison so wire-form SNI cannot miss a valid gate.
// SkipDomains take priority and use the same suffix semantics; a skip that
// matches means the host is never intercepted.
func (c *Config) MatchHost(host string) bool {
	if !c.Enable {
		return false
	}
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return false
	}
	for _, gate := range c.SkipDomains {
		if hostSuffixMatch(host, strings.TrimPrefix(gate, ".")) {
			return false
		}
	}
	for _, gate := range c.HostGates {
		if hostSuffixMatch(host, strings.TrimPrefix(gate, ".")) {
			return true
		}
	}
	return false
}

// hostSuffixMatch reports whether host equals base or lies underneath it
// (base or any subdomain of base).
func hostSuffixMatch(host, base string) bool {
	return host == base || strings.HasSuffix(host, "."+base)
}

// MatchPort reports whether dstPort is intercepted under proto ("http" or
// "https"). An empty list falls back to the protocol's standard port — 443
// for https, 80 for http — so a minimal config cannot reach out to odd
// ports where the traffic may not be HTTP at all; widening is explicit.
func (c *Config) MatchPort(proto string, dstPort uint16) bool {
	list := c.HTTPPorts
	if proto == "https" {
		list = c.HTTPSPorts
	}
	if len(list) == 0 {
		if proto == "https" {
			return dstPort == 443
		}
		return dstPort == 80
	}
	return list.Check(dstPort)
}

// TrafficMatch is the single entry point the tunnel asks per request:
// should this conn be intercepted, and by which policy block. path is the
// request path with the query stripped (h1: req.URL.Path, h2: :path minus
// query). The bool is false whenever MITM is disabled, the host/port does
// not gate in, or no policy targets the host (a config with hosts but no
// rewrite policies therefore intercepts nothing — the executor warns at
// load). Return value contract, changed with the value-prefix semantics:
// the RewritePolicy is returned BY VALUE as before, and HeaderRules inside
// it carry the decided prefix semantics — value-prefix PREPENDS to the
// client's existing header value (set replaces the value with
// prefix+existing, or just the prefix when the client sent none; add
// appends prefix+existing as an extra line). Destination-IP skips are
// checked by the caller at gate time, before the ClientHello is read.
func (c *Config) TrafficMatch(host string, proto string, dstPort uint16, path string) (RewritePolicy, bool) {
	var zero RewritePolicy
	if !c.MatchHost(host) {
		return zero, false
	}
	if !c.MatchPort(proto, dstPort) {
		return zero, false
	}
	for i := range c.RewritePolicies {
		policy := &c.RewritePolicies[i]
		if matchURLPattern(policy.URLPattern, host, path) {
			return *policy, true
		}
	}
	return zero, false
}

// matchURLPattern resolves a policy's url-pattern against a request host
// and path. The pattern carries no leading dot; the config loader stripped
// it when copying gate host into each policy. The host part uses suffix
// semantics — it matches the bare domain AND its subdomains:
//
//	"api.example.com/v2"   api.example.com (+ subdomains) and path prefix
//	"example.com/api/"     host-suffix and path prefix
//	"/api/"                path prefix at any gated host
//	"api.example.com"      host-suffix at any path
//
// The path part is a prefix match on SEGMENT boundaries: "v2" matches
// /v2, /v2/ and /v2/x but NOT /v2x. An empty path part ("host" or
// "host/") covers every path.
func matchURLPattern(pattern, host, path string) bool {
	patternHost, patternPath, hasPath := strings.Cut(pattern, "/")
	if patternHost != "" && !matchHostSuffix(patternHost, host) {
		return false
	}
	if !hasPath || patternPath == "" {
		// Host-only (or "host/"): every path.
		return true
	}
	return pathPrefixMatch(path, "/"+patternPath)
}

// pathPrefixMatch reports whether path is covered by prefix at a segment
// boundary: "/v2" matches /v2, /v2/ and /v2/x but NOT /v2x; "/v2/" matches
// /v2 and everything under it (the trailing slash is already a boundary).
func pathPrefixMatch(path, prefix string) bool {
	if path == prefix {
		return true
	}
	if !strings.HasPrefix(path, prefix) {
		if strings.HasSuffix(prefix, "/") && path+"/" == prefix {
			return true // "/v2" is the bare directory of prefix "/v2/"
		}
		return false
	}
	if strings.HasSuffix(prefix, "/") {
		return true // boundary is the trailing slash itself
	}
	rest := path[len(prefix):]
	return rest == "" || rest[0] == '/'
}

func matchHostSuffix(patternHost, host string) bool {
	if patternHost == "" {
		return true
	}
	patternHost = strings.TrimSuffix(strings.ToLower(patternHost), ".")
	patternHost = strings.TrimPrefix(patternHost, ".")
	return hostSuffixMatch(host, patternHost)
}
