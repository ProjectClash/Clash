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

	// HostGates are the intercept prefixes: rules of the form "sub.example.com"
	// (no leading dot) or ".example.com". A leading-dot rule also matches the
	// bare domain, mirroring the existing rule engine's suffix semantics.
	HostGates []string

	// SkipDomains and SkipDstAddress keep tunnel-sensitive and IP-only hosts
	// out of interception entirely.
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
	// URLPattern gates the policy on the request path. Supports the same
	// suffix/keyword syntax as the rule engine: ".example.com/api/" matches
	// by suffix; "example.com/api/" matches exact path; bare "/api/" matches
	// the suffix at any host.
	URLPattern string

	// Redirect returns an immediate 302 without contacting the upstream when
	// set. HostPrefix covers Anywhere's host-only rewrite; Redirect covers
	// full-location rewrites. Both are allowed on one policy.
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

// MaxBodyBuffer caps how much of a request body the rewrite path buffers
// before it stops inspecting and streams the rest untouched.
const MaxBodyBuffer = 128 * 1024

// MaxPolicyCount bounds one config so a pathological subscription cannot
// balloon the gate into a per-connection linear scan over thousands of
// entries.
const MaxPolicyCount = 64

// Normalize validates and fills defaults. It is called by the config layer
// after decoding; errors are configuration errors, not runtime states.
func (c *Config) Normalize() error {
	if !c.Enable {
		return nil
	}
	if len(c.HostGates) == 0 {
		return errors.New("mitm: enable requires at least one host gate")
	}
	for i := range c.HostGates {
		gate := strings.TrimSpace(c.HostGates[i])
		if gate == "" {
			return errors.New("mitm: empty host gate")
		}
		host, isDomainSuffix := gate, strings.HasPrefix(gate, ".")
		if isDomainSuffix {
			host = gate[1:]
		}
		if err := validateHost(host); err != nil {
			return fmt.Errorf("mitm: host gate %q: %w", gate, err)
		}
		c.HostGates[i] = gate
	}
	if len(c.RewritePolicies) > MaxPolicyCount {
		return fmt.Errorf("mitm: too many rewrite policies (max %d)", MaxPolicyCount)
	}
	for i := range c.RewritePolicies {
		if err := c.RewritePolicies[i].normalize(i); err != nil {
			return err
		}
	}
	return nil
}

func (p *RewritePolicy) normalize(idx int) error {
	prefix := fmt.Sprintf("mitm: rewrite[%d]", idx)
	if p.URLPattern == "" {
		return fmt.Errorf("%s: url-pattern is required", prefix)
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
		if r.Name == "" {
			return fmt.Errorf("%s: header rule needs a name", prefix)
		}
		if r.ValuePrefix != "" && (r.Action == "remove" || r.Value != "") {
			return fmt.Errorf("%s: value-prefix only applies to header set/add", prefix)
		}
		if r.Value != "" && r.ValuePrefix != "" {
			return fmt.Errorf("%s: value and value-prefix are exclusive", prefix)
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

// HostPrefix is the inverse of the leading-dot form: it joins the gate to a
// request path fragment. It exists so the UI composes "gate host" + "path"
// without concatenation rules leaking into user config.
const HostPrefix = ""

// MatchHost reports whether host is covered by the gate list. A leading-dot
// gate (".example.com") covers example.com and every subdomain; a bare gate
// ("sub.example.com") covers exactly that host and its subdomains, matching
// the rule engine's DOMAIN and DOMAIN-SUFFIX distinction.
func (c *Config) MatchHost(host string) bool {
	if !c.Enable {
		return false
	}
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if host == "" {
		return false
	}
	for _, gate := range c.SkipDomains {
		g := strings.TrimSuffix(strings.ToLower(gate), ".")
		if g == host || (strings.HasPrefix(g, ".") && strings.HasSuffix(host, g)) {
			return false
		}
	}
	for _, gate := range c.HostGates {
		var base string
		switch {
		case strings.HasPrefix(gate, "."):
			base = gate[1:]
		default:
			base = gate
		}
		if host == base || strings.HasSuffix(host, "."+base) {
			return true
		}
	}
	return false
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

// TrafficMatch is the single entry point the tunnel asks per connection:
// should this conn be intercepted, and by which policy block. The bool is
// false whenever MITM is disabled, the host/port does not gate in, or no
// policy targets the host. Destination-IP skips are checked by the caller at
// gate time, before the ClientHello is read.
func (c *Config) TrafficMatch(host string, proto string, dstPort uint16) (RewritePolicy, bool) {
	var zero RewritePolicy
	if !c.MatchHost(host) {
		return zero, false
	}
	if !c.MatchPort(proto, dstPort) {
		return zero, false
	}
	for i := range c.RewritePolicies {
		policy := &c.RewritePolicies[i]
		if matchURLPattern(policy.URLPattern, host) {
			return *policy, true
		}
	}
	return zero, false
}

// matchURLPattern resolves a policy's url-pattern against a request host.
// The pattern carries no leading dot; the config loader stripped it when
// copying gate host into each policy. Forms:
//
//	"api.example.com/v2/"  exact host and path prefix
//	"example.com/api/"     host-suffix and path prefix
//	"/api/"                path prefix at any gated host
func matchURLPattern(pattern, host string) bool {
	patternHost, path, hasPath := strings.Cut(pattern, "/")
	if !hasPath {
		// No path component: the pattern is host-only.
		return matchHostSuffix(patternHost, host)
	}
	if patternHost != "" && !matchHostSuffix(patternHost, host) {
		return false
	}
	return strings.HasPrefix("/"+path, "/")
}

func matchHostSuffix(patternHost, host string) bool {
	if patternHost == "" {
		return true
	}
	patternHost = strings.TrimSuffix(strings.ToLower(patternHost), ".")
	if host == patternHost || strings.HasSuffix(host, "."+patternHost) {
		return true
	}
	// Leading-dot gate inside a policy pattern: ".api.example.com" means the
	// bare domain too.
	if strings.HasPrefix(patternHost, ".") {
		base := patternHost[1:]
		return host == base || strings.HasSuffix(host, "."+base)
	}
	return false
}
