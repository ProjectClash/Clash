package mitm

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	N "github.com/ProjectClash/Clash/common/net"
	"github.com/ProjectClash/Clash/component/sniffer"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/log"
)

// TLS framing constants for the ClientHello peek; kept local because the
// sniffer package's copies are unexported.
const (
	tlsRecordHeaderLen     = 5
	tlsRecordTypeHandshake = 0x16
	tlsMaxPlaintext        = 1 << 14
)

// maxHeaderBytes caps the request line + headers accepted on both legs.
// Oversized input is answered 431 and the connection closed rather than
// buffering unbounded attacker-controlled memory.
const maxHeaderBytes = 64 * 1024

// maxRequestBody bounds how much of an h1 request body is buffered while
// deciding whether to forward it; beyond it the leg answers 413 and closes
// (h2 legs already refuse over-limit streams the same way in h2.go).
const maxRequestBody = 1 << 20

// maxDrainBytes bounds how much of an over-limit body is drained after
// answering 413 (see the serve loop).
const maxDrainBytes = 1 << 20

var (
	errNotTLS         = errors.New("mitm: not TLS header")
	errNotClientHello = errors.New("mitm: not client hello")
)

// Dispatcher holds the active engine and config for the tunnel hot path.
// Swapped atomically on config reload, mirroring sniffer.Dispatcher.
type Dispatcher struct {
	engine *Engine
	config atomic.Pointer[Config]
}

// Engine returns the certificate engine behind this dispatcher, for the
// bind layer's CA export; nil when MITM is disabled.
func (d *Dispatcher) Engine() *Engine {
	if d == nil {
		return nil
	}
	return d.engine
}

// StoreDir returns the configured CA persistence directory, empty when the
// CA is memory-only.
func (d *Dispatcher) StoreDir() string {
	if d == nil {
		return ""
	}
	return d.config.Load().StoreDir
}

// NewDispatcher builds a Dispatcher from a normalized Config. When a store
// directory is configured the CA is loaded from disk (or minted and saved on
// first launch); otherwise the CA lives in memory only.
func NewDispatcher(config *Config) (*Dispatcher, error) {
	d := &Dispatcher{}
	d.config.Store(config)
	if !config.Enable {
		return d, nil
	}
	engine := &Engine{leaves: make(map[string]*HostCertificate)}
	if config.StoreDir != "" {
		if err := LoadState(engine, config.StoreDir); err != nil {
			return nil, fmt.Errorf("load mitm CA state: %w", err)
		}
	} else {
		if err := engine.Regenerate(); err != nil {
			return nil, fmt.Errorf("generate mitm CA: %w", err)
		}
	}
	d.engine = engine
	return d, nil
}

// Enable reports whether interception is active.
func (d *Dispatcher) Enable() bool {
	return d != nil && d.config.Load().Enable && d.engine != nil
}

// Config returns the active config snapshot.
func (d *Dispatcher) Config() *Config {
	if d == nil {
		return nil
	}
	return d.config.Load()
}

// CaCertificatePEM exports the active root certificate for the client's
// install-profile flow; empty when MITM is off.
func (d *Dispatcher) CaCertificatePEM() ([]byte, error) {
	if d == nil || d.engine == nil {
		return nil, ErrNotEnabled
	}
	return d.engine.CaCertificatePEM()
}

// DialFunc dials the outer leg through the routing chain. The tunnel builds
// it from the rule-resolved proxy adapter, so intercepted traffic keeps the
// user's rules, proxies, and DNS: MITM changes what is said to the upstream,
// never which proxy carries it.
type DialFunc func(ctx context.Context, host string, port uint16) (net.Conn, error)

// InnerHandle intercepts one client connection. It returns true when the
// connection was fully handled (intercepted and proxied, or answered by a
// redirect/reject policy); the tunnel closes the conn then and does not dial
// its own upstream. It returns false when MITM declines the connection —
// wrong port, no ClientHello SNI, gate miss — and the tunnel must proceed
// with its normal path; peeked bytes stay buffered in conn, so the fallback
// path sees the stream unmodified.
//
// The gate is evaluated against metadata first (cheap, no I/O). Only gated
// connections read bytes from conn: the ClientHello is peeked (not consumed)
// to resolve the SNI host before any TLS state exists, so a gate miss never
// leaves the connection in a half-parsed state.
func (d *Dispatcher) InnerHandle(ctx context.Context, conn *N.BufferedConn, metadata *C.Metadata, dial DialFunc) bool {
	if !d.Enable() {
		return false
	}
	config := d.config.Load()

	proto, gated := d.gate(config, metadata)
	if !gated {
		return false
	}

	// From here the conn may be claimed: run the rest under a context that
	// keeps parent VALUES but drops its cancellation and deadline, so a
	// keep-alive leg serving requests for minutes is not killed by the
	// tunnel's 5s dial budget. Each upstream dial inside re-arms its own
	// short timeout (see mitmDialTimeout).
	serveCtx := context.WithoutCancel(ctx)

	defer func() {
		// The per-conn path must never take the process down: a panic in
		// the request loop is logged with its stack and the leg closed
		// (the deferred leg.Close in serve* handles the conn itself).
		if r := recover(); r != nil {
			log.Errorln("[MITM] recovered panic in intercept of %s: %v\n%s", metadata.RemoteAddress(), r, debug.Stack())
		}
	}()

	if proto == "http" {
		// Plain HTTP: no handshake to answer; serve the reverse proxy
		// directly on the cleartext conn. MatchHost keeps IP-named and
		// ungated hosts out now that the gate no longer requires a
		// DNS-mapping mode to consider cleartext at all.
		host := metadata.Host
		if host == "" || !config.MatchHost(host) {
			return false
		}
		d.serveCleartext(serveCtx, conn, config, host, dial, uint16(metadata.DstPort))
		return true
	}
	// HTTPS: peek the ClientHello to learn the SNI without consuming it.
	// The peek is bounded: a client that connects and stalls must release
	// the tunnel's connection slot within one handshake window instead of
	// pinning it indefinitely (bufio.Peek does not observe ctx, so the
	// dialCtx deadline never reaches this read). The deadline is cleared
	// right after, before the real handshake re-reads the buffered bytes.
	_ = conn.SetReadDeadline(time.Now().Add(innerHandshakeTimeout))
	host, err := peekClientHelloSNI(conn)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil || host == "" {
		log.Debugln("[MITM] no ClientHello SNI on port %d: %v", metadata.DstPort, err)
		return false
	}
	if !config.MatchHost(host) {
		return false
	}

	// Gated: mint the leaf for the SNI host and terminate. The buffered
	// ClientHello is re-read by crypto/tls from the same conn.
	tlsConn := tls.Server(conn, &tls.Config{
		Certificates: []tls.Certificate{leafOf(d.engine, host)},
		MinVersion:   tls.VersionTLS12,
		// Advertise both; crypto/tls intersects with the client's offer.
		NextProtos: []string{"h2", "http/1.1"},
	})
	handshakeCtx, cancel := context.WithTimeout(serveCtx, innerHandshakeTimeout)
	defer cancel()
	if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
		// Owned and untrustworthy from here on (the client saw our leaf):
		// close rather than forward.
		log.Debugln("[MITM] inner handshake with %s failed: %v", host, err)
		return true
	}

	leg := newClientLeg(tlsConn, tlsConn.ConnectionState().NegotiatedProtocol)
	defer leg.Close()
	d.serve(serveCtx, leg, config, host, "https", dial, uint16(metadata.DstPort))
	return true
}

// peekClientHelloSNI reads the first TLS record from conn via Peek (bytes
// stay buffered for the later crypto/tls handshake) and returns the SNI.
// Partial or non-TLS streams return an error; the caller treats that as a
// gate miss.
func peekClientHelloSNI(conn *N.BufferedConn) (string, error) {
	head, err := conn.Peek(tlsRecordHeaderLen)
	if err != nil {
		return "", err
	}
	if head[0] != tlsRecordTypeHandshake || head[1] != 0x03 {
		return "", errNotTLS
	}
	recordLen := int(head[3])<<8 | int(head[4])
	if recordLen <= 0 || recordLen > tlsMaxPlaintext {
		return "", errNotClientHello
	}
	// The default 4096-byte bufio buffer cannot hold a post-quantum
	// ClientHello (>4KB with big key shares); grow before the second Peek
	// or it fails with ErrBufferFull and the conn is silently skipped
	// (mirrors component/sniffer/dispatcher.go).
	conn.Grow(tlsRecordHeaderLen + recordLen)
	record, err := conn.Peek(tlsRecordHeaderLen + recordLen)
	if err != nil {
		return "", err
	}
	sni, err := sniffer.ReadClientHello(record[tlsRecordHeaderLen:])
	if err != nil {
		return "", err
	}
	if sni == nil {
		return "", errNotClientHello
	}
	return *sni, nil
}

// gate decides protocol and port eligibility from metadata only. It fails
// closed: any miss hands the connection back to the tunnel untouched.
func (d *Dispatcher) gate(config *Config, metadata *C.Metadata) (proto string, ok bool) {
	dstPort := uint16(metadata.DstPort)
	for _, prefix := range config.SkipDstAddress {
		if prefix.IsValid() && metadata.DstIP.IsValid() && prefix.Contains(metadata.DstIP) {
			return "", false
		}
	}
	// Plain HTTP is decided by the port alone: fake-ip (the default
	// enhanced mode) and the sniffer's replaceDomain both leave a DNSMode
	// other than DNSMapping on the metadata, so the old DNSMapping-only
	// requirement made port-80 interception unreachable on default
	// configs. Host quality is enforced downstream: InnerHandle runs
	// MatchHost (which filters bare IPs) before serving cleartext.
	if metadata.Host != "" && config.MatchPort("http", dstPort) && !config.MatchPort("https", dstPort) {
		return "http", true
	}
	if config.MatchPort("https", dstPort) {
		return "https", true
	}
	return "", false
}

// leafOf mints the leaf for host, falling back to a hard close signal when
// minting fails (CA exhausted, bad host encoding): the caller then aborts the
// intercepted connection instead of serving a broken certificate.
func leafOf(engine *Engine, host string) tls.Certificate {
	leaf, err := engine.MintLeaf(host)
	if err != nil {
		// Empty certificate list makes crypto/tls fail the handshake; the
		// caller logs and closes.
		return tls.Certificate{}
	}
	return leaf.Certificate
}

func (d *Dispatcher) serveCleartext(ctx context.Context, conn *N.BufferedConn, config *Config, host string, dial DialFunc, dstPort uint16) {
	leg := newClientLeg(conn, "")
	defer leg.Close()
	d.serve(ctx, leg, config, host, "http", dial, dstPort)
}

// serve runs the request loop on one intercepted client leg until the client
// goes away or a policy closes the connection. scheme is "https" or "http"
// and matches the leg, not the negotiated ALPN.
func (d *Dispatcher) serve(ctx context.Context, leg *clientLeg, config *Config, host, scheme string, dial DialFunc, dstPort uint16) {
	for {
		req, err := leg.ReadRequest()
		if err != nil {
			if isHeaderTooLarge(err) {
				_ = leg.WriteSimpleResponse(http.StatusRequestHeaderFieldsTooLarge)
			}
			return // client closed, idle timeout, or garbage: done
		}
		leg.reqClose = req.Close
		if isUpgradeRequest(req) {
			// Never forward a 101: the interceptor cannot relay a
			// tunneled protocol it does not speak (WebSocket/wss are
			// out of scope); refuse and drop the leg.
			log.Debugln("[MITM] refusing upgrade on %s: %s", host, req.Header.Get("Upgrade"))
			_ = leg.WriteSimpleResponse(http.StatusNotImplemented)
			return
		}
		if leg.proto() != "h2" && req.Body != nil && req.Body != http.NoBody {
			// h2 legs cap bodies in h2.go (per-stream 1 MiB + conn
			// budget). h1: refuse an announced over-limit body
			// outright, and cap unknown-length (chunked) bodies
			// while forwarding — parity with the h2 413 path.
			if req.ContentLength > maxRequestBody {
				// Drain a bounded amount FIRST: a Go transport
				// writes the whole body before reading the
				// response, so answering before draining makes
				// the client die on a broken pipe instead of
				// seeing the 413. Bounded so a lying Content-
				// Length cannot pin the leg.
				_, _ = io.CopyN(io.Discard, req.Body, maxDrainBytes)
				_ = leg.WriteSimpleResponse(http.StatusRequestEntityTooLarge)
				return
			}
			if req.ContentLength < 0 {
				req.Body = &cappedBody{ReadCloser: req.Body, rem: maxRequestBody}
			}
		}
		policy, ok := config.TrafficMatch(host, scheme, dstPort, req.URL.Path)
		if !ok {
			if !d.proxyPass(ctx, leg, req, host, scheme, dial, dstPort, "") {
				return
			}
			continue
		}
		if policy.Reject != 0 {
			_ = leg.WriteSimpleResponse(policy.Reject)
			return
		}
		if policy.Redirect != "" {
			location := composeRedirect(policy.Redirect, req.URL.Path, req.URL.RawQuery, scheme)
			_ = leg.WriteRedirectResponse(location)
			return
		}
		if !d.rewriteAndProxy(ctx, leg, req, host, scheme, dial, dstPort, &policy) {
			return
		}
	}
}

// isHeaderTooLarge reports whether a request parse failure was caused by the
// header-size cap rather than a client departure.
func isHeaderTooLarge(err error) bool {
	return err == errHeaderTooLarge || strings.Contains(err.Error(), errHeaderTooLarge.Error())
}

// isUpgradeRequest reports whether req asks to switch protocols.
func isUpgradeRequest(req *http.Request) bool {
	if strings.EqualFold(req.Header.Get("Connection"), "Upgrade") {
		return req.Header.Get("Upgrade") != ""
	}
	for _, v := range req.Header.Values("Connection") {
		for _, tok := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(tok), "Upgrade") && req.Header.Get("Upgrade") != "" {
				return true
			}
		}
	}
	return false
}

// rewriteAndProxy applies header rules then forwards the request upstream,
// streaming the response back with hop-by-hop filtering on both sides.
func (d *Dispatcher) rewriteAndProxy(ctx context.Context, leg *clientLeg, req *http.Request, host, scheme string, dial DialFunc, dstPort uint16, policy *RewritePolicy) bool {
	applyHeaderRules(req, policy.HeaderRules)
	return d.proxyPass(ctx, leg, req, host, scheme, dial, dstPort, "")
}

// proxyPass dials the upstream for one request, writes it, and streams the
// response back. upstreamHost is empty for direct forwards; policies that
// rewrite to another host pass the rewritten host so the dial uses it.
func (d *Dispatcher) proxyPass(ctx context.Context, leg *clientLeg, req *http.Request, host, scheme string, dial DialFunc, dstPort uint16, upstreamHost string) bool {
	dialHost := upstreamHost
	if dialHost == "" {
		dialHost = host
	}
	upstream, err := d.dialUpstream(ctx, dial, dialHost, scheme, dstPort)
	if err != nil {
		log.Errorln("[MITM] dial upstream %s (%s) failed: %v", dialHost, scheme, err)
		_ = leg.WriteSimpleResponse(http.StatusBadGateway)
		return false
	}
	defer upstream.Close()

	// HTTP/2 client leg to an HTTP/1.1 upstream is bridged per request by
	// the clientLeg's h2 engine; HTTP/1.1 legs serialize here.
	resp, err := upstream.RoundTrip(ctx, req)
	if err != nil {
		_ = leg.WriteSimpleResponse(http.StatusBadGateway)
		return false
	}
	// The upstream leg's Connection:close is OUR connection management,
	// not the client's: a client-requested keep-alive must survive the
	// upstream close, or every intercepted leg dies after one request.
	// Only a response with determinate framing (Content-Length or
	// chunked) can be written on a keep-alive conn; an indeterminate
	// (read-until-close) body must keep closing the leg to delimit.
	if !leg.reqClose && (resp.ContentLength >= 0 || len(resp.TransferEncoding) > 0) {
		resp.Close = false
	}
	if err := leg.WriteResponse(resp); err != nil {
		closeUpstreamBody(resp)
		return false
	}
	if !leg.FlushBody(resp) {
		_ = resp.Body.Close()
		return false
	}
	closeUpstreamBody(resp)
	return true
}

// closeUpstreamBody closes the real body under an upstreamDeadlineBody
// wrapper (whose own Close is a no-op so http.Response.Write cannot close
// the source out from under FlushBody — see the type comment).
func closeUpstreamBody(resp *http.Response) {
	if wb, ok := resp.Body.(*upstreamDeadlineBody); ok {
		if wb.closing != nil {
			_ = wb.closing.Close()
		}
		return
	}
	_ = resp.Body.Close()
}

// dialUpstream opens the outer leg through the tunnel-provided dial func
// (proxy chain + core DNS), then layers TLS for https scheme. Cleartext vs
// TLS is decided by the SCHEME the gate resolved, never by the port number
// — an https conn on port 8080 or a plain conn on 443 both dial correctly
// (overlapping http/https port lists are rejected at load). Dialing happens
// per request burst — Anywhere's deferred-dial: the upstream is not
// contacted until a policy has decided the request needs one. Each dial
// runs under its own short timeout so keep-alive traffic long after the
// tunnel's initial context expired still connects.
func (d *Dispatcher) dialUpstream(ctx context.Context, dial DialFunc, host, scheme string, port uint16) (upstreamConn, error) {
	if scheme == "http" {
		if port == 0 {
			port = 80
		}
	} else if port == 0 {
		port = 443
	}
	if dial == nil {
		return nil, errors.New("mitm: no upstream dial func")
	}
	dialCtx, cancel := context.WithTimeout(ctx, C.DefaultTCPTimeout)
	defer cancel()
	raw, err := dial(dialCtx, host, port)
	if err != nil {
		return nil, fmt.Errorf("dial upstream %s:%d: %w", host, port, err)
	}
	if scheme == "http" {
		return newHTTP1Upstream(raw), nil
	}
	// Verification uses the config's upstream root pool when provided (the
	// config layer seeds it with tls.custom-trust-cert); nil means the
	// system pool, which is the safe default.
	tlsConn := tls.Client(raw, &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
		RootCAs:    d.config.Load().UpstreamRoots,
		// Offer h2 so an h2-capable origin negotiates it; http/1.1
		// otherwise. Without NextProtos the outer leg was h1-only and
		// h2 upstreams were unreachable.
		NextProtos: []string{"h2", "http/1.1"},
	})
	hsCtx, hsCancel := context.WithTimeout(ctx, outerHandshakeTimeout)
	defer hsCancel()
	if err := tlsConn.HandshakeContext(hsCtx); err != nil {
		_ = raw.Close()
		return nil, fmt.Errorf("upstream handshake %s:%d: %w", host, port, err)
	}
	// If the upstream offers h2, speak h2; otherwise bridge to HTTP/1.1.
	if proto := tlsConn.ConnectionState().NegotiatedProtocol; proto == "h2" {
		return newHTTP2Upstream(tlsConn)
	}
	return newHTTP1Upstream(tlsConn), nil
}

// applyHeaderRules applies one policy's header edits to the outgoing
// request. ValuePrefix semantics (decided): the prefix PREPENDS TO THE
// CLIENT'S EXISTING VALUE, not to a static value —
//
//	set + value-prefix: header becomes prefix+<client value>; when the
//	    client sent no value (absent or empty), the header becomes just the
//	    prefix.
//	add + value-prefix: an extra line "prefix+<client value>" is appended;
//	    with no client value it degenerates to the plain prefix.
//
// value (static) and value-prefix are mutually exclusive, enforced at load.
func applyHeaderRules(req *http.Request, rules []HeaderRule) {
	for _, rule := range rules {
		switch rule.Action {
		case "set":
			if rule.ValuePrefix != "" {
				req.Header.Set(rule.Name, joinPrefix(rule.ValuePrefix, req.Header.Get(rule.Name)))
				continue
			}
			req.Header.Set(rule.Name, rule.Value)
		case "add":
			if rule.ValuePrefix != "" {
				req.Header.Add(rule.Name, joinPrefix(rule.ValuePrefix, req.Header.Get(rule.Name)))
				continue
			}
			req.Header.Add(rule.Name, rule.Value)
		case "remove":
			req.Header.Del(rule.Name)
		}
	}
}

// joinPrefix prepends prefix to the client's existing header value; a
// missing value (empty string) yields just the prefix.
func joinPrefix(prefix, existing string) string {
	return prefix + existing
}

// composeRedirect builds a Location from a policy target. A bare-host
// target (no scheme, no leading "/") rewrites the AUTHORITY and keeps the
// request's own path and query: Location = scheme://target+path+query,
// with scheme taken from the intercepted leg. A full http(s) URL passes
// through verbatim (Normalize already rejected other schemes and
// validated the host).
func composeRedirect(target, path, query, scheme string) string {
	if isBareHostTarget(target) {
		loc := scheme + "://" + target + path
		if query != "" {
			loc += "?" + query
		}
		return loc
	}
	return target
}

// isBareHostTarget reports whether target is a host name with no scheme
// and no path component — the host-only rewrite form. url.Parse alone
// cannot tell "mirror.example.com" (bare host) from a relative path, and
// parsing the former yields Host="" whose Location would point back at
// the intercepted host (a same-origin redirect loop).
func isBareHostTarget(target string) bool {
	if target == "" || strings.Contains(target, "://") {
		return false
	}
	if strings.HasPrefix(target, "/") || strings.HasPrefix(target, ".") {
		return false
	}
	host, _, hasPath := strings.Cut(target, "/")
	if hasPath {
		// "host/path" is not the bare-host form; only a pure host is.
		return false
	}
	return host != "" && !strings.ContainsAny(host, " ?#@")
}

const (
	innerHandshakeTimeout = 10 * time.Second
	outerHandshakeTimeout = 10 * time.Second
)

// idleTimeout is the per-operation idle budget on both legs. An atomic
// (not a const) purely so tests can shorten the window: tests mutate it
// while leg goroutines from earlier tests may still be running, and a
// plain var race-detector-fails on that benign test-only mutation. The
// default matches the kernel's TCP keep-alive expectation for an HTTP
// idle conn.
var idleTimeout atomic.Int64

func init() { idleTimeout.Store(int64(120 * time.Second)) }

func idleTimeoutNow() time.Duration { return time.Duration(idleTimeout.Load()) }

// ---- tunnel wiring ----

var (
	mitmDispatcher atomic.Pointer[Dispatcher]
)

// UpdateMITM swaps the active Dispatcher; nil disables.
func UpdateMITM(d *Dispatcher) {
	mitmDispatcher.Store(d)
}

// ActiveDispatcher returns the current Dispatcher for external control
// surfaces (the client's CA export reads through this).
func ActiveDispatcher() *Dispatcher {
	return mitmDispatcher.Load()
}

// TrafficMatch is the tunnel's single ask: intercept this conn? When it
// returns true the connection has been fully served and must be closed by
// the caller; when false the stream is unmodified and the normal path
// continues (peeked bytes, if any, stay buffered and are replayed).
func TrafficMatch(ctx context.Context, conn *N.BufferedConn, metadata *C.Metadata, dial DialFunc) bool {
	d := mitmDispatcher.Load()
	if d == nil || !d.Enable() {
		return false
	}
	return d.InnerHandle(ctx, conn, metadata, dial)
}

// ---- client leg (inner) ----

type clientLeg struct {
	conn     net.Conn
	br       *bufio.Reader
	protocol string // "h2" or "http/1.1" (or "" for cleartext h1)

	// hdrLimit caps request heads on this leg; see headerLimitReader.
	hdrLimit headerLimitReader

	// reqClose records whether the CURRENT request asked to close the
	// connection (HTTP/1.0 or Connection: close). It is the client-leg
	// keep-alive signal only: the upstream leg's close flag is
	// meaningless here because the interceptor forces Connection:close
	// upstream for connection management.
	reqClose bool

	h2Once sync.Once
	h2     *h2Server
	closed atomic.Bool
}

func newClientLeg(conn net.Conn, negotiated string) *clientLeg {
	l := &clientLeg{conn: conn, protocol: negotiated}
	if negotiated == "h2" {
		// The h2 engine's read loop owns the reader; its own
		// continuation/header-block caps (h2.go) bound head sizes.
		l.br = bufio.NewReader(conn)
	} else {
		l.hdrLimit.conn = conn
		l.br = bufio.NewReader(&l.hdrLimit)
	}
	return l
}

func (l *clientLeg) proto() string {
	if l.protocol == "h2" {
		return "h2"
	}
	return "http/1.1"
}

func (l *clientLeg) Close() {
	if l.closed.CompareAndSwap(false, true) {
		if l.h2 != nil {
			l.h2.Close()
		}
		_ = l.conn.Close()
	}
}

// ReadRequest returns the next request on the leg. On HTTP/1.1 it parses off
// the buffered reader; on HTTP/2 the h2 engine delivers requests through a
// channel and this method blocks until one arrives or the leg closes.
// The next-request read is bounded by the idle timeout (a keep-alive client
// that goes silent releases the conn), and the request line+headers are
// capped at maxHeaderBytes: overflowing input fails with errHeaderTooLarge
// so the caller can answer 431 and close instead of buffering without bound.
func (l *clientLeg) ReadRequest() (*http.Request, error) {
	if l.protocol == "h2" {
		l.h2Once.Do(func() {
			l.h2 = newH2Server(l.conn, l.br)
		})
		return l.h2.NextRequest()
	}
	_ = l.conn.SetReadDeadline(time.Now().Add(idleTimeoutNow()))
	defer l.conn.SetReadDeadline(time.Time{})
	l.hdrLimit.clamp(int64(maxHeaderBytes) - int64(l.br.Buffered()))
	req, err := http.ReadRequest(l.br)
	l.hdrLimit.clamp(-1) // head done: body reads are deadline-bounded, not byte-bounded
	if err != nil {
		return nil, err
	}
	if l.protocol != "h2" && req.Body != nil && req.Body != http.NoBody {
		// Re-arm the client read deadline around each body chunk: a
		// stalled uploader releases the conn within one idle window
		// while slow-but-flowing bodies are never truncated.
		req.Body = &deadlineBody{ReadCloser: req.Body, conn: l.conn}
	}
	return req, nil
}

// errHeaderTooLarge is returned (possibly wrapped) when a request or
// response head exceeds maxHeaderBytes.
var errHeaderTooLarge = errors.New("mitm: header fields too large")

// headerLimitReader sits under the leg's bufio.Reader and caps how many
// bytes one head (request line+headers, or status line+headers) may pull
// from the wire. It is CLAMPED by the caller right before each parse,
// accounting for bytes already sitting in the bufio; after the parse the
// caller clamps it to unlimited (negative) so body streams and h2 read
// loops are unaffected. Bytes the bufio already holds bypass the cap by at
// most one buffer size, which is harmless for a bound whose job is
// stopping unbounded growth. rem == 0 blocks all reads; rem < 0 is
// unlimited.
type headerLimitReader struct {
	conn net.Conn
	rem  int64
}

func (h *headerLimitReader) Read(p []byte) (int, error) {
	if h.rem == 0 {
		return 0, errHeaderTooLarge
	}
	if h.rem > 0 && int64(len(p)) > h.rem {
		p = p[:h.rem]
	}
	n, err := h.conn.Read(p)
	if h.rem > 0 {
		h.rem -= int64(n)
	}
	return n, err
}

// clamp bounds the next head parse to rem bytes; a negative rem lifts the
// bound entirely.
func (h *headerLimitReader) clamp(rem int64) {
	h.rem = rem
}

// deadlineBody re-arms conn's read deadline around every body Read.
type deadlineBody struct {
	io.ReadCloser
	conn net.Conn
}

func (b *deadlineBody) Read(p []byte) (int, error) {
	_ = b.conn.SetReadDeadline(time.Now().Add(idleTimeoutNow()))
	return b.ReadCloser.Read(p)
}

// cappedBody bounds a body of unknown length (h1 chunked): reads beyond
// rem fail with errBodyTooLarge so the forward aborts instead of
// buffering without bound.
type cappedBody struct {
	io.ReadCloser
	rem int64
}

var errBodyTooLarge = errors.New("mitm: request body too large")

func (b *cappedBody) Read(p []byte) (int, error) {
	if b.rem <= 0 {
		return 0, errBodyTooLarge
	}
	if int64(len(p)) > b.rem {
		p = p[:b.rem]
	}
	n, err := b.ReadCloser.Read(p)
	b.rem -= int64(n)
	return n, err
}

// WriteResponse streams resp to the client. HTTP/1.1 writes directly; HTTP/2
// submits to the h2 engine on the stream the request arrived on. Writes are
// bounded by an idle-based deadline that is armed per operation, so a
// non-reading client cannot pin a goroutine forever.
func (l *clientLeg) WriteResponse(resp *http.Response) error {
	if l.protocol == "h2" {
		return l.h2.SubmitResponse(resp)
	}
	if err := l.conn.SetWriteDeadline(time.Now().Add(idleTimeoutNow())); err != nil {
		return err
	}
	defer l.conn.SetWriteDeadline(time.Time{})
	return resp.Write(l.conn)
}

// FlushBody copies the body to the client and returns whether the connection
// can serve another request on it. The copy runs with a refreshed write
// deadline per buffer chunk: long streams are not truncated by a fixed cap,
// but a stalled client still times out within one idle window.
func (l *clientLeg) FlushBody(resp *http.Response) bool {
	if l.protocol == "h2" {
		return l.h2.FinishBody(resp)
	}
	buf := bufPool.Get().(*[]byte)
	defer bufPool.Put(buf)
	for {
		if err := l.conn.SetWriteDeadline(time.Now().Add(idleTimeoutNow())); err != nil {
			return false
		}
		n, readErr := resp.Body.Read(*buf)
		if n > 0 {
			if _, werr := l.conn.Write((*buf)[:n]); werr != nil {
				return false
			}
		}
		if readErr != nil {
			// The client leg stays open only when the CLIENT asked to
			// close (reqClose), never on resp.Close: the upstream
			// response carries Connection:close because we force it
			// upstream, which says nothing about the client leg.
			return readErr == io.EOF && !l.reqClose
		}
	}
}

var bufPool = sync.Pool{New: func() any {
	b := make([]byte, 32*1024)
	return &b
}}

// WriteSimpleResponse answers with a status, empty body, correct framing.
func (l *clientLeg) WriteSimpleResponse(status int) error {
	resp := &http.Response{
		StatusCode:    status,
		Status:        strconv.Itoa(status) + " " + http.StatusText(status),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(bytes.NewReader(nil)),
		ContentLength: 0,
	}
	return l.WriteResponse(resp)
}

// WriteRedirectResponse answers with a 302 to location.
func (l *clientLeg) WriteRedirectResponse(location string) error {
	resp := &http.Response{
		StatusCode:    http.StatusFound,
		Status:        "302 Found",
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(bytes.NewReader(nil)),
		ContentLength: 0,
	}
	resp.Header.Set("Location", location)
	return l.WriteResponse(resp)
}

// ---- upstream leg ----

type upstreamConn interface {
	RoundTrip(ctx context.Context, req *http.Request) (*http.Response, error)
	Close()
}

type http1Upstream struct {
	conn net.Conn
	br   *bufio.Reader
	// hdrLimit caps response heads read off this upstream.
	hdrLimit headerLimitReader
}

func newHTTP1Upstream(conn net.Conn) *http1Upstream {
	u := &http1Upstream{conn: conn}
	u.hdrLimit.conn = conn
	u.br = bufio.NewReader(&u.hdrLimit)
	return u
}

func (u *http1Upstream) RoundTrip(ctx context.Context, req *http.Request) (*http.Response, error) {
	_ = ctx
	// Absolute-form request line for proxied requests; strip hop-by-hop
	// headers on the way out.
	out := req.Clone(ctx)
	out.RequestURI = "" // net/http requires this for client writes
	if out.URL.Host == "" {
		out.URL.Host = req.Header.Get("Host")
	}
	removeHopByHopHeaders(out.Header)
	out.Header.Set("Connection", "close")
	// Fresh deadlines per operation: the write and the response-head read
	// each get a full idle window, so a response arriving after a long
	// request-body upload is not killed by a deadline set before it.
	_ = u.conn.SetDeadline(time.Now().Add(idleTimeoutNow()))
	if err := out.Write(u.conn); err != nil {
		return nil, err
	}
	_ = u.conn.SetReadDeadline(time.Now().Add(idleTimeoutNow()))
	resp, err := readResponseLimited(u.br, out, &u.hdrLimit, maxHeaderBytes)
	if err != nil {
		return nil, err
	}
	removeHopByHopHeaders(resp.Header)
	// Wrap the body so every chunk read re-arms the read deadline: a
	// streaming body slower than the idle window (but still flowing)
	// completes; a truly stalled upstream times out within one window.
	resp.Body = &upstreamDeadlineBody{r: resp.Body, conn: u.conn, closing: resp.Body}
	return resp, nil
}

// readResponseLimited parses one upstream response head under a byte cap:
// a status line+headers block larger than maxRem fails with
// errHeaderTooLarge instead of buffering attacker-controlled memory.
// Bytes already buffered in br bypass the cap by at most one bufio size,
// which is fine for a bound that exists to stop unbounded growth.
func readResponseLimited(br *bufio.Reader, req *http.Request, lim *headerLimitReader, maxRem int) (*http.Response, error) {
	if lim != nil {
		lim.clamp(int64(maxRem) - int64(br.Buffered()))
	}
	resp, err := http.ReadResponse(br, req)
	if lim != nil {
		lim.clamp(-1) // unlimited until the next RoundTrip
	}
	return resp, err
}

// upstreamDeadlineBody re-arms the upstream conn's read deadline around
// every body chunk. Its Close is idempotent and only closes the SOCKET
// half we own: the http.Response.Write path closes the body itself after
// streaming (transferWriter.writeBody), so a plain embed would make the
// later FlushBody read fail with "invalid Read on closed Body" and kill
// otherwise-healthy keep-alive legs. The underlying body therefore uses
// a no-op closer at this layer; proxyPass closes it explicitly after
// FlushBody.
type upstreamDeadlineBody struct {
	r       io.Reader
	conn    net.Conn
	closing io.Closer
}

func (b *upstreamDeadlineBody) Read(p []byte) (int, error) {
	_ = b.conn.SetReadDeadline(time.Now().Add(idleTimeoutNow()))
	return b.r.Read(p)
}

func (b *upstreamDeadlineBody) Close() error { return nil }

func (u *http1Upstream) Close() { _ = u.conn.Close() }

var hopByHopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

func removeHopByHopHeaders(h http.Header) {
	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
}

// newHTTP2Upstream speaks h2 to the upstream (client side).
func newHTTP2Upstream(conn net.Conn) (upstreamConn, error) {
	return newH2ClientConn(conn)
}
