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
	"net/url"
	"strconv"
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

	if proto == "http" {
		// Plain HTTP: no handshake to answer; serve the reverse proxy
		// directly on the cleartext conn.
		host := metadata.Host
		if host == "" {
			return false
		}
		d.serveCleartext(ctx, conn, config, host, dial, uint16(metadata.DstPort))
		return true
	}
	// HTTPS: peek the ClientHello to learn the SNI without consuming it.
	host, err := peekClientHelloSNI(conn)
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
	handshakeCtx, cancel := context.WithTimeout(ctx, innerHandshakeTimeout)
	defer cancel()
	if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
		// Owned and untrustworthy from here on (the client saw our leaf):
		// close rather than forward.
		log.Debugln("[MITM] inner handshake with %s failed: %v", host, err)
		return true
	}

	leg := newClientLeg(tlsConn, tlsConn.ConnectionState().NegotiatedProtocol)
	defer leg.Close()
	d.serve(ctx, leg, config, host, "https", dial, uint16(metadata.DstPort))
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
	if metadata.DNSMode == C.DNSMapping && metadata.Host != "" && config.MatchPort("http", dstPort) && !config.MatchPort("https", dstPort) {
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
			return // client closed, idle timeout, or garbage: done
		}
		policy, ok := config.TrafficMatch(host, scheme, dstPort)
		if !ok {
			if !d.proxyPass(ctx, leg, req, host, dial, dstPort, "") {
				return
			}
			continue
		}
		if policy.Reject != 0 {
			_ = leg.WriteSimpleResponse(policy.Reject)
			return
		}
		if policy.Redirect != "" {
			location := composeRedirect(policy.Redirect, req.URL.Path, req.URL.RawQuery)
			_ = leg.WriteRedirectResponse(location)
			return
		}
		if !d.rewriteAndProxy(ctx, leg, req, host, dial, dstPort, &policy) {
			return
		}
	}
}

// rewriteAndProxy applies header rules then forwards the request upstream,
// streaming the response back with hop-by-hop filtering on both sides.
func (d *Dispatcher) rewriteAndProxy(ctx context.Context, leg *clientLeg, req *http.Request, host string, dial DialFunc, dstPort uint16, policy *RewritePolicy) bool {
	applyHeaderRules(req, policy.HeaderRules)
	return d.proxyPass(ctx, leg, req, host, dial, dstPort, "")
}

// proxyPass dials the upstream for one request, writes it, and streams the
// response back. upstreamHost is empty for direct forwards; policies that
// rewrite to another host pass the rewritten host so the dial uses it.
func (d *Dispatcher) proxyPass(ctx context.Context, leg *clientLeg, req *http.Request, host string, dial DialFunc, dstPort uint16, upstreamHost string) bool {
	dialHost := upstreamHost
	if dialHost == "" {
		dialHost = host
	}
	upstream, err := d.dialUpstream(ctx, dial, dialHost, dstPort)
	if err != nil {
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
	defer resp.Body.Close()
	if err := leg.WriteResponse(resp); err != nil {
		return false
	}
	if !leg.FlushBody(resp) {
		return false
	}
	return true
}

// dialUpstream opens the outer leg through the tunnel-provided dial func
// (proxy chain + core DNS), then layers TLS for https ports. Dialing happens
// per request burst — Anywhere's deferred-dial: the upstream is not
// contacted until a policy has decided the request needs one.
func (d *Dispatcher) dialUpstream(ctx context.Context, dial DialFunc, host string, port uint16) (upstreamConn, error) {
	if port == 0 {
		port = 443
	}
	if dial == nil {
		return nil, errors.New("mitm: no upstream dial func")
	}
	raw, err := dial(ctx, host, port)
	if err != nil {
		return nil, fmt.Errorf("dial upstream %s:%d: %w", host, port, err)
	}
	if port == 80 {
		return newHTTP1Upstream(raw), nil
	}
	// Verification uses the config's upstream root pool when provided (the
	// config layer seeds it with tls.custom-trust-cert); nil means the
	// system pool, which is the safe default.
	tlsConn := tls.Client(raw, &tls.Config{
		ServerName: host,
		MinVersion: tls.VersionTLS12,
		RootCAs:    d.config.Load().UpstreamRoots,
	})
	hsCtx, cancel := context.WithTimeout(ctx, outerHandshakeTimeout)
	defer cancel()
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

func applyHeaderRules(req *http.Request, rules []HeaderRule) {
	for _, rule := range rules {
		switch rule.Action {
		case "set":
			req.Header.Set(rule.Name, joinPrefix(rule.ValuePrefix, rule.Value))
		case "add":
			req.Header.Add(rule.Name, joinPrefix(rule.ValuePrefix, rule.Value))
		case "remove":
			req.Header.Del(rule.Name)
		}
	}
}

func joinPrefix(prefix, value string) string {
	if prefix == "" {
		return value
	}
	return prefix + value
}

// composeRedirect builds a Location from a policy target. Host-only targets
// keep the request path and query; full URLs replace everything.
func composeRedirect(target, path, query string) string {
	u, err := url.Parse(target)
	if err != nil {
		return target
	}
	if u.Host == "" {
		// Bare-host policy: preserve the incoming path and query.
		u.Path = path
		u.RawQuery = query
		return u.String()
	}
	return target
}

const (
	innerHandshakeTimeout = 10 * time.Second
	outerHandshakeTimeout = 10 * time.Second
	idleTimeout           = 120 * time.Second
)

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

	h2Once sync.Once
	h2     *h2Server
	closed atomic.Bool
}

func newClientLeg(conn net.Conn, negotiated string) *clientLeg {
	return &clientLeg{conn: conn, br: bufio.NewReader(conn), protocol: negotiated}
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
func (l *clientLeg) ReadRequest() (*http.Request, error) {
	if l.protocol == "h2" {
		l.h2Once.Do(func() {
			l.h2 = newH2Server(l.conn, l.br)
		})
		return l.h2.NextRequest()
	}
	_ = l.conn.SetReadDeadline(time.Now().Add(idleTimeout))
	defer l.conn.SetReadDeadline(time.Time{})
	return http.ReadRequest(l.br)
}

// WriteResponse streams resp to the client. HTTP/1.1 writes directly; HTTP/2
// submits to the h2 engine on the stream the request arrived on.
func (l *clientLeg) WriteResponse(resp *http.Response) error {
	if l.protocol == "h2" {
		return l.h2.SubmitResponse(resp)
	}
	return resp.Write(l.conn)
}

// FlushBody copies the body to the client and returns whether the connection
// can serve another request on it.
func (l *clientLeg) FlushBody(resp *http.Response) bool {
	if l.protocol == "h2" {
		return l.h2.FinishBody(resp)
	}
	buf := bufPool.Get().(*[]byte)
	defer bufPool.Put(buf)
	_, copyErr := io.CopyBuffer(struct{ io.Writer }{l.conn}, resp.Body, *buf)
	keepAlive := copyErr == nil && !resp.Close
	return keepAlive
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
}

func newHTTP1Upstream(conn net.Conn) *http1Upstream {
	return &http1Upstream{conn: conn, br: bufio.NewReader(conn)}
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
	_ = u.conn.SetDeadline(time.Now().Add(idleTimeout))
	if err := out.Write(u.conn); err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(u.br, out)
	if err != nil {
		return nil, err
	}
	removeHopByHopHeaders(resp.Header)
	return resp, nil
}

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

// h2HostAuthority returns the authority a request targets, for logging.
func h2HostAuthority(req *http.Request) string {
	if req.Host != "" {
		return req.Host
	}
	return req.URL.Host
}
