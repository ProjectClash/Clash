package route

import (
	"bufio"
	"context"
	"net"
	"os"
	"sync"
	"sync/atomic"

	"github.com/metacubex/http"
	C "github.com/ProjectClash/Clash/constant"
)


type ListenerStatus struct {
	Address string
	Err     error
}

type NetworkStatus struct {
	HTTP ListenerStatus
	TLS  ListenerStatus
}

var (
	networkStatusMu sync.Mutex
	networkStatus   NetworkStatus
)

func recordHTTPStatus(status ListenerStatus) {
	networkStatusMu.Lock()
	networkStatus.HTTP = status
	networkStatusMu.Unlock()
}

func recordTLSStatus(status ListenerStatus) {
	networkStatusMu.Lock()
	networkStatus.TLS = status
	networkStatusMu.Unlock()
}

func CurrentNetworkStatus() NetworkStatus {
	networkStatusMu.Lock()
	defer networkStatusMu.Unlock()
	return networkStatus
}

func ReCreateNetworkServers(cfg *Config, revoke bool) NetworkStatus {
	serverMu.Lock()
	defer serverMu.Unlock()
	if revoke {
		start(&Config{})
		startTLS(&Config{})
		RevokeNetworkStreams()
	}
	start(cfg)
	startTLS(cfg)
	return CurrentNetworkStatus()
}

type trackedConnSet struct {
	mu    sync.Mutex
	conns map[*trackedConn]struct{}
	epoch uint64
}

var networkConns = trackedConnSet{conns: map[*trackedConn]struct{}{}}

func RevokeNetworkStreams() {
	networkConns.mu.Lock()
	networkConns.epoch++
	conns := make([]*trackedConn, 0, len(networkConns.conns))
	for conn := range networkConns.conns {
		conns = append(conns, conn)
	}
	networkConns.mu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
}

type trackedConn struct {
	net.Conn
	once sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(func() {
		networkConns.mu.Lock()
		delete(networkConns.conns, c)
		networkConns.mu.Unlock()
	})
	return c.Conn.Close()
}

type networkListener struct {
	net.Listener
	accept func(net.Addr) bool
	epoch  uint64
}

func (l *networkListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.accept != nil && !l.accept(conn.RemoteAddr()) {
			_ = conn.Close()
			continue
		}
		tracked := &trackedConn{Conn: conn}
		networkConns.mu.Lock()
		if networkConns.epoch != l.epoch {
			networkConns.mu.Unlock()
			_ = conn.Close()
			continue
		}
		networkConns.conns[tracked] = struct{}{}
		networkConns.mu.Unlock()
		return tracked, nil
	}
}

func wrapNetworkListener(l net.Listener, cfg *Config) net.Listener {
	networkConns.mu.Lock()
	defer networkConns.mu.Unlock()
	return &networkListener{Listener: l, accept: cfg.AcceptFilter, epoch: networkConns.epoch}
}

type managedListenerKey struct{}

func networkConnContext(managed bool) func(context.Context, net.Conn) context.Context {
	return func(ctx context.Context, _ net.Conn) context.Context {
		return context.WithValue(ctx, managedListenerKey{}, managed)
	}
}

func RequestFromManagedListener(r *http.Request) bool {
	managed, _ := r.Context().Value(managedListenerKey{}).(bool)
	return managed
}

func closeHijackedOnReturn(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recorder := &hijackRecorder{ResponseWriter: w}
		defer func() {
			if recorder.conn != nil {
				_ = recorder.conn.Close()
			}
		}()
		next.ServeHTTP(recorder, r)
	})
}

type hijackRecorder struct {
	http.ResponseWriter
	conn net.Conn
}

func (h *hijackRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	conn, rw, err := http.NewResponseController(h.ResponseWriter).Hijack()
	if err == nil {
		h.conn = conn
	}
	return conn, rw, err
}

func (h *hijackRecorder) Flush() { _ = http.NewResponseController(h.ResponseWriter).Flush() }

func (h *hijackRecorder) Unwrap() http.ResponseWriter { return h.ResponseWriter }

var (
	unixAddress    string
	unixSocketFile os.FileInfo
	unixHandler    *swappableHandler
	unixServing *atomic.Bool
)

type swappableHandler struct {
	handler atomic.Pointer[http.Handler]
}

func newSwappableHandler(handler http.Handler) *swappableHandler {
	swappable := &swappableHandler{}
	swappable.handler.Store(&handler)
	return swappable
}

func (s *swappableHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	(*s.handler.Load()).ServeHTTP(w, r)
}

func keepUnixListener(cfg *Config) bool {
	if unixListener == nil || unixServer == nil || unixHandler == nil || cfg.UnixAddr == "" ||
		unixServing == nil || !unixServing.Load() {
		return false
	}
	addr := C.Path.Resolve(cfg.UnixAddr)
	if addr != unixAddress {
		return false
	}
	info, err := os.Lstat(addr)
	if err != nil || info.Mode()&os.ModeSocket == 0 || unixSocketFile == nil || !os.SameFile(info, unixSocketFile) {
		return false
	}
	handler := http.Handler(router(cfg.IsDebug, "", cfg.DohServer, cfg.Cors))
	unixHandler.handler.Store(&handler)
	return true
}
