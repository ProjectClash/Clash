package route

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/metacubex/chi"
	"github.com/metacubex/http"
	"github.com/ProjectClash/Clash/component/ca"
)


func resetControlPlaneForTest(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		ReCreateServer(&Config{})
		RevokeNetworkStreams()
	})
}

func shortSocketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "rt")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return filepath.Join(dir, "c.sock")
}

func unixClient(socket string) *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", socket)
		},
		MaxIdleConnsPerHost: 1,
	}}
}

func getStatus(t *testing.T, client *http.Client, url, secret string) int {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if secret != "" {
		request.Header.Set("Authorization", "Bearer "+secret)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	return response.StatusCode
}

func TestReCreateNetworkServersLeavesTheUnixListenerAlone(t *testing.T) {
	resetControlPlaneForTest(t)
	socket := shortSocketPath(t)
	ReCreateServer(&Config{UnixAddr: socket, Addr: "127.0.0.1:0", Secret: "one"})
	if err := os.Chmod(socket, 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(socket)
	if err != nil {
		t.Fatal(err)
	}
	client := unixClient(socket)
	if code := getStatus(t, client, "http://unix/version", ""); code != http.StatusOK {
		t.Fatalf("unix /version = %d before the swap", code)
	}

	status := ReCreateNetworkServers(&Config{Addr: "127.0.0.1:0", Secret: "two"}, true)
	if status.HTTP.Err != nil {
		t.Fatalf("new TCP listener failed: %v", status.HTTP.Err)
	}

	after, err := os.Stat(socket)
	if err != nil {
		t.Fatalf("the App Group socket is gone after a TCP/TLS swap: %v", err)
	}
	if after.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v after the swap, want 0600: upstream's startUnix widens it to 0666", after.Mode().Perm())
	}
	if !os.SameFile(before, after) {
		t.Fatal("the App Group socket was re-created; the App's connection must not be cut by a setting change")
	}
	if code := getStatus(t, client, "http://unix/version", ""); code != http.StatusOK {
		t.Fatalf("unix /version = %d after the swap", code)
	}
	if code := getStatus(t, http.DefaultClient, "http://"+status.HTTP.Address+"/version", "two"); code != http.StatusOK {
		t.Fatalf("new TCP listener with the new secret = %d", code)
	}
}

func TestReCreateNetworkServersReportsTheRealListenError(t *testing.T) {
	resetControlPlaneForTest(t)
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()

	status := ReCreateNetworkServers(&Config{Addr: occupied.Addr().String(), Secret: "s"}, false)
	if status.HTTP.Err == nil || !strings.Contains(status.HTTP.Err.Error(), "address already in use") {
		t.Fatalf("HTTP error = %v, want the bind error itself (a dial to the port would have succeeded)", status.HTTP.Err)
	}
	if status.HTTP.Address != occupied.Addr().String() {
		t.Fatalf("HTTP address = %q, want the configured %q", status.HTTP.Address, occupied.Addr().String())
	}
	if got := CurrentNetworkStatus(); got.HTTP.Err == nil {
		t.Fatal("CurrentNetworkStatus lost the error")
	}

	status = ReCreateNetworkServers(&Config{TLSAddr: "127.0.0.1:0", Secret: "s", Certificate: "not a certificate", PrivateKey: "x"}, false)
	if status.TLS.Err == nil {
		t.Fatal("an unusable certificate must be reported as the TLS listener's error")
	}
	if status.HTTP.Err != nil || status.HTTP.Address != "" {
		t.Fatalf("an empty Addr is no listener and no error, got %+v", status.HTTP)
	}
}

func openWebSocket(t *testing.T, address, path, secret string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))
	fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\nAuthorization: Bearer %s\r\n\r\n", path, address, key, secret)
	reader := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	line, err := reader.ReadString('\n')
	if err != nil || !strings.Contains(line, "101") {
		t.Fatalf("websocket upgrade: %q %v", line, err)
	}
	for {
		header, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if header == "\r\n" {
			break
		}
	}
	return conn, reader
}

func TestRevokingClosesStreamsTheReplacedListenerAccepted(t *testing.T) {
	resetControlPlaneForTest(t)
	status := ReCreateNetworkServers(&Config{Addr: "127.0.0.1:0", Secret: "old"}, true)
	conn, reader := openWebSocket(t, status.HTTP.Address, "/traffic", "old")
	defer conn.Close()
	if _, err := reader.ReadByte(); err != nil {
		t.Fatalf("no traffic frame before the revoke: %v", err)
	}

	ReCreateNetworkServers(&Config{Addr: "127.0.0.1:0", Secret: "new"}, true)

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err := io.Copy(io.Discard, reader)
	if err != nil && !isConnectionEnd(err) {
		t.Fatalf("the hijacked stream did not end after the revoke: %v", err)
	}
}

func TestReplacingWithoutRevokeKeepsUpstreamStreamBehaviour(t *testing.T) {
	resetControlPlaneForTest(t)
	status := ReCreateNetworkServers(&Config{Addr: "127.0.0.1:0", Secret: "same"}, false)
	conn, reader := openWebSocket(t, status.HTTP.Address, "/traffic", "same")
	defer conn.Close()
	if _, err := reader.ReadByte(); err != nil {
		t.Fatal(err)
	}
	ReCreateServer(&Config{Addr: "127.0.0.1:0", Secret: "same"})
	_ = conn.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
	buffer := make([]byte, 64)
	if _, err := reader.Read(buffer); err != nil {
		t.Fatalf("a reload without a revoke cut a hijacked stream, which upstream never does: %v", err)
	}
}

func isConnectionEnd(err error) bool {
	if err == io.EOF {
		return true
	}
	var netErr net.Error
	if ok := asNetError(err, &netErr); ok && netErr.Timeout() {
		return false
	}
	return strings.Contains(err.Error(), "use of closed network connection") ||
		strings.Contains(err.Error(), "connection reset") || isErrno(err, syscall.ECONNRESET)
}

func asNetError(err error, target *net.Error) bool {
	ne, ok := err.(net.Error)
	if ok {
		*target = ne
	}
	return ok
}

func isErrno(err error, errno syscall.Errno) bool {
	for err != nil {
		if e, ok := err.(syscall.Errno); ok {
			return e == errno
		}
		unwrapper, ok := err.(interface{ Unwrap() error })
		if !ok {
			return false
		}
		err = unwrapper.Unwrap()
	}
	return false
}

func TestRequestsKnowWhetherAManagedListenerCarriedThem(t *testing.T) {
	resetControlPlaneForTest(t)
	previous := externalRouters
	t.Cleanup(func() { externalRouters = previous })
	Register(func(r chi.Router) {
		r.Get("/clash-test/managed", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, RequestFromManagedListener(r))
		})
	})
	body := func(client *http.Client, url string) string {
		t.Helper()
		request, _ := http.NewRequest(http.MethodGet, url, nil)
		request.Header.Set("Authorization", "Bearer s")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		data, _ := io.ReadAll(response.Body)
		return string(data)
	}

	socket := shortSocketPath(t)
	ReCreateServer(&Config{UnixAddr: socket, Addr: "127.0.0.1:0", Secret: "s"})
	if got := body(http.DefaultClient, "http://"+CurrentNetworkStatus().HTTP.Address+"/clash-test/managed"); got != "false" {
		t.Fatalf("the configuration's own listener answered managed=%s", got)
	}
	status := ReCreateNetworkServers(&Config{Addr: "127.0.0.1:0", Secret: "s", Managed: true}, true)
	if got := body(http.DefaultClient, "http://"+status.HTTP.Address+"/clash-test/managed"); got != "true" {
		t.Fatalf("the managed listener answered managed=%s", got)
	}
	if got := body(unixClient(socket), "http://unix/clash-test/managed"); got != "false" {
		t.Fatalf("the App Group socket answered managed=%s", got)
	}
}

func TestAManagedListenerServesNoExternalUI(t *testing.T) {
	resetControlPlaneForTest(t)
	previous := uiPath
	uiPath = t.TempDir()
	t.Cleanup(func() { uiPath = previous })
	if err := os.WriteFile(filepath.Join(uiPath, "index.html"), []byte("ui"), 0o644); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

	status := ReCreateNetworkServers(&Config{Addr: "127.0.0.1:0", Secret: "s"}, true)
	if code := getStatus(t, client, "http://"+status.HTTP.Address+"/ui/", ""); code != http.StatusOK {
		t.Fatalf("the configuration's own controller serves /ui as upstream does, got %d", code)
	}
	status = ReCreateNetworkServers(&Config{Addr: "127.0.0.1:0", Secret: "s", Managed: true}, true)
	if code := getStatus(t, client, "http://"+status.HTTP.Address+"/ui/", ""); code != http.StatusNotFound {
		t.Fatalf("a managed listener served /ui (%d); it sits outside the authenticated group", code)
	}
}

func TestAcceptFilterDropsSourcesItRefuses(t *testing.T) {
	resetControlPlaneForTest(t)
	status := ReCreateNetworkServers(&Config{Addr: "127.0.0.1:0", Secret: "s", AcceptFilter: func(net.Addr) bool { return false }}, true)
	client := &http.Client{Timeout: 2 * time.Second}
	request, _ := http.NewRequest(http.MethodGet, "http://"+status.HTTP.Address+"/version", nil)
	request.Header.Set("Authorization", "Bearer s")
	if response, err := client.Do(request); err == nil {
		_ = response.Body.Close()
		t.Fatalf("a refused source got an answer (%d)", response.StatusCode)
	}
	status = ReCreateNetworkServers(&Config{Addr: "127.0.0.1:0", Secret: "s", AcceptFilter: func(net.Addr) bool { return true }}, true)
	if code := getStatus(t, http.DefaultClient, "http://"+status.HTTP.Address+"/version", "s"); code != http.StatusOK {
		t.Fatalf("an admitted source got %d", code)
	}
}

func trackedNetworkConnCount() int {
	networkConns.mu.Lock()
	defer networkConns.mu.Unlock()
	return len(networkConns.conns)
}

func TestAFinishedStreamLeavesNoConnectionBehind(t *testing.T) {
	resetControlPlaneForTest(t)
	status := ReCreateNetworkServers(&Config{Addr: "127.0.0.1:0", Secret: "s"}, true)
	before := trackedNetworkConnCount()
	conn, reader := openWebSocket(t, status.HTTP.Address, "/traffic", "s")
	if _, err := reader.ReadByte(); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	deadline := time.Now().Add(4 * time.Second)
	for trackedNetworkConnCount() > before {
		if time.Now().After(deadline) {
			t.Fatalf("%d connections still tracked after the client left (baseline %d)", trackedNetworkConnCount(), before)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestReCreateServerKeepsAnUnchangedUnixListenerAndSwapsItsRouter(t *testing.T) {
	resetControlPlaneForTest(t)
	socket := shortSocketPath(t)
	ReCreateServer(&Config{UnixAddr: socket})
	if err := os.Chmod(socket, 0o600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(socket)
	client := unixClient(socket)
	if code := getStatus(t, client, "http://unix/debug/pprof/", ""); code != http.StatusNotFound {
		t.Fatalf("/debug before the reload: %d, want 404", code)
	}

	ReCreateServer(&Config{UnixAddr: socket, IsDebug: true})
	after, err := os.Stat(socket)
	if err != nil || !os.SameFile(before, after) || after.Mode().Perm() != 0o600 {
		t.Fatalf("the unchanged socket was re-created or widened: %v %v", err, after)
	}
	if code := getStatus(t, client, "http://unix/debug/pprof/", ""); code != http.StatusOK {
		t.Fatalf("/debug after a reload that turned debug on: %d, want the new router", code)
	}

	_ = os.Remove(socket)
	ReCreateServer(&Config{UnixAddr: socket})
	if _, err := os.Stat(socket); err != nil {
		t.Fatalf("a removed socket was not re-created: %v", err)
	}
	ReCreateServer(&Config{})
	if _, err := net.Dial("unix", socket); err == nil {
		t.Fatal("the socket still answers after the control plane was emptied")
	}
}

type blockingListener struct {
	conns  chan net.Conn
	closed chan struct{}
}

func (l *blockingListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *blockingListener) Close() error   { close(l.closed); return nil }
func (l *blockingListener) Addr() net.Addr { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)} }

func TestAnAcceptThatLostTheRaceWithARevokeIsClosedOnArrival(t *testing.T) {
	raw := &blockingListener{conns: make(chan net.Conn), closed: make(chan struct{})}
	listener := wrapNetworkListener(raw, &Config{})
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err == nil {
			accepted <- conn
		}
	}()

	RevokeNetworkStreams()
	server, client := net.Pipe()
	raw.conns <- server
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := client.Read(make([]byte, 1)); err == nil || isTimeout(err) {
		t.Fatalf("the late connection was not closed on arrival: %v", err)
	}
	_ = raw.Close()
	select {
	case conn := <-accepted:
		t.Fatalf("a connection from before the revoke was handed to the server: %v", conn.RemoteAddr())
	case <-time.After(200 * time.Millisecond):
	}
	if trackedNetworkConnCount() != 0 {
		t.Fatalf("%d connection(s) tracked", trackedNetworkConnCount())
	}
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}

func TestTheAcceptFilterGuardsTheTLSListener(t *testing.T) {
	resetControlPlaneForTest(t)
	certificate, key, _, err := ca.NewRandomTLSKeyPair(ca.KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	refuse := &Config{TLSAddr: "127.0.0.1:0", Secret: "s", Certificate: certificate, PrivateKey: key,
		AcceptFilter: func(net.Addr) bool { return false }}
	status := ReCreateNetworkServers(refuse, true)
	if status.TLS.Err != nil {
		t.Fatal(status.TLS.Err)
	}
	dialer := &net.Dialer{Timeout: 2 * time.Second}
	if conn, err := tls.DialWithDialer(dialer, "tcp", status.TLS.Address, &tls.Config{InsecureSkipVerify: true}); err == nil {
		_ = conn.Close()
		t.Fatal("a refused source completed a TLS handshake")
	}
	admit := *refuse
	admit.AcceptFilter = func(net.Addr) bool { return true }
	status = ReCreateNetworkServers(&admit, true)
	conn, err := tls.DialWithDialer(dialer, "tcp", status.TLS.Address, &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("an admitted source: %v", err)
	}
	_ = conn.Close()
}
