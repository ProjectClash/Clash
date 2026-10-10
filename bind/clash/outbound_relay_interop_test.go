package clash

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	N "github.com/ProjectClash/Clash/common/net"
	C "github.com/ProjectClash/Clash/constant"
)

func testControlledRelayHTTPS(t *testing.T, proxy C.Proxy) {
	t.Helper()
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(w, r.Body); err != nil {
			t.Errorf("HTTPS echo: %v", err)
		}
	}))
	defer target.Close()
	roots := x509.NewCertPool()
	roots.AddCert(target.Certificate())
	addr := target.Listener.Addr().(*net.TCPAddr).AddrPort()
	var relays sync.WaitGroup
	transport := &http.Transport{
		TLSClientConfig:   &tls.Config{RootCAs: roots},
		DisableKeepAlives: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			remote, err := proxy.DialContext(ctx, &C.Metadata{NetWork: C.TCP, Type: C.TUN, DstIP: addr.Addr(), DstPort: addr.Port()})
			if err != nil {
				return nil, err
			}
			if N.NeedHandshake(remote) {
				if _, err = remote.Write(nil); err != nil {
					remote.Close()
					return nil, err
				}
			}
			client, relay := net.Pipe()
			deadline := time.Now().Add(10 * time.Second)
			_ = remote.SetDeadline(deadline)
			_ = relay.SetDeadline(deadline)
			relays.Add(1)
			go func() { defer relays.Done(); N.Relay(relay, remote) }()
			return client, nil
		},
	}
	defer func() {
		transport.CloseIdleConnections()
		done := make(chan struct{})
		go func() { relays.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(12 * time.Second):
			t.Error("Relay did not finish after HTTPS connection close")
		}
	}()
	client := &http.Client{Transport: transport, Timeout: 8 * time.Second}
	for _, size := range []int{1, 2047, 2048, 2049, 4064, 16384, 65536} {
		t.Run(fmt.Sprintf("RelayHTTPS%d", size), func(t *testing.T) {
			payload := make([]byte, size)
			for i := range payload {
				payload[i] = byte(i*37 + i>>8)
			}
			response, err := client.Post(target.URL, "application/octet-stream", bytes.NewReader(payload))
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			got, err := io.ReadAll(response.Body)
			if err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != http.StatusOK || !bytes.Equal(got, payload) {
				t.Fatalf("HTTPS status=%d body=%d; want 200 and %d intact bytes", response.StatusCode, len(got), len(payload))
			}
		})
	}
}
