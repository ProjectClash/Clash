package outbound

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/metacubex/tls"
)

func TestNewHttpArmsSessionCache(t *testing.T) {
	h, err := NewHttp(HttpOption{Name: "tls", Server: "127.0.0.1", Port: 8080, TLS: true, SkipCertVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	if h.tlsConfig == nil || h.tlsConfig.ClientSessionCache == nil {
		t.Fatal("a TLS HTTP proxy must arm a ClientSessionCache")
	}
	plain, err := NewHttp(HttpOption{Name: "plain", Server: "127.0.0.1", Port: 8080})
	if err != nil {
		t.Fatal(err)
	}
	if plain.tlsConfig != nil {
		t.Fatal("a plaintext HTTP proxy must not build a TLS config")
	}
}

func TestNewHttpTLSConfigResumes(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "clash.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"clash.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	serverCfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: priv}},
		MaxVersion:   tls.VersionTLS12,
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverCfg)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				_, _ = io.Copy(io.Discard, c)
				_ = c.Close()
			}(conn)
		}
	}()

	_, portStr, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatal(err)
	}
	h, err := NewHttp(HttpOption{Name: "tls", Server: "127.0.0.1", Port: port, TLS: true, SkipCertVerify: true, SNI: "clash.test"})
	if err != nil {
		t.Fatal(err)
	}
	clientCfg := h.tlsConfig.Clone()
	clientCfg.MaxVersion = tls.VersionTLS12

	dialResumed := func() bool {
		conn, err := tls.Dial("tcp", listener.Addr().String(), clientCfg)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		return conn.ConnectionState().DidResume
	}
	if dialResumed() {
		t.Fatal("first handshake must be full, not resumed")
	}
	if !dialResumed() {
		t.Fatal("second handshake must resume via the proxy's session cache")
	}
}
