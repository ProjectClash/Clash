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


func TestNewSocks5ArmsSessionCache(t *testing.T) {
	proxy, err := NewSocks5(Socks5Option{
		Name: "tls", Server: "127.0.0.1", Port: 1080, TLS: true, SkipCertVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if proxy.tlsConfig == nil {
		t.Fatal("a TLS SOCKS5 proxy must build a TLS config")
	}
	if proxy.tlsConfig.ClientSessionCache == nil {
		t.Fatal("a TLS SOCKS5 proxy must arm a ClientSessionCache; without one every " +
			"proxied connection pays a full handshake and a certificate verification")
	}

	plain, err := NewSocks5(Socks5Option{Name: "plain", Server: "127.0.0.1", Port: 1080})
	if err != nil {
		t.Fatal(err)
	}
	if plain.tlsConfig != nil {
		t.Fatal("a plaintext SOCKS5 proxy must not build a TLS config")
	}
}

func TestNewSocks5TLSConfigResumes(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "socks5.clash.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"socks5.clash.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		MaxVersion:   tls.VersionTLS12,
	})
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

	_, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}

	proxy, err := NewSocks5(Socks5Option{
		Name: "tls", Server: "127.0.0.1", Port: port, TLS: true, SkipCertVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	verifications := 0
	config := proxy.tlsConfig.Clone()
	config.MaxVersion = tls.VersionTLS12
	config.ServerName = "socks5.clash.test"
	config.VerifyPeerCertificate = func([][]byte, [][]*x509.Certificate) error {
		verifications++
		return nil
	}

	dial := func() bool {
		conn, err := tls.Dial("tcp", listener.Addr().String(), config)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		return conn.ConnectionState().DidResume
	}

	if dial() {
		t.Fatal("the first handshake must be full, not resumed")
	}
	if verifications != 1 {
		t.Fatalf("the first handshake made %d verifications, want 1", verifications)
	}
	for i := 0; i < 5; i++ {
		if !dial() {
			t.Fatalf("dial %d did not resume via the proxy's session cache", i+2)
		}
	}
	if verifications != 1 {
		t.Fatalf("6 dials cost %d certificate verifications, want 1; resumed handshakes do "+
			"not re-send the certificate and must not re-verify it", verifications)
	}
}
