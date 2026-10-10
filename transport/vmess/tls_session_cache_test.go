package vmess

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/component/ech"

	"github.com/metacubex/tls"
)


func TestSessionCacheIsSharedForIdenticalSecurityIdentity(t *testing.T) {
	first := &TLSConfig{Host: "example.com", NextProtos: []string{"h2"}}
	second := &TLSConfig{Host: "example.com", NextProtos: []string{"h2"}}

	if sessionCacheFor(first) != sessionCacheFor(second) {
		t.Fatal("two configs with the same security identity must share one cache, or " +
			"resumption never happens across flows")
	}
}

func TestSessionCacheIsolatesDifferentSecurityIdentities(t *testing.T) {
	baseline := sessionCacheFor(&TLSConfig{Host: "example.com", NextProtos: []string{"h2"}})

	cases := []struct {
		name   string
		config *TLSConfig
		why    string
	}{
		{
			name:   "skip-cert-verify",
			config: &TLSConfig{Host: "example.com", NextProtos: []string{"h2"}, SkipCertVerify: true},
			why:    "sharing lets an unverified session be resumed by a config that should verify",
		},
		{
			name:   "different server name",
			config: &TLSConfig{Host: "other.example.com", NextProtos: []string{"h2"}},
			why:    "a session belongs to the server that issued it",
		},
		{
			name:   "certificate pin",
			config: &TLSConfig{Host: "example.com", NextProtos: []string{"h2"}, FingerPrint: "ab" + repeat("cd", 31)},
			why:    "differently pinned configs must not trade sessions even at the same name",
		},
		{
			name:   "name-cert-verify",
			config: &TLSConfig{Host: "example.com", NextProtos: []string{"h2"}, NameCertVerify: "pinned.example.com"},
			why:    "the verified identity differs, so the session is not interchangeable",
		},
		{
			name:   "different ALPN",
			config: &TLSConfig{Host: "example.com", NextProtos: []string{"http/1.1"}},
			why:    "a resumed session carries its negotiated protocol; mixing ALPN sets can mismatch",
		},
		{
			name:   "no ALPN",
			config: &TLSConfig{Host: "example.com"},
			why:    "absent is not the same as h2",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			cache := sessionCacheFor(testCase.config)
			if cache == nil {
				t.Fatal("every config must still get a cache")
			}
			if cache == baseline {
				t.Fatalf("shares a cache with the baseline: %s", testCase.why)
			}
		})
	}
}

func TestSessionCacheSurvivesRepeatedConfigConstruction(t *testing.T) {
	var first any
	for i := 0; i < 50; i++ {
		cache := sessionCacheFor(&TLSConfig{Host: "steady.example.com", NextProtos: []string{"h2"}})
		if i == 0 {
			first = cache
			continue
		}
		if cache != first {
			t.Fatalf("dial %d got a different cache; a per-flow config must still find the "+
				"long-lived cache for its identity", i)
		}
	}
}

func repeat(unit string, times int) string {
	out := ""
	for i := 0; i < times; i++ {
		out += unit
	}
	return out
}

func TestBucketedCacheActuallyResumes(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "flow.clash.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"flow.clash.test"},
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

	verifications := 0
	resumed := make([]bool, 0, 6)
	for i := 0; i < 6; i++ {
		flowConfig := &TLSConfig{Host: "flow.clash.test", SkipCertVerify: true}
		config, err := flowConfig.ToStdConfig()
		if err != nil {
			t.Fatal(err)
		}
		config.ClientSessionCache = sessionCacheFor(flowConfig)
		config.MaxVersion = tls.VersionTLS12
		config.VerifyPeerCertificate = func([][]byte, [][]*x509.Certificate) error {
			verifications++
			return nil
		}
		conn, err := tls.Dial("tcp", listener.Addr().String(), config)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		resumed = append(resumed, conn.ConnectionState().DidResume)
		_ = conn.Close()
	}

	if resumed[0] {
		t.Fatal("the first flow must be a full handshake")
	}
	for i, didResume := range resumed[1:] {
		if !didResume {
			t.Fatalf("flow %d did not resume; a per-flow config must still find its bucket", i+2)
		}
	}
	if verifications != 1 {
		t.Fatalf("6 flows cost %d certificate verifications, want 1", verifications)
	}
}


func TestToStdConfigDoesNotArmACacheForQUICCallers(t *testing.T) {
	config, err := (&TLSConfig{Host: "quic.clash.test", NextProtos: []string{"h3"}}).ToStdConfig()
	if err != nil {
		t.Fatal(err)
	}
	if config.ClientSessionCache != nil {
		t.Fatal("ToStdConfig armed a session cache; TrustTunnel QUIC and VLESS XHTTP/3 build " +
			"their quic-go TLS config from this and must not get one")
	}
}

func TestSessionCacheBucketsByECHIdentity(t *testing.T) {
	first := &ech.Config{}
	second := &ech.Config{}

	base := sessionCacheIdentity(&TLSConfig{Host: "ech.example.com"})
	withFirst := sessionCacheIdentity(&TLSConfig{Host: "ech.example.com", ECH: first})
	withSecond := sessionCacheIdentity(&TLSConfig{Host: "ech.example.com", ECH: second})

	if withFirst == base {
		t.Fatal("an ECH config must change the bucket identity")
	}
	if withFirst == withSecond {
		t.Fatal("two distinct ECH configs share a bucket identity; presence alone is not enough " +
			"to tell two ECH fronts apart")
	}
}
