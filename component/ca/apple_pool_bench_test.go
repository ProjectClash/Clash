//go:build darwin

package ca

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"testing"
)


func BenchmarkVerifyChainPlatformVerifier(b *testing.B) {
	leaf, intermediates, host := liveChain(b)
	pool, err := x509.SystemCertPool()
	if err != nil {
		b.Fatal(err)
	}
	benchmarkVerify(b, leaf, intermediates, pool, host)
}

func BenchmarkVerifyChainStoreMozilla(b *testing.B) {
	leaf, intermediates, host := liveChain(b)

	prior := SelectedStore()
	b.Cleanup(func() { SetStore(prior) })
	SetStore(StoreMozilla)

	pool := GetCertPool()
	if poolIsSystemMarked(pool) {
		b.Fatal("store mozilla left the pool system-marked, so this would measure the platform " +
			"verifier twice and report a saving that does not exist")
	}
	benchmarkVerify(b, leaf, intermediates, pool, host)
}

func benchmarkVerify(b *testing.B, leaf *x509.Certificate, intermediates *x509.CertPool, roots *x509.CertPool, host string) {
	b.Helper()
	options := x509.VerifyOptions{DNSName: host, Intermediates: intermediates, Roots: roots}
	if _, err := leaf.Verify(options); err != nil {
		b.Fatalf("the chain must verify before it can be timed: %v", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := leaf.Verify(options); err != nil {
			b.Fatal(err)
		}
	}
}

func liveChain(b *testing.B) (*x509.Certificate, *x509.CertPool, string) {
	b.Helper()
	host := os.Getenv("CLASH_CA_BENCH_HOST")
	if host == "" {
		b.Skip("set CLASH_CA_BENCH_HOST to a hostname whose real chain should be measured")
	}
	conn, err := tls.Dial("tcp", host+":443", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		b.Skipf("cannot reach %s: %v", host, err)
	}
	defer conn.Close()
	state := conn.ConnectionState()
	intermediates := x509.NewCertPool()
	for _, certificate := range state.PeerCertificates[1:] {
		intermediates.AddCert(certificate)
	}
	return state.PeerCertificates[0], intermediates, host
}
