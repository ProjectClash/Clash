package ca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"reflect"
	"strings"
	"testing"
	"time"
)


func withStore(t *testing.T, store Store) {
	t.Helper()
	prior := SelectedStore()
	t.Cleanup(func() { SetStore(prior) })
	SetStore(store)
}

func poolIsSystemMarked(pool *x509.CertPool) bool {
	value := reflect.ValueOf(pool)
	if value.Kind() == reflect.Ptr {
		value = value.Elem()
	}
	field := value.FieldByName("systemPool")
	return field.IsValid() && field.Bool()
}

func TestStoreSelectionDecidesThePoolShape(t *testing.T) {
	cases := []struct {
		store        Store
		systemMarked bool
		wantRoots    bool
		why          string
	}{
		{
			store:        StoreDefault,
			systemMarked: true,
			wantRoots:    false,
			why:          "no selection must be byte-for-byte the behaviour that shipped before this option existed",
		},
		{
			store:        StoreSystem,
			systemMarked: true,
			wantRoots:    false,
			why:          "system is upstream's default and keeps the platform verifier, and with it MDM and user-installed roots",
		},
		{
			store:        StoreMozilla,
			systemMarked: false,
			wantRoots:    true,
			why:          "the only reason to select a bundle is to leave the platform verifier, so the mark must be gone",
		},
		{
			store:        StoreChrome,
			systemMarked: false,
			wantRoots:    true,
			why:          "same contract as mozilla with a different root list",
		},
		{
			store:        StoreNone,
			systemMarked: false,
			wantRoots:    false,
			why:          "none means only what the configuration supplies; a system-marked empty pool would silently be the platform store instead",
		},
	}

	for _, testCase := range cases {
		t.Run(string(testCase.store)+"|default", func(t *testing.T) {
			withStore(t, testCase.store)
			pool := GetCertPool()

			if got := poolIsSystemMarked(pool); got != testCase.systemMarked {
				t.Fatalf("systemPool mark = %v, want %v — %s", got, testCase.systemMarked, testCase.why)
			}
			roots := len(pool.Subjects())
			if testCase.wantRoots && roots < 32 {
				t.Fatalf("pool carries %d roots; a public bundle carries over a hundred, so this one "+
					"did not load — %s", roots, testCase.why)
			}
			if !testCase.wantRoots && roots != 0 {
				t.Fatalf("pool carries %d roots and should carry none — %s", roots, testCase.why)
			}
		})
	}
}

func TestBundledStoresCarryRecognisableRoots(t *testing.T) {
	for _, testCase := range []struct {
		store  Store
		expect string
	}{
		{StoreMozilla, "ISRG Root X1"},
		{StoreChrome, "ISRG Root X1"},
	} {
		t.Run(string(testCase.store), func(t *testing.T) {
			withStore(t, testCase.store)

			found := false
			for _, subject := range GetCertPool().Subjects() {
				var name pkix.RDNSequence
				if _, err := asn1.Unmarshal(subject, &name); err != nil {
					continue
				}
				var distinguished pkix.Name
				distinguished.FillFromRDNSequence(&name)
				if strings.Contains(distinguished.CommonName, testCase.expect) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("no root whose common name contains %q; the vendored bundle is not the "+
					"public root list it claims to be", testCase.expect)
			}
		})
	}
}

func TestSelectedStoreIsTheOneActuallyConsulted(t *testing.T) {
	authority, authorityPEM, leaf := issueChain(t)

	t.Run("none plus the configuration's own CA verifies the leaf", func(t *testing.T) {
		withStore(t, StoreNone)
		if err := AddCertificate(authorityPEM); err != nil {
			t.Fatalf("AddCertificate: %v", err)
		}
		if _, err := leaf.Verify(x509.VerifyOptions{
			Roots:       GetCertPool(),
			CurrentTime: authority.NotBefore.Add(time.Hour),
		}); err != nil {
			t.Fatalf("leaf did not verify against the pool it was signed for: %v", err)
		}
	})

	t.Run("mozilla rejects a leaf from a private CA", func(t *testing.T) {
		withStore(t, StoreMozilla)
		_, err := leaf.Verify(x509.VerifyOptions{
			Roots:       GetCertPool(),
			CurrentTime: authority.NotBefore.Add(time.Hour),
		})
		if err == nil {
			t.Fatal("a leaf signed by a throwaway CA verified against the Mozilla root list; the " +
				"pool being consulted is not the one that was selected")
		}
		if !strings.Contains(err.Error(), "authority") && !strings.Contains(err.Error(), "unknown") {
			t.Fatalf("rejected for an unexpected reason, which may mean the pool is empty rather "+
				"than populated: %v", err)
		}
	})
}

func TestUnknownStoreFailsClosed(t *testing.T) {
	for _, value := range []string{"mozzila", "Mozilla ", "apple", "default", "true"} {
		t.Run(value, func(t *testing.T) {
			store, err := ParseStore(value)
			if value == "Mozilla " {
				if err != nil || store != StoreMozilla {
					t.Fatalf("ParseStore(%q) = %q, %v; case and padding must be tolerated", value, store, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ParseStore(%q) accepted an unknown name as %q; a typo has to fail rather "+
					"than silently keep the platform store", value, store)
			}
			for _, name := range []string{"system", "mozilla", "chrome", "none"} {
				if !strings.Contains(err.Error(), name) {
					t.Fatalf("error %q does not list the valid name %q", err, name)
				}
			}
		})
	}
}

func TestEmptyStoreParsesAsNoSelection(t *testing.T) {
	for _, value := range []string{"", "  "} {
		store, err := ParseStore(value)
		if err != nil || store != StoreDefault {
			t.Fatalf("ParseStore(%q) = %q, %v; want the empty selection", value, store, err)
		}
	}
}

func issueChain(t *testing.T) (authority *x509.Certificate, authorityPEM string, leaf *x509.Certificate) {
	t.Helper()

	authorityKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	authorityTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Clash Store Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	authorityDER, err := x509.CreateCertificate(rand.Reader, authorityTemplate, authorityTemplate, &authorityKey.PublicKey, authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	authority, err = x509.ParseCertificate(authorityDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "leaf.clash.test"},
		DNSNames:     []string{"leaf.clash.test"},
		NotBefore:    authority.NotBefore,
		NotAfter:     authority.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, authority, &leafKey.PublicKey, authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err = x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	authorityPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: authorityDER}))
	return authority, authorityPEM, leaf
}
