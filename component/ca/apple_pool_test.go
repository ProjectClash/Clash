package ca

import (
	"crypto/x509"
	"reflect"
	"runtime"
	"testing"
)


func TestSystemPoolIsWhatCostsTheXPCRoundTrip(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "ios" {
		t.Skipf("the empty-system-pool shape is Apple-specific; %s loads real roots", runtime.GOOS)
	}
	systemPool, err := x509.SystemCertPool()
	if err != nil {
		t.Fatalf("SystemCertPool: %v", err)
	}
	if got := len(systemPool.Subjects()); got != 0 {
		t.Fatalf("darwin's system pool carries %d certificates; this analysis assumes it carries "+
			"none because the roots live behind the platform verifier", got)
	}
	if !isSystemPool(systemPool) {
		t.Fatal("darwin's system pool is not marked as a system pool; if that is true then Verify " +
			"no longer routes to the platform verifier and this problem is gone")
	}
}

func TestTheSystemMarkSurvivesCloneAndAppend(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "ios" {
		t.Skipf("Apple-specific; %s does not mark a system pool", runtime.GOOS)
	}
	systemPool, err := x509.SystemCertPool()
	if err != nil {
		t.Fatalf("SystemCertPool: %v", err)
	}

	clone := systemPool.Clone()
	if !isSystemPool(clone) {
		t.Fatal("Clone dropped the system mark; sing-box's default store clones the system pool " +
			"and would behave differently from what this analysis assumes")
	}

	certificate, _, _, err := NewRandomTLSKeyPair(KeyPairTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	if !clone.AppendCertsFromPEM([]byte(certificate)) {
		t.Fatal("AppendCertsFromPEM rejected a freshly generated certificate")
	}
	if !isSystemPool(clone) {
		t.Fatal("AppendCertsFromPEM cleared the system mark; adding a CA would then silently " +
			"change which verifier every TLS client in the process uses")
	}
}

func isSystemPool(pool *x509.CertPool) bool {
	value := reflect.ValueOf(pool)
	if value.Kind() == reflect.Ptr {
		value = value.Elem()
	}
	field := value.FieldByName("systemPool")
	if !field.IsValid() {
		return false
	}
	return field.Bool()
}
