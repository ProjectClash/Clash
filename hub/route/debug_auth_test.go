package route

import (
	"testing"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)


func debugRequest(t *testing.T, handler http.Handler, method, path, secret string) int {
	t.Helper()
	request := httptest.NewRequest(method, path, nil)
	if secret != "" {
		request.Header.Set("Authorization", "Bearer "+secret)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder.Code
}

func TestDebugRoutesRequireTheSecret(t *testing.T) {
	handler := router(true, "s3cr3t", "", Cors{})

	if code := debugRequest(t, handler, http.MethodGet, "/debug/pprof/", ""); code != http.StatusUnauthorized {
		t.Fatalf("GET /debug/pprof/ without the secret returned %d, want 401: a heap profile carries proxy addresses and credential material", code)
	}
	if code := debugRequest(t, handler, http.MethodPut, "/debug/gc", ""); code != http.StatusUnauthorized {
		t.Fatalf("PUT /debug/gc without the secret returned %d, want 401", code)
	}
	if code := debugRequest(t, handler, http.MethodPut, "/debug/gc", "s3cr3t"); code == http.StatusUnauthorized {
		t.Fatal("PUT /debug/gc with the correct secret was rejected; the surface must stay usable")
	}
}

func TestDebugRoutesFollowTheControllerWhenNoSecretIsSet(t *testing.T) {
	handler := router(true, "", "", Cors{})
	if code := debugRequest(t, handler, http.MethodPut, "/debug/gc", ""); code == http.StatusUnauthorized {
		t.Fatal("an unauthenticated controller must not demand a secret for /debug")
	}
}

func TestDebugRoutesAreAbsentWhenDebugIsOff(t *testing.T) {
	handler := router(false, "s3cr3t", "", Cors{})
	if code := debugRequest(t, handler, http.MethodPut, "/debug/gc", "s3cr3t"); code != http.StatusNotFound {
		t.Fatalf("PUT /debug/gc with debug off returned %d, want 404", code)
	}
}
