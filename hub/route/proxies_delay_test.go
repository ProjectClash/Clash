package route

import (
	"context"
	"encoding/json"
	stdhttp "net/http"
	stdtest "net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
)

func delayRequest(t *testing.T, target, expected string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/proxies/x/delay?timeout=2000&url="+target+"&expected="+expected, nil)
	req = req.WithContext(context.WithValue(req.Context(), CtxKeyProxy, adapter.NewProxy(outbound.NewDirect())))
	rec := httptest.NewRecorder()
	getProxyDelay(rec, req)
	return rec
}

func TestDelayRouteReportsAnUnexpectedStatusWithoutAnError(t *testing.T) {
	server := stdtest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
		w.WriteHeader(stdhttp.StatusServiceUnavailable)
	}))
	defer server.Close()

	rec := delayRequest(t, server.URL, "200-299")
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "unexpected HTTP status 503") {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
}

func TestDelayRouteReportsASatisfiedAnswer(t *testing.T) {
	server := stdtest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
		w.WriteHeader(stdhttp.StatusNoContent)
	}))
	defer server.Close()

	rec := delayRequest(t, server.URL, "200-299")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "delay") {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	rec = delayRequest(t, server.URL, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("without expected: status %d body %s", rec.Code, rec.Body.String())
	}
}

func TestDelayRouteFollowsTheCallersCancellation(t *testing.T) {
	release := make(chan struct{})
	server := stdtest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
		<-release
	}))
	defer server.Close()
	defer close(release)

	reqCtx, hangUp := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/proxies/x/delay?timeout=8000&url="+server.URL, nil)
	req = req.WithContext(context.WithValue(reqCtx, CtxKeyProxy, adapter.NewProxy(outbound.NewDirect())))
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	start := time.Now()
	go func() {
		defer close(done)
		getProxyDelay(rec, req)
	}()
	time.Sleep(100 * time.Millisecond)
	hangUp()

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("the caller hung up and the probe kept running toward its own 8s timeout; " +
			"that orphan is the sweep-time residency the device evidence priced at ~68KB each")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("handler returned only after %v; cancellation did not propagate", elapsed)
	}
}

func TestDelayRouteAnswersWithAClassifiedFailure(t *testing.T) {
	rec := delayRequest(t, "http://127.0.0.1:1/", "200-299")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d body %s", rec.Code, rec.Body.String())
	}
	var body struct {
		Deferred bool `json:"deferred"`
		Failure  *struct {
			Kind    string `json:"kind"`
			Errno   string `json:"errno"`
			Message string `json:"message"`
		} `json:"failure"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not json: %v\n%s", err, rec.Body.String())
	}
	if body.Failure == nil {
		t.Fatalf("no classified failure in the answer: %s", rec.Body.String())
	}
	if body.Failure.Kind == "" || body.Failure.Kind == "unknown" {
		t.Errorf("kind = %q -- a refused dial has a type to read", body.Failure.Kind)
	}
	if body.Failure.Message == "" {
		t.Error("the verbatim sentence was dropped")
	}
	if body.Message == "" {
		t.Error("upstream's message field was dropped -- existing readers break")
	}
}

func TestDelayRouteClassifiesAnUnexpectedStatus(t *testing.T) {
	server := stdtest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, _ *stdhttp.Request) {
		w.WriteHeader(stdhttp.StatusForbidden)
	}))
	defer server.Close()

	rec := delayRequest(t, server.URL, "200-299")
	var body struct {
		HTTPStatus int `json:"httpStatus"`
		Failure    *struct {
			Kind string `json:"kind"`
		} `json:"failure"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not json: %v\n%s", err, rec.Body.String())
	}
	if body.Failure == nil || body.Failure.Kind != "status" {
		t.Fatalf("kind = %+v, want status\n%s", body.Failure, rec.Body.String())
	}
	if body.HTTPStatus != 403 {
		t.Errorf("httpStatus = %d, want 403", body.HTTPStatus)
	}
}

func TestDelayRouteAnswersDeferredWhenTheGateHeldItPastItsTimeout(t *testing.T) {
	adapter.SetURLTestAdmission(func(ctx context.Context) error {
		<-ctx.Done()
		return adapter.ErrURLTestDeferred
	})
	defer adapter.SetURLTestAdmission(nil)

	req := httptest.NewRequest(http.MethodGet, "/proxies/x/delay?timeout=50&url=http://127.0.0.1:1/", nil)
	req = req.WithContext(context.WithValue(req.Context(), CtxKeyProxy, adapter.NewProxy(outbound.NewDirect())))
	rec := httptest.NewRecorder()
	getProxyDelay(rec, req)

	var body struct {
		Deferred bool `json:"deferred"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not json: %v\n%s", err, rec.Body.String())
	}
	if rec.Code != http.StatusServiceUnavailable || !body.Deferred {
		t.Fatalf("a probe the gate held past its timeout answered %d %s, want 503 with deferred:true",
			rec.Code, rec.Body.String())
	}
}
