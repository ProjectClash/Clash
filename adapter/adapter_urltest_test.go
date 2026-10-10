package adapter

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/common/utils"
)

func statusRanges(t *testing.T, spec string) utils.IntRanges[uint16] {
	t.Helper()
	ranges, err := utils.NewUnsignedRanges[uint16](spec)
	if err != nil {
		t.Fatal(err)
	}
	return ranges
}

func TestAnUnexpectedStatusIsAnOutcomeNotAnError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	proxy := NewProxy(outbound.NewDirect())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	outcome, err := proxy.URLTestOutcome(ctx, server.URL, statusRanges(t, "200-299"))
	if err != nil {
		t.Fatalf("an unexpected status must not be an error: %v", err)
	}
	if outcome.Satisfied || outcome.HTTPStatus != http.StatusServiceUnavailable || outcome.Delay == 0 {
		t.Fatalf("outcome = %+v, want unsatisfied 503 with a measured delay", outcome)
	}
	if !proxy.alive.Load() {
		t.Fatal("one URL's expectation marked the proxy dead for every URL")
	}
	if proxy.AliveForTestUrl(server.URL) {
		t.Fatal("the per-URL state must record the unexpected status as not alive")
	}
	delay, err := proxy.URLTest(ctx, server.URL, statusRanges(t, "200-299"))
	if err != nil || delay == 0 {
		t.Fatalf("URLTest = (%d, %v), want a delay and no error", delay, err)
	}
}

func TestASubMillisecondAnswerIsNeverReportedAsZero(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	proxy := NewProxy(outbound.NewDirect())
	frozen := time.Unix(1_700_000_000, 0)
	proxy.now = func() time.Time { return frozen }
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	outcome, err := proxy.URLTestOutcome(ctx, server.URL, statusRanges(t, "200-299"))
	if err != nil {
		t.Fatalf("URLTestOutcome: %v", err)
	}
	if outcome.Delay != 1 || !outcome.Satisfied {
		t.Fatalf("outcome = %+v, want delay 1 and satisfied", outcome)
	}
}

func TestATransportFailureIsStillAnError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	target := server.URL
	server.Close()

	proxy := NewProxy(outbound.NewDirect())
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	outcome, err := proxy.URLTestOutcome(ctx, target, statusRanges(t, "200-299"))
	if err == nil {
		t.Fatalf("a closed target must fail, got %+v", outcome)
	}
	if outcome.Satisfied || outcome.Delay != 0 {
		t.Fatalf("a failed test must not claim a delay or satisfaction: %+v", outcome)
	}
}
