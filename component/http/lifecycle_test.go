package http

import (
	"context"
	"errors"
	"net"
	stdhttp "net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/listener/inner"
)

func TestClosedCoreDoesNotFallBackToDirectHTTP(t *testing.T) {
	old := inner.GetTunnel()
	inner.New(nil)
	defer inner.New(old)
	var requests atomic.Int32
	server := httptest.NewServer(stdhttp.HandlerFunc(func(w stdhttp.ResponseWriter, r *stdhttp.Request) { requests.Add(1); w.WriteHeader(204) }))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	response, err := HttpRequest(ctx, server.URL, "GET", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	inner.CloseTCPConnections()
	response, err = HttpRequest(ctx, server.URL, "GET", nil, nil)
	if response != nil {
		response.Body.Close()
	}
	if !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closed core must reject HTTP, got %v", err)
	}
	if requests.Load() != 1 {
		t.Fatalf("HTTP bypassed core shutdown: %d requests", requests.Load())
	}
}
