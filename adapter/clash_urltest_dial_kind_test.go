package adapter

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/component/dialer"
	C "github.com/ProjectClash/Clash/constant"
)

type kindRecordingDirect struct {
	*outbound.Direct
	kind chan string
}

func (d *kindRecordingDirect) DialContext(ctx context.Context, _ *C.Metadata) (C.Conn, error) {
	d.kind <- dialer.DialKindOf(ctx)
	return nil, errors.New("not today")
}

func TestAURLTestLabelsItsDialAsAProxyServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	direct := &kindRecordingDirect{Direct: outbound.NewDirect(), kind: make(chan string, 1)}
	proxy := NewProxy(direct)
	_, _ = proxy.URLTest(context.Background(), server.URL, nil)
	select {
	case kind := <-direct.kind:
		if kind != dialer.DialKindProbe {
			t.Fatalf("a probe's dial is labelled %q, got %q", dialer.DialKindProbe, kind)
		}
	default:
		t.Fatal("the probe never dialled")
	}
}
