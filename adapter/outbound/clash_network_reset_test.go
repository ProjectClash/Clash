package outbound

import (
	"errors"
	"testing"

	"github.com/metacubex/sing-quic/hysteria2"
)

func TestAHysteria2ResetDropsItsClientAndTheNextDialBuildsAnother(t *testing.T) {
	builds := 0
	h := &Hysteria2{buildClient: func() (*hysteria2.Client, error) {
		builds++
		return nil, errors.New("no server in a unit test")
	}}
	_, _ = h.lazyClient()
	h.ResetNetwork()
	if _, err := h.lazyClient(); errors.Is(err, errOutboundClosed) {
		t.Fatal("a network reset must not close the node")
	}
	if builds != 2 {
		t.Fatalf("builds=%d, want the client rebuilt after the reset", builds)
	}
}

func TestAClosedHysteria2StaysClosedThroughAReset(t *testing.T) {
	h := &Hysteria2{buildClient: func() (*hysteria2.Client, error) { return nil, nil }}
	_ = h.Close()
	h.ResetNetwork()
	if _, err := h.lazyClient(); !errors.Is(err, errOutboundClosed) {
		t.Fatalf("a closed node reopened by a reset: %v", err)
	}
}

var _ NetworkResetter = (*Hysteria2)(nil)
var _ NetworkResetter = (*Tuic)(nil)
var _ NetworkResetter = (*SingMux)(nil)
