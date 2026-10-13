package clash

import (
	"testing"

	"github.com/ProjectClash/Clash/adapter/outbound"
	C "github.com/ProjectClash/Clash/constant"
)

type sessionKeepingAdapter struct {
	C.ProxyAdapter
	resets *int
}

func (a sessionKeepingAdapter) ResetNetwork() { *a.resets++ }

type sessionlessAdapter struct{ C.ProxyAdapter }

func TestANetworkResetReachesEveryOutboundThatKeepsSessions(t *testing.T) {
	resets := 0
	got := resetSessionsOf([]C.ProxyAdapter{
		sessionKeepingAdapter{resets: &resets},
		sessionlessAdapter{},
		sessionKeepingAdapter{resets: &resets},
	})
	if got != 2 || resets != 2 {
		t.Fatalf("reset %d adapters (%d calls), want the two that keep sessions", got, resets)
	}
}

type sessionKeepingOutbound struct {
	*outbound.Direct
	resets *int
}

func (a sessionKeepingOutbound) ResetNetwork() { *a.resets++ }

func TestANetworkResetReachesOutboundsAsTheParserWrapsThem(t *testing.T) {
	resets := 0
	got := resetSessionsOf([]C.ProxyAdapter{
		outbound.NewAutoCloseProxyAdapter(sessionKeepingOutbound{Direct: outbound.NewDirect(), resets: &resets}),
		outbound.NewAutoCloseProxyAdapter(outbound.NewDirect()),
		outbound.NewAutoCloseProxyAdapter(sessionKeepingOutbound{Direct: outbound.NewDirect(), resets: &resets}),
	})
	if got != 2 || resets != 2 {
		t.Fatalf("reset %d wrapped adapters (%d calls), want the two that keep sessions", got, resets)
	}
}
