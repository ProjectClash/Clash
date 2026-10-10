package clash

import (
	"testing"

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
