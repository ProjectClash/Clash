package outboundgroup

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"

	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
)

type asksProvider struct {
	P.ProxyProvider
	healthChecks  int
	afterFailures int
	failed        []string
}

func (p *asksProvider) HealthCheck() { p.healthChecks++ }
func (p *asksProvider) HealthCheckAfterDialFailures(failed ...string) {
	p.afterFailures++
	p.failed = append(p.failed, failed...)
}

type upstreamProvider struct {
	P.ProxyProvider
	healthChecks int
}

func (p *upstreamProvider) HealthCheck() { p.healthChecks++ }

func TestDialFailuresAskTheRoundAfterDialFailures(t *testing.T) {
	ours, theirs := &asksProvider{}, &upstreamProvider{}
	group := NewGroupBase(GroupBaseOption{Name: "auto", Type: C.URLTest, Providers: []P.ProxyProvider{ours, theirs}})

	group.healthCheck()

	if ours.afterFailures != 1 || ours.healthChecks != 0 {
		t.Fatalf("this tree's provider was asked for %d rounds after dial failures and %d health checks, want 1 and 0", ours.afterFailures, ours.healthChecks)
	}
	if theirs.healthChecks != 1 {
		t.Fatalf("a provider without the round after dial failures was asked for %d health checks, want 1", theirs.healthChecks)
	}
}

func TestTheRoundAfterDialFailuresNamesTheMembersThatFailed(t *testing.T) {
	ours := &asksProvider{}
	group := NewGroupBase(GroupBaseOption{Name: "lb", Type: C.LoadBalance, MaxFailedTimes: 1000, Providers: []P.ProxyProvider{ours}})
	timeout := errors.New("connect error: context deadline exceeded")
	for i := 0; i < failedMembersLimit+4; i++ {
		member := typedMember{Proxy: adapter.NewProxy(outbound.NewDirectWithOption(outbound.DirectOption{Name: fmt.Sprintf("m%02d", i%(failedMembersLimit+2))})), tp: C.Vmess}
		group.onDialFailed(member, timeout, func() {})
	}
	time.Sleep(100 * time.Millisecond)
	group.failedTestMux.Lock()
	group.failedTestMux.Unlock()
	group.healthCheck()
	if len(ours.failed) != failedMembersLimit || ours.failed[0] != "m04" || ours.failed[failedMembersLimit-1] != "m01" {
		t.Fatalf("the round was told of %v, want the %d members that failed most recently, once each", ours.failed, failedMembersLimit)
	}
	group.healthCheck()
	if len(ours.failed) != failedMembersLimit {
		t.Fatalf("the next round was told again of members it measured: %v", ours.failed)
	}
}
