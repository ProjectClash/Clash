package resolver

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)


type lifecycleRecorder struct {
	clears atomic.Int64
	resets atomic.Int64
}

func (r *lifecycleRecorder) LookupIP(ctx context.Context, host string) ([]netip.Addr, error) {
	return nil, context.Canceled
}

func (r *lifecycleRecorder) LookupIPv4(ctx context.Context, host string) ([]netip.Addr, error) {
	return nil, context.Canceled
}

func (r *lifecycleRecorder) LookupIPv6(ctx context.Context, host string) ([]netip.Addr, error) {
	return nil, context.Canceled
}

func (r *lifecycleRecorder) ResolveECH(ctx context.Context, host string) ([]byte, error) {
	return nil, context.Canceled
}

func (r *lifecycleRecorder) ExchangeContext(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	return nil, context.Canceled
}

func (r *lifecycleRecorder) Invalid() bool { return false }

func (r *lifecycleRecorder) ClearCache() { r.clears.Add(1) }

func (r *lifecycleRecorder) ResetConnection() { r.resets.Add(1) }

func waitFor(t *testing.T, what string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

var lifecycleTestMu sync.Mutex

func withRecorders(t *testing.T) (defaultResolver, proxyServer, directHost, system *lifecycleRecorder) {
	t.Helper()
	lifecycleTestMu.Lock()

	priorDefault, priorProxy, priorDirect, priorSystem :=
		DefaultResolver, ProxyServerHostResolver, DirectHostResolver, SystemResolver
	t.Cleanup(func() {
		DefaultResolver, ProxyServerHostResolver, DirectHostResolver, SystemResolver =
			priorDefault, priorProxy, priorDirect, priorSystem
		lifecycleTestMu.Unlock()
	})

	defaultResolver, proxyServer, directHost, system =
		&lifecycleRecorder{}, &lifecycleRecorder{}, &lifecycleRecorder{}, &lifecycleRecorder{}
	DefaultResolver = defaultResolver
	ProxyServerHostResolver = proxyServer
	DirectHostResolver = directHost
	SystemResolver = system
	return
}

func TestClearCacheReachesEveryConfiguredResolver(t *testing.T) {
	defaultResolver, proxyServer, directHost, system := withRecorders(t)

	ClearCache()

	waitFor(t, "DefaultResolver cache clear", func() bool { return defaultResolver.clears.Load() == 1 })
	waitFor(t, "SystemResolver cache clear", func() bool { return system.clears.Load() == 1 })
	waitFor(t, "ProxyServerHostResolver cache clear — proxy-server-nameserver answers survive a "+
		"path change otherwise", func() bool { return proxyServer.clears.Load() == 1 })
	waitFor(t, "DirectHostResolver cache clear — direct-nameserver answers survive a path change "+
		"otherwise", func() bool { return directHost.clears.Load() == 1 })
}

func TestResetConnectionReachesEveryConfiguredResolver(t *testing.T) {
	defaultResolver, proxyServer, directHost, system := withRecorders(t)

	ResetConnection()

	waitFor(t, "DefaultResolver reset", func() bool { return defaultResolver.resets.Load() == 1 })
	waitFor(t, "SystemResolver reset", func() bool { return system.resets.Load() == 1 })
	waitFor(t, "ProxyServerHostResolver reset", func() bool { return proxyServer.resets.Load() == 1 })
	waitFor(t, "DirectHostResolver reset", func() bool { return directHost.resets.Load() == 1 })
}

func TestLifecycleHelpersToleratePartialConfiguration(t *testing.T) {
	defaultResolver, _, _, system := withRecorders(t)
	ProxyServerHostResolver = nil
	DirectHostResolver = nil

	ClearCache()
	ResetConnection()

	waitFor(t, "DefaultResolver still reached", func() bool {
		return defaultResolver.clears.Load() == 1 && defaultResolver.resets.Load() == 1
	})
	waitFor(t, "SystemResolver still reached", func() bool {
		return system.clears.Load() == 1 && system.resets.Load() == 1
	})
}

func TestLifecycleHelpersDoNotVisitTheSameResolverTwice(t *testing.T) {
	shared := &lifecycleRecorder{}
	system := &lifecycleRecorder{}

	priorDefault, priorProxy, priorDirect, priorSystem :=
		DefaultResolver, ProxyServerHostResolver, DirectHostResolver, SystemResolver
	lifecycleTestMu.Lock()
	t.Cleanup(func() {
		DefaultResolver, ProxyServerHostResolver, DirectHostResolver, SystemResolver =
			priorDefault, priorProxy, priorDirect, priorSystem
		lifecycleTestMu.Unlock()
	})
	DefaultResolver = shared
	ProxyServerHostResolver = shared
	DirectHostResolver = shared
	SystemResolver = system

	ClearCache()
	ResetConnection()

	waitFor(t, "the shared resolver to be cleared and reset", func() bool {
		return shared.clears.Load() >= 1 && shared.resets.Load() >= 1
	})
	waitFor(t, "SystemResolver to be cleared and reset", func() bool {
		return system.clears.Load() == 1 && system.resets.Load() == 1
	})

	if got := shared.clears.Load(); got != 1 {
		t.Fatalf("a resolver reachable through three of the four variables was cleared %d times, want 1", got)
	}
	if got := shared.resets.Load(); got != 1 {
		t.Fatalf("a resolver reachable through three of the four variables was reset %d times, want 1", got)
	}
}

type lifecycleAggregate struct {
	lifecycleRecorder
	members []Resolver
}

func (a *lifecycleAggregate) ClearCache() {
	a.lifecycleRecorder.ClearCache()
	for _, m := range a.members {
		m.ClearCache()
	}
}

func (a *lifecycleAggregate) ResetConnection() {
	a.lifecycleRecorder.ResetConnection()
	for _, m := range a.members {
		m.ResetConnection()
	}
}

func (a *lifecycleAggregate) ContainsResolver(r Resolver) bool {
	for _, m := range a.members {
		if r == m {
			return true
		}
	}
	return false
}

func TestLifecycleHelpersDoNotVisitAMemberOfTheRegisteredAggregateTwice(t *testing.T) {
	proxyMember := &lifecycleRecorder{}
	directMember := &lifecycleRecorder{}
	aggregate := &lifecycleAggregate{members: []Resolver{proxyMember, directMember}}
	system := &lifecycleRecorder{}

	priorDefault, priorProxy, priorDirect, priorSystem :=
		DefaultResolver, ProxyServerHostResolver, DirectHostResolver, SystemResolver
	lifecycleTestMu.Lock()
	t.Cleanup(func() {
		DefaultResolver, ProxyServerHostResolver, DirectHostResolver, SystemResolver =
			priorDefault, priorProxy, priorDirect, priorSystem
		lifecycleTestMu.Unlock()
	})
	DefaultResolver = aggregate
	ProxyServerHostResolver = proxyMember
	DirectHostResolver = directMember
	SystemResolver = system

	ClearCache()
	ResetConnection()

	waitFor(t, "the aggregate to be cleared and reset", func() bool {
		return aggregate.clears.Load() >= 1 && aggregate.resets.Load() >= 1
	})
	waitFor(t, "SystemResolver to be cleared and reset", func() bool {
		return system.clears.Load() == 1 && system.resets.Load() == 1
	})
	time.Sleep(50 * time.Millisecond)

	for name, m := range map[string]*lifecycleRecorder{"ProxyServerHostResolver": proxyMember, "DirectHostResolver": directMember} {
		if got := m.clears.Load(); got != 1 {
			t.Errorf("%s, a member of the registered aggregate, was cleared %d times, want 1 (once, through the aggregate)", name, got)
		}
		if got := m.resets.Load(); got != 1 {
			t.Errorf("%s, a member of the registered aggregate, was reset %d times, want 1 (once, through the aggregate)", name, got)
		}
	}
	if got := aggregate.resets.Load(); got != 1 {
		t.Errorf("the aggregate itself was reset %d times, want 1", got)
	}
}
