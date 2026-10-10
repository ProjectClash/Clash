package dns

import (
	"context"
	"net"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/ProjectClash/Clash/log"

	D "github.com/miekg/dns"
)


var (
	systemSubstituteMu    sync.RWMutex
	systemSubstituteAddrs = map[string]struct{}{}
	systemSubstituteStale atomic.Bool

	systemSubstituteLiveMu      sync.RWMutex
	systemSubstituteLiveServers []string
	systemSubstituteLiveClients []dnsClient
)

func SetSystemSubstituteServers(servers []string) bool {
	normalized := make([]string, 0, len(servers))
	for _, server := range servers {
		if key := normalizeSubstituteAddr(server); key != "" {
			normalized = append(normalized, key)
		}
	}
	systemSubstituteLiveMu.Lock()
	defer systemSubstituteLiveMu.Unlock()
	if slices.Equal(normalized, systemSubstituteLiveServers) {
		return false
	}
	previous := systemSubstituteLiveClients
	nameServers := make([]NameServer, 0, len(normalized))
	for _, server := range normalized {
		nameServers = append(nameServers, NameServer{Addr: server})
	}
	systemSubstituteLiveServers = normalized
	systemSubstituteLiveClients = transform(nameServers, nil)
	for _, client := range previous {
		client.ResetConnection()
	}
	return true
}

func SystemSubstituteServers() []string {
	systemSubstituteLiveMu.RLock()
	defer systemSubstituteLiveMu.RUnlock()
	return append([]string(nil), systemSubstituteLiveServers...)
}

func systemSubstituteLive() []dnsClient {
	systemSubstituteLiveMu.RLock()
	defer systemSubstituteLiveMu.RUnlock()
	return systemSubstituteLiveClients
}

func normalizeSubstituteAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return ""
	}
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(strings.Trim(addr, "[]"), "53")
	}
	return addr
}

func MarkSystemSubstitutes(servers []string) {
	next := make(map[string]struct{}, len(servers))
	for _, server := range servers {
		if key := normalizeSubstituteAddr(server); key != "" {
			next[key] = struct{}{}
		}
	}
	systemSubstituteMu.Lock()
	systemSubstituteAddrs = next
	systemSubstituteMu.Unlock()
}

func SystemSubstitutes() []string {
	systemSubstituteMu.RLock()
	defer systemSubstituteMu.RUnlock()
	out := make([]string, 0, len(systemSubstituteAddrs))
	for addr := range systemSubstituteAddrs {
		out = append(out, addr)
	}
	sortStrings(out)
	return out
}

func isSystemSubstitute(ns NameServer) bool {
	if ns.Net != "" && ns.Net != "udp" && ns.Net != "tcp" {
		return false
	}
	systemSubstituteMu.RLock()
	defer systemSubstituteMu.RUnlock()
	_, ok := systemSubstituteAddrs[normalizeSubstituteAddr(ns.Addr)]
	return ok
}

func SetSystemSubstitutesStale(stale bool) bool {
	return systemSubstituteStale.Swap(stale) != stale
}

func SystemSubstitutesStale() bool {
	return systemSubstituteStale.Load()
}

var systemSubstituteRefresh atomic.Pointer[func()]

func SetSystemSubstituteRefresh(refresh func()) {
	if refresh == nil {
		systemSubstituteRefresh.Store(nil)
		return
	}
	systemSubstituteRefresh.Store(&refresh)
}

type systemSubstituteClient struct {
	dnsClient
	fallback atomic.Pointer[[]dnsClient]
}

var _ dnsClient = (*systemSubstituteClient)(nil)

func (c *systemSubstituteClient) setFallback(clients []dnsClient) {
	own := make([]dnsClient, 0, len(clients))
	for _, client := range clients {
		if client != dnsClient(c) {
			own = append(own, client)
		}
	}
	c.fallback.Store(&own)
}

func (c *systemSubstituteClient) fallbackClients() []dnsClient {
	if p := c.fallback.Load(); p != nil && len(*p) != 0 {
		return *p
	}
	return upstreamLastResortClients()
}

func (c *systemSubstituteClient) ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error) {
	if refresh := systemSubstituteRefresh.Load(); refresh != nil {
		(*refresh)()
	}
	if live := systemSubstituteLive(); len(live) != 0 {
		msg, _, err := batchExchange(ctx, live, m)
		return msg, err
	}
	if !systemSubstituteStale.Load() {
		return c.dnsClient.ExchangeContext(ctx, m)
	}
	msg, _, err := batchExchange(ctx, c.fallbackClients(), m)
	return msg, err
}

func (c *systemSubstituteClient) Address() string {
	if live := SystemSubstituteServers(); len(live) != 0 {
		return c.dnsClient.Address() + "[system-substitute live: " + strings.Join(live, ",") + "]"
	}
	if systemSubstituteStale.Load() {
		return c.dnsClient.Address() + "[system-substitute stale]"
	}
	return c.dnsClient.Address() + "[system-substitute]"
}

func (c *systemSubstituteClient) ResetConnection() {
	c.dnsClient.ResetConnection()
	for _, client := range systemSubstituteLive() {
		client.ResetConnection()
	}
	if p := c.fallback.Load(); p != nil {
		for _, client := range *p {
			if client != dnsClient(c) {
				client.ResetConnection()
			}
		}
	}
}

func wrapSystemSubstitute(ns NameServer, client dnsClient) dnsClient {
	if wrapper := newSystemSubstitute(ns, client); wrapper != nil {
		return wrapper
	}
	return client
}

func newSystemSubstitute(ns NameServer, client dnsClient) *systemSubstituteClient {
	if client == nil || !isSystemSubstitute(ns) {
		return nil
	}
	if _, already := client.(*systemSubstituteClient); already {
		return nil
	}
	return &systemSubstituteClient{dnsClient: client}
}

func substituteWrappers(clients []dnsClient) []*systemSubstituteClient {
	var out []*systemSubstituteClient
	for _, client := range clients {
		for client != nil {
			if wrapper, ok := client.(*systemSubstituteClient); ok {
				out = append(out, wrapper)
				break
			}
			u, ok := client.(interface{ Unwrap() dnsClient })
			if !ok {
				break
			}
			client = u.Unwrap()
		}
	}
	return out
}

func nonSubstituteClients(clients []dnsClient) []dnsClient {
	wrappers := map[*systemSubstituteClient]struct{}{}
	for _, wrapper := range substituteWrappers(clients) {
		wrappers[wrapper] = struct{}{}
	}
	out := make([]dnsClient, 0, len(clients))
	for _, client := range clients {
		inner := client
		isWrapper := false
		for inner != nil {
			if wrapper, ok := inner.(*systemSubstituteClient); ok {
				if _, tracked := wrappers[wrapper]; tracked {
					isWrapper = true
				}
				break
			}
			u, ok := inner.(interface{ Unwrap() dnsClient })
			if !ok {
				break
			}
			inner = u.Unwrap()
		}
		if !isWrapper {
			out = append(out, client)
		}
	}
	return out
}

func wireSubstituteFallbacks(rs Resolvers, created []*systemSubstituteClient) {
	if rs.Resolver == nil || len(created) == 0 {
		return
	}
	main := rs.Resolver.main
	mainWrappers := map[*systemSubstituteClient]struct{}{}
	for _, wrapper := range substituteWrappers(main) {
		mainWrappers[wrapper] = struct{}{}
	}
	mainOthers := nonSubstituteClients(main)
	for _, wrapper := range created {
		if _, inMain := mainWrappers[wrapper]; inMain {
			wrapper.setFallback(mainOthers)
			continue
		}
		wrapper.setFallback(main)
	}
	if changed := len(created); changed != 0 {
		log.Debugln("[DNS] %d system-resolver substitute client(s) wired to their fallback chain", changed)
	}
}

var (
	upstreamLastResortOnce     sync.Once
	upstreamLastResortClients_ []dnsClient
)

func upstreamLastResortClients() []dnsClient {
	upstreamLastResortOnce.Do(func() {
		upstreamLastResortClients_ = transform([]NameServer{{Addr: "114.114.114.114:53"}, {Addr: "8.8.8.8:53"}}, nil)
	})
	return upstreamLastResortClients_
}

func sortStrings(values []string) {
	for i := 1; i < len(values); i++ {
		for j := i; j > 0 && values[j-1] > values[j]; j-- {
			values[j-1], values[j] = values[j], values[j-1]
		}
	}
}
