package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/ProjectClash/Clash/component/resolver"

	D "github.com/miekg/dns"
)

const (
	SystemDnsFlushTime   = 5 * time.Minute
	SystemDnsDeleteTimes = 12 // 12*5 = 60min
)

type systemDnsClient struct {
	disableTimes uint32
	dnsClient
}

type systemClient struct {
	mu         sync.Mutex
	dnsClients map[string]*systemDnsClient
	lastFlush  time.Time
	defaultNS  []dnsClient
}

func (c *systemClient) ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	dnsClients, err := c.getDnsClients()
	if len(dnsClients) == 0 && len(c.defaultNS) > 0 {
		dnsClients = c.defaultNS
		err = nil
	}
	if err != nil {
		return
	}
	msg, _, err = batchExchange(ctx, dnsClients, m)
	return
}

// Address implements dnsClient
func (c *systemClient) Address() string {
	dnsClients, _ := c.getDnsClients()
	isDefault := ""
	if len(dnsClients) == 0 && len(c.defaultNS) > 0 {
		dnsClients = c.defaultNS
		isDefault = "[defaultNS]"
	}
	addrs := make([]string, 0, len(dnsClients))
	for _, c := range dnsClients {
		addrs = append(addrs, c.Address())
	}
	return fmt.Sprintf("system%s(%s)", isDefault, strings.Join(addrs, ","))
}

var _ dnsClient = (*systemClient)(nil)

func newSystemClient() *systemClient {
	return &systemClient{
		dnsClients: map[string]*systemDnsClient{},
	}
}

func init() {
	SetSystemResolverDefaults(nil)
}

func SetSystemResolverDefaults(servers []string) {
	nameServers := make([]NameServer, 0, len(servers))
	for _, server := range servers {
		if server == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(server); err != nil {
			server = net.JoinHostPort(strings.Trim(server, "[]"), "53")
		}
		nameServers = append(nameServers, NameServer{Addr: server})
	}
	if len(nameServers) == 0 {
		nameServers = []NameServer{{Addr: "114.114.114.114:53"}, {Addr: "8.8.8.8:53"}}
	}
	r := NewResolver(Config{})
	c := newSystemClient()
	c.defaultNS = transform(nameServers, nil)
	for i, ns := range nameServers {
		c.defaultNS[i] = wrapSystemSubstitute(ns, c.defaultNS[i])
	}
	r.main = []dnsClient{c}
	resolver.SystemResolver = r
	addrs := make([]string, 0, len(nameServers))
	for _, ns := range nameServers {
		addrs = append(addrs, ns.Addr)
	}
	systemResolverDefaultsMu.Lock()
	systemResolverDefaults = addrs
	systemResolverDefaultsMu.Unlock()
}

func SystemResolverDefaultAddresses() []string {
	systemResolverDefaultsMu.Lock()
	defer systemResolverDefaultsMu.Unlock()
	return append([]string(nil), systemResolverDefaults...)
}

var (
	systemResolverDefaultsMu sync.Mutex
	systemResolverDefaults   []string
)
