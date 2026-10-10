package dns

import (
	"github.com/ProjectClash/Clash/component/trie"
	C "github.com/ProjectClash/Clash/constant"
)

type dnsPolicy interface {
	Match(domain string) []dnsClient
	Clients() []dnsClient
}

type domainTriePolicy struct {
	*trie.DomainTrie[[]dnsClient]
}

func (p domainTriePolicy) Clients() []dnsClient {
	if p.DomainTrie == nil {
		return nil
	}
	var clients []dnsClient
	p.DomainTrie.Foreach(func(domain string, data []dnsClient) bool {
		clients = append(clients, data...)
		return true
	})
	return clients
}

func (p domainTriePolicy) Match(domain string) []dnsClient {
	record := p.DomainTrie.Search(domain)
	if record != nil {
		return record.Data()
	}
	return nil
}

type domainMatcherPolicy struct {
	matcher    C.DomainMatcher
	dnsClients []dnsClient
}

func (p domainMatcherPolicy) Clients() []dnsClient {
	return p.dnsClients
}

func (p domainMatcherPolicy) Match(domain string) []dnsClient {
	if p.matcher.MatchDomain(domain) {
		return p.dnsClients
	}
	return nil
}
