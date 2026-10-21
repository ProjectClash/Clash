package dns

import (
	"context"

	"github.com/ProjectClash/Clash/component/resolver"

	D "github.com/miekg/dns"
)

type StandaloneClient interface {
	ExchangeContext(ctx context.Context, m *D.Msg) (*D.Msg, error)
	ResetConnection()
}

func NewStandaloneClient(server NameServer, r resolver.Resolver) StandaloneClient {
	return transform([]NameServer{server}, r)[0]
}

func (r *Resolver) HoldsAnswer(q D.Question) bool {
	if r == nil || r.cache == nil {
		return false
	}
	msg, _, hit := getMsgFromCache(r.cache, q)
	return hit && msg != nil
}
