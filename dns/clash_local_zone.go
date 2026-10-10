package dns

import (
	"context"
	"strings"

	"github.com/ProjectClash/Clash/common/atomic"

	D "github.com/miekg/dns"
)

var localZones = []string{
	"local.",
	"254.169.in-addr.arpa.",
	"8.e.f.ip6.arpa.",
	"9.e.f.ip6.arpa.",
	"a.e.f.ip6.arpa.",
	"b.e.f.ip6.arpa.",
}

func IsLocalZone(name string) bool {
	canonical := strings.ToLower(D.CanonicalName(name))
	for _, zone := range localZones {
		if canonical == zone || strings.HasSuffix(canonical, "."+zone) {
			return true
		}
	}
	return false
}

var localZoneExchanger atomic.TypedValue[func(context.Context, *D.Msg) (*D.Msg, error)]

func SetLocalZoneExchanger(exchange func(context.Context, *D.Msg) (*D.Msg, error)) {
	localZoneExchanger.Store(exchange)
}

func exchangeLocalZone(ctx context.Context, m *D.Msg) (*D.Msg, bool, error) {
	if len(m.Question) == 0 {
		return nil, false, nil
	}
	exchange := localZoneExchanger.Load()
	if exchange == nil || !IsLocalZone(m.Question[0].Name) {
		return nil, false, nil
	}
	msg, err := exchange(ctx, m)
	return msg, true, err
}
