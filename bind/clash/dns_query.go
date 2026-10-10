package clash

import (
	"context"
	"encoding/json"
	"math"
	"strings"

	"github.com/ProjectClash/Clash/component/resolver"

	"github.com/samber/lo"

	D "github.com/miekg/dns"
)

func DNSQueryJSON(name string, qType string) string {
	if resolver.DefaultResolver == nil {
		return bridgeSafeString(dnsQueryError("DNS section is disabled"))
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return bridgeSafeString(dnsQueryError("a query needs a name"))
	}
	qType = strings.TrimSpace(qType)
	if qType == "" {
		qType = "A"
	}
	queryType, ok := D.StringToType[strings.ToUpper(qType)]
	if !ok {
		return bridgeSafeString(dnsQueryError("invalid query type: " + qType))
	}

	ctx, cancel := context.WithTimeout(context.Background(), resolver.DefaultDNSTimeout)
	defer cancel()

	msg := D.Msg{}
	msg.SetQuestion(D.Fqdn(name), queryType)
	response, err := resolver.DefaultResolver.ExchangeContext(ctx, &msg)
	if err != nil {
		return bridgeSafeString(dnsQueryError(err.Error()))
	}

	payload := map[string]any{
		"Status":   response.Rcode,
		"Question": response.Question,
		"TC":       response.Truncated,
		"RD":       response.RecursionDesired,
		"RA":       response.RecursionAvailable,
		"AD":       response.AuthenticatedData,
		"CD":       response.CheckingDisabled,
	}
	recordJSON := func(rr D.RR, _ int) map[string]any {
		header := rr.Header()
		return map[string]any{
			"name": header.Name,
			"type": header.Rrtype,
			"TTL":  header.Ttl,
			"data": lo.Substring(rr.String(), len(header.String()), math.MaxUint),
		}
	}
	if len(response.Answer) > 0 {
		payload["Answer"] = lo.Map(response.Answer, recordJSON)
	}
	if len(response.Ns) > 0 {
		payload["Authority"] = lo.Map(response.Ns, recordJSON)
	}
	if len(response.Extra) > 0 {
		payload["Additional"] = lo.Map(response.Extra, recordJSON)
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		return bridgeSafeString(dnsQueryError(err.Error()))
	}
	return bridgeSafeString(string(encoded))
}

func dnsQueryError(message string) string {
	encoded, err := json.Marshal(map[string]string{"error": message})
	if err != nil {
		return `{"error":"the failure could not be encoded"}`
	}
	return string(encoded)
}
