package clash

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/ProjectClash/Clash/component/resolver"
	"github.com/ProjectClash/Clash/dns"
	"github.com/ProjectClash/Clash/hub/route"
	"github.com/metacubex/chi"
	"github.com/metacubex/http"

	D "github.com/miekg/dns"
)

func init() {
	route.Register(func(router chi.Router) {
		for _, prefix := range privateRoutePrefixes {
			router.Get(prefix+"/dns/explain", serveDNSExplain)
		}
	})
}

func probeRequested(request *http.Request) bool {
	raw := strings.TrimSpace(request.URL.Query().Get("probe"))
	if raw == "" {
		return false
	}
	enabled, err := strconv.ParseBool(raw)
	return err == nil && enabled
}

func explainableResolver(installed any) *dns.Resolver {
	switch actual := installed.(type) {
	case dns.Resolvers:
		return actual.Resolver
	case *dns.Resolvers:
		if actual == nil {
			return nil
		}
		return actual.Resolver
	case *dns.Resolver:
		return actual
	default:
		return nil
	}
}

type dnsExplainResponse struct {
	Domain      string   `json:"domain"`
	Type        string   `json:"type"`
	Source      string   `json:"source"`
	MatchedRule string   `json:"matchedRule,omitempty"`
	Candidates  []string `json:"candidates"`
	AnsweredBy  string   `json:"answeredBy,omitempty"`
	Answer      []string `json:"answer,omitempty"`
	Probed      bool     `json:"probed"`
	Cache       *struct {
		Hit       bool   `json:"hit"`
		ExpiresAt string `json:"expiresAt"`
		Stale     bool   `json:"stale"`
	} `json:"cache,omitempty"`
}

func serveDNSExplain(writer http.ResponseWriter, request *http.Request) {
	domain := strings.TrimSpace(request.URL.Query().Get("domain"))
	if domain == "" {
		writeExplainError(writer, http.StatusBadRequest, "domain is required")
		return
	}
	live := explainableResolver(resolver.DefaultResolver)
	if live == nil {
		writeExplainError(writer, http.StatusServiceUnavailable,
			"DNS is not running in this core, so there is no resolution to explain")
		return
	}

	raw := strings.ToUpper(strings.TrimSpace(request.URL.Query().Get("type")))
	qType := D.TypeA
	if raw != "" {
		known, exists := D.StringToType[raw]
		if !exists {
			writeExplainError(writer, http.StatusBadRequest, "invalid query type")
			return
		}
		qType = known
	}

	question := new(D.Msg)
	question.SetQuestion(D.Fqdn(domain), qType)
	probe := probeRequested(request)
	explanation := live.Explain(request.Context(), question, probe)

	response := dnsExplainResponse{
		Domain:      domain,
		Type:        D.TypeToString[qType],
		Source:      explanation.Source,
		MatchedRule: explanation.MatchedRule,
		Candidates:  explanation.Candidates,
		AnsweredBy:  explanation.AnsweredBy,
		Probed:      probe,
	}
	if response.Candidates == nil {
		response.Candidates = []string{}
	}
	if explanation.Answer != nil {
		for _, record := range explanation.Answer.Answer {
			response.Answer = append(response.Answer, record.String())
		}
	}
	if explanation.CacheExpiresAt != nil {
		response.Cache = &struct {
			Hit       bool   `json:"hit"`
			ExpiresAt string `json:"expiresAt"`
			Stale     bool   `json:"stale"`
		}{
			Hit:       true,
			ExpiresAt: explanation.CacheExpiresAt.Format(time.RFC3339),
			Stale:     explanation.CacheStale,
		}
	}
	writeSnapshotJSON(writer, response)
}

func writeExplainError(writer http.ResponseWriter, status int, message string) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(map[string]string{"message": message})
}
