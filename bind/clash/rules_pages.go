package clash

import (
	"encoding/json"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"

	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/hub/route"
	"github.com/ProjectClash/Clash/rules/clashindex"
	"github.com/ProjectClash/Clash/tunnel"
	"github.com/metacubex/chi"
	mhttp "github.com/metacubex/http"
)

func init() {
	route.Register(func(router chi.Router) {
		for _, prefix := range privateRoutePrefixes {
			router.Get(prefix+"/rules-page", serveRulesAnswer(func(offset, limit int, types string) string {
				return rulesPageJSON(offset, limit, typesOfList(types))
			}))
			router.Get(prefix+"/rules-hits", serveRulesAnswer(func(offset, limit int, _ string) string {
				return ruleHitsJSON(offset, limit)
			}))
		}
	})
}

const rulesPageLimit = 500

func serveRulesAnswer(answer func(offset, limit int, types string) string) mhttp.HandlerFunc {
	return func(writer mhttp.ResponseWriter, request *mhttp.Request) {
		query := request.URL.Query()
		offset, _ := strconv.Atoi(query.Get("offset"))
		limit, _ := strconv.Atoi(query.Get("limit"))
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		_, _ = io.WriteString(writer, answer(offset, limit, query.Get("types")))
	}
}

func typesOfList(list string) map[string]bool {
	var types map[string]bool
	for _, tp := range strings.Split(list, ",") {
		if tp = strings.ToUpper(strings.TrimSpace(tp)); tp != "" {
			if types == nil {
				types = map[string]bool{}
			}
			types[tp] = true
		}
	}
	return types
}

func writtenRuleTypeIn(table C.RuleTable, i int, types map[string]bool) bool {
	if prefixed, ok := table.(*C.ClashRulesBefore); ok {
		if first := prefixed.FirstAfter(); i >= first {
			j := i - first
			if len(prefixed.AfterLines) == len(prefixed.After) {
				tp, _, _, _ := ruleTypeAndTarget(prefixed.AfterLines[j])
				return types[tp]
			}
			return writtenRuleTypeIn(prefixed.After, j, types)
		}
		if i >= len(prefixed.Before) {
			return writtenRuleTypeIn(prefixed.Rest, i-len(prefixed.Before), types)
		}
		if len(prefixed.Lines) == len(prefixed.Before) {
			tp, _, _, _ := ruleTypeAndTarget(prefixed.Lines[i])
			return types[tp]
		}
		table = prefixed.Before
	}
	if indexed, ok := table.(*clashindex.Table); ok {
		x := indexed.Index()
		if tp, _, ok := x.MappedTypeAndTarget(i); ok {
			return types[tp]
		}
		if line, _, ok := x.Written(i); ok {
			tp, _, _, _ := ruleTypeAndTarget(line)
			return types[tp]
		}
		return false
	}
	rule := table.At(i)
	for _, tp := range spellingsOf.get()[rule.RuleType()] {
		if types[tp] {
			return true
		}
	}
	return false
}

var spellingsOf = &lazyValue[map[C.RuleType][]string]{build: func() map[C.RuleType][]string {
	return map[C.RuleType][]string{
		C.Domain: {"DOMAIN"}, C.DomainSuffix: {"DOMAIN-SUFFIX"}, C.DomainKeyword: {"DOMAIN-KEYWORD"},
		C.DomainRegex: {"DOMAIN-REGEX"}, C.DomainWildcard: {"DOMAIN-WILDCARD"}, C.GEOSITE: {"GEOSITE"},
		C.GEOIP: {"GEOIP"}, C.SrcGEOIP: {"SRC-GEOIP", "GEOIP"}, C.IPASN: {"IP-ASN"}, C.SrcIPASN: {"SRC-IP-ASN", "IP-ASN"},
		C.IPCIDR: {"IP-CIDR", "IP-CIDR6"}, C.SrcIPCIDR: {"SRC-IP-CIDR", "IP-CIDR", "IP-CIDR6"},
		C.IPSuffix: {"IP-SUFFIX"}, C.SrcIPSuffix: {"SRC-IP-SUFFIX", "IP-SUFFIX"},
		C.SrcPort: {"SRC-PORT"}, C.DstPort: {"DST-PORT"}, C.InPort: {"IN-PORT"}, C.DSCP: {"DSCP"},
		C.InUser: {"IN-USER"}, C.InName: {"IN-NAME"}, C.InType: {"IN-TYPE"},
		C.ProcessName: {"PROCESS-NAME"}, C.ProcessPath: {"PROCESS-PATH"},
		C.ProcessNameRegex: {"PROCESS-NAME-REGEX"}, C.ProcessPathRegex: {"PROCESS-PATH-REGEX"},
		C.ProcessNameWildcard: {"PROCESS-NAME-WILDCARD"}, C.ProcessPathWildcard: {"PROCESS-PATH-WILDCARD"},
		C.RematchName: {"REMATCH-NAME"}, C.RuleSet: {"RULE-SET"}, C.Network: {"NETWORK"}, C.Uid: {"UID"},
		C.SubRules: {"SUB-RULE"}, C.MATCH: {"MATCH"}, C.AND: {"AND"}, C.OR: {"OR"}, C.NOT: {"NOT"},
		C.SourceAppSigningID: {"SOURCE-APP-SIGNING-ID"}, C.SourceAppTeamID: {"SOURCE-APP-TEAM-ID"},
		C.Protocol: {"PROTOCOL"}, C.Subnet: {"SUBNET"}, C.CellularRadio: {"CELLULAR-RADIO"},
	}
}}

func rulePageBounds(offset, limit, total int) (int, int) {
	if limit <= 0 || limit > rulesPageLimit {
		limit = rulesPageLimit
	}
	if offset < 0 {
		offset = 0
	}
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return offset, end
}

func ruleJSON(table C.RuleTable, i int) route.Rule {
	if s, ok := table.(C.RuleTableStatistics); ok {
		if statistics, mapped := s.Statistics(i); mapped {
			return route.ClashRuleJSON(table, i, statistics, true)
		}
	}
	return route.ClashRuleJSON(table, i, C.RuleStatistics{}, false)
}

type rulesPage struct {
	Total   int          `json:"total"`
	Noted   *int         `json:"noted,omitempty"`
	Matched *int         `json:"matched,omitempty"`
	Offset  int          `json:"offset"`
	Rules   []route.Rule `json:"rules"`
	Error   string       `json:"error,omitempty"`
}

func rulesPageJSON(offset, limit int, types map[string]bool) string {
	table := tunnel.RuleTable()
	page := rulesPage{Total: table.Len(), Rules: []route.Rule{}}
	if types == nil {
		from, to := rulePageBounds(offset, limit, table.Len())
		page.Offset = from
		for i := from; i < to; i++ {
			page.Rules = append(page.Rules, ruleJSON(table, i))
		}
		b, _ := json.Marshal(page)
		return string(b)
	}
	from, to := rulePageBounds(offset, limit, table.Len())
	want := to - from
	matched := 0
	for i := 0; i < table.Len(); i++ {
		if !writtenRuleTypeIn(table, i, types) {
			continue
		}
		if matched >= offset && len(page.Rules) < want {
			page.Rules = append(page.Rules, ruleJSON(table, i))
		}
		matched++
	}
	page.Matched = &matched
	page.Offset = offset
	if page.Offset < 0 {
		page.Offset = 0
	}
	if page.Offset > matched {
		page.Offset = matched
	}
	b, _ := json.Marshal(page)
	return string(b)
}

func ruleHitsJSON(offset, limit int) string {
	table := tunnel.RuleTable()
	var noted []int
	if t, ok := table.(interface{ Noted(func(int) bool) }); ok {
		t.Noted(func(i int) bool { noted = append(noted, i); return true })
	} else {
		for i := 0; i < table.Len(); i++ {
			if w, ok := table.At(i).(C.RuleWrapper); ok && (w.HitCount() > 0 || w.IsDisabled()) {
				noted = append(noted, i)
			}
		}
	}
	count := len(noted)
	page := rulesPage{Total: table.Len(), Noted: &count, Rules: []route.Rule{}}
	from, to := rulePageBounds(offset, limit, len(noted))
	page.Offset = from
	for _, i := range noted[from:to] {
		page.Rules = append(page.Rules, ruleJSON(table, i))
	}
	b, _ := json.Marshal(page)
	return string(b)
}

func RulesPageJSON(offset, limit int32, typesJSON string) string {
	filter, err := parseRuleFilter("", "", typesJSON)
	if err != nil {
		b, _ := json.Marshal(rulesPage{Rules: []route.Rule{}, Error: err.Error()})
		return bridgeSafeString(string(b))
	}
	return bridgeSafeString(rulesPageJSON(int(offset), int(limit), filter.types))
}

func RuleHitsJSON(offset, limit int32) string {
	return bridgeSafeString(ruleHitsJSON(int(offset), int(limit)))
}

func (c *APIClient) GetRulesPage(offset, limit int32, typesJSON string) (string, error) {
	filter, err := parseRuleFilter("", "", typesJSON)
	if err != nil {
		return "", bridgeSafeError(err)
	}
	path := "/rules-page?offset=" + strconv.Itoa(int(offset)) + "&limit=" + strconv.Itoa(int(limit))
	if filter.types != nil {
		types := make([]string, 0, len(filter.types))
		for tp := range filter.types {
			types = append(types, tp)
		}
		sort.Strings(types)
		path += "&types=" + url.QueryEscape(strings.Join(types, ","))
	}
	answer, err := c.privateRequest(mhttp.MethodGet, path, nil)
	return bridgeSafeString(answer), bridgeSafeError(err)
}

func (c *APIClient) GetRuleHits(offset, limit int32) (string, error) {
	answer, err := c.privateRequest(mhttp.MethodGet, "/rules-hits?offset="+strconv.Itoa(int(offset))+"&limit="+strconv.Itoa(int(limit)), nil)
	return bridgeSafeString(answer), bridgeSafeError(err)
}
