package route

import (
	"bufio"
	"encoding/json"

	"github.com/ProjectClash/Clash/constant"

	"github.com/metacubex/chi/render"
	"github.com/metacubex/http"
)

func ClashRuleJSON(table constant.RuleTable, i int, statistics constant.RuleStatistics, ok bool) Rule {
	rule := table.At(i)
	r := Rule{
		Index:   i,
		Type:    rule.RuleType().String(),
		Payload: rule.Payload(),
		Proxy:   rule.Adapter(),
		Size:    -1,
	}
	if ok {
		r.Extra = &RuleExtra{
			Disabled:  statistics.Disabled,
			HitCount:  statistics.HitCount,
			HitAt:     statistics.HitAt,
			MissCount: statistics.MissCount,
			MissAt:    statistics.MissAt,
		}
	} else if ruleWrapper, wrapped := rule.(constant.RuleWrapper); wrapped {
		r.Extra = &RuleExtra{
			Disabled:  ruleWrapper.IsDisabled(),
			HitCount:  ruleWrapper.HitCount(),
			HitAt:     ruleWrapper.HitAt(),
			MissCount: ruleWrapper.MissCount(),
			MissAt:    ruleWrapper.MissAt(),
		}
		rule = ruleWrapper.Unwrap()
	}
	if rule.RuleType() == constant.GEOIP || rule.RuleType() == constant.GEOSITE {
		r.Size = rule.(constant.RuleGroup).GetRecodeSize()
	}
	return r
}

func rangeTableStatistics(table constant.RuleTable, f func(i int, statistics constant.RuleStatistics, ok bool) bool) {
	if ranged, ok := table.(interface {
		RangeStatistics(func(int, constant.RuleStatistics, bool) bool)
	}); ok {
		ranged.RangeStatistics(f)
		return
	}
	for i := 0; i < table.Len(); i++ {
		if !f(i, constant.RuleStatistics{}, false) {
			return
		}
	}
}

func ClashStreamRules(w http.ResponseWriter, r *http.Request, table constant.RuleTable) {
	w.Header().Set("Content-Type", "application/json")
	if status, ok := r.Context().Value(render.StatusCtxKey).(int); ok {
		w.WriteHeader(status)
	}
	out := bufio.NewWriterSize(w, 64<<10)
	if _, err := out.WriteString(`{"rules":[`); err != nil {
		return
	}
	failed := false
	rangeTableStatistics(table, func(i int, statistics constant.RuleStatistics, ok bool) bool {
		b, err := json.Marshal(ClashRuleJSON(table, i, statistics, ok))
		if err != nil {
			failed = true
			return false
		}
		if i > 0 {
			if err := out.WriteByte(','); err != nil {
				failed = true
				return false
			}
		}
		if _, err := out.Write(b); err != nil {
			failed = true
			return false
		}
		return true
	})
	if failed {
		return
	}
	if _, err := out.WriteString("]}\n"); err != nil {
		return
	}
	_ = out.Flush()
}
