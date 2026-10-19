package tunnel

import (
	"sync/atomic"
	"time"

	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/log"
)

func matchEveryMode(metadata *C.Metadata, helper C.RuleMatchHelper, version *runtimeVersion) (C.Proxy, C.Rule) {
	for _, rule := range version.routing.EveryModeRules {
		matched, ada := rule.Match(metadata, helper)
		if !matched {
			continue
		}
		adapter, ok := version.lookup(ada)
		if !ok || adapter == nil {
			continue
		}
		passed := false
		for a := adapter; a != nil; a = a.Unwrap(metadata, false) {
			if a.Type() == C.Pass {
				passed = true
				break
			}
		}
		if passed {
			continue
		}
		if metadata.NetWork == C.UDP && !adapter.SupportUDP() {
			fallback := version.routing.UDPUnsupported
			if fallback == "" {
				continue
			}
			if adapter, ok = version.lookup(fallback); !ok || adapter == nil {
				continue
			}
		}
		log.Debugln("[Rule] %s %s matched in %s mode, before the mode decides", rule.RuleType(), rule.Payload(), version.mode)
		notifyRuleMatched(metadata, rule)
		return adapter, rule
	}
	return nil, nil
}

func (v *runtimeVersion) udpFallback(metadata *C.Metadata, proxy C.Proxy) (C.Proxy, error) {
	if metadata.NetWork != C.UDP || proxy.SupportUDP() || v.routing.UDPUnsupported == "" {
		return proxy, nil
	}
	return v.proxy(v.routing.UDPUnsupported)
}

var ruleNotificationSink atomic.Pointer[func(text, rule string)]

func SetRuleNotificationSink(sink func(text, rule string)) {
	if sink == nil {
		ruleNotificationSink.Store(nil)
		return
	}
	ruleNotificationSink.Store(&sink)
}

func notifyRuleMatched(metadata *C.Metadata, rule C.Rule) {
	sink := ruleNotificationSink.Load()
	if sink == nil || rule == nil || metadata.Type == C.INNER {
		return
	}
	if indexed, ok := rule.(*C.IndexedRule); ok {
		rule = indexed.Rule
	}
	notifying, ok := rule.(interface {
		NotificationDue(now time.Time) (string, bool)
	})
	if !ok {
		return
	}
	if text, due := notifying.NotificationDue(time.Now()); due {
		line := rule.RuleType().String() + "," + rule.Payload()
		if written, ok := rule.(interface{ WrittenLine() string }); ok {
			line = written.WrittenLine()
		}
		go (*sink)(text, line)
	}
}
