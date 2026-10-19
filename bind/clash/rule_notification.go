package clash

import "github.com/ProjectClash/Clash/tunnel"

type RuleNotificationHandler interface {
	RuleMatched(text string, rule string)
}

func SetRuleNotificationHandler(handler RuleNotificationHandler) {
	tunnel.SetRuleNotificationSink(ruleNotificationSink(handler))
}

func ruleNotificationSink(handler RuleNotificationHandler) func(text, rule string) {
	if handler == nil {
		return nil
	}
	if _, decorated := handler.(bridgeSafeRuleNotificationDecorator); !decorated {
		handler = bridgeSafeRuleNotificationDecorator{handler}
	}
	return handler.RuleMatched
}
