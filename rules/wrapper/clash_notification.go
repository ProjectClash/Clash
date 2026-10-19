package wrapper

import (
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	C "github.com/ProjectClash/Clash/constant"
)


const DefaultNotificationInterval = 300 * time.Second

type NotifyingRule struct {
	C.RuleWrapper
	text     string
	interval time.Duration
	written  string
	last     atomic.Int64
}

func RuleNotification(params []string) (text string, interval time.Duration, ok bool) {
	interval = DefaultNotificationInterval
	for _, param := range params {
		key, value, found := strings.Cut(param, "=")
		if !found {
			continue
		}
		switch strings.TrimSpace(key) {
		case "notification-text":
			text, ok = strings.TrimSpace(value), true
		case "notification-interval":
			if seconds, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && seconds > 0 {
				interval = time.Duration(seconds) * time.Second
			}
		}
	}
	return text, interval, ok && text != ""
}

func NewNotifyingRule(rule C.RuleWrapper, text string, interval time.Duration, written string) *NotifyingRule {
	return &NotifyingRule{RuleWrapper: rule, text: text, interval: interval, written: written}
}

func (r *NotifyingRule) WrittenLine() string { return r.written }

func (r *NotifyingRule) NotificationDue(now time.Time) (string, bool) {
	last := r.last.Load()
	if last != 0 && now.Sub(time.Unix(0, last)) < r.interval {
		return "", false
	}
	if !r.last.CompareAndSwap(last, now.UnixNano()) {
		return "", false
	}
	return r.text, true
}
