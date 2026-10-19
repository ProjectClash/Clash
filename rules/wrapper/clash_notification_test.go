package wrapper

import (
	"testing"
	"time"

	C "github.com/ProjectClash/Clash/constant"
	RC "github.com/ProjectClash/Clash/rules/common"
)

func TestRuleNotificationReadsSurgesParameters(t *testing.T) {
	for name, tc := range map[string]struct {
		params   []string
		text     string
		interval time.Duration
		ok       bool
	}{
		"both":           {[]string{"notification-text=Example matched", "notification-interval=600"}, "Example matched", 600 * time.Second, true},
		"text only":      {[]string{"no-resolve", "notification-text=Hi"}, "Hi", DefaultNotificationInterval, true},
		"a bad interval": {[]string{"notification-text=Hi", "notification-interval=soon"}, "Hi", DefaultNotificationInterval, true},
		"no text":        {[]string{"notification-interval=600"}, "", 600 * time.Second, false},
		"an empty text":  {[]string{"notification-text="}, "", DefaultNotificationInterval, false},
		"no parameters":  {nil, "", DefaultNotificationInterval, false},
	} {
		text, interval, ok := RuleNotification(tc.params)
		if text != tc.text || interval != tc.interval || ok != tc.ok {
			t.Errorf("%s: %q %s %v, want %q %s %v", name, text, interval, ok, tc.text, tc.interval, tc.ok)
		}
	}
}

func TestANotificationIsDueOncePerInterval(t *testing.T) {
	rule := NewNotifyingRule(NewRuleWrapper(RC.NewDomain("example.com", "P")), "matched", time.Minute, "DOMAIN,example.com")
	var _ C.RuleWrapper = rule
	now := time.Unix(1_800_000_000, 0)
	if text, due := rule.NotificationDue(now); !due || text != "matched" {
		t.Fatalf("the first match: %q %v", text, due)
	}
	if _, due := rule.NotificationDue(now.Add(59 * time.Second)); due {
		t.Fatal("due again within the interval")
	}
	if _, due := rule.NotificationDue(now.Add(61 * time.Second)); !due {
		t.Fatal("not due after the interval")
	}
}
