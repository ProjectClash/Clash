package clash

import (
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/config"
)

func TestUnguardedControllerNoticeNamesTheOpenProxyConsequence(t *testing.T) {
	raw := &config.RawConfig{ExternalController: "0.0.0.0:9090"}
	notices := unguardedControllerNotices(raw)
	if len(notices) != 1 {
		t.Fatalf("expected one notice for an unguarded controller, got %d: %v", len(notices), notices)
	}
	for _, required := range []string{"allow-lan", "proxy"} {
		if !strings.Contains(notices[0], required) {
			t.Errorf("the notice never mentions %q, so a reader cannot weigh the worst outcome:\n%s",
				required, notices[0])
		}
	}
}

func TestGuardedOrLoopbackControllerSaysNothing(t *testing.T) {
	for name, raw := range map[string]*config.RawConfig{
		"secret set": {ExternalController: "0.0.0.0:9090", Secret: "hunter2"},
		"loopback":   {ExternalController: "127.0.0.1:9090"},
		"unset":      {},
	} {
		if notices := unguardedControllerNotices(raw); len(notices) != 0 {
			t.Errorf("%s produced %v", name, notices)
		}
	}
}
