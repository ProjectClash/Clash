package clash

import (
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/config"
	C "github.com/ProjectClash/Clash/constant"
)

func TestASilentStackParsesAsUpstreamParsesIt(t *testing.T) {
	const document = `
tun:
  enable: true
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, document)
	finalizeConfigForIOS(ours, true)
	if ours.General.Tun.Stack != mihomo.General.Tun.Stack {
		t.Errorf("a configuration that never mentioned tun.stack got %v, upstream %v", ours.General.Tun.Stack, mihomo.General.Tun.Stack)
	}
}

func TestAnExplicitStackIsHonoured(t *testing.T) {
	for name, stack := range map[string]C.TUNStack{
		"system": C.TunSystem,
		"mixed":  C.TunMixed,
		"gvisor": C.TunGvisor,
		"mips":   C.TunMips,
		"go":     C.TunGo,
	} {
		t.Run(name, func(t *testing.T) {
			document := `
tun:
  enable: true
  stack: ` + name + `
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
			mihomo, ours := parseBoth(t, document)
			if mihomo.General.Tun.Stack != stack {
				t.Fatalf("fixture is wrong: upstream parsed %q as %v", name, mihomo.General.Tun.Stack)
			}

			finalizeConfigForIOS(ours, true)

			if ours.General.Tun.Stack != mihomo.General.Tun.Stack {
				t.Errorf("tun.stack: mihomo %v, ours %v -- the pipeline leaves the value as written",
					mihomo.General.Tun.Stack, ours.General.Tun.Stack)
			}
		})
	}
}

func TestTheRecordsNameTheStackThatRuns(t *testing.T) {
	want := strings.ToLower(C.TunGo.String())
	var rule *deviationRule
	for i := range deviationRules {
		if deviationRules[i].field == "tun.stack" {
			rule = &deviationRules[i]
		}
	}
	if rule == nil {
		t.Fatal("tun.stack has no deviation row")
	}
	if rule.forcedValue != want {
		t.Errorf("deviation row: forcedValue %q, the tunnel runs %q", rule.forcedValue, want)
	}
	if upstream := strings.ToLower(config.DefaultRawConfig().Tun.Stack.String()); rule.upstreamDefault != upstream {
		t.Errorf("deviation row says upstream defaults to %q, upstream says %q", rule.upstreamDefault, upstream)
	}
	found := false
	for _, annotation := range fieldAnnotations() {
		if annotation.Pattern == "tun.stack" {
			found = true
			if annotation.Default != want {
				t.Errorf("field table default %q, the pipeline runs %q", annotation.Default, want)
			}
		}
	}
	if !found {
		t.Fatal("tun.stack has no field table row")
	}
}
