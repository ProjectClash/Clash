package clash

import (
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/config"
	C "github.com/ProjectClash/Clash/constant"
)

func TestSilentConfigurationStillGetsGvisor(t *testing.T) {
	const document = `
tun:
  enable: true
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, document)
	if mihomo.General.Tun.Stack != C.TunMips {
		t.Fatalf("fixture is wrong, not the code: upstream parsed a silent tun.stack as %v, not mips",
			mihomo.General.Tun.Stack)
	}

	finalizeConfigForIOS(ours, true)

	if ours.General.Tun.Stack != C.TunGvisor {
		t.Errorf("a configuration that never mentioned tun.stack got %v; the default has to stay "+
			"exactly where the device A/B left it until a device A/B moves it", ours.General.Tun.Stack)
	}
}

func TestAnExplicitStackIsHonoured(t *testing.T) {
	for name, stack := range map[string]C.TUNStack{
		"system": C.TunSystem,
		"mixed":  C.TunMixed,
		"gvisor": C.TunGvisor,
		"mips":   C.TunMips,
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
				t.Errorf("tun.stack: mihomo %v, ours %v -- the capability was measured under this "+
					"extension's own entitlements and nothing in it is denied, so there is no "+
					"platform fact left to override the user with",
					mihomo.General.Tun.Stack, ours.General.Tun.Stack)
			}
		})
	}
}

func TestTunStackNoLongerAppearsInTheDeviationReport(t *testing.T) {
	const document = `
tun:
  enable: true
  stack: system
  mtu: 1400
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	deviations, err := collectConfigDeviations(document, currentRuntimePolicy(true))
	if err != nil {
		t.Fatalf("collect deviations: %v", err)
	}
	for _, deviation := range deviations {
		if deviation.Field == "tun.stack" {
			t.Errorf("tun.stack is still reported as %q -- it is honoured now, so the entry is a "+
				"false statement rendered verbatim to a user", deviation.Effective)
		}
	}

	sawTunMTU := false
	for _, deviation := range deviations {
		if deviation.Field == "tun.mtu" {
			sawTunMTU = true
		}
	}
	if !sawTunMTU {
		t.Fatal("the deviation walk reported nothing for tun.mtu either, so this test proved " +
			"nothing about tun.stack -- it measured an empty list")
	}
}

func TestSilentConfigurationKeepsOneGvisorProcessorPerChannel(t *testing.T) {
	const document = `
tun:
  enable: true
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, document)
	if mihomo.General.Tun.ProcessorsPerChannel != 1 {
		t.Fatalf("fixture is wrong, not the code: upstream's silent default is %d, not 1",
			mihomo.General.Tun.ProcessorsPerChannel)
	}
	finalizeConfigForIOS(ours, true)
	if ours.General.Tun.ProcessorsPerChannel != 1 {
		t.Fatalf("a silent configuration reaches the tun with %d processors per channel; the device A/B chose 1",
			ours.General.Tun.ProcessorsPerChannel)
	}
}

func TestAppleUnwrittenStackIsWhatTheRecordsSay(t *testing.T) {
	want := strings.ToLower(appleUnwrittenTunStack.String())
	var rule *deviationRule
	for i := range deviationRules {
		if deviationRules[i].field == "tun.stack" {
			rule = &deviationRules[i]
		}
	}
	if rule == nil {
		t.Fatal("tun.stack has no deviation row")
	}
	if rule.forcedValue != want || !rule.unwrittenUnconditional {
		t.Errorf("deviation row: forcedValue %q unwrittenUnconditional %v, the pipeline runs %q",
			rule.forcedValue, rule.unwrittenUnconditional, want)
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
