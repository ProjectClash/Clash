package clash

import (
	"strings"
	"testing"
)

func TestAllowLanIsHonouredWithoutTheAppSayingAnything(t *testing.T) {
	const document = `
mixed-port: 7890
allow-lan: true
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, document)
	if ours.General.AllowLan != mihomo.General.AllowLan || !ours.General.AllowLan {
		t.Errorf("allow-lan: mihomo %v, ours %v -- the file asked for it and nothing overrode it",
			mihomo.General.AllowLan, ours.General.AllowLan)
	}
}

func TestAllowLanIsHonouredOnceTheAppPermitsIt(t *testing.T) {
	const document = `
mixed-port: 7890
allow-lan: true
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	SetAllowLanPermitted(true)
	t.Cleanup(func() { SetAllowLanPermitted(true) })

	mihomo, ours := parseBoth(t, document)
	if ours.General.AllowLan != mihomo.General.AllowLan {
		t.Errorf("allow-lan: mihomo %v, ours %v -- once permitted this is upstream's field again",
			mihomo.General.AllowLan, ours.General.AllowLan)
	}
}

func TestRevokingThePermissionTakesEffectOnTheNextParse(t *testing.T) {
	const document = `
mixed-port: 7890
allow-lan: true
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	SetAllowLanPermitted(true)
	t.Cleanup(func() { SetAllowLanPermitted(true) })
	if _, ours := parseBoth(t, document); !ours.General.AllowLan {
		t.Fatal("fixture is wrong: permitted parse did not honour allow-lan")
	}

	SetAllowLanPermitted(false)
	if _, ours := parseBoth(t, document); ours.General.AllowLan {
		t.Error("allow-lan survived the permission being revoked; a reload is the moment this " +
			"has to be re-read, not the next process launch")
	}
}

func TestGatingAllowLanIsReportedWithSomewhereToGo(t *testing.T) {
	const document = `
mixed-port: 7890
allow-lan: true
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	SetAllowLanPermitted(false)
	t.Cleanup(func() { SetAllowLanPermitted(true) })

	deviations, err := collectConfigDeviations(document, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true))
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	for _, deviation := range deviations {
		if deviation.Field != "allow-lan" {
			continue
		}
		if deviation.Alternative == "" {
			t.Error("the gate offers no alternative; a reader who wanted a LAN proxy is told no " +
				"and not told where yes lives")
		}
		if !strings.Contains(deviation.Source, "listener.go") {
			t.Errorf("source = %q, want the line that shows what allow-lan actually binds", deviation.Source)
		}
		SetAllowLanPermitted(true)
		after, _ := collectConfigDeviations(document, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true))
		for _, d := range after {
			if d.Field == "allow-lan" {
				t.Error("allow-lan is still reported as a deviation after the app permitted it")
			}
		}
		return
	}
	t.Error("allow-lan was gated and nothing was reported")
}

func TestPermissionAloneExposesNothingWithoutTheConfigurationAsking(t *testing.T) {
	const silentAboutLan = `
mixed-port: 7890
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	SetAllowLanPermitted(true)
	t.Cleanup(func() { SetAllowLanPermitted(true) })

	mihomo, ours := parseBoth(t, silentAboutLan)
	if ours.General.AllowLan {
		t.Error("the app switch turned allow-lan on for a configuration that never asked for it")
	}
	if ours.General.AllowLan != mihomo.General.AllowLan {
		t.Errorf("allow-lan: mihomo %v, ours %v -- a configuration silent about allow-lan should "+
			"read the same on both", mihomo.General.AllowLan, ours.General.AllowLan)
	}
	if ours.General.MixedPort != 7890 {
		t.Errorf("mixed-port = %d, want 7890 -- the listener the user asked for still opens, on "+
			"127.0.0.1", ours.General.MixedPort)
	}
}
