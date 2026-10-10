package clash

import (
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/config"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/constant/features"
)

func TestControllerConfigReachesTheServerAsWritten(t *testing.T) {
	const document = `
external-controller: 0.0.0.0:9090
external-controller-tls: 0.0.0.0:9443
secret: hunter2
external-doh-server: /dns-query
external-controller-cors:
  allow-origins: ["https://example.invalid"]
  allow-private-network: true
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	_, ours := parseBoth(t, document)
	finalizeConfigForIOS(ours, true)

	got := controllerServerConfig(ours, "/tmp/clash-test.sock")
	if got.Addr != "0.0.0.0:9090" {
		t.Errorf("addr = %q, want the address the user wrote", got.Addr)
	}
	if got.TLSAddr != "0.0.0.0:9443" {
		t.Errorf("tls addr = %q, want the address the user wrote", got.TLSAddr)
	}
	if got.Secret != "hunter2" {
		t.Error("secret did not reach the server")
	}
	if got.DohServer != "/dns-query" {
		t.Errorf("doh server = %q", got.DohServer)
	}
	if len(got.Cors.AllowOrigins) != 1 {
		t.Errorf("cors origins = %v", got.Cors.AllowOrigins)
	}
	if got.UnixAddr != "/tmp/clash-test.sock" {
		t.Errorf("the binding's own socket was dropped: %q", got.UnixAddr)
	}
}

func TestNoPermissionIsRequiredForTheControllerToRun(t *testing.T) {
	const document = `
external-controller: 0.0.0.0:9090
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	_, ours := parseBoth(t, document)
	finalizeConfigForIOS(ours, true)
	if got := controllerServerConfig(ours, "/tmp/clash-test.sock"); got.Addr == "" {
		t.Error("the controller address was dropped with no permission asked for; the ruling is " +
			"that what the user writes is what runs")
	}
}

func TestAnUnguardedControllerIsHonouredAndAnnounced(t *testing.T) {
	const document = `
external-controller: 0.0.0.0:9090
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	_, ours := parseBoth(t, document)
	finalizeConfigForIOS(ours, true)
	if got := controllerServerConfig(ours, "/tmp/s.sock"); got.Addr != "0.0.0.0:9090" {
		t.Errorf("addr = %q; an unguarded controller is not downgraded to loopback -- that was "+
			"stricter than upstream and not required by the platform, which is this repository's "+
			"own definition of an invented constraint", got.Addr)
	}
	notices := unguardedControllerNotices(mustUnmarshalRaw(t, document))
	if len(notices) == 0 {
		t.Error("nothing was said about an unguarded network-reachable controller")
	}
	for _, notice := range notices {
		if strings.Contains(notice, "refus") || strings.Contains(notice, "not started") {
			t.Errorf("the notice describes a restriction that no longer exists: %s", notice)
		}
	}
}

func TestASilentConfigurationLeavesOnlyTheBindingSocket(t *testing.T) {
	const document = `
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	_, ours := parseBoth(t, document)
	finalizeConfigForIOS(ours, true)
	got := controllerServerConfig(ours, "/tmp/clash-test.sock")
	if got.Addr != "" || got.TLSAddr != "" {
		t.Errorf("a network listener appeared for a configuration that asked for none: %+v", got)
	}
	if got.UnixAddr != "/tmp/clash-test.sock" {
		t.Error("the binding's own socket was dropped")
	}
}

func TestExternalUIIsHonouredAsUpstreamHonoursIt(t *testing.T) {
	const document = `
external-controller: 127.0.0.1:9090
external-ui: ui
external-ui-name: dashboard
external-ui-url: https://example.invalid/ui.zip
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, document)
	finalizeConfigForIOS(ours, true)

	for name, pair := range map[string][2]string{
		"external-ui":      {mihomo.Controller.ExternalUI, ours.Controller.ExternalUI},
		"external-ui-name": {mihomo.Controller.ExternalUIName, ours.Controller.ExternalUIName},
		"external-ui-url":  {mihomo.Controller.ExternalUIURL, ours.Controller.ExternalUIURL},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s: mihomo %q, ours %q", name, pair[0], pair[1])
		}
	}
}

func TestExternalUIPathHandlingMatchesUpstreamUnderEitherFeatureSet(t *testing.T) {
	document := func(path string) string {
		return `
external-controller: 127.0.0.1:9090
external-ui: ` + path + `
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	}

	for _, path := range []string{"/etc/clash/ui", "ui"} {
		_, upstreamErr := config.Parse([]byte(document(path)))
		_, oursErr := parseConfigForIOS(document(path), true)
		if (upstreamErr == nil) != (oursErr == nil) {
			t.Errorf("external-ui %q: upstream %v, ours %v -- the yardstick decides which paths a "+
				"configuration may name, in whichever build this is", path, upstreamErr, oursErr)
		}
	}

	if _, err := parseConfigForIOS(document("ui"), true); err != nil {
		t.Errorf("a relative external-ui must parse: %v", err)
	}
}

func TestSafePathCheckingIsDisarmedInEveryShippedArtifact(t *testing.T) {
	outside := "/etc/clash/ui"
	safe := C.Path.IsSafePath(outside)
	if features.CMFA != safe {
		t.Errorf("features.CMFA=%v but IsSafePath(%q)=%v; constant/path.go:88 short-circuits on "+
			"CMFA, so these two cannot disagree", features.CMFA, outside, safe)
	}
	if !features.CMFA {
		t.Log("this run is NOT the shipped feature set: cmd/build_libbox builds every Apple " +
			"artifact with -tags cmfa, so a suite run without it measures a different binary")
	}
}
