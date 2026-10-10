package clash

import (
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/config"
)

func TestControllerSurfaceMatchesUpstream(t *testing.T) {
	const document = `
external-controller: 127.0.0.1:9090
external-controller-tls: 127.0.0.1:9443
external-controller-unix: /tmp/clash-test.sock
external-controller-cors:
  allow-origins: ["https://example.invalid"]
  allow-private-network: true
external-doh-server: /dns-query
secret: hunter2
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	mihomo, ours := parseBoth(t, document)

	for name, pair := range map[string][2]string{
		"external-controller":      {mihomo.Controller.ExternalController, ours.Controller.ExternalController},
		"external-controller-tls":  {mihomo.Controller.ExternalControllerTLS, ours.Controller.ExternalControllerTLS},
		"external-controller-unix": {mihomo.Controller.ExternalControllerUnix, ours.Controller.ExternalControllerUnix},
		"external-doh-server":      {mihomo.Controller.ExternalDohServer, ours.Controller.ExternalDohServer},
		"secret":                   {mihomo.Controller.Secret, ours.Controller.Secret},
	} {
		if pair[0] != pair[1] {
			t.Errorf("%s: mihomo %q, ours %q", name, pair[0], pair[1])
		}
	}
	if len(mihomo.Controller.Cors.AllowOrigins) != len(ours.Controller.Cors.AllowOrigins) {
		t.Errorf("cors allow-origins: mihomo %d, ours %d",
			len(mihomo.Controller.Cors.AllowOrigins), len(ours.Controller.Cors.AllowOrigins))
	}
}

func TestExternalUIIsNoLongerHeldBackByAnArchitectureDecision(t *testing.T) {
	const document = `
external-controller: 127.0.0.1:9090
external-ui: ui
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	_, ours := parseBoth(t, document)
	finalizeConfigForIOS(ours, true)
	if ours.Controller.ExternalUI == "" {
		t.Error("external-ui was stripped again. This is not a platform limit -- an extension " +
			"may make outbound requests, and upstream only downloads when the directory the app " +
			"was supposed to fill is empty. Re-stripping needs a platform fact")
	}
}

func TestANetworkReachableControllerWithoutASecretIsAnnounced(t *testing.T) {
	for name, testCase := range map[string]struct {
		document string
		announce bool
	}{
		"wildcard bind, no secret": {"external-controller: 0.0.0.0:9090\n", true},
		"wildcard bind, secret":    {"external-controller: 0.0.0.0:9090\nsecret: hunter2\n", false},
		"loopback, no secret":      {"external-controller: 127.0.0.1:9090\n", false},
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := config.UnmarshalRawConfig([]byte(testCase.document +
				"proxies: []\nproxy-groups: []\nrules:\n  - MATCH,DIRECT\n"))
			if err != nil {
				t.Fatalf("fixture: %v", err)
			}
			notices := unguardedControllerNotices(raw)
			if got := len(notices) > 0; got != testCase.announce {
				t.Errorf("announced = %v, want %v (%v)", got, testCase.announce, notices)
			}
			for _, notice := range notices {
				if strings.Contains(notice, "hunter2") {
					t.Error("the notice renders the secret")
				}
			}
		})
	}
}
