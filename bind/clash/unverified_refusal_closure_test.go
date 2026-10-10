package clash

import (
	"strings"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/config"
)

func TestNegativeHealthCheckIntervalWouldPanicUpstream(t *testing.T) {
	negative := -1
	converted := time.Duration(uint(negative)) * time.Second
	if converted > 0 {
		t.Fatalf("the conversion no longer produces a non-positive duration (%v); the refusal's ground "+
			"has moved and needs re-deciding rather than re-asserting", converted)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("time.NewTicker no longer panics on a non-positive interval. The refusal was kept " +
					"because a panic in the extension takes the tunnel down; if that is no longer true, ask " +
					"again whether refusing is right.")
			}
		}()
		ticker := time.NewTicker(converted)
		ticker.Stop()
	}()

	y := "proxies:\n  - {name: n, type: ss, server: e.com, port: 8388, cipher: aes-128-gcm, password: p}\n" +
		"proxy-providers:\n  p:\n    type: inline\n    payload:\n" +
		"      - {name: m, type: ss, server: e.com, port: 8388, cipher: aes-128-gcm, password: p}\n" +
		"    health-check: {enable: true, url: \"http://e.com\", interval: -1}\n"
	if err := mihomoVerdict(t, y); err != nil {
		t.Fatalf("mihomo now refuses this at parse, so this tree no longer needs to: %v", err)
	}
	setupConfigPipelineTest(t)
	if _, err := parseConfigForIOS(y, true); err == nil {
		t.Fatal("a health-check interval that panics the ticker reached the core")
	}
}

func TestNoRuntimeProfileReachesTheNameserverRefusal(t *testing.T) {
	document := "proxies:\n  - {name: n, type: ss, server: e.com, port: 8388, cipher: aes-128-gcm, password: p}\n" +
		"dns:\n  enable: true\n  enhanced-mode: fake-ip\n"

	reached := []string{}
	for _, profile := range allRuntimeProfiles() {
		for _, underNE := range []bool{true, false} {
			raw, err := config.UnmarshalRawConfig([]byte(document))
			if err != nil {
				t.Fatalf("fixture does not parse: %v", err)
			}
			policy := runtimePolicyFor(profile, underNE)
			normalizeRawConfigForApple(raw, policy)
			cfg, err := config.ParseRawConfig(raw)
			if err != nil {
				t.Fatalf("%s underNE=%v: the normalized document does not parse: %v", profile, underNE, err)
			}
			if err := validateForApple(cfg, raw, policy); err != nil &&
				strings.Contains(err.Error(), "dns.nameserver must be set explicitly") {
				reached = append(reached, profile.String())
			}
		}
	}
	if len(reached) != 0 {
		t.Fatalf("these profiles reach the nameserver refusal: %v -- the registry records it as "+
			"reachability-unknown, and it is now known. A path that reaches it needs the repair, "+
			"not the refusal.", reached)
	}
}
