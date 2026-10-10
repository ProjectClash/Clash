package clash

import (
	"testing"

	"github.com/ProjectClash/Clash/log"
)

func TestDebugRoutesFollowTheConfiguredLogLevel(t *testing.T) {
	for name, document := range map[string]string{
		"debug": `
log-level: debug
external-controller: 127.0.0.1:9090
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`,
		"info": `
log-level: info
external-controller: 127.0.0.1:9090
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`,
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := parseConfigForIOS(document, true)
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			server := controllerServerConfig(cfg, "/tmp/clash-debug-test.sock")
			want := cfg.General.LogLevel == log.DEBUG
			if server.IsDebug != want {
				t.Errorf("log-level %s produced IsDebug=%v, want %v", name, server.IsDebug, want)
			}
			if name == "debug" && !want {
				t.Fatal("fixture is wrong: log-level debug did not parse as log.DEBUG")
			}
		})
	}
}
