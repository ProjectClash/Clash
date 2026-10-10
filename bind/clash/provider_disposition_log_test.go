package clash

import (
	"strings"
	"testing"
)

func TestEveryRuleProviderSaysWhatBecameOfIt(t *testing.T) {
	for name, testCase := range map[string]struct {
		compile bool
		want    string
	}{
		"staged without compiling": {compile: false, want: "staged as source, not compiled on this profile"},
		"kept as source":           {compile: true, want: "kept as source, every rule loads"},
	} {
		t.Run(name, func(t *testing.T) {
			compileStagingHome(t)
			source := writeRuleSource(t, "set.yaml",
				"payload:\n  - DOMAIN-KEYWORD,ads\n  - IP-CIDR,10.0.0.0/8\n")
			raw := rawWithRuleProvider(source, "classical", "yaml")
			logBuffer := capturePublishLog(t)

			runtime, err := stageProviderRuntime(raw,
				runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), testCase.compile)
			if err != nil {
				t.Fatalf("stage: %v", err)
			}
			defer runtime.close()

			logged := logBuffer.String()
			var line string
			for _, candidate := range strings.Split(logged, "\n") {
				if strings.Contains(candidate, testCase.want) {
					line = candidate
					break
				}
			}
			if line == "" {
				t.Fatalf("no disposition for the provider on this path; wanted %q in:\n%s",
					testCase.want, logged)
			}
			if !strings.Contains(line, "reject") {
				t.Errorf("the disposition line does not name the provider: %s", line)
			}
			if strings.Contains(logged, "[iOS] rule provider") {
				t.Errorf("provider lines still claim iOS on every Apple platform:\n%s", logged)
			}
		})
	}
}

func TestACompiledRuleProviderIsAccountedForToo(t *testing.T) {
	compileStagingHome(t)
	source := writeRuleSource(t, "domains.yaml",
		"payload:\n  - DOMAIN,example.com\n  - DOMAIN-SUFFIX,example.org\n")
	raw := rawWithRuleProvider(source, "classical", "yaml")
	logBuffer := capturePublishLog(t)

	runtime, err := stageProviderRuntime(raw,
		runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), true)
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	defer runtime.close()

	if logged := logBuffer.String(); !strings.Contains(logged, "compiled to MRS") {
		t.Fatalf("a compiled set produced no disposition:\n%s", logged)
	}
}
