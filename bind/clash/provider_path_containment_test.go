package clash

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/config"
	C "github.com/ProjectClash/Clash/constant"
)

func stagingRawWithProviderPath(t *testing.T, kind, path string) *config.RawConfig {
	t.Helper()
	raw := &config.RawConfig{}
	definition := map[string]any{"type": "file", "path": path}
	if kind == "rule" {
		definition["behavior"] = "classical"
		definition["format"] = "yaml"
		raw.RuleProvider = map[string]map[string]any{"probe": definition}
	} else {
		raw.ProxyProvider = map[string]map[string]any{"probe": definition}
	}
	return raw
}

func TestStagingRefusesAProviderPathOutsideTheContainer(t *testing.T) {
	home := compileStagingHome(t)
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("root:x:0:0:secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, kind := range []string{"rule", "proxy"} {
		for _, spelling := range []string{
			outside,
			filepath.Join(home, "..", filepath.Base(filepath.Dir(outside)), "secret.txt"),
		} {
			raw := stagingRawWithProviderPath(t, kind, spelling)
			runtime, err := stageProviderRuntime(raw, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), false)
			if runtime != nil {
				runtime.close()
			}
			if err == nil {
				t.Fatalf("%s provider with path %q was staged; a subscription can read any file the process can", kind, spelling)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatalf("%s: the refusal echoes the attacker-controlled path: %v", kind, err)
			}
		}
	}
}

func TestStagingAcceptsAProviderPathInsideTheContainer(t *testing.T) {
	home := compileStagingHome(t)
	inside := filepath.Join(home, "published-rule.yaml")
	if err := os.WriteFile(inside, []byte("payload:\n  - DOMAIN,example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	raw := stagingRawWithProviderPath(t, "rule", inside)
	runtime, err := stageProviderRuntime(raw, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), false)
	if err != nil {
		t.Fatalf("an in-container provider must stage: %v", err)
	}
	defer runtime.close()

	relative := stagingRawWithProviderPath(t, "rule", "published-rule.yaml")
	relativeRuntime, err := stageProviderRuntime(relative, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), false)
	if err != nil {
		t.Fatalf("a relative in-container provider must stage: %v", err)
	}
	relativeRuntime.close()
	_ = C.Path.HomeDir()
}

func TestStagingRefusesASymlinkEscapingTheContainer(t *testing.T) {
	home := compileStagingHome(t)
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("root:x:0:0:secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(home, "innocent.yaml")
	if err := os.Symlink(outside, link); err != nil {
		t.Fatal(err)
	}

	raw := stagingRawWithProviderPath(t, "rule", link)
	runtime, err := stageProviderRuntime(raw, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), false)
	if runtime != nil {
		runtime.close()
	}
	if err == nil {
		t.Fatal("a symlink escaping the container was staged; containment must resolve links, not just clean the path")
	}
}

func TestCompileRefusalDoesNotEchoFileContent(t *testing.T) {
	secret := "TOKEN-abcdef0123456789-DO-NOT-LOG"
	_, reason := domainsFromClassicalReason([]byte(secret + "\n"))
	if reason == "" {
		t.Fatal("a non-rule line must still be refused")
	}
	if strings.Contains(reason, secret) || strings.Contains(reason, secret[:12]) {
		t.Fatalf("the refusal reason echoes file content: %q", reason)
	}

	compilation := compileRuleProviderPayload([]byte(secret+"\n"), "classical", "yaml")
	if compilation.Reason == "" {
		t.Fatal("the compiler must still refuse")
	}
	if strings.Contains(compilation.Reason, secret) || strings.Contains(compilation.Reason, secret[:12]) {
		t.Fatalf("the compiler's reason echoes file content: %q", compilation.Reason)
	}
	if !strings.Contains(compilation.Reason, "1") {
		t.Fatalf("the reason names no line number, so it cannot be acted on: %q", compilation.Reason)
	}
}
