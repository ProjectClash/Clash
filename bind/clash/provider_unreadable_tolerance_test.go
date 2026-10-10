package clash

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/config"
	C "github.com/ProjectClash/Clash/constant"
)

const substoreShapedPayload = "KyCloud-HK01 = ss, 198.51.100.20, 8388, " +
	"encrypt-method=aes-256-gcm, password=secret\n" +
	"KyCloud-SG02 = ss, 198.51.100.21, 8388, " +
	"encrypt-method=aes-256-gcm, password=secret\n"

func rawWithFileProxyProvider(t *testing.T, name, content string) *config.RawConfig {
	t.Helper()
	source := filepath.Join(C.Path.HomeDir(), name)
	if err := os.WriteFile(source, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	raw := &config.RawConfig{}
	raw.ProxyProvider = map[string]map[string]any{
		"air": {"type": "file", "path": source},
	}
	return raw
}

func TestAnUnreadableProxyProviderDoesNotEndTheActivation(t *testing.T) {
	if _, _, err := sanitizeProxyProviderPayloadForIOS("", []byte(substoreShapedPayload), false); err == nil {
		t.Fatal("the payload parsed; this fixture no longer reproduces the reader's shape")
	}

	t.Run("unreadable payload stages verbatim and the activation continues", func(t *testing.T) {
		home := compileStagingHome(t)
		raw := rawWithFileProxyProvider(t, "substore.txt", substoreShapedPayload)

		runtime, err := stageProviderRuntime(raw, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), false)
		if err != nil {
			t.Fatalf("an unreadable proxy provider still ends the activation: %v", err)
		}
		defer runtime.close()

		staged, err := os.ReadFile(raw.ProxyProvider["air"]["path"].(string))
		if err != nil {
			t.Fatal(err)
		}
		if string(staged) != substoreShapedPayload {
			t.Fatalf("staged %d bytes that are not the published source", len(staged))
		}
		entry := manifestEntry(t, home, "proxy", "air")
		if !strings.Contains(entry, `"unreadableWarn"`) {
			t.Fatalf("the failure left no account in the manifest: %s", entry)
		}
	})

	t.Run("readable payload is staged as published", func(t *testing.T) {
		compileStagingHome(t)
		readable := "proxies:\n  - name: a\n    type: ss\n    server: 198.51.100.22\n    port: 443\n    cipher: aes-128-gcm\n    password: x\n    interface-name: en0\n"
		raw := rawWithFileProxyProvider(t, "readable.yaml", readable)

		runtime, err := stageProviderRuntime(raw, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), false)
		if err != nil {
			t.Fatalf("stage: %v", err)
		}
		defer runtime.close()

		staged, err := os.ReadFile(raw.ProxyProvider["air"]["path"].(string))
		if err != nil {
			t.Fatal(err)
		}
		if string(staged) != readable {
			t.Fatalf("a readable payload must be staged as published: %q", staged)
		}
	})
}
