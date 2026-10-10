package clash

import (
	"os"

	C "github.com/ProjectClash/Clash/constant"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/config"
)

func TestASkippedProviderIsNotSideUpdateable(t *testing.T) {
	setupConfigPipelineTest(t)

	home := t.TempDir()
	previousHome := C.Path.HomeDir()
	C.SetHomeDir(home)
	t.Cleanup(func() { C.SetHomeDir(previousHome) })

	absent := filepath.Join(home, "not-there.yaml")
	document := `
proxies:
  - {name: n, type: ss, server: e.com, port: 8388, cipher: aes-128-gcm, password: p}
proxy-providers:
  gone: {type: file, path: ` + absent + `}
`
	raw, err := config.UnmarshalRawConfig([]byte(document))
	if err != nil {
		t.Fatalf("fixture does not parse: %v", err)
	}

	runtime, err := stageProviderRuntime(raw, nePolicy(), false)
	if err != nil {
		t.Fatalf("a provider whose source is missing must not fail staging: %v", err)
	}
	if runtime != nil {
		t.Cleanup(runtime.close)
	}

	if path, _ := raw.ProxyProvider["gone"]["path"].(string); path != absent {
		t.Fatalf("the skipped provider's path was rewritten to %q; it must still name the source, "+
			"or this test is measuring a different code path than it describes", path)
	}

	if runtime == nil {
		return
	}
	if _, exists := runtime.entries[providerRuntimeKey("proxy", "gone")]; exists {
		t.Fatal("a provider that was skipped during staging has a runtime entry, so side-update would " +
			"accept it -- and with no shadow to write, it would write the App's published revision. " +
			"The skip must return before entries[] is touched.")
	}
}

func TestAStagedProviderKeepsItsRuntimeEntry(t *testing.T) {
	setupConfigPipelineTest(t)

	home := t.TempDir()
	previousHome := C.Path.HomeDir()
	C.SetHomeDir(home)
	t.Cleanup(func() { C.SetHomeDir(previousHome) })

	source := filepath.Join(home, "nodes.yaml")
	if err := os.WriteFile(source, []byte("proxies: []\n"), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	document := `
proxies:
  - {name: n, type: ss, server: e.com, port: 8388, cipher: aes-128-gcm, password: p}
proxy-providers:
  here: {type: file, path: ` + source + `}
`
	raw, err := config.UnmarshalRawConfig([]byte(document))
	if err != nil {
		t.Fatalf("fixture does not parse: %v", err)
	}
	runtime, err := stageProviderRuntime(raw, nePolicy(), false)
	if err != nil {
		t.Fatalf("staging a readable provider failed: %v", err)
	}
	if runtime == nil {
		t.Fatal("a readable file provider produced no runtime at all")
	}
	t.Cleanup(runtime.close)
	if _, exists := runtime.entries[providerRuntimeKey("proxy", "here")]; !exists {
		t.Fatal("a provider that staged normally lost its runtime entry, so side-update would refuse it")
	}
	if path, _ := raw.ProxyProvider["here"]["path"].(string); path == source || !strings.Contains(path, providerRuntimeDirectoryName) {
		t.Fatalf("a staged provider must be redirected to its shadow, got %q", path)
	}
}
