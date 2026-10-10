package clash

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/config"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/sirupsen/logrus"
)

const publishTestProxy = "proxies:\n" +
	"  - name: a\n    type: ss\n    server: 1.2.3.4\n    port: 443\n" +
	"    cipher: aes-128-gcm\n    password: x\n    interface-name: en0\n"

const publishTestRule = "payload:\n  - DOMAIN-SUFFIX,example.com\n  - PROCESS-NAME,Mail\n"

func publishTestConfig(t *testing.T, home string) string {
	t.Helper()
	proxyPath := filepath.Join(home, "published-proxy.yaml")
	rulePath := filepath.Join(home, "published-rule.yaml")
	if err := os.WriteFile(proxyPath, []byte(publishTestProxy), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rulePath, []byte(publishTestRule), 0o600); err != nil {
		t.Fatal(err)
	}
	return "" +
		"dns:\n  enable: true\n  nameserver: [8.8.8.8]\n" +
		"proxy-providers:\n  air:\n    type: file\n    path: " + proxyPath + "\n" +
		"rule-providers:\n  ads:\n    type: file\n    behavior: classical\n" +
		"    format: yaml\n    path: " + rulePath + "\n" +
		"proxy-groups:\n  - name: G\n    type: select\n    use: [air]\n" +
		"rules:\n  - RULE-SET,ads,G\n  - MATCH,DIRECT\n"
}

func stagedTree(t *testing.T, home string) map[string]string {
	t.Helper()
	root := filepath.Join(home, providerRuntimeDirectoryName)
	tree := map[string]string{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		payload, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		relative, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		tree[relative] = string(payload)
		return nil
	})
	if err != nil {
		t.Fatalf("walk staged tree: %v", err)
	}
	return tree
}

func capturePublishLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logBuffer bytes.Buffer
	logrus.SetOutput(&logBuffer)
	t.Cleanup(func() { logrus.SetOutput(os.Stdout) })
	return &logBuffer
}

func TestPublishLogsWhereItWroteAndTheVerdictCounts(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	home := options.WorkingPath
	C.SetHomeDir(home)
	rulePath := filepath.Join(home, "published-cidr.yaml")
	if err := os.WriteFile(rulePath,
		[]byte("payload:\n  - DOMAIN-SUFFIX,example.com\n  - IP-CIDR,10.0.0.0/8,no-resolve\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	content := "" +
		"dns:\n  enable: true\n  nameserver: [8.8.8.8]\n" +
		"rule-providers:\n  cidr:\n    type: file\n    behavior: classical\n" +
		"    format: yaml\n    path: " + rulePath + "\n" +
		"rules:\n  - RULE-SET,cidr,DIRECT\n  - MATCH,DIRECT\n"
	logBuffer := capturePublishLog(t)

	if err := StageProvidersForPublish(content, RuntimeProfileIOSPacketTunnel, true); err != nil {
		t.Fatalf("StageProvidersForPublish: %v", err)
	}

	logged := logBuffer.String()
	if !strings.Contains(logged, stagedProviderParentDirectory()) {
		t.Fatalf("publish log never names the destination directory %q:\n%s", stagedProviderParentDirectory(), logged)
	}
	for _, want := range []string{"compiled=0", "indexed=1", "notCompilable=0", "keptSource=0"} {
		if !strings.Contains(logged, want) {
			t.Fatalf("publish log misses %q:\n%s", want, logged)
		}
	}
}

func TestPublishLogsEvenWhenNothingIsFileBacked(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	C.SetHomeDir(options.WorkingPath)
	logBuffer := capturePublishLog(t)

	content := "dns:\n  enable: true\n  nameserver: [8.8.8.8]\nrules:\n  - MATCH,DIRECT\n"
	if err := StageProvidersForPublish(content, RuntimeProfileIOSPacketTunnel, true); err != nil {
		t.Fatalf("StageProvidersForPublish: %v", err)
	}

	logged := logBuffer.String()
	if !strings.Contains(logged, stagedProviderParentDirectory()) ||
		!strings.Contains(logged, "compiled=0") {
		t.Fatalf("a publish that staged nothing must still say where it would have written and that every count is zero:\n%s", logged)
	}
}

func TestPublishStagesForTheProfileTheExtensionWillRun(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	home := options.WorkingPath
	C.SetHomeDir(home)
	content := publishTestConfig(t, home)

	if err := StageProvidersForPublish(content, RuntimeProfileIOSPacketTunnel, false); err != nil {
		t.Fatalf("StageProvidersForPublish: %v", err)
	}
	published := stagedTree(t, home)
	if len(published) < 3 {
		t.Fatalf("publish staged %d files, want a manifest and two providers", len(published))
	}

	manifestName := providerRuntimeManifestName
	raw, exists := published[manifestName]
	if !exists {
		t.Fatalf("publish wrote no manifest; %d files staged", len(published))
	}
	var manifest stagedProviderManifest
	if err := json.Unmarshal([]byte(raw), &manifest); err != nil {
		t.Fatalf("decode published manifest: %v", err)
	}
	extensionPolicy := runtimePolicyFor(runtimeProfileIOSPacketTunnel, true)
	if manifest.Policy != stagedPolicyFingerprint(extensionPolicy) {
		t.Fatal("published manifest carries the App's policy, so the extension will miss every entry")
	}
}

func TestPublishAndExtensionStagingAgreeByteForByte(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	home := options.WorkingPath
	C.SetHomeDir(home)
	content := publishTestConfig(t, home)

	if err := StageProvidersForPublish(content, RuntimeProfileIOSPacketTunnel, false); err != nil {
		t.Fatalf("StageProvidersForPublish: %v", err)
	}
	byPublish := stagedTree(t, home)

	if err := os.RemoveAll(filepath.Join(home, providerRuntimeDirectoryName)); err != nil {
		t.Fatal(err)
	}
	raw, err := config.UnmarshalRawConfig([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stageProviderRuntime(raw, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), false); err != nil {
		t.Fatalf("stageProviderRuntime: %v", err)
	}
	byExtension := stagedTree(t, home)

	if len(byPublish) != len(byExtension) {
		t.Fatalf("published %d files, extension staged %d", len(byPublish), len(byExtension))
	}
	for name, publishedPayload := range byPublish {
		extensionPayload, exists := byExtension[name]
		if !exists {
			t.Fatalf("the extension did not produce %q", name)
		}
		if publishedPayload != extensionPayload {
			t.Fatalf("%q differs between publish and extension staging", name)
		}
	}
}

func TestExtensionReadsNoProviderAfterAPublish(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	home := options.WorkingPath
	C.SetHomeDir(home)
	content := publishTestConfig(t, home)

	if err := StageProvidersForPublish(content, RuntimeProfileIOSPacketTunnel, false); err != nil {
		t.Fatalf("StageProvidersForPublish: %v", err)
	}

	raw, err := config.UnmarshalRawConfig([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	startupProbing.Store(true)
	defer startupProbing.Store(false)
	before := len(StartupPhaseTrace())
	if _, err := stageProviderRuntime(raw, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), false); err != nil {
		t.Fatalf("stageProviderRuntime after publish: %v", err)
	}
	trace := StartupPhaseTrace()[before:]
	if !bytes.Contains([]byte(trace), []byte("hit=2")) {
		t.Fatalf("expected both providers served from the publish, trace = %q", trace)
	}
	if !bytes.Contains([]byte(trace), []byte("read=0/")) {
		t.Fatalf("the extension still read provider files after a publish, trace = %q", trace)
	}
}

func TestAPublishForAnotherProfileIsNotServed(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	home := options.WorkingPath
	C.SetHomeDir(home)
	content := publishTestConfig(t, home)

	if err := StageProvidersForPublish(content, RuntimeProfileMacOSPacketTunnel, false); err != nil {
		t.Fatalf("StageProvidersForPublish: %v", err)
	}
	raw, err := config.UnmarshalRawConfig([]byte(content))
	if err != nil {
		t.Fatal(err)
	}
	startupProbing.Store(true)
	defer startupProbing.Store(false)
	before := len(StartupPhaseTrace())
	if _, err := stageProviderRuntime(raw, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true), false); err != nil {
		t.Fatal(err)
	}
	trace := StartupPhaseTrace()[before:]
	if !bytes.Contains([]byte(trace), []byte("hit=0")) {
		t.Fatalf("a macOS publish was served to an iOS packet tunnel, trace = %q", trace)
	}
}

func TestPublishDoesNotRefuseAnUnreadableRuleSet(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	home := options.WorkingPath
	C.SetHomeDir(home)
	proxyPath := filepath.Join(home, "published-proxy.yaml")
	if err := os.WriteFile(proxyPath, []byte(publishTestProxy), 0o600); err != nil {
		t.Fatal(err)
	}
	brokenPath := filepath.Join(home, "broken-rule.mrs")
	if err := os.WriteFile(brokenPath, []byte("<!DOCTYPE html><html>404</html>"), 0o600); err != nil {
		t.Fatal(err)
	}
	content := "" +
		"dns:\n  enable: true\n  nameserver: [8.8.8.8]\n" +
		"proxy-providers:\n  air:\n    type: file\n    path: " + proxyPath + "\n" +
		"rule-providers:\n  broken:\n    type: file\n    behavior: domain\n" +
		"    format: mrs\n    path: " + brokenPath + "\n" +
		"proxy-groups:\n  - name: G\n    type: select\n    use: [air]\n" +
		"rules:\n  - MATCH,DIRECT\n"

	if err := StageProvidersForPublish(content, RuntimeProfileIOSPacketTunnel, false); err != nil {
		t.Fatalf("an unreadable rule set must not fail the publish: %v", err)
	}
	staged := stagedTree(t, home)
	if _, exists := staged[providerRuntimeManifestName]; !exists {
		t.Fatal("publish wrote no manifest for a configuration with one unreadable rule set")
	}
}
