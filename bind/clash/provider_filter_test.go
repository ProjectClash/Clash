package clash

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/ProjectClash/Clash/tunnel"
)

const unparsableProxyType = "clash-nonexistent-proto"

func proxyPayload(nodes ...string) []byte {
	var buffer bytes.Buffer
	buffer.WriteString("proxies:\n")
	for _, node := range nodes {
		buffer.WriteString("  - ")
		buffer.WriteString(node)
		buffer.WriteString("\n")
	}
	return buffer.Bytes()
}

func TestSanitizeProxyProviderRuntimeDefersParseToMihomo(t *testing.T) {
	payload := proxyPayload(
		"{name: Good, type: direct}",
		fmt.Sprintf("{name: FutureProto, type: %s}", unparsableProxyType),
	)
	prepared, stripped, err := sanitizeProxyProviderPayloadForIOS("", payload, false)
	if err != nil {
		t.Fatalf("runtime staging must not parse-fail on an unparsable node: %v", err)
	}
	if len(stripped) != 0 {
		t.Fatalf("unexpected egress strip: %v", stripped)
	}
	if !bytes.Equal(prepared, payload) {
		t.Fatalf("runtime staging must pass the payload through unchanged:\n got: %q\nwant: %q", prepared, payload)
	}
}

func TestSanitizeProxyProviderStandaloneParseValidates(t *testing.T) {
	payload := proxyPayload(
		"{name: Good, type: direct}",
		fmt.Sprintf("{name: FutureProto, type: %s}", unparsableProxyType),
	)
	if _, _, err := sanitizeProxyProviderPayloadForIOS("", payload, true); err == nil {
		t.Fatal("the standalone pre-fetch check must reject an unparsable node")
	}
}

func TestSanitizeProxyProviderRuntimeKeepsANodesOwnEgressFields(t *testing.T) {
	payload := proxyPayload(
		"{name: A, type: direct}",
		"{name: B, type: direct, interface-name: en0, routing-mark: 233}",
	)
	prepared, stripped, err := sanitizeProxyProviderPayloadForIOS("", payload, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(stripped) != 0 || !bytes.Equal(prepared, payload) {
		t.Fatalf("a node's egress fields must pass through as written: stripped=%v prepared=%q", stripped, prepared)
	}
}

func TestSanitizeProxyProviderRuntimeCleanPassthrough(t *testing.T) {
	payload := proxyPayload("{name: A, type: direct}", "{name: B, type: direct}")
	prepared, stripped, err := sanitizeProxyProviderPayloadForIOS("", payload, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(stripped) != 0 {
		t.Fatalf("unexpected egress strip: %v", stripped)
	}
	if !bytes.Equal(prepared, payload) {
		t.Fatalf("clean payload must pass through byte-for-byte: %q", prepared)
	}
}

func TestProxyProviderFilterExcludesUnparsableNodeStarts(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	published := filepath.Join(options.WorkingPath, "published-filtered.yaml")
	payload := proxyPayload(
		"{name: Good, type: direct}",
		fmt.Sprintf("{name: FutureProto, type: %s}", unparsableProxyType),
	)
	if err := os.WriteFile(published, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	content := fmt.Sprintf(`
dns:
  enable: true
  nameserver: [8.8.8.8]
proxy-providers:
  filtered:
    type: file
    path: %q
    filter: '^Good$'
proxy-groups:
  - name: Controlled
    type: select
    use: [filtered]
rules:
  - MATCH,Controlled
`, published)
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(content); err != nil {
		t.Fatalf("a filter-excluded unparsable node must not fail Start: %v", err)
	}
	t.Cleanup(func() { _ = service.Close() })
	if got := tunnel.Providers()["filtered"].Count(); got != 1 {
		t.Fatalf("runtime proxy provider count = %d, want 1 (mihomo filters out the excluded node)", got)
	}
}

func TestProxyProviderUnparsableNodeIsNonFatalAtStart(t *testing.T) {
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	published := filepath.Join(options.WorkingPath, "published-degraded.yaml")
	payload := proxyPayload(
		"{name: Good, type: direct}",
		fmt.Sprintf("{name: FutureProto, type: %s}", unparsableProxyType),
	)
	if err := os.WriteFile(published, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	content := fmt.Sprintf(`
dns:
  enable: true
  nameserver: [8.8.8.8]
proxy-providers:
  degraded:
    type: file
    path: %q
proxy-groups:
  - name: Controlled
    type: select
    proxies: [DIRECT]
    use: [degraded]
rules:
  - MATCH,Controlled
`, published)
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(content); err != nil {
		t.Fatalf("an unparsable provider node must be non-fatal at Start (upstream parity): %v", err)
	}
	t.Cleanup(func() { _ = service.Close() })
}
