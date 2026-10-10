package clash

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sideUpdateExpectedFixture(t *testing.T) (*BoxService, *APIClient, string, string) {
	t.Helper()
	options := testOptions(t)
	if err := Setup(options); err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(options.WorkingPath, "store", "published", "providers")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	proxyPath := filepath.Join(directory, "proxy.yaml")
	if err := os.WriteFile(proxyPath, []byte("proxies:\n  - {name: Original, type: direct}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf("mode: rule\nlog-level: info\ndns:\n  enable: true\n  nameserver: [8.8.8.8]\nproxy-providers:\n  controlled-proxy:\n    type: file\n    path: %q\nproxy-groups:\n  - name: Controlled\n    type: select\n    use: [controlled-proxy]\nrules:\n  - MATCH,DIRECT\n", proxyPath)
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(config); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = service.Close() })
	path := shortClashSocketPath(t)
	if err := startControlPlane(nil, path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { stopClashAPI(path) })
	client, err := NewAPIClientWithOptions(path, newRecordingClashAPIHandler(), &APIClientOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	return service, client, config, proxyPath
}

func configSHA256(text string) string {
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:])
}

func TestSideUpdateNamesTheConfigurationItWasPreparedFor(t *testing.T) {
	service, client, config, _ := sideUpdateExpectedFixture(t)
	payload := []byte("proxies:\n  - {name: Updated, type: direct}\n")

	if err := client.SideUpdateProxyProviderExpecting("controlled-proxy", payload, configSHA256(config)); err != nil {
		t.Fatalf("the running configuration: %v", err)
	}
	other := strings.Repeat("0", 64)
	err := client.SideUpdateProxyProviderExpecting("controlled-proxy", payload, other)
	if err == nil || !strings.HasPrefix(err.Error(), SideUpdateStalePrefix) {
		t.Fatalf("another configuration must be refused with the stale prefix: %v", err)
	}
	reloaded := strings.Replace(config, "log-level: info", "log-level: warning", 1)
	if err := service.Reload(reloaded); err != nil {
		t.Fatal(err)
	}
	if err := client.SideUpdateProxyProviderExpecting("controlled-proxy", payload, configSHA256(config)); err == nil || !strings.HasPrefix(err.Error(), SideUpdateStalePrefix) {
		t.Fatalf("the configuration before the reload: %v", err)
	}
	if err := client.SideUpdateRuleProviderExpecting("nothing-here", []byte("payload: []\n"), configSHA256(reloaded)); err == nil || strings.HasPrefix(err.Error(), SideUpdateStalePrefix) {
		t.Fatalf("an unknown rule provider under the current configuration is not stale: %v", err)
	}
	if err := client.SideUpdateProxyProviderExpecting("controlled-proxy", payload, configSHA256(reloaded)); err != nil {
		t.Fatalf("the configuration after the reload: %v", err)
	}
	if err := client.SideUpdateProxyProvider("controlled-proxy", payload); err != nil {
		t.Fatalf("SideUpdateProxyProvider: %v", err)
	}
	if err := client.SideUpdateProxyProviderExpecting("controlled-proxy", payload, "abc"); err == nil || strings.HasPrefix(err.Error(), SideUpdateStalePrefix) {
		t.Fatalf("a malformed expectation: %v", err)
	}
}

func TestSideUpdateExpectationFollowsWhatRuns(t *testing.T) {
	service, _, config, _ := sideUpdateExpectedFixture(t)
	if got := service.runningConfigurationSHA256(); got != configSHA256(config) {
		t.Fatalf("after Start: %q", got)
	}
	if err := service.Reload("mode: [\n"); err == nil {
		t.Fatal("an unparsable reload must be refused")
	}
	if got := service.runningConfigurationSHA256(); got != configSHA256(config) {
		t.Fatalf("a refused reload changed the name: %q", got)
	}
	_ = service.Close()
	if got := service.runningConfigurationSHA256(); got != "" {
		t.Fatalf("after Close: %q", got)
	}
}

func TestSideUpdateRefusalsKeepTheirPrefixAcrossTheRoute(t *testing.T) {
	for _, c := range []struct {
		err    error
		status int
		body   string
	}{
		{fmt.Errorf("%sthis rule set runs compiled; the update applies at the next activation", SideUpdateDeferredPrefix), 409, SideUpdateDeferredPrefix + "this rule set runs compiled; the update applies at the next activation"},
		{fmt.Errorf("%sthe running configuration is not the one this update was prepared for", SideUpdateStalePrefix), 409, SideUpdateStalePrefix + "the running configuration is not the one this update was prepared for"},
		{errors.New("clash: provider /secret/path failed"), 422, "provider side update rejected"},
	} {
		status, body := sideUpdateRefusal(c.err)
		if status != c.status || body != c.body {
			t.Errorf("%v: %d %q, want %d %q", c.err, status, body, c.status, c.body)
		}
	}
	if err := clientSideUpdateError("/clash/v1/providers/side-update?kind=rule&name=x", 409, SideUpdateDeferredPrefix+"x"); err == nil || !strings.HasPrefix(err.Error(), SideUpdateDeferredPrefix) {
		t.Fatalf("the client lost the deferred prefix: %v", err)
	}
}

func TestClientSideUpdateErrorClassifiesClashRefusals(t *testing.T) {
	endpoint := "/clash/v1/providers/side-update?kind=rule&name=x"
	for _, tc := range []struct{ body, want string }{
		{"clash: side update deferred: compiled rule set", SideUpdateDeferredPrefix + "compiled rule set"},
		{"clash: side update stale: expected abc", SideUpdateStalePrefix + "expected abc"},
		{SideUpdateDeferredPrefix + "y", SideUpdateDeferredPrefix + "y"},
	} {
		err := clientSideUpdateError(endpoint, 409, tc.body)
		if err == nil || err.Error() != tc.want {
			t.Fatalf("%q: got %v, want %q", tc.body, err, tc.want)
		}
	}
	err := clientSideUpdateError(endpoint, 409, "clash: side update refused: something else")
	if err == nil || strings.HasPrefix(err.Error(), SideUpdateDeferredPrefix) || strings.HasPrefix(err.Error(), SideUpdateStalePrefix) {
		t.Fatalf("an unrelated refusal was classified: %v", err)
	}
	if err := clientSideUpdateError(endpoint, 500, "clash: side update deferred: x"); err == nil || strings.HasPrefix(err.Error(), SideUpdateDeferredPrefix) {
		t.Fatalf("a non-409 was classified as a deferral: %v", err)
	}
}
