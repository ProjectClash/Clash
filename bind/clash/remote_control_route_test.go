package clash

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/config"
)

func requestOver(t *testing.T, client *http.Client, method, url, secret, contentType string, body []byte) (int, []byte) {
	t.Helper()
	request, _ := http.NewRequest(method, url, bytes.NewReader(body))
	if secret != "" {
		request.Header.Set("Authorization", "Bearer "+secret)
	}
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	defer response.Body.Close()
	data, _ := io.ReadAll(response.Body)
	return response.StatusCode, data
}

func unixHTTPClient(socket string) *http.Client {
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		Dial: func(string, string) (net.Conn, error) { return net.Dial("unix", socket) }}}
}

func TestRemoteControlStatusAndCapabilitiesAreServed(t *testing.T) {
	resetRemoteControlForTest(t)
	socket := liveControlPlane(t, &config.Config{})
	port := freePort(t)
	apply(t, map[string]any{"mode": "local", "httpPort": port, "secret": "s", "generation": 3})
	tcp := &http.Client{Timeout: 5 * time.Second}
	base := fmt.Sprintf("http://127.0.0.1:%d", port)

	code, body := requestOver(t, tcp, http.MethodGet, base+"/clash/v1/remote-control", "s", "", nil)
	var status remoteControlReply
	if code != http.StatusOK || json.Unmarshal(body, &status) != nil || status.Generation != 3 || status.Mode != "local" || !status.Running {
		t.Fatalf("remote-control: %d %s", code, body)
	}
	if code, _ := requestOver(t, tcp, http.MethodGet, base+"/clash/v1/remote-control", "", "", nil); code != http.StatusUnauthorized {
		t.Fatalf("remote-control without the secret: %d", code)
	}

	code, body = requestOver(t, unixHTTPClient(socket), http.MethodGet, "http://unix/clash/v1/capabilities", "", "", nil)
	var capabilities struct {
		API          int      `json:"api"`
		Platform     string   `json:"platform"`
		CoreVersion  string   `json:"coreVersion"`
		Capabilities []string `json:"capabilities"`
	}
	if code != http.StatusOK || json.Unmarshal(body, &capabilities) != nil {
		t.Fatalf("capabilities: %d %s", code, body)
	}
	if capabilities.API != 1 || capabilities.Platform != "ios" || capabilities.CoreVersion != Version() {
		t.Fatalf("capabilities: %+v", capabilities)
	}
	for _, want := range []string{"remote-control-v1", "rules-match-v1", "provider-update-v1", "dns-explain-v1", "connection-events-v1"} {
		found := false
		for _, have := range capabilities.Capabilities {
			found = found || have == want
		}
		if !found {
			t.Errorf("capabilities lack %q: %v", want, capabilities.Capabilities)
		}
	}
}

func TestStateChangingPrivateRoutesFollowTheExposureTable(t *testing.T) {
	resetRemoteControlForTest(t)
	configPort := freePort(t)
	cfg := &config.Config{General: &config.General{}, Controller: &config.Controller{
		ExternalController: fmt.Sprintf("127.0.0.1:%d", configPort), Secret: "config"}}
	socket := liveControlPlane(t, cfg)
	unix := unixHTTPClient(socket)
	tcp := &http.Client{Timeout: 5 * time.Second}
	configBase := fmt.Sprintf("http://127.0.0.1:%d", configPort)

	type probe struct {
		method, path, contentType string
		body                      []byte
	}
	providerUpdate := probe{http.MethodPost, "/clash/v1/provider-update", "application/json", []byte(`{}`)}
	proxyShareStart := probe{http.MethodPut, "/clash/v1/proxy-share", "application/json", []byte(`{}`)}
	proxyShareStop := probe{http.MethodDelete, "/clash/v1/proxy-share", "", nil}
	sideUpdate := probe{http.MethodPut, "/clash/v1/providers/side-update", "application/octet-stream", []byte("x")}
	reached := func(client *http.Client, base, secret string, p probe) bool {
		code, _ := requestOver(t, client, p.method, base+p.path, secret, p.contentType, p.body)
		if code == http.StatusUnauthorized {
			t.Fatalf("%s %s: 401 -- the probe must carry the right secret", p.method, p.path)
		}
		return code != http.StatusNotFound && code != http.StatusForbidden
	}

	for _, p := range []probe{providerUpdate, proxyShareStart, proxyShareStop, sideUpdate} {
		if reached(tcp, configBase, "config", p) {
			t.Errorf("the configuration's controller reaches %s %s", p.method, p.path)
		}
	}
	for _, p := range []probe{providerUpdate, proxyShareStart, proxyShareStop, sideUpdate} {
		if !reached(unix, "http://unix", "", p) {
			t.Errorf("the App lost %s %s", p.method, p.path)
		}
	}
	managedPort := freePort(t)
	apply(t, map[string]any{"mode": "local", "httpPort": managedPort, "secret": "app", "generation": 1})
	managedBase := fmt.Sprintf("http://127.0.0.1:%d", managedPort)
	if !reached(tcp, managedBase, "app", providerUpdate) {
		t.Error("the External Controller cannot update a provider; upstream's PUT /providers only rereads the cache here")
	}
	for _, p := range []probe{proxyShareStart, proxyShareStop, sideUpdate} {
		if reached(tcp, managedBase, "app", p) {
			t.Errorf("the External Controller reaches %s %s; a key holder must not widen its own reach", p.method, p.path)
		}
	}
}
