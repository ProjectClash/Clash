package clash

import (
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExternalUIIsActuallyServedAndNotJustDownloaded(t *testing.T) {
	options := testOptions(t)
	options.BasePath = shortSocketDirectory(t)
	if err := Setup(options); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	uiDirectory := filepath.Join(options.WorkingPath, "ui")
	if err := os.MkdirAll(uiDirectory, 0o755); err != nil {
		t.Fatalf("create the dashboard directory: %v", err)
	}
	const marker = "<title>clash dashboard</title>"
	if err := os.WriteFile(filepath.Join(uiDirectory, "index.html"), []byte(marker), 0o644); err != nil {
		t.Fatalf("write the dashboard: %v", err)
	}

	port := freeLoopbackPort(t)
	addr := "127.0.0.1:" + port
	cfg, err := parseConfigForIOS(`
external-controller: `+addr+`
external-ui: ui
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`, true)
	if err != nil {
		t.Fatalf("parse the fixture: %v", err)
	}

	if err := startControlPlane(cfg, APIPath()); err != nil {
		t.Fatalf("startControlPlane: %v", err)
	}
	t.Cleanup(func() { stopClashAPI(APIPath()) })

	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get("http://" + addr + "/ui/index.html")
	if err != nil {
		t.Fatalf("GET /ui/index.html: %v", err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)

	if response.StatusCode != http.StatusOK {
		t.Fatalf("GET /ui/index.html = %d, want 200. The configuration named a dashboard and this "+
			"core downloads it; serving it is the other half of the same field", response.StatusCode)
	}
	if !strings.Contains(string(body), marker) {
		t.Errorf("/ui/index.html served %q, which is not the dashboard in the container", string(body))
	}
}

func TestNoDashboardIsMountedWhenTheConfigurationNamesNone(t *testing.T) {
	options := testOptions(t)
	options.BasePath = shortSocketDirectory(t)
	if err := Setup(options); err != nil {
		t.Fatalf("Setup: %v", err)
	}

	port := freeLoopbackPort(t)
	addr := "127.0.0.1:" + port
	cfg, err := parseConfigForIOS(`
external-controller: `+addr+`
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`, true)
	if err != nil {
		t.Fatalf("parse the fixture: %v", err)
	}

	if err := startControlPlane(cfg, APIPath()); err != nil {
		t.Fatalf("startControlPlane: %v", err)
	}
	t.Cleanup(func() { stopClashAPI(APIPath()) })

	conn, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("the controller is not listening at %s: %v", addr, err)
	}
	_ = conn.Close()

	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get("http://" + addr + "/ui/index.html")
	if err != nil {
		t.Fatalf("GET /ui/index.html: %v", err)
	}
	defer response.Body.Close()

	if response.StatusCode == http.StatusOK {
		t.Error("a configuration with no external-ui served a dashboard anyway; uiPath is a " +
			"package global and something left it set from another configuration")
	}
}
