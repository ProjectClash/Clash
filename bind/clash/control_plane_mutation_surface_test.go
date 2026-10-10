package clash

import (
	"bufio"
	"net"
	"net/http"
	"strings"
	"testing"
)

func TestTheControlPlaneServesNoConfigReplacementEndpoint(t *testing.T) {
	path := shortClashSocketPath(t)
	withSetupClashAPIPath(t, path)
	if err := startControlPlane(plainConfig(t), path); err != nil {
		t.Fatalf("startControlPlane: %v", err)
	}
	t.Cleanup(func() { stopClashAPI(path) })

	ask := func(method, target, body string) int {
		t.Helper()
		conn, err := net.Dial("unix", path)
		if err != nil {
			t.Fatalf("dial the App Group socket: %v", err)
		}
		defer conn.Close()
		var reader *strings.Reader
		if body != "" {
			reader = strings.NewReader(body)
		}
		var request *http.Request
		if reader != nil {
			request, err = http.NewRequest(method, "http://clash"+target, reader)
		} else {
			request, err = http.NewRequest(method, "http://clash"+target, nil)
		}
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		if err := request.Write(conn); err != nil {
			t.Fatalf("write request: %v", err)
		}
		response, err := http.ReadResponse(bufio.NewReader(conn), request)
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		_ = response.Body.Close()
		return response.StatusCode
	}

	if status := ask(http.MethodGet, "/configs", ""); status != http.StatusOK {
		t.Fatalf("GET /configs answered %d, want 200 -- the control plane is not live, so this test measures nothing", status)
	}

	status := ask(http.MethodPut, "/configs", `{"dns":{"enable":false}}`)
	if status != http.StatusNotFound && status != http.StatusMethodNotAllowed {
		t.Errorf("PUT /configs answered %d -- the config-replacement surface is open. It bypasses "+
			"normalizeRawConfigForApple entirely (hub/route/configs.go:407 parses upstream and applies "+
			"directly), so a payload with dns.enable false reaches the core unrepaired and every hijacked "+
			"query answers SERVFAIL while the App still shows the profile it thinks is running. "+
			"Keep route.SetEmbedMode(true) in clash_api.go, or run the payload through the Apple pipeline first.",
			status)
	}
}
