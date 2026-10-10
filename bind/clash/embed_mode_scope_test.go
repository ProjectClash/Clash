package clash

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestEmbedModeClosesOnlyWhatItsReasonsCover(t *testing.T) {
	port := freeLoopbackPort(t)
	addr := "127.0.0.1:" + port
	path := shortClashSocketPath(t)
	cfg := controllerConfig(t, addr)

	if err := startControlPlane(cfg, path); err != nil {
		t.Fatalf("startControlPlane: %v", err)
	}
	t.Cleanup(func() { stopClashAPI(path) })

	client := &http.Client{Timeout: 3 * time.Second}
	call := func(method, route string) int {
		t.Helper()
		request, err := http.NewRequest(method, "http://"+addr+route, strings.NewReader("{}"))
		if err != nil {
			t.Fatalf("build %s %s: %v", method, route, err)
		}
		request.Header.Set("Content-Type", "application/json")
		response, err := client.Do(request)
		if err != nil {
			t.Fatalf("%s %s: %v", method, route, err)
		}
		defer response.Body.Close()
		return response.StatusCode
	}

	if status := call(http.MethodGet, "/configs"); status != http.StatusOK {
		t.Fatalf("GET /configs = %d; the controller is not serving, so nothing below is measured", status)
	}

	closed := map[string]string{
		"PUT /configs":      "replaces the running configuration, bypassing the immutable revision pipeline",
		"POST /configs/geo": "downloads geo data inside the extension",
		"POST /upgrade":     "replaces the binary, which Apple code signing forbids",
		"POST /upgrade/geo": "downloads and unpacks 17 MB of GeoIP inside an extension measured dying at 49.5 MiB",
		"POST /restart":     "re-executes os.Executable(), which inside an app extension is the host process",
	}
	for route, reason := range closed {
		method, target, _ := strings.Cut(route, " ")
		status := call(method, target)
		if status != http.StatusNotFound && status != http.StatusMethodNotAllowed {
			t.Errorf("%s is answered %d but is supposed to stay closed: %s", route, status, reason)
		}
	}

	open := map[string]string{
		"PATCH /configs":       "runtime switches -- mode, sniffing, log level. Writes no file and downloads nothing",
		"PATCH /rules/disable": "flips SetDisabled in memory on already-parsed rules; the configuration on disk is untouched",
		"PUT /storage/clash":   "the dashboard's own scratch key-value store; nothing in the containing app opens cache.db, so there is no second writer to protect it from",
	}
	for route, reason := range open {
		method, target, _ := strings.Cut(route, " ")
		status := call(method, target)
		if status == http.StatusNotFound || status == http.StatusMethodNotAllowed {
			t.Errorf("%s is answered %d but nothing justifies closing it: %s", route, status, reason)
		}
	}

	routedButNotInvoked := map[string]string{
		"GET /upgrade/ui": "the same u.downloadUI() the start path already calls unprompted via " +
			"AutoDownloadUI, only on demand instead of during startup",
	}
	for route, reason := range routedButNotInvoked {
		method, target, _ := strings.Cut(route, " ")
		if status := call(method, target); status != http.StatusMethodNotAllowed {
			t.Errorf("%s answered %d; 405 means the path is registered and 404 means it is not, "+
				"and this one has to be registered: %s", route, status, reason)
		}
	}
}
