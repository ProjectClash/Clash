package clash

import (
	"bufio"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/config"
)

func freeLoopbackPort(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a port: %v", err)
	}
	_, port, err := net.SplitHostPort(listener.Addr().String())
	_ = listener.Close()
	if err != nil {
		t.Fatalf("split reserved address: %v", err)
	}
	if _, err := strconv.Atoi(port); err != nil {
		t.Fatalf("reserved port is not a number: %q", port)
	}
	return port
}

func withSetupClashAPIPath(t *testing.T, path string) {
	t.Helper()
	setupMu.Lock()
	previous := setupClashAPIPath
	setupClashAPIPath = path
	setupMu.Unlock()
	t.Cleanup(func() {
		setupMu.Lock()
		setupClashAPIPath = previous
		setupMu.Unlock()
	})
}

func packageSourceFiles(t *testing.T) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read the package directory: %v", err)
	}
	sources := map[string]string{}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		body, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		sources[name] = string(body)
	}
	if len(sources) == 0 {
		t.Fatal("no non-test sources found; the scan would pass by finding nothing")
	}
	return sources
}

func controllerConfig(t *testing.T, addr string) *config.Config {
	t.Helper()
	cfg, err := parseConfigForIOS(`
external-controller: `+addr+`
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`, true)
	if err != nil {
		t.Fatalf("parse controller fixture: %v", err)
	}
	return cfg
}

func TestStartLeavesTheConfiguredControllerListening(t *testing.T) {
	port := freeLoopbackPort(t)
	addr := "127.0.0.1:" + port
	path := shortClashSocketPath(t)
	cfg := controllerConfig(t, addr)

	if err := startControlPlane(cfg, path); err != nil {
		t.Fatalf("startControlPlane: %v", err)
	}
	t.Cleanup(func() { stopClashAPI(path) })

	tcp, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("the configured controller is not listening at %s: %v -- the user wrote this "+
			"address and the core reported opening it", addr, err)
	}
	_ = tcp.Close()

	unix, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("the binding's own App Group socket is not listening at %s: %v -- both live in "+
			"one route.Config, so opening the user's address must not cost us ours", path, err)
	}
	_ = unix.Close()
}

func TestReloadKeepsTheAppGroupSocketAt0600(t *testing.T) {
	port := freeLoopbackPort(t)
	addr := "127.0.0.1:" + port
	path := shortClashSocketPath(t)
	cfg := controllerConfig(t, addr)

	if err := startControlPlane(cfg, path); err != nil {
		t.Fatalf("startControlPlane: %v", err)
	}
	t.Cleanup(func() { stopClashAPI(path) })

	withSetupClashAPIPath(t, path)
	applyExternalController(cfg)

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat the App Group socket after reload: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("the App Group socket is %04o after a reload, not 0600; upstream's startUnix "+
			"chmods 0666 on every re-create and something has to tighten it back", mode)
	}
}

func TestEveryControlPlaneCreationUsesTheMergedConfiguration(t *testing.T) {
	const teardown = "&route.Config{}"

	sources := packageSourceFiles(t)
	found := 0
	for name, body := range sources {
		for index, line := range strings.Split(body, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				continue
			}
			call := strings.Index(line, "route.ReCreateServer(")
			if call < 0 {
				continue
			}
			found++
			argument := strings.TrimSuffix(strings.TrimSpace(line[call+len("route.ReCreateServer("):]), ")")
			if argument == teardown {
				continue
			}
			derived := strings.Contains(body, argument+" := controllerServerConfig(") ||
				strings.HasPrefix(argument, "controllerServerConfig(")
			if !derived {
				t.Errorf("%s:%d creates a control plane from %q, which does not come from "+
					"controllerServerConfig. route.ReCreateServer REPLACES the whole listener "+
					"set, so a second shape here closes whatever the first one opened -- which "+
					"is how the user's external-controller lived for three milliseconds on a "+
					"device", name, index+1, argument)
			}
		}
	}
	if found == 0 {
		t.Fatal("no route.ReCreateServer call found in this package; the scan is measuring nothing")
	}
}

func TestNonNetworkExtensionStartOpensTheConfiguredController(t *testing.T) {
	port := freeLoopbackPort(t)
	addr := "127.0.0.1:" + port

	options := testOptions(t)
	options.BasePath = shortSocketDirectory(t)
	if err := Setup(options); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { _ = service.Close() })

	document := strings.Replace(helloYAML, "mode: rule", "mode: rule\nexternal-controller: "+addr, 1)
	if err := service.Start(document); err != nil {
		t.Fatalf("Start: %v", err)
	}

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("a start outside the extension did not open the configured controller at %s: "+
			"%v -- this branch used to be an unconditional line and nothing ever ran it", addr, err)
	}
	_ = conn.Close()

	unix, err := net.Dial("unix", APIPath())
	if err != nil {
		t.Fatalf("the binding socket is not listening outside the extension: %v -- if this is now "+
			"deliberate, say so here and tell the macOS lane; do not let it change silently", err)
	}
	_ = unix.Close()
}

func plainConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := parseConfigForIOS(`
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`, true)
	if err != nil {
		t.Fatalf("parse plain fixture: %v", err)
	}
	return cfg
}

func TestReloadWithoutAControllerClosesTheOneStartOpened(t *testing.T) {
	port := freeLoopbackPort(t)
	addr := "127.0.0.1:" + port
	path := shortClashSocketPath(t)
	withSetupClashAPIPath(t, path)

	if err := startControlPlane(controllerConfig(t, addr), path); err != nil {
		t.Fatalf("startControlPlane: %v", err)
	}
	t.Cleanup(func() { stopClashAPI(path) })
	before, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("positive control: the controller is not listening at %s after Start: %v", addr, err)
	}
	_ = before.Close()

	applyExternalController(plainConfig(t))

	assertNotListening(t, addr, "a reload that removed the user's controller")
	unix, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("the App Group socket is not listening at %s after a reload that removed the "+
			"user's controller: %v -- closing theirs must not close ours", path, err)
	}
	_ = unix.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat the App Group socket: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Errorf("the App Group socket is %04o after the controller was removed, not 0600", mode)
	}
}

func TestReloadWithoutAControllerOnEitherSideLeavesTheAppConnectionAlone(t *testing.T) {
	path := shortClashSocketPath(t)
	withSetupClashAPIPath(t, path)

	if err := startControlPlane(plainConfig(t), path); err != nil {
		t.Fatalf("startControlPlane: %v", err)
	}
	t.Cleanup(func() { stopClashAPI(path) })
	held, err := net.Dial("unix", path)
	if err != nil {
		t.Fatalf("dial the App Group socket: %v", err)
	}
	defer held.Close()

	applyExternalController(plainConfig(t))

	request, err := http.NewRequest(http.MethodGet, "http://clash/version", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	if err := request.Write(held); err != nil {
		t.Fatalf("the App's connection was closed by a reload that had nothing to close: %v", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(held), request)
	if err != nil {
		t.Fatalf("the App's connection was dropped by a reload that had nothing to close: %v", err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("/version over the held connection answered %d, want 200", response.StatusCode)
	}
}

func TestNonNetworkExtensionCloseClosesTheConfiguredController(t *testing.T) {
	port := freeLoopbackPort(t)
	addr := "127.0.0.1:" + port

	options := testOptions(t)
	options.BasePath = shortSocketDirectory(t)
	if err := Setup(options); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}

	document := strings.Replace(helloYAML, "mode: rule", "mode: rule\nexternal-controller: "+addr, 1)
	if err := service.Start(document); err != nil {
		t.Fatalf("Start: %v", err)
	}
	before, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("positive control: the controller is not listening at %s after Start: %v", addr, err)
	}
	_ = before.Close()

	if err := service.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	assertNotListening(t, addr, "Close outside the extension")
}
