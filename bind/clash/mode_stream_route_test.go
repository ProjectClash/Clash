package clash

import (
	"bufio"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/config"
	"github.com/ProjectClash/Clash/hub/executor"
	"github.com/ProjectClash/Clash/listener"
	"github.com/ProjectClash/Clash/tunnel"
)

func TestModeStreamSendsCurrentModeThenEveryChange(t *testing.T) {
	previous := tunnel.Mode()
	t.Cleanup(func() { tunnel.SetMode(previous) })
	tunnel.SetMode(tunnel.Rule)

	port := freeLoopbackPort(t)
	addr := "127.0.0.1:" + port
	path := shortClashSocketPath(t)
	cfg := controllerConfig(t, addr)
	if err := startControlPlane(cfg, path); err != nil {
		t.Fatalf("startControlPlane: %v", err)
	}
	t.Cleanup(func() { stopClashAPI(path) })

	connection, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial the controller: %v", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := connection.Write([]byte("GET /clash/v1/mode HTTP/1.1\r\nHost: localhost\r\n\r\n")); err != nil {
		t.Fatalf("request the mode stream: %v", err)
	}

	reader := bufio.NewReader(connection)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read the response head: %v", err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	nextMode := func(what string) string {
		t.Helper()
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("read %s: %v", what, err)
			}
			line = strings.TrimSpace(line)
			if line == "" || !strings.HasPrefix(line, "{") {
				continue
			}
			var payload struct {
				Mode     string `json:"mode"`
				AllowLan bool   `json:"allow-lan"`
			}
			if err := json.Unmarshal([]byte(line), &payload); err != nil {
				t.Fatalf("decode %s from %q: %v", what, line, err)
			}
			return payload.Mode
		}
	}

	if mode := nextMode("the mode on connect"); mode != "rule" {
		t.Fatalf("the stream opened with %q, not the mode the tunnel is actually in", mode)
	}

	tunnel.SetMode(tunnel.Global)
	if mode := nextMode("the mode after a change"); mode != "global" {
		t.Errorf("after SetMode(Global) the stream said %q; a dashboard switching mode has to "+
			"reach the App without it polling", mode)
	}
}

func TestAllowLanChangesTravelOnTheSameStream(t *testing.T) {
	previousMode, previousLan := tunnel.Mode(), listener.AllowLan()
	t.Cleanup(func() {
		tunnel.SetMode(previousMode)
		listener.SetAllowLan(previousLan)
	})
	tunnel.SetMode(tunnel.Rule)
	listener.SetAllowLan(false)

	port := freeLoopbackPort(t)
	addr := "127.0.0.1:" + port
	path := shortClashSocketPath(t)
	cfg := controllerConfig(t, addr)
	if err := startControlPlane(cfg, path); err != nil {
		t.Fatalf("startControlPlane: %v", err)
	}
	t.Cleanup(func() { stopClashAPI(path) })

	connection, err := net.DialTimeout("tcp", addr, time.Second)
	if err != nil {
		t.Fatalf("dial the controller: %v", err)
	}
	defer connection.Close()
	_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := connection.Write([]byte("GET /clash/v1/mode HTTP/1.1\r\nHost: localhost\r\n\r\n")); err != nil {
		t.Fatalf("request the stream: %v", err)
	}
	reader := bufio.NewReader(connection)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("read the response head: %v", err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
	}
	next := func(what string) (string, bool) {
		t.Helper()
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatalf("read %s: %v", what, err)
			}
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "{") {
				continue
			}
			var payload struct {
				Mode     string `json:"mode"`
				AllowLan bool   `json:"allow-lan"`
			}
			if err := json.Unmarshal([]byte(line), &payload); err != nil {
				t.Fatalf("decode %s from %q: %v", what, line, err)
			}
			return payload.Mode, payload.AllowLan
		}
	}

	if mode, lan := next("the snapshot on connect"); mode != "rule" || lan {
		t.Fatalf("the stream opened with mode=%q allow-lan=%v, not what is running", mode, lan)
	}

	listener.SetAllowLan(true)
	mode, lan := next("the snapshot after allow-lan changed")
	if !lan {
		t.Error("turning allow-lan on did not reach the stream; it has three writers and a " +
			"snapshot is blind to two of them")
	}
	if mode != "rule" {
		t.Errorf("the allow-lan message carried mode=%q, so the pair came apart", mode)
	}
}

func TestModeObserverFiresForEveryWriterNotJustTheAppsOwnRoute(t *testing.T) {
	previous := tunnel.Mode()
	t.Cleanup(func() {
		tunnel.SetModeObserver(nil)
		tunnel.SetMode(previous)
	})

	seen := make(chan tunnel.TunnelMode, 4)
	tunnel.SetModeObserver(func(mode tunnel.TunnelMode) { seen <- mode })

	tunnel.SetMode(tunnel.Direct)
	select {
	case mode := <-seen:
		if mode != tunnel.Direct {
			t.Fatalf("observer saw %v, want Direct", mode)
		}
	case <-time.After(time.Second):
		t.Fatal("tunnel.SetMode did not reach the observer")
	}

	tunnel.SetModeObserver(nil)
	tunnel.SetMode(tunnel.Rule)
	select {
	case mode := <-seen:
		t.Fatalf("observer still fired with %v after being cleared", mode)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestReloadPublishesTheModeOnceAndOnlyAfterItIsReallyApplied(t *testing.T) {
	if err := Setup(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	previous := tunnel.Mode()
	t.Cleanup(func() { tunnel.SetMode(previous) })
	installRuntimeSwitchSeams()
	tunnel.SetMode(tunnel.Direct)

	stream, unsubscribe := subscribeRuntimeSwitches()
	defer unsubscribe()

	cfg, err := parseConfigForIOS(`
mode: rule
dns:
  enable: true
  nameserver: [223.5.5.5]
rules:
  - MATCH,DIRECT
`, false)
	if err != nil {
		t.Fatalf("parseConfigForIOS: %v", err)
	}
	if live := tunnel.Mode(); live != tunnel.Direct {
		t.Fatalf("live mode after a parse = %v, want the unchanged Direct", live)
	}
	select {
	case switches := <-stream:
		t.Fatalf("parsing alone published %+v; nothing was applied yet", switches)
	default:
	}

	executor.ApplyConfig(cfg, true)

	select {
	case switches := <-stream:
		if switches.Mode != "rule" {
			t.Fatalf("the apply published mode %q, want rule", switches.Mode)
		}
	default:
		t.Fatal("applying the configuration published nothing")
	}
	select {
	case switches := <-stream:
		t.Fatalf("a second message %+v followed the apply", switches)
	default:
	}
}

func TestCheckConfigPublishesNothingOnTheModeStream(t *testing.T) {
	if err := Setup(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	previous := tunnel.Mode()
	t.Cleanup(func() { tunnel.SetMode(previous) })
	installRuntimeSwitchSeams()
	tunnel.SetMode(tunnel.Direct)

	stream, unsubscribe := subscribeRuntimeSwitches()
	defer unsubscribe()

	if err := CheckConfig(`
mode: global
dns:
  enable: true
  nameserver: [223.5.5.5]
rules:
  - MATCH,DIRECT
`); err != nil {
		t.Fatalf("CheckConfig: %v", err)
	}
	if live := tunnel.Mode(); live != tunnel.Direct {
		t.Fatalf("CheckConfig changed the live mode to %v", live)
	}
	select {
	case switches := <-stream:
		t.Fatalf("validating a candidate published %+v", switches)
	default:
	}
}

func TestEveryParseInThisPackageGoesThroughTheQuietOne(t *testing.T) {
	entryPoints := map[string]map[string]bool{
		"github.com/ProjectClash/Clash/config":       {"ParseRawConfig": true, "Parse": true},
		"github.com/ProjectClash/Clash/hub/executor": {"Parse": true, "ParseWithPath": true, "ParseWithBytes": true},
		"github.com/ProjectClash/Clash/hub":          {"Parse": true},
	}
	references := map[string][]string{}
	fileSet := token.NewFileSet()
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if name := entry.Name(); name != "." && (strings.HasPrefix(name, ".") || name == "testdata" || name == "harness" || name == "apple") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fileSet, path, nil, 0)
		if err != nil {
			return err
		}
		imported := map[string]string{}
		for _, spec := range file.Imports {
			importPath, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				return err
			}
			name := importPath[strings.LastIndex(importPath, "/")+1:]
			if spec.Name != nil {
				name = spec.Name.Name
				if name == "." {
					if _, watched := entryPoints[importPath]; watched {
						references["DOT-IMPORT"] = append(references["DOT-IMPORT"], path+":"+importPath)
					}
					continue
				}
			}
			imported[name] = importPath
		}
		ast.Inspect(file, func(n ast.Node) bool {
			selector, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkgIdent, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			if names, watched := entryPoints[imported[pkgIdent.Name]]; watched && names[selector.Sel.Name] {
				position := fileSet.Position(selector.Pos())
				references[position.Filename] = append(references[position.Filename], imported[pkgIdent.Name]+"."+selector.Sel.Name)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walk the module: %v", err)
	}
	if len(references) != 1 || len(references["mode_stream_route.go"]) != 1 ||
		references["mode_stream_route.go"][0] != "github.com/ProjectClash/Clash/config.ParseRawConfig" {
		t.Fatalf("parse entry points are referenced from %v; the only reference allowed is config.ParseRawConfig inside parseRawConfigQuietly (mode_stream_route.go), once", references)
	}
}

func TestOneParseWritesTheModeExactlyTwice(t *testing.T) {
	previous := tunnel.Mode()
	t.Cleanup(func() {
		installRuntimeSwitchSeams()
		tunnel.SetMode(previous)
	})
	tunnel.SetMode(tunnel.Direct)
	var writes []tunnel.TunnelMode
	tunnel.SetModeObserver(func(mode tunnel.TunnelMode) { writes = append(writes, mode) })

	raw, err := config.UnmarshalRawConfig([]byte("mode: rule\ndns:\n  enable: true\n  nameserver: [223.5.5.5]\nrules:\n  - MATCH,DIRECT\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := config.ParseRawConfig(raw); err != nil {
		t.Fatalf("ParseRawConfig: %v", err)
	}
	if len(writes) != parserModeWritesPerParse || writes[0] != tunnel.Rule || writes[1] != tunnel.Direct {
		t.Fatalf("one parse wrote the mode %v; want exactly [rule direct] (%d writes)", writes, parserModeWritesPerParse)
	}
}

func TestAWriteMutedInsideTheWindowIsPublishedWhenTheWindowCloses(t *testing.T) {
	previous := tunnel.Mode()
	t.Cleanup(func() { tunnel.SetMode(previous) })
	installRuntimeSwitchSeams()
	tunnel.SetMode(tunnel.Direct)
	stream, unsubscribe := subscribeRuntimeSwitches()
	defer unsubscribe()

	_, err := parseRawConfigQuietlyWith(func() { tunnel.SetMode(tunnel.Global) }, "mode: rule\ndns:\n  enable: true\n  nameserver: [223.5.5.5]\nrules:\n  - MATCH,DIRECT\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	select {
	case switches := <-stream:
		if switches.Mode != "direct" {
			t.Fatalf("the closing window published %q, want the live value direct", switches.Mode)
		}
	default:
		t.Fatal("a write muted inside the window was never made good when the window closed")
	}
	select {
	case switches := <-stream:
		t.Fatalf("second message %+v after the window closed", switches)
	default:
	}

	if _, err := parseRawConfigQuietlyWith(nil, "mode: rule\ndns:\n  enable: true\n  nameserver: [223.5.5.5]\nrules:\n  - MATCH,DIRECT\n"); err != nil {
		t.Fatalf("parse: %v", err)
	}
	select {
	case switches := <-stream:
		t.Fatalf("a plain parse published %+v", switches)
	default:
	}
}

func parseRawConfigQuietlyWith(insideWindow func(), yaml string) (*config.Config, error) {
	raw, err := config.UnmarshalRawConfig([]byte(yaml))
	if err != nil {
		return nil, err
	}
	if insideWindow != nil {
		previous := tunnel.Mode()
		fired := false
		tunnel.SetModeObserver(func(mode tunnel.TunnelMode) {
			publishRuntimeSwitches()
			if !fired && mode != previous {
				fired = true
				insideWindow()
			}
		})
		defer installRuntimeSwitchSeams()
	}
	return parseRawConfigQuietly(raw)
}

func TestTheWindowNeverLeavesAMutedWriteBehind(t *testing.T) {
	installRuntimeSwitchSeams()
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			publishRuntimeSwitches()
		}
	}()
	for i := 0; i < 500; i++ {
		_, _ = insideParseWindow(func() (*config.Config, error) {
			publishRuntimeSwitches()
			publishRuntimeSwitches()
			return nil, nil
		})
	}
	close(stop)
	wg.Wait()

	parseWindow.Lock()
	defer parseWindow.Unlock()
	if parseWindow.inFlight != 0 || parseWindow.parses != 0 || parseWindow.muted != 0 {
		t.Fatalf("bookkeeping left behind after every window closed: inFlight=%d parses=%d muted=%d",
			parseWindow.inFlight, parseWindow.parses, parseWindow.muted)
	}
}
