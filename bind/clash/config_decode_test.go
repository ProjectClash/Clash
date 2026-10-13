package clash

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	proxyprovider "github.com/ProjectClash/Clash/adapter/provider"
	"github.com/ProjectClash/Clash/component/age"
	"github.com/ProjectClash/Clash/config"
	"go.yaml.in/yaml/v3"
)

const countParsesEnvironmentKey = "CLASH_TEST_COUNT_PARSES"

func init() {
	if os.Getenv(countParsesEnvironmentKey) != "" {
		runtime.MemProfileRate = 1
	}
}

func yamlNodesBuilt(f func()) int64 {
	before := yamlNodeAllocations()
	f()
	return yamlNodeAllocations() - before
}

func yamlNodeAllocations() int64 {
	for i := 0; i < 3; i++ {
		runtime.GC()
	}
	var records []runtime.MemProfileRecord
	for {
		n, ok := runtime.MemProfile(records, true)
		if ok {
			records = records[:n]
			break
		}
		records = make([]runtime.MemProfileRecord, n+64)
	}
	var total int64
	for i := range records {
		frames := runtime.CallersFrames(records[i].Stack())
		for {
			frame, more := frames.Next()
			if strings.HasPrefix(frame.Function, "runtime.") && more {
				continue
			}
			if frame.Function == "go.yaml.in/yaml/v3.(*parser).node" {
				total += records[i].AllocObjects
			}
			break
		}
	}
	return total
}

func TestStartAndReloadParseTheTextOnce(t *testing.T) {
	command := exec.Command(os.Args[0], "-test.run=^TestCountTheParsesOfStartAndReload$", "-test.v", "-test.count=1")
	command.Env = append(os.Environ(), countParsesEnvironmentKey+"=1")
	output, err := command.CombinedOutput()
	for _, line := range strings.Split(string(output), "\n") {
		if strings.Contains(line, "config_decode_test.go") {
			t.Log(strings.TrimSpace(line))
		}
	}
	if err != nil || !strings.Contains(string(output), "--- PASS: TestCountTheParsesOfStartAndReload") {
		t.Fatalf("the counting child failed (%v)", err)
	}
}

func TestCountTheParsesOfStartAndReload(t *testing.T) {
	if os.Getenv(countParsesEnvironmentKey) == "" {
		t.Skip("run by TestStartAndReloadParseTheTextOnce")
	}
	text := startedIntentYAML(400)
	one := yamlNodesBuilt(func() {
		if _, err := config.UnmarshalRawConfig([]byte(text)); err != nil {
			t.Fatal(err)
		}
	})
	if one < 400*8 {
		t.Fatalf("one parse of the text built %d nodes: the count does not see the parser", one)
	}
	if err := Setup(testOptions(t)); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { _ = service.Close() })
	started := yamlNodesBuilt(func() {
		if err := service.Start(text); err != nil {
			t.Fatalf("Start: %v", err)
		}
	})
	reloaded := yamlNodesBuilt(func() {
		if err := service.Reload(text); err != nil {
			t.Fatalf("Reload: %v", err)
		}
	})
	fakeReloadMemoryReaders(t, 1<<40, 1<<20)
	judged := yamlNodesBuilt(func() {
		if err := service.Reload(text); err != nil {
			t.Fatalf("Reload under a wall: %v", err)
		}
	})
	t.Logf("nodes built: one parse %d, Start %d, Reload %d, Reload judged %d", one, started, reloaded, judged)
	for _, phase := range []struct {
		name  string
		built int64
	}{{"Start", started}, {"Reload", reloaded}, {"Reload under a memory wall", judged}} {
		if phase.built > one+one/4 {
			t.Errorf("%s built %d YAML nodes, %.1f parses of the text (one parse builds %d)", phase.name, phase.built, float64(phase.built)/float64(one), one)
		}
	}
}

func TestOneDecodeReadsWhatEachDecodeRead(t *testing.T) {
	if err := Setup(testOptions(t)); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	write := func(name string, size int) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, make([]byte, size), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	proxiesFile, rulesFile, otherFile := write("p.yaml", 5000), write("r.yaml", 3000), write("o.yaml", 7000)

	secret, public, err := age.GenX25519KeyPair()
	if err != nil {
		t.Fatal(err)
	}
	age.SetGlobalSecretKeys(secret)
	t.Cleanup(func() { age.SetGlobalSecretKeys() })
	armored, err := age.EncryptBytes([]byte("mode: global\nunified-delay: true\nproxies:\n  - {name: a, type: socks5, server: 10.0.0.1, port: 1080}\nrules:\n  - MATCH,DIRECT\n"), public)
	if err != nil {
		t.Fatal(err)
	}

	documents := map[string]string{
		"empty":           "",
		"comment":         "# nothing\n",
		"minimal":         "mode: rule\n",
		"typical":         startedIntentYAML(6) + "unified-delay: false\nprofile:\n  store-fake-ip: false\ntun:\n  enable: true\n  stack: system\n  mtu: 1400\ndns:\n  enable: true\n  listen-routing-mark: 7\n",
		"nulls":           "unified-delay: ~\nprofile: ~\ntun: ~\nproxies: ~\nrules: ~\n",
		"root merge":      "base: &b\n  unified-delay: true\n  tun:\n    stack: mixed\n  profile:\n    store-fake-ip: true\n<<: *b\nproxies: []\n",
		"merge in a node": "x-node: &n {type: socks5, server: 10.0.0.1, port: 1080}\nproxies:\n  - {<<: *n, name: a}\n  - &second {name: b, type: socks5, server: 10.0.0.2, port: 1080}\n  - {<<: *second, name: c}\nproxy-groups:\n  - {name: G, type: select, proxies: [a, b, c]}\n",
		"aliased list":    "x-list: &l\n  - {name: a, type: socks5, server: 10.0.0.1, port: 1080}\nproxies: *l\n",
		"flow list":       "proxies: [{name: a, type: socks5, server: 10.0.0.1, port: 1080}, {name: b, type: http, server: 10.0.0.2, port: 80}]\n",
		"odd entries":     "proxies:\n  - {name: a, type: easytier, network-name: n, network-secret: s}\n  - {1: one, name: b, type: easytier}\n  - ~\n  - {name: c, type: socks5, server: 10.0.0.1, port: 1080}\n",
		"scalar entry":    "proxies:\n  - just-a-name\n",
		"easytier":        easyTierWallDocument,
		"metadata rules":  "rules:\n  - PROCESS-NAME,Safari,DIRECT\n  - PROCESS-NAME-REGEX,.*,REJECT\n  - UID,501,DIRECT\n  - AND,((UID,501),(DOMAIN,x.com)),DIRECT\n  - 42\n  - MATCH,DIRECT\nsub-rules:\n  s1:\n    - UID,0,DIRECT\n    - MATCH,DIRECT\n  s0:\n    - PROCESS-PATH,/bin/x,DIRECT\n",
		"bad probe value": "unified-delay: maybe\n",
		"bad tun":         "tun:\n  stack: [a]\n",
		"bad port":        "mixed-port: lots\n",
		"duplicate key":   "mode: rule\nmode: global\n",
		"odd key":         "x-odd:\n  ? [a, b]\n  : c\nmode: rule\n",
		"syntax":          "proxies:\n  - {name: a\nrules: [\n",
		"two documents":   "mode: rule\n---\nmode: global\n",
		"not a mapping":   "- a\n- b\n",
		"armor":           string(armored),
		"bad armor":       age.FileHeader + "\nnot really\n-----END AGE ENCRYPTED FILE-----\n",
		"providers":       "proxy-providers:\n  p:\n    type: file\n    path: " + proxiesFile + "\n  mixed:\n    type: http\n    Path: " + otherFile + "\n    PATH: " + rulesFile + "\n    url: http://127.0.0.1:1/x\n  url-only:\n    type: http\n    url: http://127.0.0.1:1/y\nrule-providers:\n  r:\n    type: file\n    behavior: domain\n    path: " + rulesFile + "\n  gone:\n    type: file\n    behavior: domain\n    path: " + filepath.Join(dir, "absent.yaml") + "\n",
		"settings":        "allow-lan: true\nfind-process-mode: always\ninterface-name: en0\nrouting-mark: 3\nexternal-controller-pipe: x\ngeodata-loader: standard\ngeo-auto-update: true\nntp:\n  enable: true\n  write-to-system: true\niptables:\n  enable: true\ntun:\n  enable: true\n  device: utun9\n  auto-route: false\n  include-uid: [1]\n  route-address-set: [a]\n  gso: true\nclash-for-android:\n  append-system-dns: true\n",
	}

	documents["400 nodes"] = startedIntentYAML(400)

	type policyCase struct {
		name   string
		policy appleRuntimePolicy
	}
	var policies []policyCase
	for _, profile := range []runtimeProfile{runtimeProfileIOSPacketTunnel, runtimeProfileMacOSPacketTunnel, runtimeProfileMacOSApplication, runtimeProfileTVOSPacketTunnel} {
		for _, underNE := range []bool{true, false} {
			policies = append(policies, policyCase{fmt.Sprintf("profile %d NE %v", profile, underNE), runtimePolicyFor(profile, underNE)})
		}
	}
	defer SetAllowLanPermitted(!allowLanForcedOff.Load())
	previousInclude := includeAllNetworksRequested.Load()
	defer includeAllNetworksRequested.Store(previousInclude)

	for name, text := range documents {
		t.Run(name, func(t *testing.T) {
			decoded := decodeConfigText(text)

			raw, rawErr := upstreamRawConfig(text)
			if fmt.Sprint(rawErr) != fmt.Sprint(decoded.err) {
				t.Fatalf("decode error %v, upstream UnmarshalRawConfig's %v", decoded.err, rawErr)
			}
			if got, want := decoded.providerBytes(), providerPayloadBytes(text); got != want {
				t.Fatalf("provider estimate %d, providerPayloadBytes %d", got, want)
			}
			if rawErr != nil {
				return
			}
			if !reflect.DeepEqual(decoded.raw, raw) {
				t.Fatalf("the RawConfig differs from upstream UnmarshalRawConfig's")
			}
			if got, want := decoded.unwritten, probeUnwrittenAppleDefaults([]byte(text)); got != want {
				t.Fatalf("unwritten defaults %+v, the probe's %+v", got, want)
			}
			for _, lanOff := range []bool{false, true} {
				SetAllowLanPermitted(!lanOff)
				for _, include := range []bool{false, true} {
					includeAllNetworksRequested.Store(include)
					for _, c := range policies {
						want, wantErr := collectConfigDeviations(text, c.policy)
						got, gotErr := decoded.deviationRows(c.policy)
						if fmt.Sprint(gotErr) != fmt.Sprint(wantErr) {
							t.Fatalf("%s lan-off %v include-all %v: report error %v, want %v", c.name, lanOff, include, gotErr, wantErr)
						}
						gotJSON, _ := json.Marshal(got)
						wantJSON, _ := json.Marshal(want)
						if string(gotJSON) != string(wantJSON) {
							t.Fatalf("%s lan-off %v include-all %v: rows\n%s\nwant\n%s", c.name, lanOff, include, gotJSON, wantJSON)
						}
					}
				}
			}
		})
	}
	if !strings.HasPrefix(documents["armor"], age.FileHeader) {
		t.Fatal("the armored document is not armor")
	}
}

func upstreamRawConfig(text string) (*config.RawConfig, error) {
	raw := config.DefaultRawConfig()
	buf, err := age.DecryptBytes([]byte(text))
	if err != nil {
		return nil, fmt.Errorf("decrypt config error: %w", err)
	}
	if err := yaml.Unmarshal(buf, raw); err != nil {
		return nil, err
	}
	return raw, nil
}

func TestStartAndReloadLetGoOfTheirDecode(t *testing.T) {
	text := startedIntentYAML(20)
	if err := Setup(testOptions(t)); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	service, err := NewService(newRecordingPlatform())
	if err != nil {
		t.Fatalf("NewService: %v", err)
	}
	t.Cleanup(func() { _ = service.Close() })

	released := make(chan string, 8)
	previous := configDecodeObserver
	t.Cleanup(func() { configDecodeObserver = previous })
	var label string
	configDecodeObserver = func(decoded *configDecode) {
		name := label
		runtime.SetFinalizer(decoded.raw, func(*config.RawConfig) { released <- name })
	}
	waitReleased := func(name string) {
		t.Helper()
		for i := 0; i < 50; i++ {
			runtime.GC()
			select {
			case got := <-released:
				if got != name {
					t.Fatalf("released %s while waiting for %s", got, name)
				}
				return
			default:
			}
		}
		t.Fatalf("%s's decode is still reachable after it returned", name)
	}

	label = "Start"
	if err := service.Start(text); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitReleased("Start")
	label = "Reload"
	if err := service.Reload(text); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	waitReleased("Reload")
	fakeReloadMemoryReaders(t, 1<<40, 1<<20)
	label = "Reload under a memory wall"
	if err := service.Reload(text); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	waitReleased("Reload under a memory wall")
}

func TestProviderPayloadsDecodeAsUpstreamDecodesThem(t *testing.T) {
	payloads := map[string]string{
		"list":         "proxies:\n" + strings.Repeat("  - {name: a, type: socks5, server: 10.0.0.1, port: 1080}\n", 3),
		"whole config": startedIntentYAML(50),
		"share links":  "ss://YWVzLTEyOC1nY206cGFzc3dvcmQ=@10.0.0.1:8388#a\n",
		"merged node":  "x: &n {type: socks5, port: 1}\nproxies:\n  - {<<: *n, name: a, server: 10.0.0.1}\n",
		"bad node":     "proxies:\n  - {name: a, name: b}\n",
		"empty":        "",
	}
	for name, payload := range payloads {
		var want, got proxyprovider.ProxySchema
		wantErr := yaml.Unmarshal([]byte(payload), &want)
		gotErr := unmarshalProxySchema([]byte(payload), &got)
		if fmt.Sprint(gotErr) != fmt.Sprint(wantErr) || !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %v %#v, yaml.Unmarshal's %v %#v", name, gotErr, got, wantErr, want)
		}
	}
}
