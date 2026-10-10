package clash

import (
	"encoding/json"
	"go/build/constraint"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func catalogFieldsByPath(t *testing.T, profile string) map[string]syntaxField {
	t.Helper()
	box, err := SyntaxCatalogForIOS(profile)
	if err != nil {
		t.Fatal(err)
	}
	var catalog syntaxCatalog
	if err := json.Unmarshal([]byte(box.Value), &catalog); err != nil {
		t.Fatal(err)
	}
	fields := map[string]syntaxField{}
	for _, field := range catalog.Fields {
		fields[field.Path] = field
	}
	return fields
}

func unavailable(field syntaxField, value string) (syntaxUnavailableValue, bool) {
	for _, entry := range field.UnavailableValues {
		if entry.Value == value {
			return entry, true
		}
	}
	return syntaxUnavailableValue{}, false
}

func TestTheCatalogMarksValuesThePlatformCannotRun(t *testing.T) {
	for _, name := range []string{RuntimeProfileIOSPacketTunnel, RuntimeProfileTVOSPacketTunnel, RuntimeProfileMacOSPacketTunnel, RuntimeProfileMacOSApplication} {
		profile, err := normalizeRuntimeProfile(name)
		if err != nil {
			t.Fatal(err)
		}
		fields := catalogFieldsByPath(t, name)
		for _, path := range []string{"proxies[hysteria].protocol", "proxies[hysteria].obfs-protocol"} {
			entry, marked := unavailable(fields[path], "faketcp")
			if !marked || entry.Alternative != "" || !strings.Contains(entry.Reason, "udp") {
				t.Errorf("%s %s: faketcp %+v marked %v", name, path, entry, marked)
			}
		}
		listenerTypes := 0
		for path, field := range fields {
			if !strings.HasPrefix(path, "listeners[") || !strings.HasSuffix(path, "].type") {
				continue
			}
			listenerTypes++
			for value, port := range map[string]string{"tproxy": "tproxy-port", "redir": "redir-port"} {
				entry, marked := unavailable(field, value)
				if !marked || entry.Reason == "" || entry.Reason != deviationReason(port) {
					t.Errorf("%s %s: %s %+v marked %v", name, path, value, entry, marked)
				}
			}
		}
		if listenerTypes == 0 {
			t.Errorf("%s: no listener type checked", name)
		}
		walled := easyTierWalledProfile(runtimePolicyFor(profile, true))
		types := 0
		for path, field := range fields {
			if !strings.HasPrefix(path, "proxies[") || !strings.HasSuffix(path, "].type") {
				continue
			}
			types++
			if _, marked := unavailable(field, "easytier"); marked != walled {
				t.Errorf("%s %s: easytier marked %v, walled %v", name, path, marked, walled)
			}
		}
		if types < 20 {
			t.Errorf("%s: %d node types checked", name, types)
		}
		if len(fields["proxy-providers.*.exclude-type"].UnavailableValues) != 0 {
			t.Errorf("%s: exclude-type marks %+v", name, fields["proxy-providers.*.exclude-type"].UnavailableValues)
		}
		for path, field := range fields {
			for _, entry := range field.UnavailableValues {
				if !slices.Contains(field.Values, entry.Value) {
					t.Errorf("%s %s: marks %q, which it does not offer", name, path, entry.Value)
				}
			}
		}
	}
}

func TestFaketcpIsBuiltOnlyForLinux(t *testing.T) {
	directory := filepath.Join("..", "..", "transport", "hysteria", "conns", "faketcp")
	tags := map[string]bool{"unix": true, "cgo": true}
	for _, tag := range strings.Split(iPhoneSliceTags(t), ",") {
		tags[strings.TrimSpace(tag)] = true
	}
	built := func(file, goos string) bool {
		if strings.HasSuffix(file, "_linux.go") && goos != "linux" {
			return false
		}
		data, err := os.ReadFile(filepath.Join(directory, file))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			if constraint.IsGoBuild(line) {
				expr, err := constraint.Parse(line)
				if err != nil {
					t.Fatal(err)
				}
				return expr.Eval(func(tag string) bool {
					return tags[tag] || tag == goos || (goos == "ios" && tag == "darwin")
				})
			}
		}
		return true
	}
	for _, goos := range []string{"darwin", "ios"} {
		if !built("tcp_stub.go", goos) || built("tcp_linux.go", goos) {
			t.Errorf("%s: the stub built %v, the Linux implementation %v", goos, built("tcp_stub.go", goos), built("tcp_linux.go", goos))
		}
	}
	stub, err := os.ReadFile(filepath.Join(directory, "tcp_stub.go"))
	if err != nil || !strings.Contains(string(stub), `errors.New("faketcp is not supported on this platform")`) {
		t.Errorf("the stub's Dial no longer refuses (%v)", err)
	}
	client, err := os.ReadFile(filepath.Join("..", "..", "transport", "hysteria", "transport", "client.go"))
	if err != nil || !strings.Contains(string(client), `proto == "faketcp"`) || !strings.Contains(string(client), "faketcp.Dial(") {
		t.Errorf("hysteria no longer dials faketcp for its protocol value (%v)", err)
	}
}

func TestAWalledValueMarksOnlyTheFieldsThatOfferIt(t *testing.T) {
	fields := []syntaxField{
		{Path: "proxies[hysteria].protocol", Values: []string{"udp", "wechat-video"}},
		{Path: "proxies[hysteria].obfs-protocol", Values: []string{"udp", "faketcp"}},
	}
	markUnavailableValues(fields, runtimePolicyFor(runtimeProfileIOSPacketTunnel, true))
	if len(fields[0].UnavailableValues) != 0 || len(fields[1].UnavailableValues) != 1 {
		t.Errorf("marked %+v and %+v", fields[0].UnavailableValues, fields[1].UnavailableValues)
	}
}

func TestTheListenersThisPlatformCannotOpen(t *testing.T) {
	stub, err := os.ReadFile(filepath.Join("..", "..", "listener", "tproxy", "setsockopt_other.go"))
	if err != nil {
		t.Fatal(err)
	}
	built := false
	for _, line := range strings.Split(string(stub), "\n") {
		if constraint.IsGoBuild(line) {
			expr, err := constraint.Parse(line)
			if err != nil {
				t.Fatal(err)
			}
			built = expr.Eval(func(tag string) bool { return tag == "darwin" || tag == "ios" || tag == "unix" })
		}
	}
	if !built || !strings.Contains(string(stub), `errors.New("not supported on current platform")`) {
		t.Errorf("tproxy's refusing setsockopt is no longer what Apple builds (built %v)", built)
	}
	redir, err := os.ReadFile(filepath.Join("..", "..", "listener", "redir", "tcp_darwin.go"))
	if err != nil || !strings.Contains(string(redir), `syscall.Open("/dev/pf"`) {
		t.Errorf("redir on darwin no longer reads /dev/pf (%v)", err)
	}
	for _, port := range []string{"tproxy-port", "redir-port"} {
		if deviationReason(port) == "" {
			t.Errorf("the deviation table has no reason for %s", port)
		}
	}
}
