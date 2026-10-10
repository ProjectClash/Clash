package clash

import (
	"net"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestTVOSPacketTunnelIsANamedRuntimeProfile(t *testing.T) {
	profile, err := normalizeRuntimeProfile(RuntimeProfileTVOSPacketTunnel)
	if err != nil {
		t.Fatalf("normalizeRuntimeProfile(%q) = %v", RuntimeProfileTVOSPacketTunnel, err)
	}
	if profile != runtimeProfileTVOSPacketTunnel {
		t.Fatalf("normalizeRuntimeProfile(%q) = %v, want the tvOS profile",
			RuntimeProfileTVOSPacketTunnel, profile)
	}
	if got := profile.String(); got != RuntimeProfileTVOSPacketTunnel {
		t.Fatalf("profile.String() = %q, want %q", got, RuntimeProfileTVOSPacketTunnel)
	}
	if profile == runtimeProfileIOSPacketTunnel {
		t.Fatal("the tvOS profile is the same value as the iOS one; then it is not a seat, " +
			"and every diagnostic that prints a profile keeps reporting an Apple TV as an iPhone")
	}
}

var tvOSPolicyExceptions = map[string]bool{"bindsUnixControlSocket": true}

func TestTVOSPolicyIsFieldForFieldTheIOSPolicy(t *testing.T) {
	for _, underNE := range []bool{true, false} {
		tvOS := runtimePolicyFor(runtimeProfileTVOSPacketTunnel, underNE)
		iOS := runtimePolicyFor(runtimeProfileIOSPacketTunnel, underNE)
		if tvOS.profile != runtimeProfileTVOSPacketTunnel {
			t.Fatalf("underNetworkExtension=%v: policy carries profile %v, want the tvOS seat",
				underNE, tvOS.profile)
		}
		tvOS.profile = iOS.profile
		if tvOS != iOS {
			for _, field := range differingPolicyFields(tvOS, iOS) {
				if !tvOSPolicyExceptions[field] {
					t.Fatalf("underNetworkExtension=%v: tvOS policy differs from iOS in %s, "+
						"which is not one of the measured exceptions. A divergence has to be "+
						"a deliberate edit with a device behind it, not a side effect.",
						underNE, field)
				}
			}
		}
	}
}

func TestTVOSResolvesTheSameOwnerMetadataAsIOS(t *testing.T) {
	for _, underNE := range []bool{true, false} {
		tvOS := runtimePolicyFor(runtimeProfileTVOSPacketTunnel, underNE).processMetadata()
		iOS := runtimePolicyFor(runtimeProfileIOSPacketTunnel, underNE).processMetadata()
		if tvOS != iOS {
			t.Fatalf("underNetworkExtension=%v: tvOS process metadata = %+v, iOS = %+v",
				underNE, tvOS, iOS)
		}
	}
}

func TestTVOSInheritsTheIOSPacketTunnelBehaviorPredicate(t *testing.T) {
	if !runtimeProfileTVOSPacketTunnel.inheritsIOSPacketTunnelBehavior() {
		t.Fatal("the tvOS profile does not inherit iOS packet tunnel behavior; " +
			"the geo updater turns on and the end-pause timer turns off, neither of which was decided")
	}
	if !runtimeProfileIOSPacketTunnel.inheritsIOSPacketTunnelBehavior() {
		t.Fatal("the iOS profile does not inherit its own behavior")
	}
	for _, profile := range []runtimeProfile{runtimeProfileMacOSPacketTunnel, runtimeProfileMacOSApplication} {
		if profile.inheritsIOSPacketTunnelBehavior() {
			t.Fatalf("%v inherits iOS packet tunnel behavior; the macOS profiles were measured "+
				"out of it on purpose", profile)
		}
	}
}

func TestNoShippingGateComparesAgainstTheIOSProfileDirectly(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	pattern := regexp.MustCompile(`[!=]=\s*runtimeProfileIOSPacketTunnel|runtimeProfileIOSPacketTunnel\s*[!=]=`)
	if !pattern.MatchString("if currentRuntimeProfile() != runtimeProfileIOSPacketTunnel {") {
		t.Fatal("the scan pattern no longer matches the shape it exists to catch")
	}

	var offenders []string
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		if name == "runtime_profile.go" {
			continue
		}
		source, err := os.ReadFile(filepath.Join(".", name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		for index, line := range strings.Split(string(source), "\n") {
			if pattern.MatchString(line) {
				offenders = append(offenders, filepath.Join(name)+":"+itoa(index+1)+" "+strings.TrimSpace(line))
			}
		}
	}
	if len(offenders) > 0 {
		t.Fatalf("these gates decide behavior by comparing against the iOS profile, which answers "+
			"\"no\" for tvOS without anyone deciding that:\n  %s\nuse "+
			"inheritsIOSPacketTunnelBehavior() unless the difference is the point",
			strings.Join(offenders, "\n  "))
	}
}

func differingPolicyFields(got, want appleRuntimePolicy) []string {
	gotValue := reflect.ValueOf(got)
	wantValue := reflect.ValueOf(want)
	var fields []string
	for index := 0; index < gotValue.NumField(); index++ {
		if !reflect.DeepEqual(
			gotValue.Field(index).String()+gotValue.Field(index).Type().String(),
			wantValue.Field(index).String()+wantValue.Field(index).Type().String(),
		) || gotValue.Field(index).Kind() == reflect.Bool &&
			gotValue.Field(index).Bool() != wantValue.Field(index).Bool() {
			fields = append(fields, gotValue.Type().Field(index).Name)
		}
	}
	if len(fields) == 0 {
		fields = append(fields, "(no field differs; the struct comparison and this reporter disagree)")
	}
	return fields
}

func itoa(value int) string {
	if value == 0 {
		return "0"
	}
	var digits []byte
	for value > 0 {
		digits = append([]byte{byte('0' + value%10)}, digits...)
		value /= 10
	}
	return string(digits)
}

func TestTVOSDoesNotBindTheBindingControlSocket(t *testing.T) {
	for _, underNE := range []bool{true, false} {
		if runtimePolicyFor(runtimeProfileTVOSPacketTunnel, underNE).bindsUnixControlSocket {
			t.Fatal("the tvOS profile still opens the binding Unix socket; on a device that " +
				"bind returns EPERM, the readiness dial never succeeds, and the core stops " +
				"three seconds after the tunnel came up")
		}
		if !runtimePolicyFor(runtimeProfileIOSPacketTunnel, underNE).bindsUnixControlSocket {
			t.Fatal("iOS stopped binding the control socket; the App Group socket is how the " +
				"containing app reaches the controller there")
		}
		if !runtimePolicyFor(runtimeProfileMacOSPacketTunnel, underNE).bindsUnixControlSocket {
			t.Fatal("macOS stopped binding the control socket")
		}
	}
}

func TestTVOSResolvesNoBindingSocketAddress(t *testing.T) {
	const path = "/tmp/clash-test/clash.sock"
	withRuntimeProfile(t, runtimeProfileTVOSPacketTunnel)
	if address := bindingSocketPathFor(path); address != "" {
		t.Fatalf("tvOS resolved a binding socket address %q; binding it returns EPERM on the "+
			"device, and the readiness dial that follows never completes", address)
	}

	for _, profile := range []runtimeProfile{
		runtimeProfileIOSPacketTunnel,
		runtimeProfileMacOSPacketTunnel,
		runtimeProfileMacOSApplication,
	} {
		setupRuntimeProfile.Store(uint32(profile))
		if address := bindingSocketPathFor(path); address != path {
			t.Fatalf("%v resolved %q instead of the binding socket; the containing app "+
				"reaches the controller through it", profile, address)
		}
	}
}

func TestTheBindingSocketDecisionDoesNotDependOnProcessPlacement(t *testing.T) {
	for _, profile := range allRuntimeProfiles() {
		inExtension := runtimePolicyFor(profile, true).bindsUnixControlSocket
		onHost := runtimePolicyFor(profile, false).bindsUnixControlSocket
		if inExtension != onHost {
			t.Fatalf("%v binds the control socket in the extension (%v) and outside it (%v). "+
				"bindingSocketPathFor asks currentRuntimePolicy(true) from both the reload path "+
				"and a non-extension Start, so it now answers about the wrong process on one of "+
				"them -- give it the placement instead of hardcoding it", profile, inExtension, onHost)
		}
	}
}

func TestNoControlPlaneEntryPointTouchesThePathnameOnTVOS(t *testing.T) {
	port := freeLoopbackPort(t)
	addr := "127.0.0.1:" + port
	path := shortClashSocketPath(t)

	withRuntimeProfile(t, runtimeProfileTVOSPacketTunnel)
	withSetupClashAPIPath(t, path)
	cfg := controllerConfig(t, addr)
	t.Cleanup(func() { stopClashAPI(path) })

	writeDecoy(t, path)
	if err := startControlPlane(cfg, path); err != nil {
		t.Fatalf("startControlPlane on tvOS: %v -- it must bring up the user's controller and "+
			"return, not fail, and not wait on a socket that cannot exist", err)
	}
	assertDecoyIntact(t, path, "startControlPlane")

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("tvOS opened no controller at %s: %v -- the socket is what tvOS cannot have; "+
			"the address the user wrote is not", addr, err)
	}
	_ = conn.Close()

	applyExternalController(cfg)
	assertDecoyIntact(t, path, "applyExternalController (the reload path)")

	stopClashAPI(path)
	assertDecoyIntact(t, path, "stopClashAPI")
	assertNotListening(t, addr, "stopClashAPI on tvOS")
}

func TestTheDecoyIsSomethingTheControlPlaneWouldTouch(t *testing.T) {
	path := shortClashSocketPath(t)
	withRuntimeProfile(t, runtimeProfileIOSPacketTunnel)
	withSetupClashAPIPath(t, path)
	t.Cleanup(func() { stopClashAPI(path) })

	writeDecoy(t, path)
	if err := startControlPlane(nil, path); err != nil {
		t.Fatalf("startControlPlane on iOS: %v", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("nothing at the socket pathname after an iOS start: %v", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatalf("the pathname is %v after an iOS start, not a socket. The decoy survived the "+
			"profile that DOES own this pathname, so its survival on tvOS proves nothing",
			info.Mode())
	}
}

const decoyContents = "not a socket"

func writeDecoy(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(decoyContents), 0o644); err != nil {
		t.Fatalf("place the decoy at %s: %v", path, err)
	}
}

func assertDecoyIntact(t *testing.T, path, after string) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("after %s the decoy at %s is gone (%v). Nothing on tvOS bound this pathname, "+
			"so removing it is this process deleting a file it did not create", after, path, err)
	}
	if info.Mode()&os.ModeSocket != 0 {
		t.Fatalf("after %s the pathname is a socket; on the device that bind returns EPERM", after)
	}
	if mode := info.Mode().Perm(); mode != 0o644 {
		t.Fatalf("after %s the decoy is %04o, not 0644. Something chmod'ed the raw pathname -- "+
			"the 0600 narrowing belongs to a socket this profile never created, and on a device "+
			"it logs `secure Clash API Unix socket: no such file` instead", after, mode)
	}
	body, err := os.ReadFile(path)
	if err != nil || string(body) != decoyContents {
		t.Fatalf("after %s the decoy's contents are %q/%v, want %q", after, string(body), err, decoyContents)
	}
}

func assertNotListening(t *testing.T, addr string, after string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err != nil {
			return
		}
		_ = conn.Close()
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("the user's controller is still listening at %s after %s. Whatever gates that "+
		"operation gates the pathname half; the listener half must run regardless, or a Close or "+
		"a reload leaves an open surface behind", addr, after)
}

func TestNoSocketOperationTakesTheUnresolvedPathname(t *testing.T) {
	operations := map[string]*regexp.Regexp{
		"os.Remove":                  regexp.MustCompile(`os\.Remove\(([^)]*)\)`),
		"os.Chmod":                   regexp.MustCompile(`os\.Chmod\(([^,]*),`),
		`net.DialTimeout("unix", …)`: regexp.MustCompile(`net\.DialTimeout\("unix",\s*([^,]*),`),
		"secureBindingControlSocket": regexp.MustCompile(`secureBindingControlSocket\(([^)]*)\)`),
		"controllerServerConfig":     regexp.MustCompile(`controllerServerConfig\([^,]*,\s*([^)]*)\)`),
		"recreateControlPlane":       regexp.MustCompile(`recreateControlPlane\([^,]*,\s*([^)]*)\)`),
	}
	resolved := map[string]bool{"socket": true, "bindingSocketPath": true}

	if arg := operations["secureBindingControlSocket"].FindStringSubmatch(
		"\tif err := secureBindingControlSocket(path); err != nil {"); arg == nil || resolved[arg[1]] {
		t.Fatal("the scan no longer recognises the shape it exists to catch")
	}
	if arg := operations["secureBindingControlSocket"].FindStringSubmatch(
		"\tif err := secureBindingControlSocket(socket); err != nil {"); arg == nil || !resolved[arg[1]] {
		t.Fatal("the scan no longer accepts the shape that fixed the bug")
	}
	if arg := operations["recreateControlPlane"].FindStringSubmatch(
		"\tserver := recreateControlPlane(cfg, raw)"); arg == nil || resolved[arg[1]] {
		t.Fatal("a renamed raw pathname escapes the scan; the allowlist is not being applied")
	}

	sources := packageSourceFiles(t)
	found := map[string]int{}
	for _, name := range []string{"clash_api.go", "external_controller.go"} {
		body, ok := sources[name]
		if !ok {
			t.Fatalf("%s is not in this package; the scan is looking at nothing", name)
		}
		for index, line := range strings.Split(body, "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "func ") ||
				strings.Contains(line, "bindingSocketPathFor(path)") {
				continue
			}
			for operation, shape := range operations {
				match := shape.FindStringSubmatch(line)
				if match == nil {
					continue
				}
				found[operation]++
				if argument := strings.TrimSpace(match[1]); !resolved[argument] {
					t.Errorf("%s:%d %s operates on %q, which is not a resolved pathname:\n    %s\n"+
						"bindingSocketPathFor has already decided whether this profile owns that "+
						"pathname. Using anything but its answer afterwards is how the reload path "+
						"came to chmod a socket the same function had just declined to create",
						name, index+1, operation, argument, trimmed)
				}
			}
		}
	}
	for operation := range operations {
		if found[operation] == 0 {
			t.Errorf("no %s call found across the two files; the scan is measuring nothing for "+
				"that shape -- if the operation moved, move the scan with it", operation)
		}
	}
}
