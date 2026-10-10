package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)


const appleCPUOverlayRelativeSource = "cmd/build_libbox/overlay/internal_cpu_arm64_ios.go.src"

const appleCPUOverlayMarkerSymbol = "clashAppleCPUOverlayMarker"

func requireOverlayableGOROOT(goroot, modcache, version string) (string, error) {
	if modcache != "" && strings.HasPrefix(goroot, filepath.Clean(modcache)+string(os.PathSeparator)) {
		return "", fmt.Errorf("the bind module pins %s and this machine only has it as a module-cache download under %s; go build refuses to overlay files beneath GOMODCACHE, so the Apple slices cannot be built at all. Install it for real: go install golang.org/dl/%s@latest && %s download", version, modcache, version, version)
	}
	return goroot, nil
}

func goInBindModule(root string, env []string, args ...string) (string, error) {
	cmd := exec.Command("go", args...)
	cmd.Dir = filepath.Join(root, bindModuleDir)
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) && len(exit.Stderr) > 0 {
			return "", fmt.Errorf("go %s in %s: %w: %s", strings.Join(args, " "), bindModuleDir, err, strings.TrimSpace(string(exit.Stderr)))
		}
		return "", fmt.Errorf("go %s in %s: %w", strings.Join(args, " "), bindModuleDir, err)
	}
	return strings.TrimSpace(string(out)), nil
}

func parseGoEnvLines(output string, names []string) map[string]string {
	values := map[string]string{}
	lines := strings.Split(strings.TrimRight(output, "\n"), "\n")
	for i, name := range names {
		if i < len(lines) {
			line := lines[i]
			if strings.HasPrefix(line, name+"=") {
				line = strings.TrimPrefix(line, name+"=")
			}
			values[name] = strings.TrimSpace(line)
		}
	}
	return values
}

func goEnvValues(values map[string]string, names ...string) ([]string, error) {
	out := make([]string, 0, len(names))
	for _, name := range names {
		v, ok := values[name]
		if !ok || v == "" {
			return nil, fmt.Errorf("go env gave no %s", name)
		}
		out = append(out, v)
	}
	return out, nil
}

func pinnedToolchainAvailable(pin, hostVersion string, lookPath func(string) (string, error)) bool {
	if compareGoVersions(hostVersion, pin) >= 0 {
		return true
	}
	_, err := lookPath(pin)
	return err == nil
}

func compareGoVersions(a, b string) int {
	parse := func(v string) [3]int {
		var out [3]int
		v = strings.TrimPrefix(v, "go")
		v = strings.SplitN(v, "-", 2)[0]
		for i, part := range strings.SplitN(v, ".", 3) {
			n := 0
			for _, r := range part {
				if r < '0' || r > '9' {
					break
				}
				n = n*10 + int(r-'0')
			}
			out[i] = n
		}
		return out
	}
	x, y := parse(a), parse(b)
	for i := range x {
		if x[i] != y[i] {
			if x[i] < y[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

func appleOverlayToolchain(root string, env []string) (string, error) {
	names := []string{"GOROOT", "GOMODCACHE", "GOVERSION"}
	output, err := goInBindModule(root, env, append([]string{"env"}, names...)...)
	if err != nil {
		return "", err
	}
	values, err := goEnvValues(parseGoEnvLines(output, names), names...)
	if err != nil {
		return "", err
	}
	return requireOverlayableGOROOT(values[0], values[1], values[2])
}

func verifyAppleCPUOverlayMarker(slice, nmOutput string) error {
	present := strings.Contains(nmOutput, "internal/cpu."+appleCPUOverlayMarkerSymbol)
	iosFamily := strings.HasPrefix(slice, "ios") || strings.HasPrefix(slice, "tvos")
	wantsMarker := iosFamily && strings.Contains(slice, "arm64")
	switch {
	case wantsMarker && !present:
		return fmt.Errorf("slice %s was built past the cpu overlay: internal/cpu.%s is missing, so AES-GCM runs in software on it", slice, appleCPUOverlayMarkerSymbol)
	case !wantsMarker && present:
		return fmt.Errorf("slice %s carries the arm64 iOS cpu overlay marker; the overlay's build constraint leaked", slice)
	}
	return nil
}

func sliceSymbolArgs(binary string) []string {
	return []string{"-arch", "all", "-a", binary}
}

func sliceSymbolCommand(binary string) (string, []string) {
	return "xcrun", append([]string{"nm"}, sliceSymbolArgs(binary)...)
}

func requireSilentFeatureFile(path string) error {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		return fmt.Errorf("apple cpu overlay: %s no longer parses as the file the overlay was written for: %w", filepath.Base(path), err)
	}
	selectsIOS := false
	for _, group := range file.Comments {
		for _, c := range group.List {
			if !constraint.IsGoBuild(c.Text) {
				continue
			}
			expr, err := constraint.Parse(c.Text)
			if err != nil {
				return fmt.Errorf("apple cpu overlay: %s build constraint: %w", filepath.Base(path), err)
			}
			if expr.Eval(func(tag string) bool { return tag == "arm64" || tag == "ios" || tag == "darwin" }) {
				selectsIOS = true
			}
		}
	}
	if !selectsIOS {
		return fmt.Errorf("apple cpu overlay: %s no longer selects arm64 && ios, so this toolchain handles iOS elsewhere; retire the overlay after reading what it does now", filepath.Base(path))
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "osInit" {
			continue
		}
		if fn.Body == nil || len(fn.Body.List) == 0 {
			return nil
		}
		return fmt.Errorf("apple cpu overlay: %s now has an osInit that does something on iOS; the overlay would overwrite it, so it needs a human to compare before it is applied again", filepath.Base(path))
	}
	return fmt.Errorf("apple cpu overlay: %s defines no osInit; the toolchain has changed shape, retire or rewrite the overlay", filepath.Base(path))
}

func xcframeworkSliceDirs(xcframework string) ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(xcframework, "*-*"))
	if err != nil {
		return nil, err
	}
	dirs := make([]string, 0, len(matches))
	for _, match := range matches {
		info, err := os.Stat(match)
		if err != nil {
			return nil, err
		}
		if info.IsDir() {
			dirs = append(dirs, match)
		}
	}
	return dirs, nil
}

func verifyAppleCPUOverlayInXCFramework(xcframework string) error {
	sliceDirs, err := xcframeworkSliceDirs(xcframework)
	if err != nil {
		return err
	}
	checked := 0
	for _, sliceDir := range sliceDirs {
		slice := filepath.Base(sliceDir)
		binary, err := appleSliceBinary(sliceDir)
		if err != nil {
			return err
		}
		name, args := sliceSymbolCommand(binary)
		out, err := exec.Command(name, args...).Output()
		if err != nil {
			return fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
		}
		if err := verifyAppleCPUOverlayMarker(slice, string(out)); err != nil {
			return err
		}
		checked++
	}
	if checked == 0 {
		return fmt.Errorf("no slices found under %s", xcframework)
	}
	fmt.Fprintf(os.Stderr, "build_libbox: apple cpu overlay marker verified in %d slice(s)\n", checked)
	return nil
}

func appleSliceBinary(sliceDir string) (string, error) {
	for _, candidate := range []string{
		filepath.Join(sliceDir, "Clash.framework", "Clash"),
		filepath.Join(sliceDir, "Clash.framework", "Versions", "A", "Clash"),
	} {
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("no Clash framework binary under %s", sliceDir)
}

func appleCPUOverlaySource(root string) string {
	return filepath.Join(root, filepath.FromSlash(appleCPUOverlayRelativeSource))
}

func writeAppleCPUOverlay(root, goroot, dir string) (string, error) {
	source := appleCPUOverlaySource(root)
	if _, err := os.Stat(source); err != nil {
		return "", fmt.Errorf("apple cpu overlay source: %w", err)
	}
	replaced := filepath.Join(goroot, "src", "internal", "cpu", "cpu_arm64_other.go")
	if _, err := os.Stat(replaced); err != nil {
		return "", fmt.Errorf("apple cpu overlay: %s is missing from GOROOT %s; the toolchain may detect ARM64 features on iOS itself now, in which case retire the overlay (%w)", "cpu_arm64_other.go", goroot, err)
	}
	if err := requireSilentFeatureFile(replaced); err != nil {
		return "", err
	}
	payload, err := json.Marshal(map[string]map[string]string{"Replace": {replaced: source}})
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "apple-cpu-overlay.json")
	if err := os.WriteFile(path, payload, 0o644); err != nil {
		return "", err
	}
	return path, nil
}

var goShimCompilingSubcommands = []string{"build", "install", "list", "test", "vet", "run"}

func writeGoShim(dir, realGo, overlayJSON string) (string, error) {
	binDir := filepath.Join(dir, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		return "", err
	}
	var script strings.Builder
	script.WriteString("#!/bin/sh\n")
	script.WriteString("# Clash build shim: hands go build the internal/cpu overlay for the iOS family.\n")
	script.WriteString("real=" + shellQuote(realGo) + "\n")
	script.WriteString("overlay=" + shellQuote(overlayJSON) + "\n")
	script.WriteString("case \"$1\" in\n")
	script.WriteString("  " + strings.Join(goShimCompilingSubcommands, "|") + ")\n")
	script.WriteString("    sub=\"$1\"; shift\n")
	script.WriteString("    printf '%s\\n' \"$sub\" >> \"$overlay.injected\"\n")
	script.WriteString(goShimCFlagsFix)
	script.WriteString("    exec \"$real\" \"$sub\" \"-overlay=$overlay\" \"$@\"\n")
	script.WriteString("    ;;\n")
	script.WriteString("  *)\n")
	script.WriteString("    exec \"$real\" \"$@\"\n")
	script.WriteString("    ;;\n")
	script.WriteString("esac\n")
	shim := filepath.Join(binDir, "go")
	if err := os.WriteFile(shim, []byte(script.String()), 0o755); err != nil {
		return "", err
	}
	return binDir, nil
}

const goShimCFlagsFix = `    for var in CGO_CFLAGS CGO_CXXFLAGS CGO_LDFLAGS; do
      eval "value=\${$var}"
      [ -n "$value" ] || continue
      value=$(printf ' %s ' "$value" | sed -E 's/ -fembed-bitcode( -fembed-bitcode)* / /g; s/^ //; s/ $//')
      if [ "$var" != CGO_LDFLAGS ]; then
        case " $value " in *" -O"*|*" \"-O"*|*" '-O"*) ;; *) value="${value:+$value }-O2" ;; esac
      fi
      export "$var=$value"
    done
    printf '%s\n' "$CGO_CFLAGS" >> "$overlay.cflags"
`

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func withAppleCPUOverlay(env []string, root string) (_ []string, cleanup func(), err error) {
	realGo, err := exec.LookPath("go")
	if err != nil {
		return nil, nil, err
	}
	goroot, err := appleOverlayToolchain(root, env)
	if err != nil {
		return nil, nil, err
	}
	dir, err := os.MkdirTemp("", "clash-apple-cpu-overlay-")
	if err != nil {
		return nil, nil, err
	}
	shimWritten := false
	cleanup = func() {
		if shimWritten {
			if marks, err := os.ReadFile(filepath.Join(dir, "apple-cpu-overlay.json.injected")); err == nil {
				fmt.Fprintf(os.Stderr, "build_libbox: apple cpu overlay rode into %d go invocation(s)\n", strings.Count(string(marks), "\n"))
			} else {
				fmt.Fprintln(os.Stderr, "build_libbox: apple cpu overlay rode into 0 go invocations -- the shim was never used")
			}
			if flags, err := os.ReadFile(filepath.Join(dir, "apple-cpu-overlay.json.cflags")); err == nil {
				optimised, bitcode, total := 0, 0, 0
				for _, line := range strings.Split(strings.TrimSpace(string(flags)), "\n") {
					if line == "" {
						continue
					}
					total++
					if strings.Contains(" "+line+" ", " -O2 ") {
						optimised++
					}
					if strings.Contains(line, "-fembed-bitcode") {
						bitcode++
					}
				}
				fmt.Fprintf(os.Stderr, "build_libbox: cgo C flags: -O2 in %d of %d apple go invocation(s), bitcode in %d\n", optimised, total, bitcode)
			}
		}
		_ = os.RemoveAll(dir)
	}
	overlayJSON, err := writeAppleCPUOverlay(root, goroot, dir)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	binDir, err := writeGoShim(dir, realGo, overlayJSON)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	shimWritten = true
	fmt.Fprintf(os.Stderr, "build_libbox: apple cpu overlay %s via %s\n", overlayJSON, filepath.Join(binDir, "go"))
	out := make([]string, 0, len(env)+1)
	pathSeen := false
	for _, entry := range env {
		if strings.HasPrefix(entry, "PATH=") {
			out = append(out, "PATH="+binDir+string(os.PathListSeparator)+strings.TrimPrefix(entry, "PATH="))
			pathSeen = true
			continue
		}
		out = append(out, entry)
	}
	if !pathSeen {
		out = append(out, "PATH="+binDir)
	}
	return out, cleanup, nil
}

func isAppleBindTarget(target string) bool {
	for _, item := range strings.Split(target, ",") {
		switch strings.SplitN(strings.TrimSpace(item), "/", 2)[0] {
		case "ios", "iossimulator", "macos", "maccatalyst", "tvos", "tvossimulator":
		default:
			return false
		}
	}
	return target != ""
}
