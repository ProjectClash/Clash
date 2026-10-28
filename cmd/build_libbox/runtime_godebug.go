package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const appleStackStartGODEBUG = "adaptivestackstart=0"

const appleHeapSamplingGODEBUG = "memprofilerate=0"

func appleRuntimeGODEBUG(root string) (string, error) {
	defaults, err := gomobileMainDefaultGODEBUG(root)
	if err != nil {
		return "", err
	}
	return withAppleGODEBUG(defaults), nil
}

func withAppleGODEBUG(defaults string) string {
	own := appleStackStartGODEBUG + "," + appleHeapSamplingGODEBUG
	if defaults == "" {
		return own
	}
	return defaults + "," + own
}

func gomobileMainDefaultGODEBUG(root string) (string, error) {
	goVersion, err := bindModuleGoVersion(root)
	if err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp("", "clash-godebug-")
	if err != nil {
		return "", fmt.Errorf("create the GODEBUG probe module: %w", err)
	}
	defer os.RemoveAll(dir)
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module gobind\n\ngo "+goVersion+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("write the GODEBUG probe module: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
		return "", fmt.Errorf("write the GODEBUG probe module: %w", err)
	}
	command := exec.Command("go", "list", "-f", "{{.DefaultGODEBUG}}", ".")
	command.Dir = dir
	command.Env = buildEnv()
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("read the default GODEBUG of gomobile's main package: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

func bindModuleGoVersion(root string) (string, error) {
	command := exec.Command("go", "list", "-m", "-f", "{{.GoVersion}}")
	command.Dir = filepath.Join(root, bindModuleDir)
	command.Env = buildEnv()
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("read the bind module's go version: %w", err)
	}
	version := strings.TrimSpace(string(output))
	if version == "" || strings.ContainsAny(version, " \n") {
		return "", fmt.Errorf("the bind module's go version %q is not one", version)
	}
	return version, nil
}

func verifyRuntimeGODEBUGInXCFramework(xcframework, godebug string) error {
	sliceDirs, err := xcframeworkSliceDirs(xcframework)
	if err != nil {
		return err
	}
	checked := 0
	for _, sliceDir := range sliceDirs {
		binary, err := appleSliceBinary(sliceDir)
		if err != nil {
			return err
		}
		contents, err := os.ReadFile(binary)
		if err != nil {
			return fmt.Errorf("read %s: %w", binary, err)
		}
		if err := runtimeGODEBUGVerdict(filepath.Base(sliceDir), contents, godebug); err != nil {
			return err
		}
		checked++
	}
	if checked == 0 {
		return fmt.Errorf("no slices found under %s", xcframework)
	}
	fmt.Fprintf(os.Stderr, "build_libbox: runtime GODEBUG %q linked in %d slice(s)\n", godebug, checked)
	return nil
}

func runtimeGODEBUGVerdict(slice string, contents []byte, godebug string) error {
	if !bytes.Contains(contents, []byte(godebug)) {
		return fmt.Errorf("slice %s does not carry the runtime GODEBUG %q: the -X runtime.godebugDefault "+
			"linked nothing, so goroutines in it start on the adaptive stack size and package "+
			"initialisation samples the heap", slice, godebug)
	}
	return nil
}
