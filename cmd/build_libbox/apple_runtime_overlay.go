package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)


const appleRuntimeOverlayMarkerSymbol = "clashAppleRuntimeOverlayMarker"

var appleRuntimeOverlayAddedFiles = map[string]string{
	"clash_apple_tunnel.go":     "cmd/build_libbox/overlay/runtime_clash_apple_tunnel.go.src",
	"clash_apple_tunnel_off.go": "cmd/build_libbox/overlay/runtime_clash_apple_tunnel_off.go.src",
}

type appleRuntimeEdit struct {
	old, new string
}

var appleRuntimeOverlayEdits = map[string][]appleRuntimeEdit{
	"malloc.go": {{
		old: "\t_StackCacheSize = 32 * 1024\n",
		new: "\t_StackCacheSize = clashStackCacheSize // clash_apple_tunnel*.go\n",
	}},
	"mspanset.go": {{
		old: "\tspanSetBlockEntries = 512 // 4KB on 64-bit\n\tspanSetInitSpineCap = 256 // Enough for 1GB heap on 64-bit\n",
		new: "\tspanSetBlockEntries = clashSpanSetBlockEntries // clash_apple_tunnel*.go\n\tspanSetInitSpineCap = clashSpanSetInitSpineCap\n",
	}},
	"proc.go": {
		{
			old: "\tif stksize != uintptr(startingStackSize) {\n\t\t// non-standard stack size - free it.\n",
			new: "\tif stksize != uintptr(startingStackSize) || clashAppleSmallProcess { // clash_apple_tunnel*.go\n\t\t// non-standard stack size - free it.\n",
		},
		{
			old: "\tif _cgo_pthread_key_created != nil && *(*uintptr)(_cgo_pthread_key_created) != 0 {\n\t\tcgoBindM()\n",
			new: "\tif !clashAppleDropExtraM && _cgo_pthread_key_created != nil && *(*uintptr)(_cgo_pthread_key_created) != 0 { // clash_apple_tunnel*.go\n\t\tcgoBindM()\n",
		},
		{
			old: "func schedinit() {\n",
			new: "func schedinit() {\n\tif clashAppleSmallProcess {\n\t\tclashAppleRuntimeOverlayMarker() // clash_apple_tunnel*.go\n\t}\n",
		},
	},
	"asm_arm64.s": {{
		old: "\t// Skip dropm to reuse it in the next call, when a pthread key has been created.\n",
		new: "\t// Clash, clash_apple_tunnel*.go: the iOS family gives the m back after every call.\n\tMOVBU\truntime·clashAppleDropExtraM(SB), R6\n\tCBNZ\tR6, dropm\n\n\t// Skip dropm to reuse it in the next call, when a pthread key has been created.\n",
	}},
}

func applyAppleRuntimeEdits(name, text string, edits []appleRuntimeEdit) (string, error) {
	for _, edit := range edits {
		if n := strings.Count(text, edit.old); n != 1 {
			return "", fmt.Errorf("apple runtime overlay: runtime/%s has %d copies of the text an edit replaces, not 1; the toolchain changed this code, so read it again before the edit is applied:\n%s", name, n, edit.old)
		}
		text = strings.Replace(text, edit.old, edit.new, 1)
	}
	return text, nil
}

func writeAppleRuntimeOverlay(root, goroot, dir string) (map[string]string, error) {
	runtimeDir := filepath.Join(goroot, "src", "runtime")
	outDir := filepath.Join(dir, "runtime")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, err
	}
	replace := map[string]string{}
	for name, edits := range appleRuntimeOverlayEdits {
		original := filepath.Join(runtimeDir, name)
		data, err := os.ReadFile(original)
		if err != nil {
			return nil, fmt.Errorf("apple runtime overlay: %w", err)
		}
		edited, err := applyAppleRuntimeEdits(name, string(data), edits)
		if err != nil {
			return nil, err
		}
		out := filepath.Join(outDir, name)
		if err := os.WriteFile(out, []byte(edited), 0o644); err != nil {
			return nil, err
		}
		replace[original] = out
	}
	for name, source := range appleRuntimeOverlayAddedFiles {
		added := filepath.Join(runtimeDir, name)
		if _, err := os.Stat(added); err == nil {
			return nil, fmt.Errorf("apple runtime overlay: GOROOT %s already has runtime/%s; the overlay would replace it", goroot, name)
		}
		path := filepath.Join(root, filepath.FromSlash(source))
		if _, err := os.Stat(path); err != nil {
			return nil, fmt.Errorf("apple runtime overlay source: %w", err)
		}
		replace[added] = path
	}
	return replace, nil
}

func verifyAppleRuntimeOverlayMarker(slice, nmOutput string) error {
	present := strings.Contains(nmOutput, "runtime."+appleRuntimeOverlayMarkerSymbol)
	iosFamily := strings.HasPrefix(slice, "ios") || strings.HasPrefix(slice, "tvos")
	switch {
	case iosFamily && !present:
		return fmt.Errorf("slice %s was built past the runtime overlay: runtime.%s is missing, so its Go runtime keeps upstream's server-sized metadata", slice, appleRuntimeOverlayMarkerSymbol)
	case !iosFamily && present:
		return fmt.Errorf("slice %s carries the iOS-family runtime overlay marker; the overlay's build constraint leaked", slice)
	}
	return nil
}
