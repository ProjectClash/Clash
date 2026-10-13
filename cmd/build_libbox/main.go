package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var sdkTagPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+-clash\.[1-9][0-9]*$`)
var sourceRevisionPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

var coreVersionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

var (
	target        string
	output        string
	debugBuild    bool
	internalBuild bool
	withoutQUIC   bool
	slices        string
)

type appleSlicePlan struct {
	name    string
	targets []string
}

const (
	bindModuleDir               = "bind/clash"
	privacyManifestRelativePath = "cmd/build_libbox/PrivacyInfo.xcprivacy"
	buildInfoResourceName       = "ClashBuildInfo.json"
	appleBindTarget             = "ios,iossimulator,macos,tvos,tvossimulator"
	iosVersion                  = "15.0"
	macosVersion                = "13.0"
	tvosVersion                 = "17.0"

	baseTags       = "with_gvisor,cmfa,with_quic"
	baseTagsNoQUIC = "with_gvisor,cmfa"
	notMacosTags   = "with_low_memory,no_easytier"
)

func init() {
	flag.StringVar(&target, "target", "apple", "bind target: apple = "+appleBindTarget+", or an explicit gomobile target list")
	flag.StringVar(&output, "output", "Clash.xcframework", "output xcframework path (relative to repo root)")
	flag.BoolVar(&debugBuild, "debug", false, "keep symbols and build ids")
	flag.BoolVar(&internalBuild, "internal", false, "compile internal-only diagnostics and keep symbols")
	flag.BoolVar(&withoutQUIC, "without-quic", false, "exclude HTTP/3 Network Quality support")
	flag.StringVar(&slices, "slices", "", "build only these Apple slices (comma separated); "+
		"names "+strings.Join(appleSliceNames(), ", ")+", groups "+strings.Join(appleSliceGroupNames(), ", ")+
		"; empty means every slice")
}

func main() {
	flag.Parse()

	root, err := os.Getwd()
	if err != nil {
		fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, bindModuleDir, "go.mod")); err != nil {
		fatal(fmt.Errorf("run from the repository root (missing %s/go.mod): %w", bindModuleDir, err))
	}

	bindTarget := target
	if target == "apple" {
		bindTarget = appleBindTarget
	}

	version, err := coreVersion(root)
	if err != nil {
		fatal(err)
	}
	sdk, err := sdkVersion(root)
	if err != nil {
		fatal(err)
	}
	revision, dirty, err := gitSourceState(root)
	if err != nil {
		fatal(err)
	}

	outPath := output
	if !filepath.IsAbs(outPath) {
		outPath = filepath.Join(root, output)
	}

	runtimeGODEBUG, err := appleRuntimeGODEBUG(root)
	if err != nil {
		fatal(err)
	}
	ldflags := appleLdflags(version, !debugBuild && !internalBuild, runtimeGODEBUG)
	buildTags := effectiveBaseTags(internalBuild, !withoutQUIC)
	toolchain, err := goToolchainVersion(root)
	if err != nil {
		fatal(err)
	}
	buildInfo, err := encodeAppleBuildInfo(
		revision,
		dirty,
		sdk,
		version,
		buildTags,
		notMacosTags,
		toolchain,
		debugBuild,
		internalBuild,
		!withoutQUIC,
	)
	if err != nil {
		fatal(err)
	}

	overlayCleanup := func() {}
	if target == "apple" {
		if err := buildAppleSerial(root, outPath, buildInfo); err != nil {
			fatal(err)
		}
	} else {
		args := []string{
			"bind", "-v",
			"-target", bindTarget,
			"-o", outPath,
			"-iosversion=" + iosVersion,
			"-macosversion=" + macosVersion,
			"-tvosversion=" + tvosVersion,
			"-tags", buildTags,
			"-tags-not-macos=" + notMacosTags,
			"-trimpath",
			"-buildvcs=false",
			"-ldflags", ldflags,
			".",
		}

		gomobile, err := findTool("gomobile")
		if err != nil {
			fatal(err)
		}

		cmd := exec.Command(gomobile, args...)
		cmd.Dir = filepath.Join(root, bindModuleDir)
		cmd.Env = buildEnv()
		if isAppleBindTarget(bindTarget) {
			env, cleanup, err := withAppleCPUOverlay(cmd.Env, root)
			if err != nil {
				fatal(err)
			}
			defer cleanup()
			overlayCleanup = cleanup
			cmd.Env = env
		}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		fmt.Fprintf(os.Stderr, "build_libbox: core version %s (SDK %s)\nbuild_libbox: (cd %s && %s %s)\n",
			version, sdk, bindModuleDir, gomobile, strings.Join(args, " "))
		if err := cmd.Run(); err != nil {
			overlayCleanup()
			fatal(err)
		}
		if err := finalizeXCFramework(root, outPath, buildInfo); err != nil {
			overlayCleanup()
			fatal(err)
		}
	}

	slices, err := xcframeworkSliceDirs(outPath)
	if err != nil || len(slices) == 0 {
		overlayCleanup()
		fatal(fmt.Errorf("no slices found in %s", outPath))
	}
	fmt.Fprintf(os.Stderr, "build_libbox: %s slices:\n", outPath)
	for _, s := range slices {
		fmt.Fprintf(os.Stderr, "  %s\n", filepath.Base(s))
	}
	if target == "apple" || isAppleBindTarget(bindTarget) {
		if err := verifyAppleCPUOverlayInXCFramework(outPath); err != nil {
			overlayCleanup()
			fatal(err)
		}
		if err := verifyMDNSClientInXCFramework(outPath); err != nil {
			overlayCleanup()
			fatal(err)
		}
		if err := verifyRuntimeGODEBUGInXCFramework(outPath, runtimeGODEBUG); err != nil {
			overlayCleanup()
			fatal(err)
		}
	}
}

func appleLdflags(version string, strip bool, runtimeGODEBUG string) string {
	ldflags := "-X github.com/ProjectClash/Clash/constant.Version=" + version
	ldflags += " -X runtime.godebugDefault=" + runtimeGODEBUG
	if strip {
		ldflags += " -s -w -buildid="
	}
	return ldflags
}

func appleSerialBuildPlan() []appleSlicePlan {
	return []appleSlicePlan{
		{name: "ios-device", targets: []string{"ios/arm64"}},
		{name: "ios-simulator", targets: []string{"iossimulator/arm64", "iossimulator/amd64"}},
		{name: "macos", targets: []string{"macos/arm64", "macos/amd64"}},
		{name: "tvos-device", targets: []string{"tvos/arm64"}},
		{name: "tvos-simulator", targets: []string{"tvossimulator/arm64", "tvossimulator/amd64"}},
	}
}

func appleSliceGroups() map[string][]string {
	return map[string][]string{
		"ios":   {"ios-device", "ios-simulator"},
		"macos": {"macos"},
		"tvos":  {"tvos-device", "tvos-simulator"},
	}
}

func appleSliceNames() []string {
	plans := appleSerialBuildPlan()
	names := make([]string, 0, len(plans))
	for _, plan := range plans {
		names = append(names, plan.name)
	}
	return names
}

func appleSliceGroupNames() []string {
	groups := appleSliceGroups()
	names := make([]string, 0, len(groups))
	for name := range groups {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func selectAppleSlices(request string, plans []appleSlicePlan) ([]appleSlicePlan, error) {
	request = strings.TrimSpace(request)
	if request == "" {
		return plans, nil
	}
	groups := appleSliceGroups()
	wanted := make(map[string]bool)
	for _, token := range strings.Split(request, ",") {
		token = strings.TrimSpace(token)
		if token == "" {
			continue
		}
		if expanded, ok := groups[token]; ok {
			for _, name := range expanded {
				wanted[name] = true
			}
			continue
		}
		known := false
		for _, plan := range plans {
			if plan.name == token {
				known = true
				break
			}
		}
		if !known {
			return nil, fmt.Errorf("unknown Apple slice %q; slices are %s, groups are %s",
				token, strings.Join(appleSliceNames(), ", "), strings.Join(appleSliceGroupNames(), ", "))
		}
		wanted[token] = true
	}
	if len(wanted) == 0 {
		return nil, fmt.Errorf("-slices %q selected nothing", request)
	}
	selected := make([]appleSlicePlan, 0, len(wanted))
	for _, plan := range plans {
		if wanted[plan.name] {
			selected = append(selected, plan)
		}
	}
	return selected, nil
}

func buildAppleSerial(root, outPath string, expectedBuildInfo []byte) error {
	if !strings.HasSuffix(outPath, ".xcframework") {
		return fmt.Errorf("Apple output %q must end in .xcframework", outPath)
	}
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate build_libbox executable: %w", err)
	}
	workRoot, err := os.MkdirTemp("", "clash-apple-serial-")
	if err != nil {
		return fmt.Errorf("create serial Apple build directory: %w", err)
	}
	defer os.RemoveAll(workRoot)

	selected, err := selectAppleSlices(slices, appleSerialBuildPlan())
	if err != nil {
		return err
	}
	if len(selected) != len(appleSerialBuildPlan()) {
		names := make([]string, 0, len(selected))
		for _, plan := range selected {
			names = append(names, plan.name)
		}
		fmt.Fprintf(os.Stderr, "build_libbox: PARTIAL Apple artifact, slices: %s\n", strings.Join(names, ", "))
	}

	var assembledFrameworks []string
	for _, plan := range selected {
		var thinFrameworks []string
		for _, thinTarget := range plan.targets {
			thinRoot := filepath.Join(
				workRoot,
				strings.NewReplacer("/", "-", ",", "-").Replace(thinTarget),
			)
			thinOutput := filepath.Join(thinRoot, "Clash.xcframework")
			if err := os.MkdirAll(thinRoot, 0o755); err != nil {
				return fmt.Errorf("create %s build directory: %w", thinTarget, err)
			}
			arguments := []string{"-target", thinTarget, "-output", thinOutput}
			if debugBuild {
				arguments = append(arguments, "-debug")
			}
			if internalBuild {
				arguments = append(arguments, "-internal")
			}
			if withoutQUIC {
				arguments = append(arguments, "-without-quic")
			}
			fmt.Fprintf(os.Stderr, "build_libbox: serial Apple target %s\n", thinTarget)
			command := exec.Command(executable, arguments...)
			command.Dir = root
			command.Env = os.Environ()
			command.Stdout = os.Stdout
			command.Stderr = os.Stderr
			if err := command.Run(); err != nil {
				return fmt.Errorf("build %s: %w", thinTarget, err)
			}
			frameworks, err := filepath.Glob(
				filepath.Join(thinOutput, "*-*", "Clash.framework"),
			)
			if err != nil || len(frameworks) != 1 {
				return fmt.Errorf("%s produced %d frameworks, want 1", thinTarget, len(frameworks))
			}
			thinFrameworks = append(thinFrameworks, frameworks[0])
		}

		framework := thinFrameworks[0]
		if len(thinFrameworks) > 1 {
			for _, candidate := range thinFrameworks[1:] {
				if err := compareFrameworkMetadata(framework, candidate); err != nil {
					return fmt.Errorf("%s architecture metadata mismatch: %w", plan.name, err)
				}
			}
			fatRoot := filepath.Join(workRoot, "fat", plan.name)
			framework = filepath.Join(fatRoot, "Clash.framework")
			if err := os.MkdirAll(fatRoot, 0o755); err != nil {
				return fmt.Errorf("create %s assembly directory: %w", plan.name, err)
			}
			if err := runStreamingCommand(exec.Command("ditto", thinFrameworks[0], framework)); err != nil {
				return fmt.Errorf("copy %s framework: %w", plan.name, err)
			}
			lipoArguments := []string{"lipo"}
			for _, thinFramework := range thinFrameworks {
				lipoArguments = append(
					lipoArguments,
					filepath.Join(thinFramework, "Versions", "A", "Clash"),
				)
			}
			lipoArguments = append(
				lipoArguments,
				"-create", "-output", filepath.Join(framework, "Versions", "A", "Clash"),
			)
			if err := runStreamingCommand(exec.Command("xcrun", lipoArguments...)); err != nil {
				return fmt.Errorf("merge %s architectures: %w", plan.name, err)
			}
		}
		assembledFrameworks = append(assembledFrameworks, framework)
	}

	if err := os.RemoveAll(outPath); err != nil {
		return fmt.Errorf("remove previous Apple output: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(outPath), 0o755); err != nil {
		return fmt.Errorf("create Apple output directory: %w", err)
	}
	arguments := []string{"-create-xcframework"}
	for _, framework := range assembledFrameworks {
		arguments = append(arguments, "-framework", framework)
	}
	arguments = append(arguments, "-output", outPath)
	if err := runStreamingCommand(exec.Command("xcodebuild", arguments...)); err != nil {
		return fmt.Errorf("assemble Apple XCFramework: %w", err)
	}
	if err := canonicalizeXCFrameworkPlist(outPath); err != nil {
		return err
	}
	if err := verifyAppleBuildInfo(outPath, expectedBuildInfo, len(selected)); err != nil {
		return err
	}
	return nil
}

func canonicalizeXCFrameworkPlist(artifact string) error {
	plist := filepath.Join(artifact, "Info.plist")
	script := `import plistlib, sys
path = sys.argv[1]
with open(path, "rb") as handle:
    root = plistlib.load(handle)
libraries = root.get("AvailableLibraries")
if not isinstance(libraries, list):
    raise SystemExit("XCFramework Info.plist has no AvailableLibraries array")
root["AvailableLibraries"] = sorted(libraries, key=lambda item: item.get("LibraryIdentifier", ""))
with open(path, "wb") as handle:
    plistlib.dump(root, handle, sort_keys=True)
`
	command := exec.Command("python3", "-c", script, plist)
	command.Stderr = os.Stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("canonicalize XCFramework Info.plist: %w", err)
	}
	return nil
}

func runStreamingCommand(command *exec.Cmd) error {
	command.Env = buildEnv()
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	return command.Run()
}

func compareFrameworkMetadata(left, right string) error {
	leftMetadata, err := frameworkMetadata(left)
	if err != nil {
		return err
	}
	rightMetadata, err := frameworkMetadata(right)
	if err != nil {
		return err
	}
	if len(leftMetadata) != len(rightMetadata) {
		return fmt.Errorf("metadata entry count %d != %d", len(leftMetadata), len(rightMetadata))
	}
	for name, leftDigest := range leftMetadata {
		if rightDigest, ok := rightMetadata[name]; !ok || rightDigest != leftDigest {
			return fmt.Errorf("metadata differs at %s", name)
		}
	}
	return nil
}

func frameworkMetadata(root string) (map[string]string, error) {
	metadata := make(map[string]string)
	err := filepath.WalkDir(root, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(root, current)
		if err != nil {
			return err
		}
		if relative == "." || relative == filepath.Join("Versions", "A", "Clash") {
			return nil
		}
		if entry.IsDir() {
			metadata[relative] = "directory"
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			target, err := os.Readlink(current)
			if err != nil {
				return err
			}
			metadata[relative] = "symlink:" + target
			return nil
		}
		contents, err := os.ReadFile(current)
		if err != nil {
			return err
		}
		metadata[relative] = fmt.Sprintf("file:%x", sha256.Sum256(contents))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return metadata, nil
}

func verifyAppleBuildInfo(artifact string, expected []byte, wantSlices int) error {
	paths, err := filepath.Glob(filepath.Join(
		artifact,
		"*-*",
		"Clash.framework",
		"Versions",
		"A",
		"Resources",
		buildInfoResourceName,
	))
	if err != nil {
		return fmt.Errorf("enumerate Apple build info: %w", err)
	}
	if len(paths) != wantSlices {
		return fmt.Errorf("Apple build info count is %d, want %d", len(paths), wantSlices)
	}
	for _, path := range paths {
		actual, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		if !bytes.Equal(actual, expected) {
			return fmt.Errorf("Apple build info differs at %s", path)
		}
	}
	return nil
}

func finalizeXCFramework(root, artifact string, buildInfo []byte) error {
	manifest, err := os.ReadFile(filepath.Join(root, privacyManifestRelativePath))
	if err != nil {
		return fmt.Errorf("read SDK privacy manifest: %w", err)
	}
	slices, err := xcframeworkSliceDirs(artifact)
	if err != nil {
		return fmt.Errorf("enumerate XCFramework slices: %w", err)
	}
	if len(slices) == 0 {
		return fmt.Errorf("no slices found in %s", artifact)
	}
	oldInitializer := []byte("- (nullable instancetype)init;")
	newInitializer := []byte("- (nonnull instancetype)init;")
	for _, slice := range slices {
		framework := filepath.Join(slice, "Clash.framework", "Versions", "A")
		headerPath := filepath.Join(framework, "Headers", "Clash.objc.h")
		header, err := os.ReadFile(headerPath)
		if err != nil {
			return fmt.Errorf("read %s public header: %w", filepath.Base(slice), err)
		}
		if count := bytes.Count(header, oldInitializer); count != 2 {
			return fmt.Errorf("%s nullable constructor count is %d, want 2", filepath.Base(slice), count)
		}
		header = bytes.ReplaceAll(header, oldInitializer, newInitializer)
		if err := os.WriteFile(headerPath, header, 0o644); err != nil {
			return fmt.Errorf("write %s public header: %w", filepath.Base(slice), err)
		}
		manifestPath := filepath.Join(framework, "Resources", "PrivacyInfo.xcprivacy")
		if err := os.MkdirAll(filepath.Dir(manifestPath), 0o755); err != nil {
			return fmt.Errorf("create %s resource directory: %w", filepath.Base(slice), err)
		}
		if err := os.WriteFile(manifestPath, manifest, 0o644); err != nil {
			return fmt.Errorf("write %s privacy manifest: %w", filepath.Base(slice), err)
		}
		buildInfoPath := filepath.Join(framework, "Resources", buildInfoResourceName)
		if err := os.WriteFile(buildInfoPath, buildInfo, 0o644); err != nil {
			return fmt.Errorf("write %s build info: %w", filepath.Base(slice), err)
		}
	}
	return nil
}

type appleBuildInfo struct {
	Schema              int      `json:"schema"`
	SourceRevision      string   `json:"sourceRevision"`
	SourceDirty         bool     `json:"sourceDirty"`
	SDKVersion          string   `json:"sdkVersion"`
	MihomoCoreVersion   string   `json:"mihomoCoreVersion"`
	GoToolchain         string   `json:"goToolchain"`
	BuildTags           []string `json:"buildTags"`
	BuildTagsNotMacos   []string `json:"buildTagsNotMacos"`
	DebugBuild          bool     `json:"debugBuild"`
	InternalDiagnostics bool     `json:"internalDiagnostics"`
	HTTP3NetworkQuality bool     `json:"http3NetworkQuality"`
}

var goVersionPattern = regexp.MustCompile(`^go[0-9]+\.[0-9]+(\.[0-9]+)?([a-z]+[0-9]+)?$`)

func splitBuildTags(tags string) []string {
	buildTags := strings.FieldsFunc(tags, func(character rune) bool {
		return character == ',' || character == ' '
	})
	sort.Strings(buildTags)
	uniqueTags := buildTags[:0]
	for _, tag := range buildTags {
		if len(uniqueTags) == 0 || uniqueTags[len(uniqueTags)-1] != tag {
			uniqueTags = append(uniqueTags, tag)
		}
	}
	if uniqueTags == nil {
		return []string{}
	}
	return uniqueTags
}

func encodeAppleBuildInfo(
	revision string,
	dirty bool,
	sdk string,
	core string,
	tags string,
	tagsNotMacos string,
	toolchain string,
	debug bool,
	internal bool,
	http3 bool,
) ([]byte, error) {
	if !sourceRevisionPattern.MatchString(revision) {
		return nil, fmt.Errorf("source revision must be a full lowercase Git revision")
	}
	if strings.TrimSpace(sdk) == "" || strings.TrimSpace(core) == "" {
		return nil, fmt.Errorf("SDK and core versions are required")
	}
	if !goVersionPattern.MatchString(toolchain) {
		return nil, fmt.Errorf("go toolchain %q is not a go version (want the form go1.26.6)", toolchain)
	}
	payload := appleBuildInfo{
		Schema:              2,
		SourceRevision:      revision,
		SourceDirty:         dirty,
		SDKVersion:          sdk,
		MihomoCoreVersion:   core,
		GoToolchain:         toolchain,
		BuildTags:           splitBuildTags(tags),
		BuildTagsNotMacos:   splitBuildTags(tagsNotMacos),
		DebugBuild:          debug,
		InternalDiagnostics: internal,
		HTTP3NetworkQuality: http3,
	}
	encoded, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode Apple build info: %w", err)
	}
	return append(encoded, '\n'), nil
}

func goToolchainVersion(root string) (string, error) {
	command := exec.Command("go", "env", "GOVERSION")
	command.Dir = filepath.Join(root, bindModuleDir)
	command.Env = buildEnv()
	output, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("read the bind module's go toolchain: %w", err)
	}
	version := strings.TrimSpace(string(output))
	if !goVersionPattern.MatchString(version) {
		return "", fmt.Errorf("go env GOVERSION answered %q, not a go version", version)
	}
	return version, nil
}

func gitSourceState(root string) (string, bool, error) {
	revisionCommand := exec.Command("git", "rev-parse", "HEAD")
	revisionCommand.Dir = root
	revisionOutput, err := revisionCommand.Output()
	if err != nil {
		return "", false, fmt.Errorf("read source revision: %w", err)
	}
	revision := strings.TrimSpace(string(revisionOutput))
	if !sourceRevisionPattern.MatchString(revision) {
		return "", false, fmt.Errorf("source revision is not a full lowercase Git revision")
	}
	statusCommand := exec.Command("git", "status", "--porcelain", "--untracked-files=normal")
	statusCommand.Dir = root
	statusOutput, err := statusCommand.Output()
	if err != nil {
		return "", false, fmt.Errorf("read source status: %w", err)
	}
	entries := dirtySourceEntries(statusOutput)
	if len(entries) > 0 {
		fmt.Fprintf(os.Stderr, "build_libbox: source tree is dirty, so this artifact records sourceDirty=true\n")
		fmt.Fprintf(os.Stderr, "build_libbox: a formal SDK cannot be packaged from it (scripts/package_release.sh)\n")
		for _, entry := range entries {
			fmt.Fprintf(os.Stderr, "  %s\n", entry)
		}
	}
	return revision, len(entries) != 0, nil
}

func dirtySourceEntries(statusOutput []byte) []string {
	trimmed := bytes.TrimSpace(statusOutput)
	if len(trimmed) == 0 {
		return nil
	}
	lines := strings.Split(string(trimmed), "\n")
	entries := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		entries = append(entries, strings.TrimSpace(line))
	}
	return entries
}

func effectiveBaseTags(internal bool, includeQUIC bool) string {
	tags := baseTags
	if !includeQUIC {
		tags = baseTagsNoQUIC
	}
	if internal {
		return tags + ",clash_internal"
	}
	return tags
}

func coreVersion(root string) (string, error) {
	if pinned, err := os.ReadFile(filepath.Join(root, "UPSTREAM_VERSION")); err == nil {
		return parseCoreVersion(string(pinned))
	} else if !os.IsNotExist(err) {
		return "", fmt.Errorf("read upstream version: %w", err)
	}
	cmd := exec.Command("git", "describe", "--tags", "--abbrev=0", "--match", "v*")
	cmd.Dir = root
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git describe: %w", err)
	}
	return parseCoreVersion(string(out))
}

func parseCoreVersion(describeOut string) (string, error) {
	v := stripSDKSuffix(strings.TrimPrefix(strings.TrimSpace(describeOut), "v"))
	if !coreVersionPattern.MatchString(v) {
		return "", fmt.Errorf("core version %q from git tag is not a valid semver; check the nearest v* tag", v)
	}
	return v, nil
}

func stripSDKSuffix(tag string) string {
	for _, suffix := range []string{"-clash."} {
		if i := strings.Index(tag, suffix); i >= 0 {
			return tag[:i]
		}
	}
	return tag
}

func sdkVersion(root string) (string, error) {
	tagCmd := exec.Command("git", "tag", "--points-at", "HEAD")
	tagCmd.Dir = root
	tagOut, _ := tagCmd.Output()

	short := exec.Command("git", "rev-parse", "--short", "HEAD")
	short.Dir = root
	shortOut, _ := short.Output()

	return selectSDKVersion(string(tagOut), strings.TrimSpace(string(shortOut)))
}

func selectSDKVersion(tagOutput, shortSHA string) (string, error) {
	var matches []string
	for _, tag := range strings.Fields(tagOutput) {
		if sdkTagPattern.MatchString(tag) {
			matches = append(matches, tag)
		}
	}
	switch len(matches) {
	case 0:
		if shortSHA != "" {
			return "dev-" + shortSHA, nil
		}
		return "dev", nil
	case 1:
		return matches[0], nil
	default:
		return "", fmt.Errorf("multiple SDK release tags point at HEAD (%s); exactly one v*-clash.N is required", strings.Join(matches, ", "))
	}
}

func findTool(name string) (string, error) {
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	gopath, err := exec.Command("go", "env", "GOPATH").Output()
	if err == nil {
		p := filepath.Join(strings.TrimSpace(string(gopath)), "bin", name)
		if _, statErr := os.Stat(p); statErr == nil {
			return p, nil
		}
	}
	return "", fmt.Errorf("%s not found in PATH or GOPATH/bin (install gomobile)", name)
}

func buildEnv() []string {
	env := os.Environ()
	if os.Getenv("DEVELOPER_DIR") == "" {
		sel, err := exec.Command("xcode-select", "-p").Output()
		const xcodeDev = "/Applications/Xcode.app/Contents/Developer"
		if err == nil && !strings.Contains(string(sel), "Xcode.app") {
			if _, statErr := os.Stat(xcodeDev); statErr == nil {
				env = append(env, "DEVELOPER_DIR="+xcodeDev)
			}
		}
	}
	if gopath, err := exec.Command("go", "env", "GOPATH").Output(); err == nil {
		gobin := filepath.Join(strings.TrimSpace(string(gopath)), "bin")
		env = append(env, "PATH="+gobin+string(os.PathListSeparator)+os.Getenv("PATH"))
	}
	env = append(env, "ZERO_AR_DATE=1")
	return env
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "build_libbox:", err)
	os.Exit(1)
}
