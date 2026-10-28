package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

var sliceBuilds = []struct{ goos, tags string }{
	{"ios", "with_gvisor,cmfa,with_quic,with_low_memory,no_easytier"},
	{"darwin", "with_gvisor,cmfa,with_quic,with_low_memory,no_easytier,ios,tvos"},
	{"darwin", "with_gvisor,cmfa,with_quic"},
}

type goModule struct {
	Path    string    `json:"Path"`
	Version string    `json:"Version"`
	Dir     string    `json:"Dir"`
	Main    bool      `json:"Main"`
	Replace *goModule `json:"Replace"`
}

type goPackage struct {
	Module *goModule `json:"Module"`
}

type licenseEntry struct {
	Module      string        `json:"module"`
	Version     string        `json:"version,omitempty"`
	Replacement string        `json:"replacement,omitempty"`
	Files       []licenseFile `json:"files"`
}

type licenseFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

type licenseIndex struct {
	Schema  int            `json:"schema"`
	Modules []licenseEntry `json:"modules"`
}

func main() {
	var output string
	var clientResource string
	flag.StringVar(&output, "output", "dist/THIRD_PARTY_LICENSES", "output directory relative to the repository root")
	flag.StringVar(&clientResource, "client-resource", "",
		"path of a separately maintained acknowledgements list this command does not write; "+
			"named in the success report so a caller cannot mistake one for the other")
	flag.Parse()

	root, err := os.Getwd()
	if err != nil {
		fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "bind", "clash", "go.mod")); err != nil {
		fatal(errors.New("run package_licenses from the repository root"))
	}
	if !filepath.IsAbs(output) {
		output = filepath.Join(root, output)
	}
	if err := packageLicenses(root, output); err != nil {
		fatal(err)
	}
	reportWhatWasAndWasNotWritten(os.Stderr, output, clientResource)
}

func reportWhatWasAndWasNotWritten(out io.Writer, output, clientResource string) {
	fmt.Fprintf(out, "package_licenses: wrote the linked-module inventory to %s\n", output)
	if clientResource == "" {
		return
	}
	fmt.Fprintf(out, "package_licenses: this does NOT update %s\n", clientResource)
	fmt.Fprintf(out, "package_licenses: that one is a manual pin -- its core entry (github.com/ProjectClash/Clash) "+
		"version is the first 12 characters of ClashSDK.lock.json's coreRevision, and "+
		"AcknowledgementsTests fails when they disagree\n")
}

func packageLicenses(root, output string) error {
	modules, err := linkedModules(filepath.Join(root, "bind", "clash"))
	if err != nil {
		return err
	}
	if err := os.RemoveAll(output); err != nil {
		return fmt.Errorf("clear license output: %w", err)
	}
	if err := os.MkdirAll(output, 0o755); err != nil {
		return fmt.Errorf("create license output: %w", err)
	}

	index := licenseIndex{Schema: 1}
	for _, module := range modules {
		// A slice and a loop rather than the obvious `a || b`, because the OSS
		// export rewrites both of these paths to the same public module name.
		// As `||` that collapses to `x || x` and `go vet` rejects it as a
		// redundant or; as a map or a switch, duplicate keys and duplicate cases
		// are outright compile errors. Identical slice entries are legal and
		// silent, so the export cannot break this file by doing its job.
		selfModules := []string{
			"github.com/ProjectClash/Clash",
			"github.com/ProjectClash/Clash",
		}
		isSelf := false
		for _, self := range selfModules {
			if module.Path == self {
				isSelf = true
				break
			}
		}
		if module.Main || isSelf {
			continue
		}
		source := module.Dir
		replacement := ""
		if module.Replace != nil {
			replacement = module.Replace.Path
			if module.Replace.Version != "" {
				replacement += "@" + module.Replace.Version
			}
			if module.Replace.Dir != "" {
				source = module.Replace.Dir
			}
		}
		files, err := discoverLicenseFiles(source)
		if err != nil {
			return fmt.Errorf("%s: %w", module.Path, err)
		}
		if len(files) == 0 {
			return fmt.Errorf("linked module %s has no root LICENSE/COPYING/NOTICE/COPYRIGHT file", module.Path)
		}

		destination := filepath.Join(output, safeModuleDirectory(module.Path))
		if err := os.MkdirAll(destination, 0o755); err != nil {
			return fmt.Errorf("create license directory for %s: %w", module.Path, err)
		}
		entry := licenseEntry{Module: module.Path, Version: module.Version, Replacement: replacement}
		for _, sourceFile := range files {
			name, err := filepath.Rel(source, sourceFile)
			if err != nil || name == "." || strings.HasPrefix(name, "..") {
				return fmt.Errorf("resolve %s license path: %w", module.Path, err)
			}
			name = filepath.ToSlash(name)
			destinationFile := filepath.Join(destination, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(destinationFile), 0o755); err != nil {
				return fmt.Errorf("create license subdirectory for %s: %w", module.Path, err)
			}
			sum, err := copyAndHash(sourceFile, destinationFile)
			if err != nil {
				return fmt.Errorf("copy %s license %s: %w", module.Path, name, err)
			}
			entry.Files = append(entry.Files, licenseFile{Name: name, SHA256: sum})
		}
		index.Modules = append(index.Modules, entry)
	}
	if len(index.Modules) == 0 {
		return errors.New("linked module license inventory is empty")
	}
	payload, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return fmt.Errorf("encode license index: %w", err)
	}
	payload = append(payload, '\n')
	if err := os.WriteFile(filepath.Join(output, "INDEX.json"), payload, 0o644); err != nil {
		return fmt.Errorf("write license index: %w", err)
	}
	return nil
}

func linkedModules(moduleDir string) ([]goModule, error) {
	unique := make(map[string]goModule)
	for _, build := range sliceBuilds {
		if err := addLinkedModules(moduleDir, build.goos, build.tags, unique); err != nil {
			return nil, err
		}
	}
	modules := make([]goModule, 0, len(unique))
	for _, module := range unique {
		modules = append(modules, module)
	}
	sort.Slice(modules, func(i, j int) bool { return modules[i].Path < modules[j].Path })
	return modules, nil
}

func addLinkedModules(moduleDir, goos, tags string, unique map[string]goModule) error {
	cmd := exec.Command("go", "list", "-deps", "-json", "-tags="+tags, ".")
	cmd.Dir = moduleDir
	cmd.Env = append(os.Environ(), "GOOS="+goos, "GOARCH=arm64", "CGO_ENABLED=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("open go list output: %w", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start go list: %w", err)
	}
	decoder := json.NewDecoder(stdout)
	for {
		var pkg goPackage
		if err := decoder.Decode(&pkg); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			_ = cmd.Wait()
			return fmt.Errorf("decode go list: %w", err)
		}
		if pkg.Module != nil {
			unique[pkg.Module.Path] = *pkg.Module
		}
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("go list linked modules (%s, %s): %w", goos, tags, err)
	}
	return nil
}

func discoverLicenseFiles(directory string) ([]string, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("read module root: %w", err)
	}
	var files []string
	for _, entry := range entries {
		if entry.IsDir() || !isLicenseFile(entry.Name()) {
			continue
		}
		files = append(files, filepath.Join(directory, entry.Name()))
	}
	sort.Strings(files)
	if len(files) != 0 {
		return files, nil
	}
	err = filepath.WalkDir(directory, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == directory {
			return nil
		}
		if entry.IsDir() {
			if strings.HasPrefix(entry.Name(), ".") || entry.Name() == "vendor" || entry.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if isLicenseFile(entry.Name()) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk module root: %w", err)
	}
	sort.Strings(files)
	return files, nil
}

func isLicenseFile(name string) bool {
	upper := strings.ToUpper(name)
	for _, prefix := range []string{"LICENSE", "LICENCE", "COPYING", "NOTICE", "COPYRIGHT"} {
		if strings.HasPrefix(upper, prefix) {
			return true
		}
	}
	return false
}

func safeModuleDirectory(module string) string {
	replacer := strings.NewReplacer("/", "__", "\\", "__", ":", "_", "@", "_")
	return replacer.Replace(module)
}

func copyAndHash(source, destination string) (string, error) {
	in, err := os.Open(source)
	if err != nil {
		return "", err
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(out, hash), in)
	closeErr := out.Close()
	if copyErr != nil {
		return "", copyErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "package_licenses:", err)
	os.Exit(1)
}
