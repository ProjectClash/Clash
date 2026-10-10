package clash

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ProjectClash/Clash/component/geodata"
	C "github.com/ProjectClash/Clash/constant"
)

const breadcrumbFileName = "startup-breadcrumb.json"

var breadcrumbDirectory string

var breadcrumbMutex sync.Mutex

type startupBreadcrumb struct {
	Stage          string `json:"stage"`
	Resource       string `json:"resource"`
	Count          int64  `json:"count,omitempty"`
	Completed      bool   `json:"completed"`
	FootprintBytes int64  `json:"footprintBytes"`
	BudgetBytes    int64  `json:"budgetBytes,omitempty"`
	StartedAt      string `json:"startedAt"`
	UpdatedAt      string `json:"updatedAt"`
	Install        string `json:"install"`
	FailureReason  string `json:"failureReason"`
}

func breadcrumbPath() string {
	directory := breadcrumbDirectory
	if directory == "" {
		directory = homeDirectoryForBreadcrumb()
	}
	if directory == "" {
		return ""
	}
	return filepath.Join(directory, breadcrumbFileName)
}

func recordStartupStage(stage string) {
	recordStartupStageNaming(stage, "")
}

func recordStartupStageNaming(stage string, resource string) {
	recordStartupStep(stage, resource, 0)
}

func recordStartupStageCounting(stage string, count int64) {
	recordStartupStep(stage, "", count)
}

func recordStartupStep(stage string, resource string, count int64) {
	breadcrumbMutex.Lock()
	defer breadcrumbMutex.Unlock()

	path := breadcrumbPath()
	if path == "" {
		return
	}
	now := time.Now().UTC().Format(time.RFC3339)
	record := startupBreadcrumb{
		Stage:          stage,
		Resource:       resource,
		Count:          count,
		Completed:      false,
		FootprintBytes: MemoryFootprint(),
		BudgetBytes:    runtimeSetupSnapshot().softMemoryLimit,
		StartedAt:      now,
		UpdatedAt:      now,
		Install:        currentInstallIdentity(),
	}
	if existing, err := readBreadcrumb(path); err == nil && !existing.Completed && existing.StartedAt != "" {
		record.StartedAt = existing.StartedAt
	}
	writeBreadcrumb(path, record)
}

func recordStartupResource(resource string) {
	breadcrumbMutex.Lock()
	defer breadcrumbMutex.Unlock()

	path := breadcrumbPath()
	if path == "" {
		return
	}
	record := currentRecord(path)
	record.Install = currentInstallIdentity()
	record.Resource = resource
	record.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	record.FootprintBytes = MemoryFootprint()
	record.BudgetBytes = runtimeSetupSnapshot().softMemoryLimit
	writeBreadcrumb(path, record)
}

func recordStartupFailure(startErr error) {
	if startErr == nil || !breadcrumbRecording.Load() {
		return
	}
	breadcrumbMutex.Lock()
	defer breadcrumbMutex.Unlock()

	path := breadcrumbPath()
	if path == "" {
		return
	}
	record := currentRecord(path)
	record.Install = currentInstallIdentity()
	record.FailureReason = startErr.Error()
	record.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	record.FootprintBytes = MemoryFootprint()
	record.BudgetBytes = runtimeSetupSnapshot().softMemoryLimit
	writeBreadcrumb(path, record)
}

func refreshStartupBreadcrumbFootprint() {
	if !breadcrumbRecording.Load() {
		return
	}
	breadcrumbMutex.Lock()
	defer breadcrumbMutex.Unlock()
	path := breadcrumbPath()
	if path == "" {
		return
	}
	existing, err := readBreadcrumb(path)
	if err != nil || existing.Completed {
		return
	}
	existing.FootprintBytes = MemoryFootprint()
	existing.BudgetBytes = runtimeSetupSnapshot().softMemoryLimit
	existing.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	writeBreadcrumb(path, existing)
}

func currentRecord(path string) startupBreadcrumb {
	now := time.Now().UTC().Format(time.RFC3339)
	if existing, err := readBreadcrumb(path); err == nil && !existing.Completed {
		return existing
	}
	return startupBreadcrumb{StartedAt: now, UpdatedAt: now}
}

func markStartupComplete() {
	setStartupBreadcrumbRecording(false)
	geodata.SetGeodataProgressReporter(nil)
	recordStartupComplete()
}

func recordStartupComplete() {
	breadcrumbMutex.Lock()
	defer breadcrumbMutex.Unlock()

	if path := breadcrumbPath(); path != "" {
		_ = os.Remove(path)
	}
}

func ExplainLastStartup() string {
	return bridgeSafeString(recoverAppCallValue("ExplainLastStartup", func() string { return explainLastStartupUnguarded() }))
}

func explainLastStartupUnguarded() string {
	breadcrumbMutex.Lock()
	defer breadcrumbMutex.Unlock()

	path := breadcrumbPath()
	if path == "" {
		return ""
	}
	record, err := readBreadcrumb(path)
	if err != nil {
		return ""
	}
	if record.Install == "" || record.Install != currentInstallIdentity() {
		return ""
	}
	encoded, err := json.Marshal(record)
	if err != nil {
		return ""
	}
	return bridgeSafeString(string(encoded))
}

func ClearLastStartupExplanation() {
	recordStartupComplete()
}

func readBreadcrumb(path string) (startupBreadcrumb, error) {
	var record startupBreadcrumb
	content, err := os.ReadFile(path)
	if err != nil {
		return record, err
	}
	if err := json.Unmarshal(content, &record); err != nil {
		return record, err
	}
	return record, nil
}

func writeBreadcrumb(path string, record startupBreadcrumb) {
	encoded, err := json.Marshal(record)
	if err != nil {
		return
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".breadcrumb-*")
	if err != nil {
		return
	}
	defer os.Remove(temporary.Name())
	if _, err := temporary.Write(encoded); err != nil {
		temporary.Close()
		return
	}
	if err := temporary.Close(); err != nil {
		return
	}
	_ = os.Rename(temporary.Name(), path)
}

func homeDirectoryForBreadcrumb() string {
	return C.Path.HomeDir()
}

func progressReporterInstalled() func(string) { return geodata.GeodataProgressReporter() }

func restoreProgressReporter(report func(string)) { geodata.SetGeodataProgressReporter(report) }

func currentInstallIdentity() string {
	executable, err := os.Executable()
	if err != nil || executable == "" {
		return "unknown-install"
	}
	if resolved, err := filepath.EvalSymlinks(executable); err == nil {
		executable = resolved
	}

	source := filepath.Dir(executable)
	if index := strings.Index(executable, bundleContainerMarker); index >= 0 {
		rest := executable[index+len(bundleContainerMarker):]
		if end := strings.IndexByte(rest, filepath.Separator); end > 0 {
			source = rest[:end]
		} else if rest != "" {
			source = rest
		}
	}
	sum := sha256.Sum256([]byte(source))
	return hex.EncodeToString(sum[:6])
}

const bundleContainerMarker = "/Bundle/Application/"
