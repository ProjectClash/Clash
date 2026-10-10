package clash

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
)

const (
	goCrashReportFileName         = "go-crash.log"
	goCrashReportPreviousFileName = "go-crash.previous.log"

	goCrashReportApplicationFileName         = "go-crash-app.log"
	goCrashReportApplicationPreviousFileName = "go-crash-app.previous.log"

	goCrashReportMaxBytes = 128 << 10

	goCrashReportTruncationNotice = "\n[clash: traceback truncated]\n"
)

var (
	goCrashReportMu       sync.Mutex
	goCrashOutputArmedFor string
)

type goCrashRole int

const (
	goCrashRoleExtension goCrashRole = iota
	goCrashRoleApplication
)

func (r goCrashRole) String() string {
	if r == goCrashRoleApplication {
		return "application"
	}
	return "extension"
}

func goCrashRoleForExecutable(executable string) goCrashRole {
	if executable == "" || strings.Contains(executable, ".appex/") {
		return goCrashRoleExtension
	}
	return goCrashRoleApplication
}

func currentGoCrashRole() goCrashRole {
	executable, err := os.Executable()
	if err != nil {
		return goCrashRoleExtension
	}
	return goCrashRoleForExecutable(executable)
}

func goCrashReportFileNames(role goCrashRole) (live, previous string) {
	if role == goCrashRoleApplication {
		return goCrashReportApplicationFileName, goCrashReportApplicationPreviousFileName
	}
	return goCrashReportFileName, goCrashReportPreviousFileName
}

func armGoCrashOutputAt(basePath string, role goCrashRole) error {
	goCrashReportMu.Lock()
	defer goCrashReportMu.Unlock()

	if basePath == "" {
		return errors.New("clash: Go crash output needs a base path")
	}
	armedKey := filepath.Join(basePath, role.String())
	if goCrashOutputArmedFor == armedKey {
		return nil
	}
	if err := os.MkdirAll(basePath, 0o755); err != nil {
		return fmt.Errorf("clash: create Go crash output directory: %w", err)
	}

	liveName, previousName := goCrashReportFileNames(role)
	live := filepath.Join(basePath, liveName)
	previous := filepath.Join(basePath, previousName)

	if info, err := os.Stat(live); err == nil && info.Size() > 0 {
		if err := os.Rename(live, previous); err != nil {
			return fmt.Errorf("clash: archive previous Go crash output: %w", err)
		}
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("clash: stat Go crash output: %w", err)
	} else if err == nil {
		_ = os.Remove(live)
	}

	file, err := os.OpenFile(live, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("clash: open Go crash output: %w", err)
	}
	defer file.Close()

	if err := debug.SetCrashOutput(file, debug.CrashOptions{}); err != nil {
		return fmt.Errorf("clash: set Go crash output: %w", err)
	}
	goCrashOutputArmedFor = armedKey
	return nil
}

func disarmGoCrashOutput() error {
	goCrashReportMu.Lock()
	defer goCrashReportMu.Unlock()
	goCrashOutputArmedFor = ""
	return debug.SetCrashOutput(nil, debug.CrashOptions{})
}

func consumeGoCrashReportAt(basePath string, role goCrashRole) (string, error) {
	goCrashReportMu.Lock()
	defer goCrashReportMu.Unlock()

	if basePath == "" {
		return "", errors.New("clash: Go crash report needs a base path")
	}
	_, previousName := goCrashReportFileNames(role)
	return consumeCrashFileLocked(filepath.Join(basePath, previousName))
}

func consumeCrashFileLocked(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	info, statErr := file.Stat()
	if statErr == nil && !info.Mode().IsRegular() {
		_ = file.Close()
		_ = os.Remove(path)
		return "", errors.New("clash: Go crash report is not a regular file")
	}
	data, readErr := io.ReadAll(io.LimitReader(file, goCrashReportMaxBytes+1))
	_ = file.Close()

	if removeErr := os.Remove(path); removeErr != nil && readErr == nil {
		return "", fmt.Errorf("clash: remove Go crash report: %w", removeErr)
	}
	if readErr != nil {
		return "", fmt.Errorf("clash: read Go crash report: %w", readErr)
	}

	if len(data) > goCrashReportMaxBytes {
		return string(data[:goCrashReportMaxBytes]) + goCrashReportTruncationNotice, nil
	}
	return string(data), nil
}

func ConsumeGoCrashReport() (*StringBox, error) {
	basePath, role, err := goCrashReportBasePath()
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	report, err := consumeGoCrashReportAt(basePath, role)
	if role == goCrashRoleApplication {
		recovered, recoveredErr := consumeRecoveredAppPanicsAt(basePath)
		switch {
		case recoveredErr == nil && err == nil:
			report = report + "\n" + recovered
		case recoveredErr == nil:
			report, err = recovered, nil
		case !os.IsNotExist(recoveredErr) && os.IsNotExist(err):
			err = recoveredErr
		}
	}
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return WrapString(report), nil
}

func goCrashReportBasePath() (string, goCrashRole, error) {
	setupMu.Lock()
	defer setupMu.Unlock()
	if !setupDone || setupGoCrashReportBasePath == "" {
		return "", goCrashRoleExtension, errors.New("clash: Go crash report before Setup")
	}
	return setupGoCrashReportBasePath, setupGoCrashReportRole, nil
}
