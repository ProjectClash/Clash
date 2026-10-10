package clash

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"sync/atomic"
	"time"

	"github.com/ProjectClash/Clash/log"
)

// The containing App calls into the core on its own threads to validate, merge, finalize and
// plan the documents the user is editing. A panic there -- an upstream constructor handed a
// half-typed document, the class was -- used to take the whole App down; the.ips shows
// only runtime.raise_trampoline (TF 103, iOS 18.7.8, while editing a profile). Every export
// the App process calls now runs under recoverAppCall: the panic becomes an error the App can
// show, and its stack is kept where the App can read it next (ConsumeGoCrashReport, App role).
//
// What this cannot catch, deliberately not claimed: runtime fatal errors -- concurrent map
// writes, out-of-memory throws -- are not panics and kill the process whatever is deferred.
// Those land in the App's own crash file (go-crash-app.log) through the crash output that
// Setup arms. Setup itself is not guarded: a panic halfway through it leaves process state half
// set, and dying with a traceback in the crash file is the honest outcome.
//
// appCallTestPanic makes the named export panic inside its guard; tests use it to prove each
// export is actually guarded, not only that the helper works.
var appCallTestPanic atomic.Pointer[string]

var appCallRecoveredCount atomic.Int64

func recoverAppCall[T any](name string, call func() (T, error)) (result T, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			var zero T
			result, err = zero, appCallPanicked(name, recovered, debug.Stack())
		}
	}()
	if target := appCallTestPanic.Load(); target != nil && *target == name {
		panic("clash test: deliberate panic in " + name)
	}
	return call()
}

func recoverAppCallError(name string, call func() error) error {
	_, err := recoverAppCall(name, func() (struct{}, error) { return struct{}{}, call() })
	return err
}

func recoverAppCallValue[T any](name string, call func() T) T {
	result, _ := recoverAppCall(name, func() (T, error) { return call(), nil })
	return result
}

func recoverAppCallValueOr[T any](name string, fallback T, call func() T) T {
	result, err := recoverAppCall(name, func() (T, error) { return call(), nil })
	if err != nil {
		return fallback
	}
	return result
}

func appCallPanicked(name string, recovered any, stack []byte) error {
	appCallRecoveredCount.Add(1)
	log.Errorln("[App] %s panicked and returned an error instead: %v\n%s", name, recovered, stack)
	recordRecoveredAppPanic(name, recovered, stack)
	return fmt.Errorf("clash: %s: internal error: %v", name, recovered)
}

const recoveredAppPanicFileName = "go-panic-app.log"

func recordRecoveredAppPanic(name string, recovered any, stack []byte) {
	setupMu.Lock()
	basePath, role, ready := setupGoCrashReportBasePath, setupGoCrashReportRole, setupDone
	setupMu.Unlock()
	if !ready || basePath == "" || role != goCrashRoleApplication {
		return
	}
	entry := fmt.Sprintf("recovered panic in %s at %s (the App kept running): %v\n\n%s\n",
		name, time.Now().UTC().Format(time.RFC3339), recovered, stack)

	goCrashReportMu.Lock()
	defer goCrashReportMu.Unlock()
	if err := appendRecoveredPanic(filepath.Join(basePath, recoveredAppPanicFileName), []byte(entry)); err != nil {
		log.Warnln("[App] could not keep the stack of the recovered panic in %s: %v", name, err)
	}
}

func appendRecoveredPanic(path string, data []byte) error {
	flags := os.O_CREATE | os.O_APPEND | os.O_WRONLY
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			_ = os.Remove(path)
		} else if info.Size()+int64(len(data)) > goCrashReportMaxBytes {
			flags = os.O_CREATE | os.O_TRUNC | os.O_WRONLY
		}
	}
	file, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func consumeRecoveredAppPanicsAt(basePath string) (string, error) {
	goCrashReportMu.Lock()
	defer goCrashReportMu.Unlock()
	return consumeCrashFileLocked(filepath.Join(basePath, recoveredAppPanicFileName))
}
