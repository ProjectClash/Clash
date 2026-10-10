package clash

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGoCrashOutputArchivesThePreviousRunBeforeTruncating(t *testing.T) {
	base := t.TempDir()
	live := filepath.Join(base, goCrashReportFileName)
	previous := filepath.Join(base, goCrashReportPreviousFileName)

	const traceback = "panic: clash internal diagnostics: intentional Go crash\n\ngoroutine 42 [running]:\n"
	if err := os.WriteFile(live, []byte(traceback), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := armGoCrashOutputAt(base, goCrashRoleExtension); err != nil {
		t.Fatalf("armGoCrashOutputAt: %v", err)
	}
	t.Cleanup(func() { _ = disarmGoCrashOutput() })

	archived, err := os.ReadFile(previous)
	if err != nil {
		t.Fatalf("the previous run's traceback must be archived, not truncated: %v", err)
	}
	if string(archived) != traceback {
		t.Fatalf("archived traceback = %q, want it byte-identical", string(archived))
	}
	info, err := os.Stat(live)
	if err != nil {
		t.Fatalf("the live crash file must exist so the runtime has somewhere to write: %v", err)
	}
	if info.Size() != 0 {
		t.Fatalf("live crash file is %d bytes; it must start empty or a later reader cannot tell runs apart", info.Size())
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("live crash file mode = %o, want 600: a traceback carries file paths and function names", mode)
	}
}

func TestGoCrashOutputWithNoPreviousRunLeavesNoArchive(t *testing.T) {
	base := t.TempDir()

	if err := armGoCrashOutputAt(base, goCrashRoleExtension); err != nil {
		t.Fatalf("armGoCrashOutputAt on a clean directory: %v", err)
	}
	t.Cleanup(func() { _ = disarmGoCrashOutput() })

	if _, err := os.Stat(filepath.Join(base, goCrashReportPreviousFileName)); !os.IsNotExist(err) {
		t.Fatalf("a clean first run must not leave an empty archive behind (err=%v)", err)
	}
}

func TestConsumeGoCrashReportReturnsAndRemoves(t *testing.T) {
	base := t.TempDir()
	previous := filepath.Join(base, goCrashReportPreviousFileName)
	const traceback = "panic: concurrent map writes\n\ngoroutine 7 [running]:\n"
	if err := os.WriteFile(previous, []byte(traceback), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := consumeGoCrashReportAt(base, goCrashRoleExtension)
	if err != nil {
		t.Fatalf("consumeGoCrashReportAt: %v", err)
	}
	if report != traceback {
		t.Fatalf("report = %q, want %q", report, traceback)
	}
	if _, err := os.Stat(previous); !os.IsNotExist(err) {
		t.Fatal("the report must be removed once handed over")
	}

	if _, err := consumeGoCrashReportAt(base, goCrashRoleExtension); !os.IsNotExist(err) {
		t.Fatalf("a second consume must report absence, got %v", err)
	}
}

func TestConsumeGoCrashReportTruncatesInsteadOfFailing(t *testing.T) {
	base := t.TempDir()
	previous := filepath.Join(base, goCrashReportPreviousFileName)

	head := "panic: runtime error: index out of range [5] with length 3\n\ngoroutine 1 [running]:\n"
	oversized := head + strings.Repeat("goroutine noise\n", goCrashReportMaxBytes)
	if err := os.WriteFile(previous, []byte(oversized), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := consumeGoCrashReportAt(base, goCrashRoleExtension)
	if err != nil {
		t.Fatalf("an oversized traceback must be truncated, not rejected: %v", err)
	}
	if !strings.HasPrefix(report, head) {
		t.Fatal("the panicking goroutine comes first and must survive truncation")
	}
	if len(report) > goCrashReportMaxBytes+len(goCrashReportTruncationNotice) {
		t.Fatalf("report is %d bytes, want at most %d plus the notice",
			len(report), goCrashReportMaxBytes)
	}
	if !strings.HasSuffix(report, goCrashReportTruncationNotice) {
		t.Fatal("a truncated report must say so, or a reader will think the traceback ended there")
	}
	if _, err := os.Stat(previous); !os.IsNotExist(err) {
		t.Fatal("an oversized report must still be removed after being handed over")
	}
}

func TestRealPanicLandsInTheCrashFile(t *testing.T) {
	if base := os.Getenv(crashProbeEnvironmentKey); base != "" {
		if err := armGoCrashOutputAt(base, goCrashRoleExtension); err != nil {
			os.Exit(3)
		}
		panic(crashProbePanicMessage)
	}

	base := t.TempDir()
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()

	command := exec.Command(os.Args[0], "-test.run=TestRealPanicLandsInTheCrashFile")
	command.Env = append(os.Environ(), crashProbeEnvironmentKey+"="+base)
	command.Stdout = devNull
	command.Stderr = devNull
	if err := command.Run(); err == nil {
		t.Fatal("the child must have died; a surviving child proves nothing about crash capture")
	}

	data, err := os.ReadFile(filepath.Join(base, goCrashReportFileName))
	if err != nil {
		t.Fatalf("no crash file after a real panic with fd 2 discarded: %v", err)
	}
	report := string(data)
	for _, want := range []string{
		"panic: " + crashProbePanicMessage,
		"goroutine",
		"TestRealPanicLandsInTheCrashFile",
	} {
		if !strings.Contains(report, want) {
			t.Fatalf("crash file does not contain %q", want)
		}
	}
}

const (
	crashProbeEnvironmentKey = "CLASH_CRASH_PROBE_BASE"
	crashProbePanicMessage   = "clash crash probe: deliberate panic"
)
