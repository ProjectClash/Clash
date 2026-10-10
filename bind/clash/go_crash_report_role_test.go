package clash

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGoCrashRoleFollowsTheExecutablePath(t *testing.T) {
	for _, tc := range []struct {
		executable string
		want       goCrashRole
	}{
		{"/private/var/containers/Bundle/Application/X/Clash.app/Clash", goCrashRoleApplication},
		{"/private/var/containers/Bundle/Application/X/Clash.app/PlugIns/ClashExtension.appex/ClashExtension", goCrashRoleExtension},
		{"/Applications/Clash.app/Contents/MacOS/Clash", goCrashRoleApplication},
		{"/Applications/Clash.app/Contents/PlugIns/ClashMacExtension.appex/Contents/MacOS/ClashMacExtension", goCrashRoleExtension},
		{"", goCrashRoleExtension},
	} {
		if got := goCrashRoleForExecutable(tc.executable); got != tc.want {
			t.Errorf("goCrashRoleForExecutable(%q) = %v, want %v", tc.executable, got, tc.want)
		}
	}
}

func TestGoCrashExtensionKeepsTheHistoricalFileNames(t *testing.T) {
	live, previous := goCrashReportFileNames(goCrashRoleExtension)
	if live != "go-crash.log" || previous != "go-crash.previous.log" {
		t.Fatalf("extension files = %q, %q", live, previous)
	}
	appLive, appPrevious := goCrashReportFileNames(goCrashRoleApplication)
	if appLive == live || appPrevious == previous || appLive == appPrevious {
		t.Fatalf("application files %q, %q must differ from the extension's and from each other", appLive, appPrevious)
	}
}

func TestGoCrashArmingOneRoleLeavesTheOtherRolesFilesAlone(t *testing.T) {
	base := t.TempDir()
	extLive, extPrevious := goCrashReportFileNames(goCrashRoleExtension)
	appLive, appPrevious := goCrashReportFileNames(goCrashRoleApplication)

	const extensionTraceback = "panic: extension died\n\ngoroutine 9 [running]:\n"
	const appTraceback = "panic: app died\n\ngoroutine 3 [running]:\n"
	if err := os.WriteFile(filepath.Join(base, extLive), []byte(extensionTraceback), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, appPrevious), []byte(appTraceback), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := armGoCrashOutputAt(base, goCrashRoleApplication); err != nil {
		t.Fatalf("arm application: %v", err)
	}
	t.Cleanup(func() { _ = disarmGoCrashOutput() })
	if data, err := os.ReadFile(filepath.Join(base, extLive)); err != nil || string(data) != extensionTraceback {
		t.Fatalf("the App's Setup touched the extension's live file: %q, %v", data, err)
	}
	if _, err := os.Stat(filepath.Join(base, extPrevious)); !os.IsNotExist(err) {
		t.Fatalf("the App's Setup archived the extension's file (err=%v)", err)
	}
	if _, err := os.Stat(filepath.Join(base, appLive)); err != nil {
		t.Fatalf("the App's own live file must exist after arming: %v", err)
	}

	if _, err := consumeGoCrashReportAt(base, goCrashRoleExtension); !os.IsNotExist(err) {
		t.Fatalf("the extension must not see the App's report, got err=%v", err)
	}
	report, err := consumeGoCrashReportAt(base, goCrashRoleApplication)
	if err != nil || report != appTraceback {
		t.Fatalf("application consume = %q, %v; want its own traceback", report, err)
	}
}
