package clash

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

var guardedAppCalls = map[string]func() (errored bool){
	"CheckConfig":        func() bool { return CheckConfig("") != nil },
	"ApplyRemoteControl": func() bool { return strings.Contains(ApplyRemoteControl("{}"), `"error"`) },
	"GenerateControllerCertificate": func() bool {
		return strings.Contains(GenerateControllerCertificate(), `"error"`)
	},
	"CompileCheckForIOS":            func() bool { _, err := CompileCheckForIOS("", ""); return err != nil },
	"EditYAMLForIOS":                func() bool { _, err := EditYAMLForIOS("", "", "", ""); return err != nil },
	"EditYAMLForIOSWithOptions":     func() bool { _, err := EditYAMLForIOSWithOptions("", "", "", "", ""); return err != nil },
	"YAMLOutlineForIOSWithOptions":  func() bool { _, err := YAMLOutlineForIOSWithOptions("", ""); return err != nil },
	"FinalizeForIOSWithOptions":     func() bool { _, err := FinalizeForIOSWithOptions("", "", ""); return err != nil },
	"YamlToJSONWithOptions":         func() bool { _, err := YamlToJSONWithOptions("", ""); return err != nil },
	"RenameReferencesForIOS":        func() bool { _, err := RenameReferencesForIOS("", "", "", ""); return err != nil },
	"ValidateItemForIOS":            func() bool { _, err := ValidateItemForIOS("", "", ""); return err != nil },
	"MatchRuleForIOS":               func() bool { _, err := MatchRuleForIOS("", "", ""); return err != nil },
	"SyntaxCatalogForIOS":           func() bool { _, err := SyntaxCatalogForIOS(""); return err != nil },
	"YAMLOutlineForIOS":             func() bool { _, err := YAMLOutlineForIOS(""); return err != nil },
	"CompileRuleProvider":           func() bool { _, err := CompileRuleProvider("", "", "", ""); return err != nil },
	"ConfigDeviationsJSON":          func() bool { _, err := ConfigDeviationsJSON("", ""); return err != nil },
	"DecryptAgeForIOS":              func() bool { _, err := DecryptAgeForIOS(nil, ""); return err != nil },
	"ExplainLastStartup":            func() bool { return ExplainLastStartup() == "" },
	"FinalizeForIOS":                func() bool { _, err := FinalizeForIOS("", ""); return err != nil },
	"GeodataModeEnabled":            func() bool { return !GeodataModeEnabled("") },
	"GeoIPCountryLines":             func() bool { return GeoIPCountryLines("") == "" },
	"GeoSiteCategoryLines":          func() bool { return GeoSiteCategoryLines("") == "" },
	"InspectProviderForIOS":         func() bool { _, err := InspectProviderForIOS("", "", "", nil); return err != nil },
	"InspectProxyPayloadForIOS":     func() bool { _, err := InspectProxyPayloadForIOS(nil, ""); return err != nil },
	"InvalidDomainPatternsJSON":     func() bool { _, err := InvalidDomainPatternsJSON("", ""); return err != nil },
	"JSONToYaml":                    func() bool { _, err := JSONToYaml(""); return err != nil },
	"MergeOverrideForIOS":           func() bool { _, err := MergeOverrideForIOS("", ""); return err != nil },
	"NewAPIClientWithOptions":       func() bool { _, err := NewAPIClientWithOptions("", nil, nil); return err != nil },
	"PlanResourcesForProfile":       func() bool { _, err := PlanResourcesForProfile("", ""); return err != nil },
	"PlatformConfigIntentJSON":      func() bool { _, err := PlatformConfigIntentJSON(""); return err != nil },
	"PrepareGeoIPCache":             func() bool { _, err := PrepareGeoIPCache("", true); return err != nil },
	"PrepareGeoSiteCache":           func() bool { _, err := PrepareGeoSiteCache(""); return err != nil },
	"ProxyCatalogForIOS":            func() bool { _, err := ProxyCatalogForIOS("", "", ""); return err != nil },
	"RuleEffectForIOS":              func() bool { return RuleEffectForIOS("") == "" },
	"RuleProviderCatalogForIOS":     func() bool { _, err := RuleProviderCatalogForIOS("", "", false); return err != nil },
	"StageProvidersForPublish":      func() bool { return StageProvidersForPublish("", "", false) != nil },
	"SystemResolverLines":           func() bool { return SystemResolverLines() == "" },
	"ValidateConfigShape":           func() bool { return ValidateConfigShape("") != nil },
	"ValidateGeodataForIOS":         func() bool { return ValidateGeodataForIOS("", "", "") != nil },
	"YamlToJSON":                    func() bool { _, err := YamlToJSON(""); return err != nil },
	"ReadProxyPayloadForIOS":        func() bool { _, err := ReadProxyPayloadForIOS(nil, ""); return err != nil },
	"UpdateAppPolicy":               func() bool { return UpdateAppPolicy(&AppPolicyOptions{}) != nil },
	"FormatConfig":                  func() bool { _, err := FormatConfig(""); return err != nil },
	"GeoIPDatEntryCount":            func() bool { return GeoIPDatEntryCount("") == -1 },
	"GeoIPNetworkCount":             func() bool { return GeoIPNetworkCount("") == -1 },
	"PolicyNamesJSON":               func() bool { _, err := PolicyNamesJSON(""); return err != nil },
	"OpenProxyPayloadForIOS":        func() bool { _, err := OpenProxyPayloadForIOS(nil, ""); return err != nil },
	"OpenNodeCatalogForIOS":         func() bool { _, err := OpenNodeCatalogForIOS("", "", ""); return err != nil },
	"ProviderAgeSecretKeysJSON":     func() bool { _, err := ProviderAgeSecretKeysJSON(""); return err != nil },
	"PruneNodeLibraries":            func() bool { return PruneNodeLibraries("", "") != nil },
	"PruneNodeLibrariesKeeping":     func() bool { return PruneNodeLibrariesKeeping("", "") != nil },
	"ReadProxyPayloadSummaryForIOS": func() bool { _, err := ReadProxyPayloadSummaryForIOS(nil, ""); return err != nil },
	"InspectProxyPayloadSummaryForIOS": func() bool {
		_, err := InspectProxyPayloadSummaryForIOS(nil, "")
		return err != nil
	},
	"YamlToJSONOmitting":          func() bool { _, err := YamlToJSONOmitting("", ""); return err != nil },
	"PreparePendingProviderSeeds": func() bool { _, err := PreparePendingProviderSeeds("", ""); return err != nil },
	"GeoSiteDomainCount":          func() bool { return GeoSiteDomainCount("") == -1 },
	"ASNNetworkCount":             func() bool { return ASNNetworkCount("") == -1 },
	"WidgetGroupJSON":             func() bool { return WidgetGroupJSON("", 0) == "" },
	"WidgetStatsJSON":             func() bool { return WidgetStatsJSON("") == "" },
}

func TestEveryGuardedAppCallTurnsAPanicIntoAnError(t *testing.T) {
	t.Cleanup(func() { appCallTestPanic.Store(nil) })
	names := make([]string, 0, len(guardedAppCalls))
	for name := range guardedAppCalls {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		target := name
		appCallTestPanic.Store(&target)
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Errorf("%s let the panic reach its caller: %v", name, recovered)
				}
			}()
			before := appCallRecoveredCount.Load()
			reported := guardedAppCalls[name]()
			if appCallRecoveredCount.Load() != before+1 {
				t.Errorf("%s never reached its guard: the injected panic did not fire", name)
			}
			if !reported {
				t.Errorf("%s swallowed the panic without reporting it (no error, no fallback value)", name)
			}
		}()
	}
}

func TestRecoveredAppPanicIsKeptForTheAppsCrashReport(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "working")
	if err := Setup(&SetupOptions{BasePath: base, WorkingPath: home, TempPath: filepath.Join(base, "temp")}); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	t.Cleanup(func() { _ = disarmGoCrashOutput() })
	if setupGoCrashReportRole != goCrashRoleApplication {
		t.Skip("the test binary is expected to run in the App role")
	}

	target := "MergeOverrideForIOS"
	appCallTestPanic.Store(&target)
	t.Cleanup(func() { appCallTestPanic.Store(nil) })
	if _, err := MergeOverrideForIOS("a: 1", ""); err == nil || !strings.Contains(err.Error(), "MergeOverrideForIOS") {
		t.Fatalf("error = %v, want one naming the export", err)
	}
	appCallTestPanic.Store(nil)

	box, err := ConsumeGoCrashReport()
	if err != nil {
		t.Fatalf("ConsumeGoCrashReport: %v", err)
	}
	report := box.Value
	for _, want := range []string{"recovered panic in MergeOverrideForIOS", "deliberate panic", "goroutine"} {
		if !strings.Contains(report, want) {
			t.Fatalf("App crash report lacks %q:\n%s", want, report)
		}
	}
	if _, err := os.Stat(filepath.Join(base, goCrashReportPreviousFileName)); !os.IsNotExist(err) {
		t.Fatalf("a recovered App panic must not appear as the extension's crash (err=%v)", err)
	}
}

func TestRecoveredPanicsAndFatalCrashesDoNotCrowdEachOtherOut(t *testing.T) {
	base := t.TempDir()
	_, previous := goCrashReportFileNames(goCrashRoleApplication)
	if err := os.WriteFile(filepath.Join(base, previous), []byte("fatal error: concurrent map writes\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	panics := filepath.Join(base, recoveredAppPanicFileName)
	entry := strings.Repeat("x", 1000) + "\n"
	for i := 0; i < 2*goCrashReportMaxBytes/len(entry); i++ {
		if err := appendRecoveredPanic(panics, []byte(entry)); err != nil {
			t.Fatal(err)
		}
	}
	if err := appendRecoveredPanic(panics, []byte("recovered panic in NEWEST\n")); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(panics); err != nil || info.Size() > goCrashReportMaxBytes {
		t.Fatalf("recovered-panic file must stay within the reader's limit: %v %v", info.Size(), err)
	}
	crash, err := consumeGoCrashReportAt(base, goCrashRoleApplication)
	if err != nil || !strings.Contains(crash, "concurrent map writes") {
		t.Fatalf("fatal crash lost: %q %v", crash, err)
	}
	recovered, err := consumeRecoveredAppPanicsAt(base)
	if err != nil || !strings.Contains(recovered, "NEWEST") {
		t.Fatalf("newest recovered panic lost: %v", err)
	}
}

func TestExtensionArchiveKeepsTheNewestCrash(t *testing.T) {
	base := t.TempDir()
	live, previous := goCrashReportFileNames(goCrashRoleExtension)
	if err := os.WriteFile(filepath.Join(base, previous), []byte(strings.Repeat("old\n", goCrashReportMaxBytes)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(base, live), []byte("fatal error: NEWEST\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := armGoCrashOutputAt(base, goCrashRoleExtension); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = disarmGoCrashOutput() })
	report, err := consumeGoCrashReportAt(base, goCrashRoleExtension)
	if err != nil || !strings.Contains(report, "NEWEST") {
		t.Fatalf("the newest crash must win: %v", err)
	}
}

func TestRearmingTheSameFileLeavesTheLiveFileAlone(t *testing.T) {
	base := t.TempDir()
	if err := armGoCrashOutputAt(base, goCrashRoleApplication); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = disarmGoCrashOutput() })
	live, previous := goCrashReportFileNames(goCrashRoleApplication)
	before, err := os.Stat(filepath.Join(base, live))
	if err != nil {
		t.Fatal(err)
	}
	if err := armGoCrashOutputAt(base, goCrashRoleApplication); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(filepath.Join(base, live))
	if err != nil || !os.SameFile(before, after) {
		t.Fatalf("re-arming replaced the live file the runtime holds (err=%v)", err)
	}
	if _, err := os.Stat(filepath.Join(base, previous)); !os.IsNotExist(err) {
		t.Fatalf("re-arming archived a run that did not crash (err=%v)", err)
	}
}
