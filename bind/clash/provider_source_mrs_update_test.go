package clash

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/tunnel"
)

func TestSourceMRSSideUpdatePreservesLiveProvider(t *testing.T) {
	withoutRuleSetMapping(t)
	for _, tc := range []struct {
		name, behavior, format, oldRule, newRule string
		oldMeta, newMeta                         C.Metadata
		deferred                                 bool
	}{
		{"domain", "domain", "mrs", "old.example.com\n", "new.example.com\n", C.Metadata{Host: "old.example.com"}, C.Metadata{Host: "new.example.com"}, false},
		{"ipcidr", "ipcidr", "mrs", "192.0.2.0/24\n", "198.51.100.0/24\n", C.Metadata{DstIP: netip.MustParseAddr("192.0.2.1")}, C.Metadata{DstIP: netip.MustParseAddr("198.51.100.1")}, false},
		{"compiled-yaml-control", "domain", "yaml", "payload:\n  - old.example.com\n", "payload:\n  - new.example.com\n", C.Metadata{Host: "old.example.com"}, C.Metadata{Host: "new.example.com"}, true},
		{"compiled-default-control", "domain", "", "payload:\n  - old.example.com\n", "payload:\n  - new.example.com\n", C.Metadata{Host: "old.example.com"}, C.Metadata{Host: "new.example.com"}, true},
		{"compiled-text-control", "domain", "text", "old.example.com\n", "new.example.com\n", C.Metadata{Host: "old.example.com"}, C.Metadata{Host: "new.example.com"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := testOptions(t)
			if err := Setup(opts); err != nil {
				t.Fatal(err)
			}
			oldBody, newBody := []byte(tc.oldRule), []byte(tc.newRule)
			if tc.format == "mrs" {
				a := compileRuleProviderPayload(oldBody, tc.behavior, "text")
				b := compileRuleProviderPayload(newBody, tc.behavior, "text")
				if a.Reason != "" || b.Reason != "" {
					t.Fatalf("fixture compile: %s; %s", a.Reason, b.Reason)
				}
				oldBody, newBody = a.artifact, b.artifact
			}
			source := filepath.Join(opts.WorkingPath, "probe-rule-source")
			if err := os.WriteFile(source, oldBody, 0600); err != nil {
				t.Fatal(err)
			}
			raw := rawWithRuleProvider(source, tc.behavior, tc.format)
			raw.RuleProvider["reject"][providerSideUpdateSafeField] = true
			primed, err := stageProviderRuntime(raw, currentRuntimePolicy(false), true)
			if err != nil {
				t.Fatal(err)
			}
			primed.close()
			cfg := fmt.Sprintf("dns:\n  enable: true\n  nameserver: [8.8.8.8]\nrule-providers:\n  reject:\n    type: file\n    behavior: %s\n    format: %s\n    x-clash-side-update-safe: true\n    path: %q\nrules:\n  - RULE-SET,reject,DIRECT\n  - MATCH,DIRECT\n", tc.behavior, tc.format, source)
			svc, err := NewService(newRecordingPlatform())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = svc.Close() })
			if err = svc.Start(cfg); err != nil {
				t.Fatal(err)
			}
			entry := svc.providerRuntime.entries[providerRuntimeKey("rule", "reject")]
			if !entry.sideUpdateSafe {
				t.Fatal("fixture did not retain safe metadata")
			}
			live := tunnel.RuleProviders()["reject"]
			if live == nil || !live.Match(&tc.oldMeta, C.RuleMatchHelper{}) || live.Match(&tc.newMeta, C.RuleMatchHelper{}) {
				t.Fatal("initial live rule matching incorrect")
			}
			if !tc.deferred {
				before, err := os.ReadFile(entry.runtimePath)
				if err != nil {
					t.Fatal(err)
				}
				wrongBehavior := "domain"
				wrongText := "wrong.example.com\n"
				if tc.behavior == "domain" {
					wrongBehavior = "ipcidr"
					wrongText = "203.0.113.0/24\n"
				}
				wrong := compileRuleProviderPayload([]byte(wrongText), wrongBehavior, "text")
				if wrong.Reason != "" {
					t.Fatal(wrong.Reason)
				}
				for _, bad := range [][]byte{[]byte("invalid mrs"), newBody[:len(newBody)/2], wrong.artifact} {
					err := svc.sideUpdateProvider("rule", "reject", bad, "")
					if err == nil || strings.HasPrefix(err.Error(), SideUpdateDeferredPrefix) {
						t.Fatalf("invalid MRS must be rejected by validation: %v", err)
					}
					got, err := os.ReadFile(entry.runtimePath)
					if err != nil || !bytes.Equal(got, before) {
						t.Fatal("invalid payload changed runtime bytes")
					}
					if !live.Match(&tc.oldMeta, C.RuleMatchHelper{}) || live.Match(&tc.newMeta, C.RuleMatchHelper{}) {
						t.Fatal("invalid payload changed installed matches")
					}
				}
			}
			err = svc.sideUpdateProvider("rule", "reject", newBody, "")
			if tc.deferred {
				if err == nil || !strings.HasPrefix(err.Error(), SideUpdateDeferredPrefix) {
					t.Fatalf("converted text must still defer: %v", err)
				}
			} else {
				if err != nil {
					t.Fatalf("original MRS with unchanged behavior/format should update live: %v", err)
				}
				if tunnel.RuleProviders()["reject"] != live {
					t.Fatal("provider instance replaced")
				}
				if live.Match(&tc.oldMeta, C.RuleMatchHelper{}) || !live.Match(&tc.newMeta, C.RuleMatchHelper{}) {
					t.Fatal("live matching did not replace old content")
				}
				if raw, present := readManifest(t, C.Path.HomeDir())[providerRuntimeKey("rule", "reject")]; present {
					var record stagedProviderRecord
					if err := json.Unmarshal(raw, &record); err != nil || record.ContentSHA256 != "" {
						t.Fatalf("successful side update left a manifest entry that still matches: %s", raw)
					}
				}
			}
			persisted, err := os.ReadFile(source)
			if err != nil || !bytes.Equal(persisted, oldBody) {
				t.Fatal("side update mutated immutable source")
			}
			if !tc.deferred {
				if err := svc.Close(); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(source, newBody, 0600); err != nil {
					t.Fatal(err)
				}
				next, err := NewService(newRecordingPlatform())
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = next.Close() })
				if err = next.Start(cfg); err != nil {
					t.Fatal(err)
				}
				loaded := tunnel.RuleProviders()["reject"]
				if loaded.Match(&tc.oldMeta, C.RuleMatchHelper{}) || !loaded.Match(&tc.newMeta, C.RuleMatchHelper{}) {
					t.Fatal("restart ignored new published source")
				}
			}
		})
	}
}

func TestSourceMRSStagingPreservesRecompileAndRouteSafety(t *testing.T) {
	withoutRuleSetMapping(t)
	for _, format := range []string{"mrs", "text", "yaml", ""} {
		t.Run("format="+format, func(t *testing.T) {
			opts := testOptions(t)
			if err := Setup(opts); err != nil {
				t.Fatal(err)
			}
			body := []byte("old.example.com\n")
			if format == "mrs" {
				c := compileRuleProviderPayload(body, "domain", "text")
				if c.Reason != "" {
					t.Fatal(c.Reason)
				}
				body = c.artifact
			}
			if format == "yaml" || format == "" {
				body = []byte("payload:\n  - old.example.com\n")
			}
			source := filepath.Join(opts.WorkingPath, "source")
			if err := os.WriteFile(source, body, 0600); err != nil {
				t.Fatal(err)
			}
			for _, safe := range []bool{true, false, true} {
				for _, compile := range []bool{true, false} {
					raw := rawWithRuleProvider(source, "domain", format)
					raw.RuleProvider["reject"][providerSideUpdateSafeField] = safe
					runtime, err := stageProviderRuntime(raw, currentRuntimePolicy(false), compile)
					if err != nil {
						t.Fatal(err)
					}
					entry := runtime.entries[providerRuntimeKey("rule", "reject")]
					if entry.compiled != (format != "mrs") {
						t.Fatalf("format=%q compile=%v classified deferred=%v", format, compile, entry.compiled)
					}
					if entry.sideUpdateSafe != safe {
						t.Fatal("cache retained prior route safety")
					}
					if !safe {
						service := &BoxService{running: true, providerRuntime: runtime}
						err = service.sideUpdateProvider("rule", "reject", body, "")
						if err == nil || !strings.Contains(err.Error(), "Apple platform routes") {
							t.Fatalf("route guard lost priority: %v", err)
						}
					}
					runtime.close()
				}
			}
		})
	}
}

func TestSourceMRSSideUpdateRollsBackMissingLiveProvider(t *testing.T) {
	withoutRuleSetMapping(t)
	opts := testOptions(t)
	if err := Setup(opts); err != nil {
		t.Fatal(err)
	}
	old := compileRuleProviderPayload([]byte("old.example.com\n"), "domain", "text")
	next := compileRuleProviderPayload([]byte("new.example.com\n"), "domain", "text")
	source := filepath.Join(opts.WorkingPath, "source")
	if err := os.WriteFile(source, old.artifact, 0600); err != nil {
		t.Fatal(err)
	}
	raw := rawWithRuleProvider(source, "domain", "mrs")
	raw.RuleProvider["reject"][providerSideUpdateSafeField] = true
	runtime, err := stageProviderRuntime(raw, currentRuntimePolicy(false), true)
	if err != nil {
		t.Fatal(err)
	}
	defer runtime.close()
	entry := runtime.entries[providerRuntimeKey("rule", "reject")]
	svc := &BoxService{running: true, providerRuntime: runtime}
	err = svc.sideUpdateProvider("rule", "reject", next.artifact, "")
	if err == nil || !strings.Contains(err.Error(), "live rule provider is unavailable") {
		t.Fatalf("installer did not reach intended rollback: %v", err)
	}
	for _, path := range []string{source, entry.runtimePath} {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, old.artifact) {
			t.Fatal("rollback lost previous runtime/source")
		}
	}
	if _, err = os.Stat(entry.runtimePath + ".rollback"); !os.IsNotExist(err) {
		t.Fatalf("rollback link not consumed: %v", err)
	}
}

func withoutRuleSetMapping(t *testing.T) {
	t.Helper()
	previous := stagingMapsRuleSets
	stagingMapsRuleSets = false
	t.Cleanup(func() { stagingMapsRuleSets = previous })
}
