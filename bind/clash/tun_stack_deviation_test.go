package clash

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/log"
)

func tunStackDocument(stack string) string {
	document := "tun:\n  enable: true\n"
	if stack != "" {
		document += "  stack: " + stack + "\n"
	}
	return document + "proxies: []\nproxy-groups: []\nrules:\n  - MATCH,DIRECT\n"
}

func tunStackDeviations(t *testing.T, document string, policy appleRuntimePolicy) []configDeviation {
	t.Helper()
	all, err := collectConfigDeviations(document, policy)
	if err != nil {
		t.Fatalf("collectConfigDeviations: %v", err)
	}
	var rows []configDeviation
	for _, deviation := range all {
		if deviation.Field == "tun.stack" {
			rows = append(rows, deviation)
		}
	}
	return rows
}

func TestTheReportSaysEveryFileRunsTheGoStack(t *testing.T) {
	for _, profile := range []runtimeProfile{runtimeProfileIOSPacketTunnel, runtimeProfileMacOSPacketTunnel, runtimeProfileTVOSPacketTunnel} {
		tunnel := runtimePolicyFor(profile, true)
		{
			for _, written := range []string{"system", "mixed", "gvisor", "mips"} {
				rows := tunStackDeviations(t, tunStackDocument(written), tunnel)
				if len(rows) != 1 {
					t.Fatalf("%v, %s: want one tun.stack row, got %+v", profile, written, rows)
				}
				row := rows[0]
				if row.Category != deviationForced || row.Given != written || !row.Written || row.Recoverable ||
					!strings.HasPrefix(row.Effective, "go") {
					t.Fatalf("%v, %s: row %+v; want forced, given as written, not recoverable, effective go", profile, written, row)
				}
			}
			if rows := tunStackDeviations(t, tunStackDocument("go"), tunnel); len(rows) != 0 {
				t.Fatalf("%v: a file that writes go was changed, the report says %+v", profile, rows)
			}
			assertSilentStackRow(t, tunStackDeviations(t, tunStackDocument(""), tunnel), profile.String())
		}
	}
	if rows := tunStackDeviations(t, tunStackDocument("system"), runtimePolicyFor(runtimeProfileMacOSApplication, false)); len(rows) != 0 {
		t.Fatalf("the application profile reports a packet-tunnel move: %+v", rows)
	}
}

func assertSilentStackRow(t *testing.T, rows []configDeviation, when string) {
	t.Helper()
	if len(rows) != 1 {
		t.Fatalf("silent tun.stack %s: want the one default row, got %d: %+v", when, len(rows), rows)
	}
	row := rows[0]
	if row.Written || row.UpstreamDefault != "mips" || row.Given != "not set (core default: mips)" ||
		!strings.HasPrefix(row.Effective, "go") {
		t.Fatalf("silent tun.stack %s: row = %+v; want the unwritten default row (mips -> go)", when, row)
	}
}

func TestSetupDoesNotRefuseFlippingIncludeAllNetworks(t *testing.T) {
	base := t.TempDir()
	options := func(on bool) *SetupOptions {
		return &SetupOptions{BasePath: base, WorkingPath: filepath.Join(base, "working"), TempPath: filepath.Join(base, "temp"), IncludeAllNetworks: on}
	}
	if err := Setup(options(false)); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	activeCoreCount.Add(1)
	t.Cleanup(func() { activeCoreCount.Add(-1) })
	if err := Setup(options(true)); err != nil {
		t.Fatalf("flipping IncludeAllNetworks under an active core: %v", err)
	}
}

func TestAWrittenStackOtherThanGoStartsAndIsWarnedOf(t *testing.T) {
	previous := publishedDeviations.Load()
	t.Cleanup(func() { publishedDeviations.Store(previous) })
	subscription := log.Subscribe()
	t.Cleanup(func() { log.UnSubscribe(subscription) })

	stackWarning := func(t *testing.T, stack string) (line string) {
		t.Helper()
		if _, _, err := parseConfigForIOSRuntime(tunStackDocument(stack), true, deviationEntryStart); err != nil {
			t.Fatalf("stack %s: the file was refused: %v", stack, err)
		}
		rows := -1
		deadline := time.After(5 * time.Second)
		for rows != 0 {
			select {
			case event := <-subscription:
				if rows < 0 {
					if _, count, found := strings.Cut(event.Payload, "[Apple] deviations published:"); found {
						if _, err := fmt.Sscanf(count[strings.LastIndex(count, "rows="):], "rows=%d", &rows); err != nil {
							t.Fatalf("stack %s: the summary line counts no rows: %s", stack, event.Payload)
						}
					}
					continue
				}
				if !strings.Contains(event.Payload, "[Apple] deviation ") {
					continue
				}
				rows--
				if strings.Contains(event.Payload, "[Apple] deviation tun.stack:") {
					if event.LogLevel != log.WARNING {
						t.Fatalf("stack %s: the line is %s, not a warning: %s", stack, event.LogLevel, event.Payload)
					}
					line = event.Payload
				}
			case <-deadline:
				t.Fatalf("stack %s: the publish and its rows are not all in the log within 5 s", stack)
			}
		}
		return line
	}
	for _, written := range []string{"system", "mixed", "gvisor", "mips"} {
		line := stackWarning(t, written)
		if !strings.Contains(line, `given="`+written+`"`) || !strings.Contains(line, `effective="go`) {
			t.Fatalf("stack %s: want a warning that the file wrote %s and go runs, got %q", written, written, line)
		}
	}
	if line := stackWarning(t, "go"); line != "" {
		t.Fatalf("a file that writes go is warned of: %q", line)
	}
}
