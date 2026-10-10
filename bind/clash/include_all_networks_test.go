package clash

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"

	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/listener/sing_tun"
	tun "github.com/metacubex/sing-tun"
)

func withIncludeAllNetworks(t *testing.T, on bool) {
	t.Helper()
	previous := includeAllNetworksRequested.Load()
	includeAllNetworksRequested.Store(on)
	t.Cleanup(func() { includeAllNetworksRequested.Store(previous) })
}

func tunStackDocument(stack string) string {
	document := "tun:\n  enable: true\n"
	if stack != "" {
		document += "  stack: " + stack + "\n"
	}
	return document + "proxies: []\nproxy-groups: []\nrules:\n  - MATCH,DIRECT\n"
}

func TestIncludeAllNetworksMovesSystemAndMixedToGVisor(t *testing.T) {
	for _, tc := range []struct {
		name    string
		written string
		on      bool
		want    C.TUNStack
	}{
		{"system under include-all-networks", "system", true, C.TunGvisor},
		{"mixed under include-all-networks", "mixed", true, C.TunGvisor},
		{"gvisor under include-all-networks", "gvisor", true, C.TunGvisor},
		{"unset under include-all-networks", "", true, C.TunGvisor},
		{"system without it", "system", false, C.TunSystem},
		{"mixed without it", "mixed", false, C.TunMixed},
		{"unset without it", "", false, C.TunGvisor},
		{"mips under include-all-networks", "mips", true, C.TunMips},
		{"mips without it", "mips", false, C.TunMips},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withIncludeAllNetworks(t, tc.on)
			_, ours := parseBoth(t, tunStackDocument(tc.written))
			finalizeConfigForIOS(ours, true)
			if ours.General.Tun.Stack != tc.want {
				t.Fatalf("tun.stack %q with includeAllNetworks=%v finalized to %v, want %v",
					tc.written, tc.on, ours.General.Tun.Stack, tc.want)
			}
		})
	}
}

func TestIncludeAllNetworksLeavesTheStackAloneOutsideAPacketTunnel(t *testing.T) {
	withIncludeAllNetworks(t, true)
	_, ours := parseBoth(t, tunStackDocument("system"))
	finalizeConfigForApple(ours, runtimePolicyFor(runtimeProfileMacOSApplication, false))
	if ours.General.Tun.Stack != C.TunSystem {
		t.Fatalf("the application profile moved tun.stack to %v; only packet tunnels run under Include All Networks",
			ours.General.Tun.Stack)
	}
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

func TestIncludeAllNetworksReportsTheMoveAndOnlyTheMove(t *testing.T) {
	tunnel := runtimePolicyFor(runtimeProfileIOSPacketTunnel, true)

	withIncludeAllNetworks(t, true)
	for _, written := range []string{"system", "mixed"} {
		rows := tunStackDeviations(t, tunStackDocument(written), tunnel)
		if len(rows) != 1 {
			t.Fatalf("%s under Include All Networks: want one tun.stack row, got %d: %+v", written, len(rows), rows)
		}
		row := rows[0]
		if row.Category != deviationForced || row.Given != written || !row.Written || !row.Recoverable {
			t.Fatalf("%s: row = %+v; want forced, given %q, written, recoverable", written, row, written)
		}
		if !strings.Contains(row.Effective, "gvisor") {
			t.Fatalf("%s: effective %q does not name the stack the tunnel actually runs", written, row.Effective)
		}
		if row.Alternative == "" {
			t.Fatalf("%s: a recoverable move must tell the reader how to recover", written)
		}
	}
	if rows := tunStackDeviations(t, tunStackDocument("gvisor"), tunnel); len(rows) != 0 {
		t.Fatalf("tun.stack gvisor moved nothing, yet the report says %+v", rows)
	}
	assertSilentStackRow(t, tunStackDeviations(t, tunStackDocument(""), tunnel), "with Include All Networks")
	if rows := tunStackDeviations(t, tunStackDocument("system"), runtimePolicyFor(runtimeProfileMacOSApplication, false)); len(rows) != 0 {
		t.Fatalf("the application profile reports a packet-tunnel move: %+v", rows)
	}

	withIncludeAllNetworks(t, false)
	if rows := tunStackDeviations(t, tunStackDocument("system"), tunnel); len(rows) != 0 {
		t.Fatalf("without Include All Networks the stack stays as written, yet the report says %+v", rows)
	}
	assertSilentStackRow(t, tunStackDeviations(t, tunStackDocument(""), tunnel), "without Include All Networks")
}

func assertSilentStackRow(t *testing.T, rows []configDeviation, when string) {
	t.Helper()
	if len(rows) != 1 {
		t.Fatalf("silent tun.stack %s: want the one default row, got %d: %+v", when, len(rows), rows)
	}
	row := rows[0]
	if row.Written || row.UpstreamDefault != "mips" || row.Given != "not set (core default: mips)" ||
		!strings.HasPrefix(row.Effective, "gvisor") {
		t.Fatalf("silent tun.stack %s: row = %+v; want the unwritten default row (mips -> gvisor)", when, row)
	}
}

func TestSetupCarriesIncludeAllNetworksToTheOverrideAndTheStack(t *testing.T) {
	withIncludeAllNetworks(t, false)
	previousStackFlag := sing_tun.IncludeAllNetworks
	t.Cleanup(func() { sing_tun.IncludeAllNetworks = previousStackFlag })

	base := t.TempDir()
	options := func(on bool) *SetupOptions {
		return &SetupOptions{
			BasePath:           base,
			WorkingPath:        filepath.Join(base, "working"),
			TempPath:           filepath.Join(base, "temp"),
			IncludeAllNetworks: on,
		}
	}
	if err := Setup(options(true)); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if !includeAllNetworksRequested.Load() || !sing_tun.IncludeAllNetworks {
		t.Fatalf("Setup(IncludeAllNetworks: true) left override=%v stack=%v",
			includeAllNetworksRequested.Load(), sing_tun.IncludeAllNetworks)
	}
	if err := Setup(options(false)); err != nil {
		t.Fatalf("Setup: %v", err)
	}
	if includeAllNetworksRequested.Load() || sing_tun.IncludeAllNetworks {
		t.Fatalf("Setup(IncludeAllNetworks: false) left override=%v stack=%v",
			includeAllNetworksRequested.Load(), sing_tun.IncludeAllNetworks)
	}

	activeCoreCount.Add(1)
	t.Cleanup(func() { activeCoreCount.Add(-1) })
	err := Setup(options(true))
	if err == nil || !strings.Contains(err.Error(), "IncludeAllNetworks") || !strings.Contains(err.Error(), "restart") {
		t.Fatalf("flipping IncludeAllNetworks under an active core: err = %v; want a restart-required refusal", err)
	}
	if err := Setup(options(false)); err != nil {
		t.Fatalf("Setup with the unchanged value under an active core must still pass: %v", err)
	}
}

func TestSingTunRefusesSystemAndMixedUnderIncludeAllNetworks(t *testing.T) {
	for _, stack := range []string{"system", "mixed"} {
		_, err := tun.NewStack(stack, tun.StackOptions{IncludeAllNetworks: true})
		if !errors.Is(err, tun.ErrIncludeAllNetworks) {
			t.Fatalf("NewStack(%q) under IncludeAllNetworks: err = %v; want ErrIncludeAllNetworks", stack, err)
		}
	}
}
