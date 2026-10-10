package clash

import (
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/ProjectClash/Clash/config"
	"github.com/ProjectClash/Clash/dns"
)

func restoreSubstituteState(t *testing.T) {
	t.Helper()
	oldFlush, oldReset, oldClose, oldClear :=
		flushInterfaceCache, resetResolverConnection, closeTrackedConnections, clearResolverCache
	var noop atomic.Int64
	flushInterfaceCache = func() { noop.Add(1) }
	resetResolverConnection = func() { noop.Add(1) }
	closeTrackedConnections = func() { noop.Add(1) }
	clearResolverCache = func() { noop.Add(1) }
	previousRead := readPhysicalResolvers
	previousChanged := dnsConfigurationChanged
	previousSubstitutes := systemDNSSubstitutes.Load()
	wifi := []string{"192.168.1.1"}
	systemDNSSubstitutes.Store(&wifi)
	dns.SetSystemSubstituteServers(nil)
	dns.SetSystemSubstitutesStale(false)
	t.Cleanup(func() {
		flushInterfaceCache, resetResolverConnection, closeTrackedConnections, clearResolverCache =
			oldFlush, oldReset, oldClose, oldClear
		readPhysicalResolvers = previousRead
		dnsConfigurationChanged = previousChanged
		systemDNSSubstitutes.Store(previousSubstitutes)
		dns.SetSystemSubstituteServers(nil)
		dns.SetSystemSubstitutesStale(false)
	})
}

func TestLeavingTheStartPathMarksSystemSubstitutesStale(t *testing.T) {
	oldFlush, oldReset, oldClose, oldClear :=
		flushInterfaceCache, resetResolverConnection, closeTrackedConnections, clearResolverCache
	var noop atomic.Int64
	flushInterfaceCache = func() { noop.Add(1) }
	resetResolverConnection = func() { noop.Add(1) }
	closeTrackedConnections = func() { noop.Add(1) }
	clearResolverCache = func() { noop.Add(1) }
	previous := systemDNSSubstitutes.Load()
	substitutes := []string{"192.168.1.1"}
	systemDNSSubstitutes.Store(&substitutes)
	previousRead := readPhysicalResolvers
	readPhysicalResolvers = func(int32) []string { return nil }
	t.Cleanup(func() { readPhysicalResolvers = previousRead })
	t.Cleanup(func() {
		flushInterfaceCache, resetResolverConnection, closeTrackedConnections, clearResolverCache =
			oldFlush, oldReset, oldClose, oldClear
		systemDNSSubstitutes.Store(previous)
		dns.SetSystemSubstitutesStale(false)
	})
	dns.SetSystemSubstitutesStale(true)

	updater := &interfaceUpdater{}
	dns.SetSystemSubstitutesStale(false)
	updater.UpdateDefaultInterface("en0", 5, false, false, true, true)
	if dns.SystemSubstitutesStale() {
		t.Fatal("the first path is the start path; nothing is stale")
	}
	updater.UpdateDefaultInterface("en0", 5, false, false, true, true)
	updater.UpdateDefaultInterface("en0", 5, true, false, true, true)
	if dns.SystemSubstitutesStale() {
		t.Fatal("flags are not identity")
	}
	updater.UpdateDefaultInterface("pdp_ip0", 7, true, false, true, true)
	if !dns.SystemSubstitutesStale() {
		t.Fatal("leaving en0 for cellular must mark the substitutes stale")
	}
	updater.UpdateDefaultInterface("pdp_ip0", 7, true, true, true, true)
	if !dns.SystemSubstitutesStale() {
		t.Fatal("still away: still stale")
	}
	updater.UpdateDefaultInterface("en0", 5, false, false, true, true)
	if dns.SystemSubstitutesStale() {
		t.Fatal("back on the start path restores the substitutes")
	}
	updater.UpdateDefaultInterface("en0", 9, false, false, true, true)
	if !dns.SystemSubstitutesStale() {
		t.Fatal("the same name with another index is another path")
	}
}

func TestThePipelineRecordsTheSubstitutesItWrote(t *testing.T) {
	previous := systemDNSSubstitutes.Load()
	substitutes := []string{"1.1.1.1", "9.9.9.9:5353"}
	systemDNSSubstitutes.Store(&substitutes)
	t.Cleanup(func() {
		systemDNSSubstitutes.Store(previous)
		dns.MarkSystemSubstitutes(nil)
	})
	raw, err := config.UnmarshalRawConfig([]byte("dns:\n  enable: true\n  nameserver:\n    - system\n    - 8.8.8.8\n  direct-nameserver:\n    - system\n"))
	if err != nil {
		t.Fatal(err)
	}
	normalizeRawConfigForApple(raw, nePolicy())
	if got := dns.SystemSubstitutes(); len(got) != 2 || got[0] != "1.1.1.1:53" || got[1] != "9.9.9.9:5353" {
		t.Fatalf("recorded substitutes = %v", got)
	}
	plain, err := config.UnmarshalRawConfig([]byte("dns:\n  enable: true\n  nameserver:\n    - 8.8.8.8\n"))
	if err != nil {
		t.Fatal(err)
	}
	normalizeRawConfigForApple(plain, nePolicy())
	if got := dns.SystemSubstitutes(); len(got) != 0 {
		t.Fatalf("a document without system entries must record none, got %v", got)
	}
}

func TestALiveReadReplacesTheSubstitutesInsteadOfStalingThem(t *testing.T) {
	oldFlush, oldReset, oldClose, oldClear :=
		flushInterfaceCache, resetResolverConnection, closeTrackedConnections, clearResolverCache
	var noop atomic.Int64
	flushInterfaceCache = func() { noop.Add(1) }
	resetResolverConnection = func() { noop.Add(1) }
	closeTrackedConnections = func() { noop.Add(1) }
	clearResolverCache = func() { noop.Add(1) }
	previousRead := readPhysicalResolvers
	previousSubstitutes := systemDNSSubstitutes.Load()
	wifi := []string{"192.168.1.1"}
	systemDNSSubstitutes.Store(&wifi)
	t.Cleanup(func() {
		flushInterfaceCache, resetResolverConnection, closeTrackedConnections, clearResolverCache =
			oldFlush, oldReset, oldClose, oldClear
		readPhysicalResolvers = previousRead
		systemDNSSubstitutes.Store(previousSubstitutes)
		dns.SetSystemSubstituteServers(nil)
		dns.SetSystemSubstitutesStale(false)
	})

	byIndex := map[int32][]string{
		5: {"192.168.1.1"},
		7: {"2001:db8:46::5", "192.0.2.37"},
	}
	readPhysicalResolvers = func(index int32) []string { return byIndex[index] }

	updater := &interfaceUpdater{}
	dns.SetSystemSubstitutesStale(true)
	updater.UpdateDefaultInterface("en0", 5, false, false, true, true)
	if dns.SystemSubstitutesStale() {
		t.Fatal("a live read clears the stale mark")
	}
	if got := dns.SystemSubstituteServers(); len(got) != 1 || got[0] != "192.168.1.1:53" {
		t.Fatalf("Wi-Fi resolvers = %v", got)
	}

	updater.UpdateDefaultInterface("pdp_ip0", 7, true, false, true, true)
	if dns.SystemSubstitutesStale() {
		t.Fatal("cellular has its own resolvers; nothing is stale")
	}
	got := dns.SystemSubstituteServers()
	if len(got) != 2 || got[0] != "[2001:db8:46::5]:53" || got[1] != "192.0.2.37:53" {
		t.Fatalf("cellular resolvers = %v", got)
	}

	updater.UpdateDefaultInterface("en1", 9, false, false, true, true)
	if !dns.SystemSubstitutesStale() {
		t.Fatal("a network with no readable resolvers must stale the Setup-time substitutes")
	}

	byIndex[11] = []string{"198.18.0.1"}
	updater.UpdateDefaultInterface("en2", 11, false, false, true, true)
	if !dns.SystemSubstitutesStale() {
		t.Fatal("a tunnel-owned resolver is not a physical resolver")
	}
}

func TestLivePhysicalResolversAreDroppedWithTheirPath(t *testing.T) {
	restoreSubstituteState(t)
	byIndex := map[int32][]string{5: {"192.168.1.1"}}
	readPhysicalResolvers = func(index int32) []string { return byIndex[index] }

	updater := &interfaceUpdater{}
	updater.UpdateDefaultInterface("en0", 5, false, false, true, true)
	if got := dns.SystemSubstituteServers(); len(got) != 1 || got[0] != "192.168.1.1:53" {
		t.Fatalf("Wi-Fi resolvers = %v", got)
	}

	updater.UpdateDefaultInterface("pdp_ip0", 7, true, false, true, true)
	if got := dns.SystemSubstituteServers(); len(got) != 0 {
		t.Fatalf("the previous path's resolvers must be dropped, still published: %v", got)
	}
	if !dns.SystemSubstitutesStale() {
		t.Fatal("with nothing readable the stale-resolver rule takes over")
	}
}

func TestLivePhysicalResolversDropThisConfigurationsTunnelRanges(t *testing.T) {
	restoreSubstituteState(t)
	previous := currentTunnelPrefixes()
	t.Cleanup(func() { setConfiguredTunnelPrefixes(previous) })
	setConfiguredTunnelPrefixes([]netip.Prefix{netip.MustParsePrefix("28.0.0.0/8")})

	readPhysicalResolvers = func(int32) []string { return []string{"28.0.0.2"} }
	updater := &interfaceUpdater{}
	updater.UpdateDefaultInterface("en0", 5, false, false, true, true)
	if got := dns.SystemSubstituteServers(); len(got) != 0 {
		t.Fatalf("an address inside this configuration's own tunnel range is this process, not a resolver: %v", got)
	}
	if dns.SystemSubstitutesStale() {
		t.Fatal("the tunnel's own start path is where the Setup-time substitutes are good")
	}
}

func TestRefreshHookRereadsWhenTheDNSConfigurationChanges(t *testing.T) {
	restoreSubstituteState(t)
	servers := []string{"192.168.1.1"}
	readPhysicalResolvers = func(int32) []string { return servers }

	updater := &interfaceUpdater{}
	updater.UpdateDefaultInterface("en0", 5, false, false, true, true)
	if got := dns.SystemSubstituteServers(); len(got) != 1 || got[0] != "192.168.1.1:53" {
		t.Fatalf("initial resolvers = %v", got)
	}

	servers = []string{"192.168.1.254"}
	dnsConfigurationChanged = func() bool { return true }
	updater.refreshLivePhysicalResolvers()
	if got := dns.SystemSubstituteServers(); len(got) != 1 || got[0] != "192.168.1.254:53" {
		t.Fatalf("a changed DNS configuration must be re-read; live servers = %v", got)
	}

	reads := 0
	readPhysicalResolvers = func(int32) []string { reads++; return []string{"192.168.1.9"} }
	dnsConfigurationChanged = func() bool { return false }
	updater.refreshLivePhysicalResolvers()
	if reads != 0 {
		t.Fatal("an unchanged DNS configuration must not be re-read on every query")
	}
	if got := dns.SystemSubstituteServers(); len(got) != 1 || got[0] != "192.168.1.254:53" {
		t.Fatalf("an unchanged configuration must leave the live list alone; got %v", got)
	}
}

func TestRefreshHookDoesNotEatAChangeItCannotActOn(t *testing.T) {
	restoreSubstituteState(t)
	readPhysicalResolvers = func(int32) []string { return []string{"192.168.1.1"} }
	checks := 0
	dnsConfigurationChanged = func() bool { checks++; return true }

	updater := &interfaceUpdater{}
	updater.refreshLivePhysicalResolvers()
	if checks != 0 {
		t.Fatal("the change token must not be consumed before the updater can act on it")
	}
}

func TestDroppingTheLiveListAlsoRecomputesTheStaleMark(t *testing.T) {
	restoreSubstituteState(t)
	byIndex := map[int32][]string{5: {"192.168.1.1"}, 7: {"119.29.29.29"}}
	readPhysicalResolvers = func(index int32) []string { return byIndex[index] }

	updater := &interfaceUpdater{}
	updater.UpdateDefaultInterface("en0", 5, false, false, true, true)
	updater.UpdateDefaultInterface("pdp_ip0", 7, true, false, true, true)
	if dns.SystemSubstitutesStale() {
		t.Fatal("cellular had its own resolvers; nothing is stale yet")
	}

	delete(byIndex, 7)
	dnsConfigurationChanged = func() bool { return true }
	updater.refreshLivePhysicalResolvers()

	if got := dns.SystemSubstituteServers(); len(got) != 0 {
		t.Fatalf("the live list must be dropped, still published: %v", got)
	}
	if !dns.SystemSubstitutesStale() {
		t.Fatal("off the start path with nothing readable, `system` must take the fallback chain rather than the Setup-time resolver of another network")
	}
}

func TestDroppingTheLiveListOnTheStartPathKeepsTheSetupSubstitutes(t *testing.T) {
	restoreSubstituteState(t)
	byIndex := map[int32][]string{5: {"192.168.1.1"}}
	readPhysicalResolvers = func(index int32) []string { return byIndex[index] }

	updater := &interfaceUpdater{}
	updater.UpdateDefaultInterface("en0", 5, false, false, true, true)
	delete(byIndex, 5)
	dnsConfigurationChanged = func() bool { return true }
	updater.refreshLivePhysicalResolvers()

	if got := dns.SystemSubstituteServers(); len(got) != 0 {
		t.Fatalf("the live list must be dropped, still published: %v", got)
	}
	if dns.SystemSubstitutesStale() {
		t.Fatal("the tunnel's own start path is where the Setup-time substitutes are good")
	}
}
