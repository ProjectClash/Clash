package clash

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/ProjectClash/Clash/component/dialer"
)

func setupNAT64PolicyTest(t *testing.T) {
	t.Helper()
	originalTransform := dialer.DefaultAddressTransform
	originalSynthesize := synthesizeIPv4Literal
	originalIPv4 := physicalPathSupportsIPv4.Load()
	originalIPv6 := physicalPathSupportsIPv6.Load()
	t.Cleanup(func() {
		dialer.DefaultAddressTransform = originalTransform
		synthesizeIPv4Literal = originalSynthesize
		physicalPathSupportsIPv4.Store(originalIPv4)
		physicalPathSupportsIPv6.Store(originalIPv6)
		nat64SynthesisAttempts.Store(0)
		nat64SynthesisApplied.Store(0)
		nat64SynthesisFailures.Store(0)
	})
	installPhysicalAddressTransform(true)
}

func TestNAT64SynthesisRejectsAddressesThatCannotBeATranslation(t *testing.T) {
	setupNAT64PolicyTest(t)
	physicalPathSupportsIPv4.Store(false)
	physicalPathSupportsIPv6.Store(true)

	destination := netip.MustParseAddr("93.184.216.34")
	for _, hostile := range []struct {
		name      string
		synthetic string
	}{
		{"loopback", "::1"},
		{"link-local", "fe80::1"},
		{"multicast", "ff02::1"},
		{"unspecified", "::"},
		{"unrelated destination", "2001:db8:64::c0a8:0101"},
	} {
		synthesizeIPv4Literal = func(string, netip.Addr) (netip.Addr, error) {
			return netip.MustParseAddr(hostile.synthetic), nil
		}
		got, err := transformPhysicalAddressForApple("tcp", destination)
		if err == nil {
			t.Fatalf("%s: a synthesized %s was accepted and would be dialed (%v)", hostile.name, hostile.synthetic, got)
		}
	}

	synthesizeIPv4Literal = func(string, netip.Addr) (netip.Addr, error) {
		return netip.MustParseAddr("64:ff9b::5db8:d822"), nil
	}
	got, err := transformPhysicalAddressForApple("tcp", destination)
	if err != nil {
		t.Fatalf("a real NAT64 translation must be accepted: %v", err)
	}
	if got.String() != "64:ff9b::5db8:d822" {
		t.Fatalf("the accepted address changed: %v", got)
	}
}

func TestNAT64SynthesisAcceptsEveryRFC6052PrefixLength(t *testing.T) {
	setupNAT64PolicyTest(t)
	physicalPathSupportsIPv4.Store(false)
	physicalPathSupportsIPv6.Store(true)
	destination := netip.MustParseAddr("192.0.2.33")

	for _, form := range []struct {
		name      string
		synthetic string
	}{
		{"/32", "2001:db8:c000:221::"},
		{"/40", "2001:db8:1c0:2:21::"},
		{"/48", "2001:db8:122:c000:2:2100::"},
		{"/56", "2001:db8:122:3c0:0:221::"},
		{"/64", "2001:db8:122:344:c0:2:2100:0"},
		{"/96", "64:ff9b::c000:221"},
	} {
		synthesizeIPv4Literal = func(string, netip.Addr) (netip.Addr, error) {
			return netip.MustParseAddr(form.synthetic), nil
		}
		got, err := transformPhysicalAddressForApple("tcp", destination)
		if err != nil {
			t.Fatalf("%s translation %s was rejected; on a network using that prefix length every IPv4 destination would become unreachable: %v",
				form.name, form.synthetic, err)
		}
		if got.String() != netip.MustParseAddr(form.synthetic).String() {
			t.Fatalf("%s: dial address changed to %v", form.name, got)
		}
	}

	synthesizeIPv4Literal = func(string, netip.Addr) (netip.Addr, error) {
		return netip.MustParseAddr("2001:db8::dead:beef"), nil
	}
	if _, err := transformPhysicalAddressForApple("tcp", destination); err == nil {
		t.Fatal("an address embedding the destination nowhere was accepted")
	}
}

func TestNAT64SynthesisAcceptsAppleNetworkSpecificPrefix(t *testing.T) {
	setupNAT64PolicyTest(t)
	physicalPathSupportsIPv4.Store(false)
	physicalPathSupportsIPv6.Store(true)

	for _, measured := range []struct {
		name        string
		destination string
		synthesized string
	}{
		{"ipv4only.arpa", "192.0.0.170", "2001:2:0:1baa::c000:aa"},
		{"ipv4-only host", "198.51.100.100", "2001:2:0:1baa::c633:6464"},
	} {
		destination := netip.MustParseAddr(measured.destination)
		synthesizeIPv4Literal = func(string, netip.Addr) (netip.Addr, error) {
			return netip.MustParseAddr(measured.synthesized), nil
		}
		got, err := transformPhysicalAddressForApple("tcp", destination)
		if err != nil {
			t.Fatalf("%s: a real Apple NAT64 network's answer %s was refused; every IPv4 destination there would be unreachable: %v",
				measured.name, measured.synthesized, err)
		}
		if got.String() != netip.MustParseAddr(measured.synthesized).String() {
			t.Fatalf("%s: dial address changed to %v", measured.name, got)
		}
	}

	synthesizeIPv4Literal = func(string, netip.Addr) (netip.Addr, error) {
		return netip.MustParseAddr("2001:2:0:1baa::dead:beef"), nil
	}
	if _, err := transformPhysicalAddressForApple("tcp", netip.MustParseAddr("198.51.100.100")); err == nil {
		t.Fatal("the real prefix carrying an unrelated address was accepted; the prefix alone is not what makes an answer a translation")
	}
}

func TestNAT64SynthesisSkipsPrivateAndLinkLocalDestinations(t *testing.T) {
	setupNAT64PolicyTest(t)
	physicalPathSupportsIPv4.Store(false)
	physicalPathSupportsIPv6.Store(true)
	synthesizeIPv4Literal = func(string, netip.Addr) (netip.Addr, error) {
		t.Fatal("a private destination must never reach the system translator")
		return netip.Addr{}, nil
	}

	for _, address := range []string{"10.0.0.5", "192.168.1.1", "172.16.0.9", "169.254.1.1"} {
		destination := netip.MustParseAddr(address)
		got, err := transformPhysicalAddressForApple("tcp", destination)
		if err != nil {
			t.Fatalf("%s: a private destination must pass through untouched: %v", address, err)
		}
		if got != destination {
			t.Fatalf("%s: destination was rewritten to %v", address, got)
		}
	}
}

func TestNAT64TransformOnlyRunsOnIPv6OnlyPhysicalPath(t *testing.T) {
	setupNAT64PolicyTest(t)
	called := 0
	synthesizeIPv4Literal = func(network string, destination netip.Addr) (netip.Addr, error) {
		called++
		if network != "tcp" || destination.String() != "192.0.2.1" {
			t.Fatalf("synthesis input = %s %s", network, destination)
		}
		return netip.MustParseAddr("64:ff9b::c000:201"), nil
	}

	v4 := netip.MustParseAddr("192.0.2.1")
	setPhysicalNetworkCapabilities(true, true)
	if got, err := transformPhysicalAddressForApple("tcp", v4); err != nil || got != v4 {
		t.Fatalf("dual-stack transform = %s, %v", got, err)
	}
	setPhysicalNetworkCapabilities(false, false)
	if got, err := transformPhysicalAddressForApple("tcp", v4); err != nil || got != v4 {
		t.Fatalf("unavailable-path transform = %s, %v", got, err)
	}
	setPhysicalNetworkCapabilities(false, true)
	got, err := transformPhysicalAddressForApple("tcp", v4)
	if err != nil || got.String() != "64:ff9b::c000:201" {
		t.Fatalf("IPv6-only transform = %s, %v", got, err)
	}
	if called != 1 {
		t.Fatalf("synthesizer called %d times, want 1", called)
	}
	snapshot := nat64DiagnosticsSnapshot()
	if snapshot.attempts != 1 || snapshot.applied != 1 || snapshot.failures != 0 {
		t.Fatalf("NAT64 metrics = %#v", snapshot)
	}
}

func TestNAT64TransformFailsClosedAndLeavesIPv6AndLoopbackUntouched(t *testing.T) {
	setupNAT64PolicyTest(t)
	want := errors.New("injected synthesis failure")
	synthesizeIPv4Literal = func(string, netip.Addr) (netip.Addr, error) {
		return netip.Addr{}, want
	}
	setPhysicalNetworkCapabilities(false, true)

	if got, err := transformPhysicalAddressForApple("udp", netip.IPv6Loopback()); err != nil || got != netip.IPv6Loopback() {
		t.Fatalf("native IPv6 changed: %s, %v", got, err)
	}
	loopback4 := netip.MustParseAddr("127.0.0.1")
	if got, err := transformPhysicalAddressForApple("tcp", loopback4); err != nil || got != loopback4 {
		t.Fatalf("loopback changed: %s, %v", got, err)
	}
	_, err := transformPhysicalAddressForApple("udp", netip.MustParseAddr("198.51.100.7"))
	if !errors.Is(err, want) {
		t.Fatalf("transform error = %v, want %v", err, want)
	}
	snapshot := nat64DiagnosticsSnapshot()
	if snapshot.attempts != 1 || snapshot.applied != 0 || snapshot.failures != 1 {
		t.Fatalf("NAT64 failure metrics = %#v", snapshot)
	}
}

func TestInstallSocketHookOwnsPhysicalAddressTransform(t *testing.T) {
	setupNAT64PolicyTest(t)
	installSocketHook(&hookPlatform{enabled: false})
	if dialer.DefaultAddressTransform == nil {
		t.Fatal("a platform with the hook off lost the physical address transform")
	}
	physicalPathSupportsIPv4.Store(false)
	physicalPathSupportsIPv6.Store(true)
	destination := netip.MustParseAddr("93.184.216.34")
	synthetic := netip.MustParseAddr("64:ff9b::5db8:d822")
	synthesizeIPv4Literal = func(string, netip.Addr) (netip.Addr, error) { return synthetic, nil }
	got, err := dialer.TransformPhysicalAddress("tcp", destination)
	if err != nil || got != synthetic {
		t.Fatalf("hook off, IPv6-only path: %s -> %s, %v; want the NAT64 synthesis %s", destination, got, err, synthetic)
	}
	installSocketHook(&hookPlatform{enabled: true})
	if dialer.DefaultAddressTransform == nil {
		t.Fatal("opt-in did not install physical address transform")
	}
	installSocketHook(nil)
	if dialer.DefaultAddressTransform != nil {
		t.Fatal("no platform left the physical address transform installed")
	}
}
