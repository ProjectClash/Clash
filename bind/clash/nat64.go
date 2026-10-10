package clash

import (
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"

	"github.com/ProjectClash/Clash/component/dialer"
)

var (
	physicalPathSupportsIPv4 atomic.Bool
	physicalPathSupportsIPv6 atomic.Bool
	nat64SynthesisAttempts   atomic.Uint64
	nat64SynthesisApplied    atomic.Uint64
	nat64SynthesisFailures   atomic.Uint64

	synthesizeIPv4Literal = systemSynthesizeIPv4Literal
)

type nat64Snapshot struct {
	supportsIPv4 bool
	supportsIPv6 bool
	attempts     uint64
	applied      uint64
	failures     uint64
}

func installPhysicalAddressTransform(enabled bool) {
	physicalPathSupportsIPv4.Store(false)
	physicalPathSupportsIPv6.Store(false)
	nat64SynthesisAttempts.Store(0)
	nat64SynthesisApplied.Store(0)
	nat64SynthesisFailures.Store(0)
	if !enabled {
		dialer.DefaultAddressTransform = nil
		return
	}
	dialer.DefaultAddressTransform = transformPhysicalAddressForApple
}

func setPhysicalNetworkCapabilities(supportsIPv4, supportsIPv6 bool) {
	physicalPathSupportsIPv4.Store(supportsIPv4)
	physicalPathSupportsIPv6.Store(supportsIPv6)
}

func transformPhysicalAddressForApple(network string, destination netip.Addr) (netip.Addr, error) {
	if currentIPStackSettings().tunIPv6Mode != "" &&
		destination.Is6() && !destination.Is4In6() && destination.IsGlobalUnicast() && !destination.IsPrivate() &&
		physicalPathSupportsIPv4.Load() && !physicalPathSupportsIPv6.Load() {
		return netip.Addr{}, dialer.ErrPhysicalIPv6Unavailable
	}
	if !destination.IsValid() || !destination.Is4() || destination.IsLoopback() {
		return destination, nil
	}
	if destination.IsPrivate() || destination.IsLinkLocalUnicast() || destination.IsLinkLocalMulticast() {
		return destination, nil
	}
	if physicalPathSupportsIPv4.Load() || !physicalPathSupportsIPv6.Load() {
		return destination, nil
	}

	nat64SynthesisAttempts.Add(1)
	synthesized, err := synthesizeIPv4Literal(network, destination)
	if err != nil {
		nat64SynthesisFailures.Add(1)
		return netip.Addr{}, fmt.Errorf("clash: system NAT64 synthesis for %s destination failed: %w", network, err)
	}
	if err := validateNAT64Synthesis(synthesized, destination); err != nil {
		nat64SynthesisFailures.Add(1)
		return netip.Addr{}, err
	}
	nat64SynthesisApplied.Add(1)
	return synthesized, nil
}

var allowLoopbackNAT64Synthesis = false

func validateNAT64Synthesis(synthesized, destination netip.Addr) error {
	if !synthesized.IsValid() || !synthesized.Is6() || synthesized.Is4In6() {
		return errors.New("clash: system NAT64 synthesis did not return a native IPv6 destination")
	}
	if allowLoopbackNAT64Synthesis && synthesized.IsLoopback() {
		return nil
	}
	if synthesized.IsLoopback() || synthesized.IsUnspecified() ||
		synthesized.IsLinkLocalUnicast() || synthesized.IsLinkLocalMulticast() ||
		synthesized.IsMulticast() || synthesized.IsInterfaceLocalMulticast() {
		return errors.New("clash: system NAT64 synthesis returned an address that cannot be a remote destination")
	}
	if !embedsIPv4PerRFC6052(synthesized, destination) {
		return errors.New("clash: system NAT64 synthesis does not embed the requested destination")
	}
	return nil
}

var rfc6052EmbeddingOffsets = [][4]int{
	{4, 5, 6, 7},
	{5, 6, 7, 9},
	{6, 7, 9, 10},
	{7, 9, 10, 11},
	{9, 10, 11, 12},
	{12, 13, 14, 15},
}

func embedsIPv4PerRFC6052(synthesized, destination netip.Addr) bool {
	address := synthesized.As16()
	want := destination.Unmap().As4()
	for _, offsets := range rfc6052EmbeddingOffsets {
		if address[offsets[0]] == want[0] && address[offsets[1]] == want[1] &&
			address[offsets[2]] == want[2] && address[offsets[3]] == want[3] {
			return true
		}
	}
	return false
}

func nat64DiagnosticsSnapshot() nat64Snapshot {
	return nat64Snapshot{
		supportsIPv4: physicalPathSupportsIPv4.Load(),
		supportsIPv6: physicalPathSupportsIPv6.Load(),
		attempts:     nat64SynthesisAttempts.Load(),
		applied:      nat64SynthesisApplied.Load(),
		failures:     nat64SynthesisFailures.Load(),
	}
}
