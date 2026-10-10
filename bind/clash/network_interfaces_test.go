package clash

import (
	"errors"
	"net"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/component/dialer"
)

type interfaceListPlatform struct {
	recordingPlatform
	entries []*NetworkInterface
	err     error
	reads   int
}

func (p *interfaceListPlatform) GetInterfaces() (NetworkInterfaceIterator, error) {
	p.reads++
	if p.err != nil {
		return nil, p.err
	}
	return newNetworkInterfaceIterator(p.entries), nil
}

func newInterfaceListPlatform(entries ...*NetworkInterface) *interfaceListPlatform {
	platform := &interfaceListPlatform{recordingPlatform: *newRecordingPlatform(), entries: entries}
	platform.useAutoDetect = true
	return platform
}

func restoreInterfaceProvider(t *testing.T) {
	t.Helper()
	previous := dialer.NetworkInterfaceProvider.Load()
	t.Cleanup(func() {
		dialer.NetworkInterfaceProvider.Store(previous)
		installNetworkInterfaceProvider(nil)
		dialer.NetworkInterfaceProvider.Store(previous)
	})
}

func upRunning() int32 { return int32(net.FlagUp | net.FlagRunning) }

func TestDecodeNetworkInterfacesReadsTheFlagContract(t *testing.T) {
	decoded := decodeNetworkInterfaces(newNetworkInterfaceIterator([]*NetworkInterface{
		{Index: 4, Name: "en0", Type: 1, Flags: upRunning() | interfaceFlagAvailable | interfaceFlagDefault},
		{Index: 10, Name: "pdp_ip0", Type: 2, Flags: upRunning() | interfaceFlagAvailable, Metered: true},
		{Index: 12, Name: "utun4", Type: 5, Flags: upRunning() | interfaceFlagAvailable | interfaceFlagOwnTunnel},
	}))
	if len(decoded) != 3 {
		t.Fatalf("expected three interfaces, got %d", len(decoded))
	}
	if decoded[0].Type != dialer.InterfaceTypeWIFI || !decoded[0].Default || !decoded[0].Available || decoded[0].OwnTunnel {
		t.Fatalf("en0 decoded wrong: %+v", decoded[0])
	}
	if decoded[1].Type != dialer.InterfaceTypeCellular || decoded[1].Default || !decoded[1].Metered {
		t.Fatalf("pdp_ip0 decoded wrong: %+v", decoded[1])
	}
	if !decoded[2].OwnTunnel {
		t.Fatalf("utun4 must be marked as our own tunnel: %+v", decoded[2])
	}
}

func TestDecodeNetworkInterfacesRequiresBothAvailabilityHalves(t *testing.T) {
	decoded := decodeNetworkInterfaces(newNetworkInterfaceIterator([]*NetworkInterface{
		{Index: 4, Name: "platform-says-no", Type: 1, Flags: upRunning()},
		{Index: 5, Name: "kernel-says-no", Type: 1, Flags: interfaceFlagAvailable},
		{Index: 6, Name: "up-but-not-running", Type: 1, Flags: int32(net.FlagUp) | interfaceFlagAvailable},
		{Index: 7, Name: "both-agree", Type: 1, Flags: upRunning() | interfaceFlagAvailable},
	}))
	for _, candidate := range decoded {
		if candidate.Available != (candidate.Name == "both-agree") {
			t.Fatalf("%s availability wrong: %+v", candidate.Name, candidate)
		}
	}
}

func TestInstallNetworkInterfaceProviderPublishesAndClears(t *testing.T) {
	restoreInterfaceProvider(t)
	platform := newInterfaceListPlatform(&NetworkInterface{
		Index: 4, Name: "en0", Type: 1, Flags: upRunning() | interfaceFlagAvailable | interfaceFlagDefault,
	})
	installNetworkInterfaceProvider(platform)
	provider := dialer.NetworkInterfaceProvider.Load()
	if provider == nil {
		t.Fatal("installing a platform must publish a provider")
	}
	if got := provider(); len(got) != 1 || got[0].Name != "en0" {
		t.Fatalf("provider answered %+v", got)
	}
	installNetworkInterfaceProvider(nil)
	if dialer.NetworkInterfaceProvider.Load() != nil {
		t.Fatal("clearing the platform must clear the provider")
	}
}

func TestInterfaceProviderIsPublishedWhereTheHookIsOff(t *testing.T) {
	restoreInterfaceProvider(t)
	platform := newInterfaceListPlatform(&NetworkInterface{
		Index: 4, Name: "en0", Type: 1, Flags: upRunning() | interfaceFlagAvailable | interfaceFlagDefault,
	})
	platform.useAutoDetect = false
	installNetworkInterfaceProvider(platform)
	if dialer.NetworkInterfaceProvider.Load() == nil {
		t.Fatal("a platform that does not bind its sockets must still publish an interface provider")
	}
}

func TestNetworkInterfaceListIsCachedUntilInvalidated(t *testing.T) {
	restoreInterfaceProvider(t)
	platform := newInterfaceListPlatform(&NetworkInterface{
		Index: 4, Name: "en0", Type: 1, Flags: upRunning() | interfaceFlagAvailable | interfaceFlagDefault,
	})
	installNetworkInterfaceProvider(platform)
	provider := dialer.NetworkInterfaceProvider.Load()
	for range 5 {
		provider()
	}
	if platform.reads != 1 {
		t.Fatalf("expected one platform read behind five dials, got %d", platform.reads)
	}
	invalidateNetworkInterfaces()
	provider()
	if platform.reads != 2 {
		t.Fatalf("an invalidated cache must read again, got %d reads", platform.reads)
	}
}

func TestNetworkInterfaceCacheExpiresOnItsOwn(t *testing.T) {
	restoreInterfaceProvider(t)
	platform := newInterfaceListPlatform(&NetworkInterface{
		Index: 4, Name: "en0", Type: 1, Flags: upRunning() | interfaceFlagAvailable,
	})
	installNetworkInterfaceProvider(platform)
	provider := dialer.NetworkInterfaceProvider.Load()
	provider()
	platformInterfaces.mu.Lock()
	platformInterfaces.readAt = time.Now().Add(-networkInterfaceCacheTTL - time.Second)
	platformInterfaces.mu.Unlock()
	if got := provider(); len(got) != 1 {
		t.Fatalf("an expired cache must still answer, got %+v", got)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		platformInterfaces.mu.Lock()
		reads := platform.reads
		platformInterfaces.mu.Unlock()
		if reads == 2 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("expected the expired cache to be refreshed in the background, got %d reads", reads)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestNetworkInterfaceReadFailureAnswersEmpty(t *testing.T) {
	restoreInterfaceProvider(t)
	platform := newInterfaceListPlatform()
	platform.err = errors.New("no interfaces for you")
	installNetworkInterfaceProvider(platform)
	provider := dialer.NetworkInterfaceProvider.Load()
	if got := provider(); got != nil {
		t.Fatalf("a failed read must answer with nothing, got %+v", got)
	}
}

func TestPathUpdateInvalidatesTheInterfaceList(t *testing.T) {
	restoreInterfaceProvider(t)
	platform := newInterfaceListPlatform(&NetworkInterface{
		Index: 4, Name: "en0", Type: 1, Flags: upRunning() | interfaceFlagAvailable,
	})
	installNetworkInterfaceProvider(platform)
	provider := dialer.NetworkInterfaceProvider.Load()
	provider()
	updater := &interfaceUpdater{}
	updater.UpdateDefaultInterface("pdp_ip0", 10, true, false, true, false)
	provider()
	if platform.reads != 2 {
		t.Fatalf("a path change must invalidate the interface list, got %d reads", platform.reads)
	}
}
