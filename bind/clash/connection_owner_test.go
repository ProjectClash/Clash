package clash

import (
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/ProjectClash/Clash/component/process"
)

type fakeOwnerResolver struct {
	calls atomic.Int32
	last  []any
	owner *ConnectionOwner
	err   error
}

func (f *fakeOwnerResolver) FindConnectionOwner(ipProtocol int32, sourceAddress string, sourcePort int32, destinationAddress string, destinationPort int32) (*ConnectionOwner, error) {
	f.calls.Add(1)
	f.last = []any{ipProtocol, sourceAddress, sourcePort, destinationAddress, destinationPort}
	return f.owner, f.err
}

func installOwnerResolver(t *testing.T, r ConnectionOwnerResolver) {
	t.Helper()
	SetConnectionOwnerResolver(r)
	t.Cleanup(func() { SetConnectionOwnerResolver(nil) })
}

var (
	ownerSource      = netip.MustParseAddr("198.18.0.1")
	ownerDestination = netip.MustParseAddr("198.18.0.20")
)

func TestTheMacTunnelAsksThePlatformWhoOwnsAConnection(t *testing.T) {
	withRuntimeProfile(t, runtimeProfileMacOSPacketTunnel)
	fake := &fakeOwnerResolver{owner: &ConnectionOwner{UserId: 501, UserName: "ejan", ProcessPath: "/Applications/Telegram.app/Contents/MacOS/Telegram"}}
	installOwnerResolver(t, fake)
	uid, path, err := process.FindConnectionOwner(process.TCP, ownerSource, 52000, ownerDestination, 443)
	if err != nil || uid != 501 || path != "/Applications/Telegram.app/Contents/MacOS/Telegram" {
		t.Fatalf("uid=%d path=%q err=%v", uid, path, err)
	}
	want := []any{int32(6), "198.18.0.1", int32(52000), "198.18.0.20", int32(443)}
	for i := range want {
		if fake.last[i] != want[i] {
			t.Fatalf("asked %v, want %v", fake.last, want)
		}
	}
	_, _, _ = process.FindConnectionOwner(process.UDP, ownerSource, 53000, ownerDestination, 443)
	if fake.last[0] != int32(17) {
		t.Fatalf("UDP asked as protocol %v, want 17", fake.last[0])
	}
}

func TestOtherProfilesDoNotAskThePlatform(t *testing.T) {
	for _, profile := range []runtimeProfile{runtimeProfileIOSPacketTunnel, runtimeProfileTVOSPacketTunnel, runtimeProfileMacOSApplication} {
		withRuntimeProfile(t, profile)
		fake := &fakeOwnerResolver{owner: &ConnectionOwner{ProcessPath: "/x"}}
		installOwnerResolver(t, fake)
		_, _, _ = process.FindConnectionOwner(process.TCP, ownerSource, 52000, ownerDestination, 443)
		if fake.calls.Load() != 0 {
			t.Fatalf("profile %v asked the platform", profile)
		}
	}
}

func TestAPlatformThatCannotAnswerIsAskedAgainNextTime(t *testing.T) {
	withRuntimeProfile(t, runtimeProfileMacOSPacketTunnel)
	for _, fake := range []*fakeOwnerResolver{
		{err: errors.New("the App is not running")},
		{owner: nil},
		{owner: &ConnectionOwner{UserId: 501}},
	} {
		installOwnerResolver(t, fake)
		_, path, _ := process.FindConnectionOwner(process.TCP, ownerSource, 52000, ownerDestination, 443)
		_, _, _ = process.FindConnectionOwner(process.TCP, ownerSource, 52000, ownerDestination, 443)
		if fake.calls.Load() != 2 {
			t.Fatalf("asked %d times, want every lookup to ask", fake.calls.Load())
		}
		if path == "/x" {
			t.Fatal("unreachable")
		}
	}
}

func TestANilResolverUnregisters(t *testing.T) {
	withRuntimeProfile(t, runtimeProfileMacOSPacketTunnel)
	fake := &fakeOwnerResolver{owner: &ConnectionOwner{ProcessPath: "/x"}}
	SetConnectionOwnerResolver(fake)
	SetConnectionOwnerResolver(nil)
	_, _, _ = process.FindConnectionOwner(process.TCP, ownerSource, 52000, ownerDestination, 443)
	if fake.calls.Load() != 0 {
		t.Fatal("an unregistered resolver was asked")
	}
}
