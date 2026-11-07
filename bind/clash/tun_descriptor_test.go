package clash

import (
	"testing"

	LC "github.com/ProjectClash/Clash/listener/config"
	"golang.org/x/sys/unix"
)

func TestABridgeDescriptorIsNotTakenForAUtun(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	if name, err := tunDescriptorUtun(fds[0]); name != "" || err == nil {
		t.Fatalf("a socketpair end read as the utun %q (%v)", name, err)
	}
	recordTunDescriptor(fds[0])
	if kind := lastTunDescriptor(); kind != "a PacketFlow bridge (no utun name: a unix socket, not a utun's control socket)" {
		t.Fatalf("a socketpair end is %q in the diagnostics", kind)
	}
	if name, err := tunDescriptorUtun(-1); name != "" || err == nil {
		t.Fatalf("a closed descriptor read as the utun %q (%v)", name, err)
	}
}

func TestTheBridgeDescriptorIsHandedOverForTheOrdinaryRead(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	tun := LC.Tun{RecvMsgX: true}
	handOverTunDescriptor(&tun, fds[0])
	if tun.FileDescriptor != fds[0] || tun.RecvMsgX {
		t.Fatalf("handed over the bridge as fd %d with recvmsgx %v, want fd %d without", tun.FileDescriptor, tun.RecvMsgX, fds[0])
	}
}
