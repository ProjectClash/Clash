package tun

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestASocketpairIsNotAUtunControlSocket(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	if raw, err := unix.GetsockoptString(fds[0], 2, 2); err == nil {
		t.Logf("UTUN_OPT_IFNAME on a socketpair reads %q without an error", raw)
	}
	if name, ok := UtunControlName(fds[0]); ok {
		t.Fatalf("a socketpair was taken for the utun %q", name)
	}
}

func TestOnlyTheUtunsControlSocketIsTakenForAUtun(t *testing.T) {
	unconnected, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(unconnected)
	if name, ok := UtunControlName(unconnected); ok {
		t.Fatalf("an unconnected control socket was taken for the utun %q", name)
	}

	statistics, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(statistics)
	id, ok := kernelControlID(statistics, "com.apple.network.statistics")
	if !ok {
		t.Fatal("no id for the network statistics control")
	}
	if err := unix.Connect(statistics, &unix.SockaddrCtl{ID: id}); err != nil {
		t.Fatalf("connecting to the network statistics control: %v", err)
	}
	if peer, ok := kernelControlPeer(statistics); !ok || peer != id {
		t.Fatalf("a socket connected to control %d reads its peer as %d (%v)", id, peer, ok)
	}
	if name, ok := UtunControlName(statistics); ok {
		t.Fatalf("the network statistics control's socket was taken for the utun %q", name)
	}

	utun, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(utun)
	id, ok = kernelControlID(utun, "com.apple.net.utun_control")
	if !ok {
		t.Fatal("no id for the utun control")
	}
	if err := unix.Connect(utun, &unix.SockaddrCtl{ID: id}); errors.Is(err, unix.EPERM) {
		t.Skip("making a utun takes root; the utun's side is checked on a device, from the core's diagnostics")
	} else if err != nil {
		t.Fatalf("making a utun: %v", err)
	}
	if name, ok := UtunControlName(utun); !ok || !strings.HasPrefix(name, "utun") {
		t.Fatalf("a utun's control socket reads %q (%v)", name, ok)
	}
}
