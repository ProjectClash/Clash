package tun

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestDetachingFromTheRuntimePollerKeepsTheDescriptorNumber(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[1])
	device, err := New(Options{Name: "utun", MTU: 1500, FileDescriptor: fds[0]})
	if err != nil {
		t.Fatal(err)
	}
	native := device.(*NativeTun)
	queue, err := unix.Kqueue()
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(queue)
	register := []unix.Kevent_t{{Ident: uint64(fds[0]), Filter: unix.EVFILT_READ, Flags: unix.EV_ADD | unix.EV_CLEAR}}
	if _, err := unix.Kevent(queue, register, nil, nil); err != nil {
		t.Fatal(err)
	}
	pending := func() int {
		events := make([]unix.Kevent_t, 4)
		n, err := unix.Kevent(queue, nil, events, &unix.Timespec{})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if _, err := unix.Write(fds[1], []byte("before")); err != nil {
		t.Fatal(err)
	}
	if pending() != 1 {
		t.Fatal("the stand-in poller saw no packet before the detach; the test proves nothing")
	}
	buffer := make([]byte, 16)
	if _, err := unix.Read(fds[0], buffer); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(uintptr(fds[0]), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
		t.Fatal(err)
	}

	if err := native.DetachFromRuntimePoller(); err != nil {
		t.Fatal(err)
	}
	if native.tunFd != fds[0] {
		t.Fatalf("the device moved to descriptor %d from %d", native.tunFd, fds[0])
	}
	if flags, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFD, 0); err != nil || flags&unix.FD_CLOEXEC == 0 {
		t.Fatalf("the descriptor lost close-on-exec (%#x, %v)", flags, err)
	}
	if _, err := unix.Write(fds[1], []byte("after")); err != nil {
		t.Fatal(err)
	}
	if n := pending(); n != 0 {
		t.Fatalf("the stand-in poller still woke for a packet (%d events)", n)
	}
	n, err := unix.Read(fds[0], buffer)
	if err != nil || string(buffer[:n]) != "after" {
		t.Fatalf("the descriptor read %q (%v), want the packet on the same socket", buffer[:n], err)
	}

	if err := native.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFD, 0); err == nil {
		t.Fatal("Close left the descriptor open")
	}
}
