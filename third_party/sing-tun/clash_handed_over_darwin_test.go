package tun

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestAHandedOverDescriptorThatRefusesBatchSizingStillStarts(t *testing.T) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	if err = configure(fds[0], true, 1500); err == nil {
		t.Fatal("a socketpair accepted the utun's pending-packet option; the test no longer exercises the fallback")
	}
	if err = configureHandedOver(fds[0], Options{MTU: 1500, EXP_RecvMsgX: true}); err != nil {
		t.Fatalf("configureHandedOver = %v, want the plain read", err)
	}
	flags, err := unix.FcntlInt(uintptr(fds[0]), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_NONBLOCK == 0 {
		t.Fatalf("descriptor flags %#x (%v), want non-blocking", flags, err)
	}
}

func TestAHandedOverDescriptorThatCannotBePreparedStillFails(t *testing.T) {
	if err := configureHandedOver(-1, Options{MTU: 1500, EXP_RecvMsgX: true}); err == nil {
		t.Fatal("configureHandedOver accepted a closed descriptor")
	}
}
