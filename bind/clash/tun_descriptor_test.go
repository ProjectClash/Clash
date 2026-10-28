package clash

import (
	"strings"
	"testing"

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
	if kind := lastTunDescriptor(); !strings.HasPrefix(kind, "a PacketFlow bridge (no utun name: ") {
		t.Fatalf("a socketpair end is %q in the diagnostics", kind)
	}
	if name, err := tunDescriptorUtun(-1); name != "" || err == nil {
		t.Fatalf("a closed descriptor read as the utun %q (%v)", name, err)
	}
}
