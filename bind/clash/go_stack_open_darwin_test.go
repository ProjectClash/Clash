package clash

import (
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/listener/sing_tun"
	tun "github.com/metacubex/sing-tun"

	gotun "github.com/sagernet/sing-tun"
	"golang.org/x/sys/unix"
)

func TestAGoStackThatPanicsOpeningTheUtunFailsInsteadOfKillingTheTunnel(t *testing.T) {
	previous := goStackOpenTunOnce
	t.Cleanup(func() { goStackOpenTunOnce = previous })
	goStackOpenTunOnce = func(gotun.Options) (gotun.Tun, error) { panic("too many open files") }

	var err error
	panicked := func() (out bool) {
		defer func() {
			if recover() != nil {
				out = true
			}
		}()
		_, err = goStackNewTun(gotun.Options{MTU: 1500})
		return false
	}()
	if panicked {
		t.Fatal("a panic opening the utun escaped goStackNewTun, and with it the process")
	}
	if err == nil || !strings.Contains(err.Error(), "too many open files") {
		t.Fatalf("the open returned %v, want the panic as an error", err)
	}
}

func TestTheGoStacksCopyOfTheUtunIsCloseOnExec(t *testing.T) {
	var pipe [2]int
	if err := unix.Pipe(pipe[:]); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(pipe[0]); _ = unix.Close(pipe[1]) })
	copied, err := goStackDupDescriptor(pipe[0])
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(copied) })
	flags, err := unix.FcntlInt(uintptr(copied), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	if flags&unix.FD_CLOEXEC == 0 {
		t.Fatal("the go stack's copy of the utun descriptor survives an exec")
	}
}

func TestAGoStackWhoseOpenPanickedLeavesItsUtunCopyToTheOrphanedFile(t *testing.T) {
	standInForAUtun(t)
	previous := goStackOpenTunOnce
	t.Cleanup(func() { goStackOpenTunOnce = previous })
	goStackOpenTunOnce = func(options gotun.Options) (gotun.Tun, error) {
		_ = os.NewFile(uintptr(options.FileDescriptor), "utun")
		panic("too many open files")
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(pair[0]); _ = unix.Close(pair[1]) })
	if _, err := newGoStack(sing_tun.GoStackOptions{Device: utunStandIn{fd: pair[0]}, TunOptions: tun.Options{MTU: 1500}}); err == nil {
		t.Fatal("newGoStack built a stack whose open panicked")
	}
	next, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(next) })
	for range 3 {
		runtime.GC()
		time.Sleep(50 * time.Millisecond)
	}
	if _, err := unix.FcntlInt(uintptr(next), unix.F_GETFD, 0); err != nil {
		t.Fatalf("the socket opened after the failed start was closed under it (%v): the orphaned file's finalizer closed a number newGoStack had already closed and the socket reused", err)
	}
}
