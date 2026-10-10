package process

import (
	"errors"
	"net/netip"
	"testing"
)

var (
	ownerSrc = netip.MustParseAddr("198.18.0.1")
	ownerDst = netip.MustParseAddr("198.18.0.20")
)

func TestAnInstalledOwnerResolverAnswersWithTheFullFiveTuple(t *testing.T) {
	var got []any
	SetConnectionOwnerResolver(func(network string, src netip.Addr, srcPort int, dst netip.Addr, dstPort int) (uint32, string, error) {
		got = []any{network, src, srcPort, dst, dstPort}
		return 501, "/Applications/Safari.app/Contents/MacOS/Safari", nil
	})
	t.Cleanup(func() { SetConnectionOwnerResolver(nil) })
	uid, path, err := FindConnectionOwner(TCP, ownerSrc, 52000, ownerDst, 443)
	if err != nil || uid != 501 || path != "/Applications/Safari.app/Contents/MacOS/Safari" {
		t.Fatalf("uid=%d path=%q err=%v", uid, path, err)
	}
	if got[0] != TCP || got[1] != ownerSrc || got[2] != 52000 || got[3] != ownerDst || got[4] != 443 {
		t.Fatalf("resolver asked %v", got)
	}
}

func TestAFailingOwnerResolverFallsBackToTheOwnLookup(t *testing.T) {
	calls := 0
	SetConnectionOwnerResolver(func(string, netip.Addr, int, netip.Addr, int) (uint32, string, error) {
		calls++
		return 0, "", errors.New("the App is not running")
	})
	t.Cleanup(func() { SetConnectionOwnerResolver(nil) })
	_, _, errWith := FindConnectionOwner(TCP, ownerSrc, 52000, ownerDst, 443)
	SetConnectionOwnerResolver(nil)
	_, _, errWithout := FindConnectionOwner(TCP, ownerSrc, 52000, ownerDst, 443)
	if calls != 1 {
		t.Fatalf("resolver called %d times", calls)
	}
	if (errWith == nil) != (errWithout == nil) {
		t.Fatalf("fallback differs from the own lookup: with=%v without=%v", errWith, errWithout)
	}
}

func TestAnEmptyAnswerFallsBackToo(t *testing.T) {
	SetConnectionOwnerResolver(func(string, netip.Addr, int, netip.Addr, int) (uint32, string, error) {
		return 0, "", nil
	})
	t.Cleanup(func() { SetConnectionOwnerResolver(nil) })
	_, path, _ := FindConnectionOwner(TCP, ownerSrc, 52000, ownerDst, 443)
	if path != "" {
		_, want, _ := findProcessName(TCP, ownerSrc, 52000)
		if path != want {
			t.Fatalf("path %q is neither empty nor the own lookup's %q", path, want)
		}
	}
}
