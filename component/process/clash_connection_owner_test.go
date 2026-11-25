package process

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
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

func countOwnLookups(t *testing.T) *int {
	t.Helper()
	calls := 0
	saved := ownLookup
	ownLookup = func(string, netip.Addr, int) (uint32, string, error) {
		calls++
		return 0, "", ErrNotFound
	}
	t.Cleanup(func() { ownLookup = saved })
	return &calls
}

func TestAFinalResolverFailureIsNotFollowedByTheOwnLookup(t *testing.T) {
	own := countOwnLookups(t)
	SetConnectionOwnerResolver(func(string, netip.Addr, int, netip.Addr, int) (uint32, string, error) {
		return 0, "", fmt.Errorf("%w (%w)", errors.New("the App did not answer in time"), ErrOwnerResolverIsFinal)
	})
	t.Cleanup(func() { SetConnectionOwnerResolver(nil) })
	_, path, err := FindConnectionOwner(TCP, ownerSrc, 52000, ownerDst, 443)
	if *own != 0 {
		t.Fatalf("the own lookup ran %d times after a final failure", *own)
	}
	if path != "" || !errors.Is(err, ErrNotFound) || !errors.Is(err, ErrOwnerResolverIsFinal) {
		t.Fatalf("path=%q err=%v, want no owner, ErrNotFound and the resolver's reason", path, err)
	}
	if strings.Contains(err.Error(), "\n") {
		t.Fatalf("err %q spans lines", err.Error())
	}
}

func TestANonFinalResolverFailureStillFallsBack(t *testing.T) {
	own := countOwnLookups(t)
	SetConnectionOwnerResolver(func(string, netip.Addr, int, netip.Addr, int) (uint32, string, error) {
		return 0, "", errors.New("not this platform's resolver")
	})
	t.Cleanup(func() { SetConnectionOwnerResolver(nil) })
	_, _, _ = FindConnectionOwner(TCP, ownerSrc, 52000, ownerDst, 443)
	if *own != 1 {
		t.Fatalf("the own lookup ran %d times, want 1", *own)
	}
}
