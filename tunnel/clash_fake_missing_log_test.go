package tunnel

import (
	"net/netip"
	"testing"
)

func TestAMissingFakeRecordIsReportedOncePerAddressPerWindow(t *testing.T) {
	a, b := netip.MustParseAddr("198.18.3.200"), netip.MustParseAddr("198.18.3.201")
	if !missingRecordReport(a) {
		t.Fatal("the first packet on a lost address was not reported")
	}
	for i := 0; i < 100; i++ {
		if missingRecordReport(a) {
			t.Fatalf("packet %d on the same address was reported again", i+2)
		}
	}
	if !missingRecordReport(b) {
		t.Fatal("another lost address was not reported")
	}
}
