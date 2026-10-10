//go:build with_quic

package clash

import "testing"

func TestNetworkQualityHTTP3IsAdvertisedWhenIncluded(t *testing.T) {
	if !NetworkQualityHTTP3Available() {
		t.Fatal("QUIC build did not advertise HTTP/3")
	}
}
