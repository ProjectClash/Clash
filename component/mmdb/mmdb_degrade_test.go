package mmdb

import (
	"net"
	"testing"
)

func TestLookupsSurviveAnUnavailableDatabase(t *testing.T) {
	var ip IPReader
	if codes := ip.LookupCode(net.ParseIP("198.51.100.1")); len(codes) != 0 {
		t.Fatalf("an unavailable database matched something: %v", codes)
	}

	var asn ASNReader
	if number, org := asn.LookupASN(net.ParseIP("198.51.100.1")); number != "" || org != "" {
		t.Fatalf("an unavailable ASN database matched: %q %q", number, org)
	}
}

func TestAnUnknownDatabaseTypeDoesNotPanic(t *testing.T) {
	reader := IPReader{reader: nil, databaseType: 99}
	if codes := reader.LookupCode(net.ParseIP("198.51.100.1")); len(codes) != 0 {
		t.Fatalf("unknown type matched: %v", codes)
	}
}
