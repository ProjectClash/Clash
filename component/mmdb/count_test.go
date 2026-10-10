package mmdb

import "testing"

func TestNetworkCountsCountEachNetworkOnceUnderEveryCodeItCarries(t *testing.T) {
	for _, c := range []struct {
		fixture string
		want    map[string]int
	}{
		{"country-a.mmdb", map[string]int{"aa": 1}},
		{"metav0-mixed-record.mmdb", map[string]int{"us": 1}},
	} {
		t.Run(c.fixture, func(t *testing.T) {
			p, _ := newTestPublisher(t)
			if err := p.Publish(fixture(t, c.fixture)); err != nil {
				t.Fatal(err)
			}
			got, ok := IPReader{holder: p.holder}.NetworkCounts()
			if !ok {
				t.Fatal("a published database should answer")
			}
			if len(got) != len(c.want) {
				t.Fatalf("counts = %v, want %v", got, c.want)
			}
			for code, n := range c.want {
				if got[code] != n {
					t.Fatalf("counts = %v, want %v", got, c.want)
				}
			}
		})
	}
}

func TestNetworkCountsWithoutADatabaseSayNothing(t *testing.T) {
	if _, ok := (IPReader{}).NetworkCounts(); ok {
		t.Fatal("no database must not answer, not even with zeros")
	}
	p, _ := newTestPublisher(t)
	if _, ok := (IPReader{holder: p.holder}).NetworkCounts(); ok {
		t.Fatal("an empty holder must not answer")
	}
}

func TestNetworkCountsFollowAPublish(t *testing.T) {
	p, _ := newTestPublisher(t)
	if err := p.Publish(fixture(t, "country-a.mmdb")); err != nil {
		t.Fatal(err)
	}
	reader := IPReader{holder: p.holder}
	if got, _ := reader.NetworkCounts(); got["aa"] != 1 {
		t.Fatalf("before: %v", got)
	}
	if err := p.Publish(fixture(t, "country-b.mmdb")); err != nil {
		t.Fatal(err)
	}
	got, _ := reader.NetworkCounts()
	if got["aa"] != 0 || got["bb"] != 1 {
		t.Fatalf("after the publish the counts should be B's: %v", got)
	}
}

func TestASNNetworkCountsAreKeyedByTheNumberALookupReports(t *testing.T) {
	for _, c := range []struct {
		fixture string
		want    map[string]int
	}{
		{"asn-a.mmdb", map[string]int{"64500": 1}},
		{"asn-b.mmdb", map[string]int{"64501": 1}},
		{"ipinfo-short-asn.mmdb", map[string]int{}},
	} {
		t.Run(c.fixture, func(t *testing.T) {
			p, _ := newTestPublisher(t)
			if err := p.Publish(fixture(t, c.fixture)); err != nil {
				t.Fatal(err)
			}
			got, ok := ASNReader{holder: p.holder}.NetworkCounts()
			if !ok {
				t.Fatal("a published database should answer")
			}
			if len(got) != len(c.want) {
				t.Fatalf("counts = %v, want %v", got, c.want)
			}
			for asn, n := range c.want {
				if got[asn] != n {
					t.Fatalf("counts = %v, want %v", got, c.want)
				}
			}
		})
	}
	if _, ok := (ASNReader{}).NetworkCounts(); ok {
		t.Fatal("no database must not answer")
	}
}

func TestASNNetworkCountsOfAnUnreadableTypeSayNothing(t *testing.T) {
	p, _ := newTestPublisher(t)
	if err := p.Publish(fixture(t, "country-a.mmdb")); err != nil {
		t.Fatal(err)
	}
	if got, ok := (ASNReader{holder: p.holder}).NetworkCounts(); ok {
		t.Fatalf("a GeoLite2-Country database must not answer as ASN counts: %v", got)
	}
}
