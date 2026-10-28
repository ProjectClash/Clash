package outboundgroup

import "testing"

func TestGroupsWithOneFilterShareItsRegexp(t *testing.T) {
	option := GroupBaseOption{Name: "a", ExcludeFilter: `(?i)(群|返利|过期)` + "`" + `^MODULE-ENGINE$`, Filter: `(?i)(香港|HK)`}
	a := NewGroupBase(option)
	option.Name = "b"
	b := NewGroupBase(option)
	if len(a.excludeFilterRegs) != 2 || len(a.filterRegs) != 1 {
		t.Fatalf("parsed %d exclude-filters and %d filters, want 2 and 1", len(a.excludeFilterRegs), len(a.filterRegs))
	}
	for i := range a.excludeFilterRegs {
		if a.excludeFilterRegs[i] != b.excludeFilterRegs[i] {
			t.Fatalf("exclude-filter %d compiled once per group", i)
		}
	}
	if a.filterRegs[0] != b.filterRegs[0] {
		t.Fatal("the filter compiled once per group")
	}
}
