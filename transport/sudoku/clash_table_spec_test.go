package sudoku

import (
	"fmt"
	"testing"
)

func clashErrorText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestValidateClientTablePatternsMatchesTheBuilder(t *testing.T) {
	cases := []struct {
		tableType    string
		customTable  string
		customTables []string
	}{
		{"prefer_entropy", "", nil},
		{"prefer_ascii", "xxxxvvvv", nil},
		{"up_ascii_down_entropy", "xpxvvpvv", nil},
		{"prefer_entropy", "", []string{"xpxvvpvv", " vvpxxpvv "}},
		{"prefer_entropy", "xpxvvpvv", []string{""}},
		{"", "", nil},
		{"bogus", "", nil},
		{"up_ascii", "", nil},
		{"up_x_down_ascii", "", nil},
		{"prefer_entropy", "xxxxvvvv", nil},
		{"prefer_entropy", "xpxvvpv", nil},
		{"entropy", "xpxvvpvq", nil},
		{"prefer_entropy", "", []string{"xpxvvpvv", "bad"}},
		{"prefer_entropy", "", []string{"bad", "xpxvvpvv"}},
		{"up_ascii_down_entropy", "xxxxvvvv", nil},
		{"up_entropy_down_ascii", "", []string{"xxpp"}},
		{"bogus", "xxxxvvvv", []string{"bad"}},
	}
	var accepted int
	for _, tc := range cases {
		name := fmt.Sprintf("%q %q %q", tc.tableType, tc.customTable, tc.customTables)
		t.Run(name, func(t *testing.T) {
			_, buildErr := NewClientTablesWithCustomPatterns("seed", tc.tableType, tc.customTable, tc.customTables)
			validateErr := ValidateClientTablePatterns(tc.tableType, tc.customTable, tc.customTables)
			if got, want := clashErrorText(validateErr), clashErrorText(buildErr); got != want {
				t.Fatalf("validate answers %q, the builder %q", got, want)
			}
			if buildErr == nil {
				accepted++
			}
		})
	}
	if accepted == 0 || accepted == len(cases) {
		t.Fatalf("%d of %d settings build; the table no longer covers both answers", accepted, len(cases))
	}
}

func TestClientTablePatternsFollowTheBuilder(t *testing.T) {
	for _, tc := range []struct {
		customTable  string
		customTables []string
		want         string
	}{
		{"", nil, `[""]`},
		{" xpxvvpvv ", nil, `["xpxvvpvv"]`},
		{"xpxvvpvv", []string{"vvpxxpvv", " xpxvvpvv"}, `["vvpxxpvv" "xpxvvpvv"]`},
		{"   ", nil, `[""]`},
	} {
		patterns := ClientTablePatterns(tc.customTable, tc.customTables)
		if got := fmt.Sprintf("%q", patterns); got != tc.want {
			t.Errorf("ClientTablePatterns(%q, %q) = %s, want %s", tc.customTable, tc.customTables, got, tc.want)
		}
		tables, err := NewClientTablesWithCustomPatterns("seed", "prefer_entropy", tc.customTable, tc.customTables)
		if err != nil {
			t.Fatal(err)
		}
		if len(tables) != len(patterns) {
			t.Errorf("%d patterns for %d tables", len(patterns), len(tables))
		}
	}
}
