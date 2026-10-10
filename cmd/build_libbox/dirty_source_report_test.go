package main

import (
	"reflect"
	"testing"
)

func TestDirtySourceEntriesNamesEveryPathGitReported(t *testing.T) {
	for name, testCase := range map[string]struct {
		status string
		want   []string
	}{
		"clean tree reports nothing": {
			status: "",
			want:   nil,
		},
		"whitespace only is still clean": {
			status: "\n  \n",
			want:   nil,
		},
		"untracked build output is named, not just counted": {
			status: "?? .derived-macos/\n?? .derived-ios/\n",
			want:   []string{"?? .derived-macos/", "?? .derived-ios/"},
		},
		"modified sources are named too": {
			status: " M bind/clash/service.go\n?? bind/clash/scratch.go\n",
			want:   []string{"M bind/clash/service.go", "?? bind/clash/scratch.go"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			got := dirtySourceEntries([]byte(testCase.status))
			if !reflect.DeepEqual(got, testCase.want) {
				t.Errorf("dirtySourceEntries(%q) = %#v, want %#v", testCase.status, got, testCase.want)
			}
		})
	}
}

func TestDirtyFlagAndReportCannotDisagree(t *testing.T) {
	for _, status := range []string{"", "\n", "?? .derived/\n", " M a.go\n?? b.go\n"} {
		entries := dirtySourceEntries([]byte(status))
		dirty := len(entries) != 0
		if dirty != (len(entries) > 0) {
			t.Fatalf("status %q: flag %v, entries %v", status, dirty, entries)
		}
	}
}
