package main

import (
	"strings"
	"testing"
)


func sliceNames(plans []appleSlicePlan) []string {
	names := make([]string, 0, len(plans))
	for _, plan := range plans {
		names = append(names, plan.name)
	}
	return names
}

func TestSelectAppleSlices(t *testing.T) {
	plans := appleSerialBuildPlan()
	full := strings.Join(sliceNames(plans), ",")

	cases := []struct {
		name    string
		request string
		want    string
		why     string
	}{
		{
			name:    "empty means everything",
			request: "",
			want:    full,
			why:     "the default must stay the complete release artifact",
		},
		{
			name:    "whitespace only is still everything",
			request: "   ",
			want:    full,
			why:     "an empty variable expanded by make must not silently narrow the artifact",
		},
		{
			name:    "the ios group expands to device plus simulator",
			request: "ios",
			want:    "ios-device,ios-simulator",
			why:     "an iOS artifact without the simulator slice cannot be built against in Xcode",
		},
		{
			name:    "the macos group is a single slice",
			request: "macos",
			want:    "macos",
			why:     "the macOS slice is already universal (arm64 + amd64)",
		},
		{
			name:    "groups combine",
			request: "ios,macos",
			want:    "ios-device,ios-simulator,macos",
			why:     "the Apple family delivery needs both platforms in one artifact",
		},
		{
			name:    "explicit slice names work alongside groups",
			request: "macos,ios-device",
			want:    "ios-device,macos",
			why:     "plan order is preserved so a partial artifact assembles like the full one",
		},
		{
			name:    "duplicates collapse",
			request: "ios,ios-device,ios",
			want:    "ios-device,ios-simulator",
			why:     "a repeated slice must not be built twice",
		},
		{
			name:    "surrounding whitespace is tolerated",
			request: " macos , ios-device ",
			want:    "ios-device,macos",
			why:     "make and shell quoting routinely leave spaces",
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			selected, err := selectAppleSlices(testCase.request, plans)
			if err != nil {
				t.Fatalf("selectAppleSlices(%q) failed: %v — %s", testCase.request, err, testCase.why)
			}
			if got := strings.Join(sliceNames(selected), ","); got != testCase.want {
				t.Fatalf("selectAppleSlices(%q) = %s, want %s — %s",
					testCase.request, got, testCase.want, testCase.why)
			}
		})
	}
}

func TestSelectAppleSlicesRejectsUnknownNames(t *testing.T) {
	plans := appleSerialBuildPlan()

	for _, request := range []string{
		"iOS",
		"ios-sim",
		"macos-device",
		"watchos",
		"ios,tvos-arm64",
	} {
		t.Run(request, func(t *testing.T) {
			selected, err := selectAppleSlices(request, plans)
			if err == nil {
				t.Fatalf("selectAppleSlices(%q) accepted an unknown name and selected %v; a typo "+
					"has to fail the build, because a partial xcframework still looks valid and "+
					"only breaks at the consumer", request, sliceNames(selected))
			}
			for _, expected := range []string{"macos", "ios-device"} {
				if !strings.Contains(err.Error(), expected) {
					t.Fatalf("error %q does not mention the valid name %q", err, expected)
				}
			}
		})
	}
}

func TestAppleSliceGroupsCoverEveryPlan(t *testing.T) {
	covered := make(map[string]bool)
	for _, names := range appleSliceGroups() {
		for _, name := range names {
			covered[name] = true
		}
	}
	for _, plan := range appleSerialBuildPlan() {
		if !covered[plan.name] {
			t.Fatalf("slice %q belongs to no group, so asking for every group would miss it; "+
				"add it to appleSliceGroups", plan.name)
		}
	}
}

func TestASharedNameMeansTheSameThing(t *testing.T) {
	groups := appleSliceGroups()
	for _, plan := range appleSerialBuildPlan() {
		expansion, shared := groups[plan.name]
		if !shared {
			continue
		}
		if len(expansion) != 1 || expansion[0] != plan.name {
			t.Fatalf("%q is both a slice and a group, and the group now expands to %v instead of "+
				"just itself. Groups resolve first, so %q can no longer select that one slice — "+
				"rename one of them.", plan.name, expansion, plan.name)
		}
	}
}
