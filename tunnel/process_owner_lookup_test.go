package tunnel

import (
	"runtime"
	"testing"

	"github.com/ProjectClash/Clash/constant/features"
)

func TestOnlyAnAndroidHostSuppliesPackageNames(t *testing.T) {
	for _, testCase := range []struct {
		name string
		cmfa bool
		goos string
		want bool
	}{
		{name: "ClashMetaForAndroid", cmfa: true, goos: "android", want: true},
		{name: "Apple framework (macOS)", cmfa: true, goos: "darwin", want: false},
		{name: "Apple framework (iOS names itself darwin)", cmfa: true, goos: "ios", want: false},
		{name: "mihomo CLI on Android", cmfa: false, goos: "android", want: false},
		{name: "mihomo CLI on macOS", cmfa: false, goos: "darwin", want: false},
		{name: "mihomo CLI on Linux", cmfa: false, goos: "linux", want: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := ownerLookupUsesPackageName(testCase.cmfa, testCase.goos); got != testCase.want {
				t.Fatalf("ownerLookupUsesPackageName(cmfa=%v, goos=%q) = %v, want %v",
					testCase.cmfa, testCase.goos, got, testCase.want)
			}
		})
	}
}

func TestThisBuildAsksThePredicateRatherThanTheTagDirectly(t *testing.T) {
	want := ownerLookupUsesPackageName(features.CMFA, runtime.GOOS)
	if resolvesOwnerByPackageName != want {
		t.Fatalf("resolvesOwnerByPackageName = %v for cmfa=%v goos=%q, want %v",
			resolvesOwnerByPackageName, features.CMFA, runtime.GOOS, want)
	}
}
