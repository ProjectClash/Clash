package common

import (
	"testing"

	"github.com/ProjectClash/Clash/component/geodata"
)

func TestUnknownCountryIsNoCountryAtAll(t *testing.T) {
	for codes, want := range map[*[]string]bool{
		{}:                      true,
		{"private"}:             true,
		{""}:                    true,
		{"cn"}:                  false,
		{"private", "us"}:       false,
		{"telegram", "private"}: false,
	} {
		if got := unknownCountry(*codes); got != want {
			t.Errorf("%v: %v, want %v", *codes, got, want)
		}
	}
}

func TestGEOIPUnknownIsRefusedUnderGeodataMode(t *testing.T) {
	previous := geodata.GeodataMode()
	geodata.SetGeodataMode(true)
	t.Cleanup(func() { geodata.SetGeodataMode(previous) })
	if _, err := NewGEOIP("UNKNOWN", "P", false, true); err == nil {
		t.Fatal("GEOIP,UNKNOWN was accepted under geodata-mode, where nothing can answer it")
	}
}
