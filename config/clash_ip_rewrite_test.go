package config

import (
	"strings"
	"testing"

	singtun "github.com/metacubex/sing-tun"
)

func TestIPRewriteLinesParseAsSurgeAndLoonWriteThem(t *testing.T) {
	raw, err := UnmarshalRawConfig([]byte("x-clash-ip-rewrite:\n  - 10.7.0.1 = reflect\n  - 203.0.113.0/24 = reject\n  - 2001:db8::/32 = DROP\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := ParseRawConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		prefix string
		action singtun.IPRewriteAction
	}{{"10.7.0.1/32", singtun.IPRewriteReflect}, {"203.0.113.0/24", singtun.IPRewriteReject}, {"2001:db8::/32", singtun.IPRewriteDrop}}
	if len(cfg.IPRewrite) != len(want) {
		t.Fatalf("parsed %v", cfg.IPRewrite)
	}
	for i, w := range want {
		if cfg.IPRewrite[i].Prefix.String() != w.prefix || cfg.IPRewrite[i].Action != w.action {
			t.Errorf("line %d parsed %v, want %s %d", i, cfg.IPRewrite[i], w.prefix, w.action)
		}
	}
	for _, line := range []string{"10.7.0.1 reflect", "10.7.0.1 = loop", "example.com = drop"} {
		raw, _ := UnmarshalRawConfig([]byte("x-clash-ip-rewrite:\n  - " + line + "\n"))
		if _, err := ParseRawConfig(raw); err == nil || !strings.Contains(err.Error(), "x-clash-ip-rewrite") {
			t.Errorf("%q: %v", line, err)
		}
	}
}

func TestIPRewriteHasALineCap(t *testing.T) {
	doc := "x-clash-ip-rewrite:\n" + strings.Repeat("  - 10.7.0.1 = reflect\n", maxIPRewriteLines+1)
	raw, err := UnmarshalRawConfig([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRawConfig(raw); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("%d lines: %v", maxIPRewriteLines+1, err)
	}
}
