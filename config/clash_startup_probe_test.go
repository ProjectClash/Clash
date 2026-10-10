package config_test

import (
	"slices"
	"testing"

	"github.com/ProjectClash/Clash/config"
	_ "github.com/ProjectClash/Clash/hub/executor"
)

func TestTheNodeListAnnouncesItselfAndItsSizeBeforeItIsBuilt(t *testing.T) {
	raw, err := config.UnmarshalRawConfig([]byte(`
proxies:
  - {name: a, type: socks5, server: 127.0.0.1, port: 1}
  - {name: b, type: socks5, server: 127.0.0.1, port: 2}
  - {name: c, type: socks5, server: 127.0.0.1, port: 3}
`))
	if err != nil {
		t.Fatal(err)
	}
	var sections []string
	config.StartupProbe = func(section string) { sections = append(sections, section) }
	t.Cleanup(func() { config.StartupProbe = nil })

	if _, err := config.ParseRawConfig(raw); err != nil {
		t.Fatal(err)
	}

	begin := slices.Index(sections, "proxies-begin:3")
	done := slices.Index(sections, "proxies")
	if begin < 0 || done < 0 || begin > done {
		t.Fatalf("sections = %v; want \"proxies-begin:3\" reported before \"proxies\"", sections)
	}
	if tls := slices.Index(sections, "tls"); tls < 0 || tls > begin {
		t.Fatalf("sections = %v; the announcement belongs after \"tls\", immediately before the build", sections)
	}
}
