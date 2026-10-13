package clash

import (
	"fmt"
	"strings"
	"testing"
)

func TestTheAppInspectsARuleSetAsLargeAsItValidates(t *testing.T) {
	was := tunnelProcess.Load()
	tunnelProcess.Store(false)
	t.Cleanup(func() { tunnelProcess.Store(was) })
	var b strings.Builder
	lines := 0
	for b.Len() <= maximumProviderResourceBytes {
		fmt.Fprintf(&b, "d%07d.example.com\n", lines)
		lines++
	}
	payload := []byte(b.String())
	if err := ValidateProviderForIOS("rule", "domain", "text", payload); err != nil {
		t.Fatalf("validate: %v", err)
	}
	count, err := InspectProviderForIOS("rule", "domain", "text", payload)
	if err != nil || count != lines {
		t.Fatalf("inspect of %d bytes: %d, %v; want %d", len(payload), count, err, lines)
	}
	tunnelProcess.Store(true)
	if _, err := InspectProviderForIOS("rule", "domain", "text", payload); err == nil {
		t.Fatal("the tunnel inspected a payload over its limit")
	}
}
