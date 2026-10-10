package provider

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"

	P "github.com/ProjectClash/Clash/constant/provider"
)

func TestALowMemoryArtifactReadsBackToTheSameSet(t *testing.T) {
	var source strings.Builder
	for i := 0; i < 60000; i++ {
		fmt.Fprintf(&source, "+.host%d.example\nexact%d.example\n", i, i)
	}
	dump := func(artifact []byte) []string {
		strategy, err := rulesParse(artifact, newStrategy(P.Domain, nil), P.MrsRule)
		if err != nil {
			t.Fatal(err)
		}
		var keys []string
		strategy.(mrsRuleStrategy).DumpMrs(func(key string) bool { keys = append(keys, key); return true })
		slices.Sort(keys)
		return keys
	}
	var upstream bytes.Buffer
	if err := ConvertToMrs([]byte(source.String()), P.Domain, P.TextRule, &upstream); err != nil {
		t.Fatal(err)
	}
	previous := lowMemoryMrsEncoder.Load()
	UseLowMemoryMrsEncoder()
	t.Cleanup(func() { lowMemoryMrsEncoder.Store(previous) })
	var lean bytes.Buffer
	if err := ConvertToMrs([]byte(source.String()), P.Domain, P.TextRule, &lean); err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(lean.Bytes(), upstream.Bytes()) {
		t.Fatalf("the options did not reach the encoder")
	}
	if got, want := dump(lean.Bytes()), dump(upstream.Bytes()); !slices.Equal(got, want) || len(got) != 120000 {
		t.Fatalf("the low-memory artifact reads back to %d keys, upstream's to %d", len(got), len(want))
	}
}
