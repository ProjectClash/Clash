package provider

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/ProjectClash/Clash/component/cidr"
	"github.com/ProjectClash/Clash/component/geodata/compiled"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
)

func TestCompiledGeoIPArtifactIsReadableAsARuleSet(t *testing.T) {
	set := cidr.NewIpCidrSet()
	for _, prefix := range []string{"1.1.1.0/24", "8.8.8.0/24", "2001:db8::/32"} {
		if err := set.AddIpCidr(netip.MustParsePrefix(prefix)); err != nil {
			t.Fatal(err)
		}
	}
	if err := set.Merge(); err != nil {
		t.Fatal(err)
	}

	var artifact bytes.Buffer
	if err := compiled.WriteIPCIDR(&artifact, set, 3); err != nil {
		t.Fatal(err)
	}

	strategy, err := rulesMrsParse(artifact.Bytes(), newStrategy(P.IPCIDR, nil))
	if err != nil {
		t.Fatalf("the rule set reader refused a compiled country: %v", err)
	}
	if strategy.Count() != 3 {
		t.Fatalf("count = %d, want 3", strategy.Count())
	}
	matches := func(address string) bool {
		return strategy.Match(&C.Metadata{DstIP: netip.MustParseAddr(address)}, C.RuleMatchHelper{})
	}
	for _, hit := range []string{"1.1.1.1", "8.8.8.8", "2001:db8::1"} {
		if !matches(hit) {
			t.Fatalf("the rule set does not match %s", hit)
		}
	}
	if matches("9.9.9.9") {
		t.Fatal("the rule set matches an address it was not given")
	}
}
