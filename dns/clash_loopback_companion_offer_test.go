package dns

import (
	"github.com/ProjectClash/Clash/adapter/inbound"
	"testing"
)

func TestClashProductionListenConfigOffersCompanions(t *testing.T) {
	var lc interface{} = inbound.NewListenConfig()
	if _, ok := lc.(loopbackPacketCompanions); !ok {
		t.Fatalf("%T does not offer loopback companions", lc)
	}
}
