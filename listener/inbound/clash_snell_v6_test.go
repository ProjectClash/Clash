package inbound_test

import (
	"testing"

	"github.com/ProjectClash/Clash/adapter/outbound"
	snelllistener "github.com/ProjectClash/Clash/listener/snell"
)

func skipWithoutSnellV6(t *testing.T) {
	t.Helper()
	if outbound.NewSnellV6Client == nil || snelllistener.NewV6ConnHandler == nil {
		t.Skip("snell version 6 is linked by the binding, not by this module")
	}
}
