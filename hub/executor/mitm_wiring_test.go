package executor

// R1 regression: updateMITM must register the dispatcher with the component
// store the hot path actually reads (mitm.ActiveDispatcher). The original
// defect stored into a tunnel-local write-only variable, leaving MITM dead
// in production while every direct-InnerHandle test stayed green.

import (
	"testing"

	"github.com/ProjectClash/Clash/component/mitm"
)

func TestFixUpdateMITMRegistersActiveDispatcher(t *testing.T) {
	t.Cleanup(func() { mitm.UpdateMITM(nil) })

	cfg := &mitm.Config{
		Enable:    true,
		HostGates: []string{"wired.test"},
		RewritePolicies: []mitm.RewritePolicy{
			{URLPattern: "wired.test/"},
		},
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatalf("normalize: %v", err)
	}
	updateMITM(cfg, nil)

	d := mitm.ActiveDispatcher()
	if d == nil {
		t.Fatal("updateMITM did not register the dispatcher with mitm.ActiveDispatcher — the hot path would never intercept")
	}
	if !d.Enable() {
		t.Fatal("registered dispatcher is not enabled")
	}
	// And the disable path clears it.
	updateMITM(nil, nil)
	if d := mitm.ActiveDispatcher(); d != nil && d.Enable() {
		t.Fatal("updateMITM(nil) did not disable the active dispatcher")
	}
}
