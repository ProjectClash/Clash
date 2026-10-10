package clash

import (
	"testing"

	"github.com/ProjectClash/Clash/config"
	P "github.com/ProjectClash/Clash/constant/provider"
)

type fakeRuleProvider struct {
	P.RuleProvider
	vehicle P.VehicleType
}

func (f *fakeRuleProvider) Name() string               { return "remote-rules" }
func (f *fakeRuleProvider) VehicleType() P.VehicleType { return f.vehicle }

type fakeProxyProvider struct {
	P.ProxyProvider
	vehicle P.VehicleType
}

func (f *fakeProxyProvider) Name() string               { return "remote-proxies" }
func (f *fakeProxyProvider) VehicleType() P.VehicleType { return f.vehicle }

func TestValidateProvidersAcceptsRemote(t *testing.T) {
	http := &config.Config{
		DNS:           &config.DNS{Enable: false},
		RuleProviders: map[string]P.RuleProvider{"remote-rules": &fakeRuleProvider{vehicle: P.HTTP}},
	}
	if err := validateForIOS(http, false); err != nil {
		t.Fatalf("remote provider must pass validation now, got %v", err)
	}

	file := &config.Config{
		DNS:           &config.DNS{Enable: false},
		RuleProviders: map[string]P.RuleProvider{"local-rules": &fakeRuleProvider{vehicle: P.File}},
	}
	if err := validateForIOS(file, false); err != nil {
		t.Fatalf("file provider should pass: %v", err)
	}
}
