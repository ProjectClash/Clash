package clash

import (
	"errors"
	"fmt"

	"github.com/ProjectClash/Clash/dns"
)

type AppPolicyOptions struct {
	IPQueryMode          string
	TunIPv6Mode          string
	SystemDNSServerLines string
}

func UpdateAppPolicy(options *AppPolicyOptions) error {
	return bridgeSafeError(recoverAppCallError("UpdateAppPolicy", func() error { return updateAppPolicy(options) }))
}

func updateAppPolicy(options *AppPolicyOptions) error {
	if options == nil {
		return errors.New("clash: UpdateAppPolicy called with nil options")
	}
	appParseMu.Lock()
	defer appParseMu.Unlock()
	setupMu.Lock()
	defer setupMu.Unlock()
	if !setupDone {
		return errors.New("clash: call Setup before UpdateAppPolicy")
	}
	stack, err := parseIPStackSettings(options.IPQueryMode, options.TunIPv6Mode)
	if err != nil {
		return err
	}
	if activeCoreCount.Load() > 0 && stack != currentIPStackSettings() {
		return errors.New("clash: changing IP Stack requires restart")
	}
	resolvers, err := parseSystemDNSServerLines(options.SystemDNSServerLines)
	if err != nil {
		return fmt.Errorf("clash: AppPolicyOptions.SystemDNSServerLines: %w", err)
	}
	setIPStackSettings(stack)
	systemDNSSubstitutes.Store(&resolvers)
	dns.SetSystemResolverDefaults(resolvers)
	return nil
}
