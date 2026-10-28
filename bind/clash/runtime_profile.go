package clash

import (
	"fmt"
	"strings"
	"sync/atomic"
)

const (
	RuntimeProfileIOSPacketTunnel   = "iosPacketTunnel"
	RuntimeProfileMacOSPacketTunnel = "macosPacketTunnel"
	RuntimeProfileMacOSApplication  = "macosApplication"
	RuntimeProfileTVOSPacketTunnel  = "tvosPacketTunnel"
)

type runtimeProfile uint32

const (
	runtimeProfileIOSPacketTunnel runtimeProfile = iota
	runtimeProfileMacOSPacketTunnel
	runtimeProfileMacOSApplication
	runtimeProfileTVOSPacketTunnel
)

var setupRuntimeProfile atomic.Uint32

type appleRuntimePolicy struct {
	profile                   runtimeProfile
	networkExtension          bool
	packetTunnel              bool
	trustedProcessMetadata    bool
	requirePacketTunnelDNS    bool
	memoryConservativeGeodata bool
	compiledGeoSiteOnly       bool
	compiledGeoIPOnly         bool
	useSystemDNS              bool
	repairPacketTunnelDNS     bool
	stripLoopbackResolvers    bool
	boundedDNSCache           bool
	releaseWhenQuiet          bool
	bindsUnixControlSocket    bool
}

func normalizeRuntimeProfile(value string) (runtimeProfile, error) {
	switch value {
	case "", RuntimeProfileIOSPacketTunnel:
		return runtimeProfileIOSPacketTunnel, nil
	case RuntimeProfileMacOSPacketTunnel:
		return runtimeProfileMacOSPacketTunnel, nil
	case RuntimeProfileMacOSApplication:
		return runtimeProfileMacOSApplication, nil
	case RuntimeProfileTVOSPacketTunnel:
		return runtimeProfileTVOSPacketTunnel, nil
	default:
		return runtimeProfileIOSPacketTunnel, fmt.Errorf(
			"clash: invalid SetupOptions.RuntimeProfile %q; expected %q, %q, %q or %q",
			value,
			RuntimeProfileIOSPacketTunnel,
			RuntimeProfileMacOSPacketTunnel,
			RuntimeProfileMacOSApplication,
			RuntimeProfileTVOSPacketTunnel,
		)
	}
}

func (profile runtimeProfile) inheritsIOSPacketTunnelBehavior() bool {
	return profile == runtimeProfileIOSPacketTunnel || profile == runtimeProfileTVOSPacketTunnel
}

func currentRuntimeProfile() runtimeProfile {
	return runtimeProfile(setupRuntimeProfile.Load())
}

func allRuntimeProfiles() []runtimeProfile {
	var profiles []runtimeProfile
	for value := runtimeProfile(0); ; value++ {
		if strings.HasPrefix(value.String(), "unknown(") {
			return profiles
		}
		profiles = append(profiles, value)
	}
}

type appleProcessMetadataCapability struct {
	processPath   bool
	socketUser    bool
	inboundUser   bool
	codeSignature bool
}

func (p appleRuntimePolicy) processMetadata() appleProcessMetadataCapability {
	if p.trustedProcessMetadata {
		return appleProcessMetadataCapability{
			processPath: true, socketUser: true, inboundUser: true, codeSignature: true,
		}
	}
	if p.profile == runtimeProfileMacOSPacketTunnel {
		return appleProcessMetadataCapability{processPath: true, socketUser: true}
	}
	return appleProcessMetadataCapability{}
}

func (c appleProcessMetadataCapability) resolves(kind string) bool {
	switch strings.ToUpper(strings.TrimSpace(kind)) {
	case "PROCESS-NAME", "PROCESS-NAME-REGEX", "PROCESS-NAME-WILDCARD",
		"PROCESS-PATH", "PROCESS-PATH-REGEX", "PROCESS-PATH-WILDCARD":
		return c.processPath
	case "UID":
		return c.socketUser
	case "IN-USER":
		return c.inboundUser
	case "SOURCE-APP-SIGNING-ID", "SOURCE-APP-TEAM-ID":
		return c.codeSignature
	default:
		return true
	}
}

func runtimePolicyFor(profile runtimeProfile, underNetworkExtension bool) appleRuntimePolicy {
	policy := appleRuntimePolicy{profile: profile}
	switch profile {
	case runtimeProfileTVOSPacketTunnel:
		policy.networkExtension = underNetworkExtension
		policy.packetTunnel = true
		policy.requirePacketTunnelDNS = underNetworkExtension
		policy.repairPacketTunnelDNS = underNetworkExtension
		policy.stripLoopbackResolvers = underNetworkExtension
		policy.boundedDNSCache = underNetworkExtension
		policy.releaseWhenQuiet = underNetworkExtension
		policy.memoryConservativeGeodata = true
		policy.compiledGeoSiteOnly = underNetworkExtension
		policy.compiledGeoIPOnly = underNetworkExtension
	case runtimeProfileIOSPacketTunnel:
		policy.bindsUnixControlSocket = true
		policy.networkExtension = underNetworkExtension
		policy.packetTunnel = true
		policy.requirePacketTunnelDNS = underNetworkExtension
		policy.repairPacketTunnelDNS = underNetworkExtension
		policy.stripLoopbackResolvers = underNetworkExtension
		policy.boundedDNSCache = underNetworkExtension
		policy.releaseWhenQuiet = underNetworkExtension
		policy.memoryConservativeGeodata = true
		policy.compiledGeoSiteOnly = underNetworkExtension
		policy.compiledGeoIPOnly = underNetworkExtension
	case runtimeProfileMacOSPacketTunnel:
		policy.bindsUnixControlSocket = true
		policy.networkExtension = underNetworkExtension
		policy.packetTunnel = true
		policy.requirePacketTunnelDNS = underNetworkExtension
		policy.repairPacketTunnelDNS = underNetworkExtension
	case runtimeProfileMacOSApplication:
		policy.bindsUnixControlSocket = true
		policy.trustedProcessMetadata = true
		policy.useSystemDNS = true
	}
	return policy
}

func currentRuntimePolicy(underNetworkExtension bool) appleRuntimePolicy {
	return runtimePolicyFor(currentRuntimeProfile(), underNetworkExtension)
}

func (profile runtimeProfile) String() string {
	switch profile {
	case runtimeProfileIOSPacketTunnel:
		return RuntimeProfileIOSPacketTunnel
	case runtimeProfileMacOSPacketTunnel:
		return RuntimeProfileMacOSPacketTunnel
	case runtimeProfileMacOSApplication:
		return RuntimeProfileMacOSApplication
	case runtimeProfileTVOSPacketTunnel:
		return RuntimeProfileTVOSPacketTunnel
	default:
		return fmt.Sprintf("unknown(%d)", profile)
	}
}
