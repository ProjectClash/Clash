package clash

import (
	"runtime/debug"

	"github.com/ProjectClash/Clash/log"
)

const neJetsamBudgetBytes = 50 * 1024 * 1024

const nePacingSoftLimitBytes = neJetsamBudgetBytes * 3 / 4

func machineBudgetForPacing(pacing int64) int64 {
	return pacing * 4 / 3
}

var pacingBudgetedPlatform = buildIsNEBudgetedPlatform

func nePacingSoftLimit(budgetedPlatform, underNetworkExtension bool, existing int64) int64 {
	if existing > 0 || !underNetworkExtension || !budgetedPlatform {
		return 0
	}
	return nePacingSoftLimitBytes
}

const macPacketTunnelSoftLimitBytes = 1 << 30

func macPacingSoftLimit(profile runtimeProfile, existing int64) int64 {
	if existing > 0 || profile != runtimeProfileMacOSPacketTunnel {
		return 0
	}
	return macPacketTunnelSoftLimitBytes
}

func armNEPacingForService(platform PlatformInterface) {
	setupMu.Lock()
	existing := currentRuntimeSetup.softMemoryLimit
	if currentRuntimeSetup.softMemoryLimitIsPacingDefault {
		existing = 0
	}
	limit := nePacingSoftLimit(pacingBudgetedPlatform, platform.UnderNetworkExtension(), existing)
	if limit > 0 {
		debug.SetMemoryLimit(limit)
		currentRuntimeSetup.softMemoryLimit = limit
		currentRuntimeSetup.softMemoryLimitIsPacingDefault = true
	}
	macLimit := macPacingSoftLimit(currentRuntimeProfile(), existing)
	if macLimit > 0 {
		debug.SetMemoryLimit(macLimit)
	}
	machineLimit := int64(0)
	if soft := currentRuntimeSetup.softMemoryLimit; soft > 0 {
		machineLimit = machineBudgetForPacing(soft)
	}
	if limit > 0 {
		log.Infoln("[Memory] GC pacing armed: GOMEMLIMIT=%d (NE budget default; no explicit limit was configured)", limit)
	}
	if macLimit > 0 {
		log.Infoln("[Memory] GC pacing armed: GOMEMLIMIT=%d (macOS packet tunnel default; no explicit limit was configured)", macLimit)
	}
	startPressureThresholdMonitor(machineLimit, pressureThresholdShedEnabled.Load())
	setupMu.Unlock()

	armSessionRelease()
	armChosenFirst()

	if probeAdmissionShouldArm(pacingBudgetedPlatform, platform.UnderNetworkExtension()) {
		armProbeAdmission()
		log.Infoln("[Memory] probe admission armed: interactive=%d background=%d/%d/%d by node count", probeInteractiveCap,
			probeBackgroundCap(0), probeBackgroundCap(1000), probeBackgroundCap(10000))
	} else {
		disarmProbeAdmission()
	}
}
