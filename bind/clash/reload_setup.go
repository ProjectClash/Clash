package clash

import (
	"errors"
	"fmt"
	"runtime/debug"
)

const (
	minReloadSoftMemoryLimit = int64(16 << 20)
	maxReloadSoftMemoryLimit = int64(256 << 20)
	minReloadGCPercent       = 10
	maxReloadGCPercent       = 200
	minReloadLogMaxLines     = 100
	maxReloadLogMaxLines     = 5000
)

type RuntimeSetupOptions struct {
	SoftMemoryLimit int64
	GCPercent       int
	LogMaxLines     int

	BasePath           string
	WorkingPath        string
	TempPath           string
	TimeZone           string
	MaxProcs           int
	TunMTU             int
	ClashAPISocketPath string
	CoreIdentity       string
}

type runtimeSetupState struct {
	softMemoryLimit                int64
	softMemoryLimitIsPacingDefault bool
	gcPercent                      int
	logMaxLines                    int
}

var currentRuntimeSetup = runtimeSetupState{
	logMaxLines: defaultLogMaxLines,
}

func ReloadSetupOptions(options *RuntimeSetupOptions) error {
	setupMu.Lock()
	defer setupMu.Unlock()

	if !setupDone {
		return bridgeSafeError(errors.New("clash: ReloadSetupOptions before Setup"))
	}
	if options == nil {
		return bridgeSafeError(errors.New("clash: ReloadSetupOptions called with nil options"))
	}
	if err := validateRuntimeSetupOptions(options); err != nil {
		return bridgeSafeError(err)
	}

	if options.SoftMemoryLimit != 0 {
		debug.SetMemoryLimit(options.SoftMemoryLimit)
		currentRuntimeSetup.softMemoryLimit = options.SoftMemoryLimit
		currentRuntimeSetup.softMemoryLimitIsPacingDefault = false
		startPressureThresholdMonitor(machineBudgetForPacing(options.SoftMemoryLimit), pressureThresholdShedEnabled.Load())
	}
	if options.GCPercent != 0 {
		debug.SetGCPercent(options.GCPercent)
		currentRuntimeSetup.gcPercent = options.GCPercent
	}
	if options.LogMaxLines != 0 {
		recentLogs.setMax(options.LogMaxLines)
		currentRuntimeSetup.logMaxLines = options.LogMaxLines
	}
	return nil
}

func validateRuntimeSetupOptions(options *RuntimeSetupOptions) error {
	restartFields := []struct {
		name    string
		changed bool
	}{
		{"BasePath", options.BasePath != ""},
		{"WorkingPath", options.WorkingPath != ""},
		{"TempPath", options.TempPath != ""},
		{"TimeZone", options.TimeZone != ""},
		{"MaxProcs", options.MaxProcs != 0},
		{"TunMTU", options.TunMTU != 0},
		{"ClashAPISocketPath", options.ClashAPISocketPath != ""},
		{"CoreIdentity", options.CoreIdentity != ""},
	}
	for _, field := range restartFields {
		if field.changed {
			return fmt.Errorf("clash: changing %s requires restart", field.name)
		}
	}
	if value := options.SoftMemoryLimit; value != 0 &&
		(value < minReloadSoftMemoryLimit || value > maxReloadSoftMemoryLimit) {
		return fmt.Errorf(
			"clash: SoftMemoryLimit must be 0 (unchanged) or %d...%d bytes",
			minReloadSoftMemoryLimit,
			maxReloadSoftMemoryLimit,
		)
	}
	if value := options.GCPercent; value != 0 &&
		(value < minReloadGCPercent || value > maxReloadGCPercent) {
		return fmt.Errorf(
			"clash: GCPercent must be 0 (unchanged) or %d...%d",
			minReloadGCPercent,
			maxReloadGCPercent,
		)
	}
	if value := options.LogMaxLines; value != 0 &&
		(value < minReloadLogMaxLines || value > maxReloadLogMaxLines) {
		return fmt.Errorf(
			"clash: LogMaxLines must be 0 (unchanged) or %d...%d",
			minReloadLogMaxLines,
			maxReloadLogMaxLines,
		)
	}
	return nil
}

func runtimeSetupSnapshot() runtimeSetupState {
	setupMu.Lock()
	defer setupMu.Unlock()
	return currentRuntimeSetup
}
