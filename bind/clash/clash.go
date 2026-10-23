package clash

import (
	"errors"
	"fmt"
	"runtime"
	"runtime/debug"
	"time"

	"github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/constant/features"
)

const CommandSchemaVersion int32 = 2

const CommandSchemaMinVersion int32 = 1

func CheckCommandSchema(peerMin, peerCurrent int32) error {
	if peerMin <= 0 || peerCurrent < peerMin {
		return bridgeSafeError(errors.New("clash: invalid peer command schema range"))
	}
	if peerCurrent < CommandSchemaMinVersion || peerMin > CommandSchemaVersion {
		return bridgeSafeError(fmt.Errorf(
			"clash: incompatible command schema: local=%d...%d peer=%d...%d",
			CommandSchemaMinVersion, CommandSchemaVersion, peerMin, peerCurrent,
		))
	}
	return nil
}

func Version() string {
	return bridgeSafeString(constant.Version)
}

func GoVersion() string {
	return bridgeSafeString(runtime.Version() + ", " + runtime.GOOS + "/" + runtime.GOARCH)
}

func FreeMemory() {
	dropKeptParse()
	debug.FreeOSMemory()
}

func MemoryFootprint() int64 {
	return physFootprint()
}

func LowMemoryBuild() bool {
	return features.WithLowMemory
}

func TZProbe() string {
	now := clashLocalTime(time.Now())
	return bridgeSafeString(fmt.Sprintf("loc=%s offset=%s now=%s",
		now.Location().String(),
		now.Format("-07:00"),
		now.Format("2006-01-02 15:04:05")))
}
