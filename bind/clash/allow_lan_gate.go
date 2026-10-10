package clash

import "sync/atomic"

var allowLanForcedOff atomic.Bool

func SetAllowLanPermitted(permitted bool) {
	allowLanForcedOff.Store(!permitted)
}

func AllowLanPermitted() bool {
	return !allowLanForcedOff.Load()
}
