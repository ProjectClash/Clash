package clash

import "sync/atomic"

var includeAllNetworksRequested atomic.Bool

func includeAllNetworksActive() bool {
	return includeAllNetworksRequested.Load()
}
