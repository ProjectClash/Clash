package clash

import "github.com/ProjectClash/Clash/common/atomic"

var unscopedResolversArePhysical = atomic.NewBool(true)

func setUnscopedResolversArePhysical(value bool) {
	unscopedResolversArePhysical.Store(value)
}
