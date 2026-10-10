package tunnel

import (
	C "github.com/ProjectClash/Clash/constant"
)

func (t tunnel) WouldDialPhysically(metadata *C.Metadata) bool { return WouldDialPhysically(metadata) }

func WouldDialPhysically(metadata *C.Metadata) bool {
	flow := metadata.Clone()
	if err := preHandleMetadata(flow); err != nil {
		return false
	}
	proxy, _, err := resolveMetadata(flow)
	if err != nil {
		return false
	}
	for adapter := proxy; adapter != nil; adapter = adapter.Unwrap(flow, false) {
		if adapter.Type() == C.Direct {
			return true
		}
	}
	return false
}
