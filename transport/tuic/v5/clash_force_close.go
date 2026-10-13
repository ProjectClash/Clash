package v5

import "github.com/ProjectClash/Clash/transport/tuic/types"

func (t *clientImpl) ForceClose() {
	t.closed.Store(true)
	t.forceClose(nil, types.ClientClosed)
}
