package clash

import (
	"github.com/ProjectClash/Clash/listener/inner"
	"testing"
)

func TestIndependentInternalInboundsAfterCoreShutdown(t *testing.T) {
	old := inner.GetTunnel()
	inner.CloseTCPConnections()
	defer inner.New(old)
	t.Run("Reality", TestControlledRealityInterop)
	t.Run("Hysteria2Realm", TestControlledHysteria2RealmInterop)
}
