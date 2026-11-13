package clash

import (
	"github.com/ProjectClash/Clash/adapter/outbound"
	mieru "github.com/enfein/mieru/v3/pkg/protocol"
)

const tunnelMieruStreamReceiveLimit = 256 << 10

func applyMieruTunnelBounds(profile runtimeProfile) {
	tunnel := profile.inheritsIOSPacketTunnelBehavior()
	limit := int64(0)
	if tunnel {
		limit = tunnelMieruStreamReceiveLimit
	}
	mieru.SetStreamReceiveByteLimit(limit)
	mieru.SetClientSkipsReplayCache(tunnel)
	mieru.SetReleaseOnApplicationClose(tunnel)
	outbound.SetMieruTunnelMultiplexingOff(tunnel)
	mieru.SetPacketRepairs(true)
}
