//go:build !no_zerotier

package outbound

func (z *ZeroTier) clashMakeFrameQueue() {
	if z.frameCh == nil {
		z.frameCh = make(chan zeroTierInboundFrame, zeroTierFrameQueueSize)
	}
}
