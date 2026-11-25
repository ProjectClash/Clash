package sniffer

import C "github.com/ProjectClash/Clash/constant"

func (sd *Dispatcher) ReadsTCP(metadata *C.Metadata) bool {
	if !sd.Enable() || !sd.shouldOverride(metadata) {
		return false
	}
	for _, current := range sd.sniffers {
		if current.supportsNetwork(C.TCP) && current.SupportPort(metadata.DstPort) {
			return true
		}
	}
	return false
}
