package sniffer

import C "github.com/ProjectClash/Clash/constant"

func (sd *Dispatcher) ReadsPastDnsMapping(metadata *C.Metadata) bool {
	if !sd.Enable() || metadata.Host == "" || metadata.DNSMode != C.DNSMapping {
		return false
	}
	if !sd.shouldOverride(metadata) || sd.forceSniff(metadata) {
		return false
	}
	if count, ok := sd.skipList.Get(metadata.AddrPort()); ok && count > 5 {
		return false
	}
	for _, current := range sd.sniffers {
		if current.supportsNetwork(C.TCP) && current.SupportPort(metadata.DstPort) {
			return true
		}
	}
	return false
}
