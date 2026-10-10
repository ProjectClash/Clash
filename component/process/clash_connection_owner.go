package process

import (
	"net/netip"
	"sync/atomic"
)

type ConnectionOwnerResolver func(network string, srcIP netip.Addr, srcPort int, dstIP netip.Addr, dstPort int) (uid uint32, path string, err error)

var connectionOwnerResolver atomic.Pointer[ConnectionOwnerResolver]

func SetConnectionOwnerResolver(resolver ConnectionOwnerResolver) {
	if resolver == nil {
		connectionOwnerResolver.Store(nil)
		return
	}
	connectionOwnerResolver.Store(&resolver)
}

func FindConnectionOwner(network string, srcIP netip.Addr, srcPort int, dstIP netip.Addr, dstPort int) (uint32, string, error) {
	if resolver := connectionOwnerResolver.Load(); resolver != nil {
		if uid, path, err := (*resolver)(network, srcIP, srcPort, dstIP, dstPort); err == nil && path != "" {
			return uid, path, nil
		}
	}
	return findProcessName(network, srcIP, srcPort)
}
