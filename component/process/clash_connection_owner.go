package process

import (
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"
)

type ConnectionOwnerResolver func(network string, srcIP netip.Addr, srcPort int, dstIP netip.Addr, dstPort int) (uid uint32, path string, err error)

var connectionOwnerResolver atomic.Pointer[ConnectionOwnerResolver]

var ErrOwnerResolverIsFinal = errors.New("process: the resolver is the only lookup that can see this socket")

var ownLookup = findProcessName

func SetConnectionOwnerResolver(resolver ConnectionOwnerResolver) {
	if resolver == nil {
		connectionOwnerResolver.Store(nil)
		return
	}
	connectionOwnerResolver.Store(&resolver)
}

func FindConnectionOwner(network string, srcIP netip.Addr, srcPort int, dstIP netip.Addr, dstPort int) (uint32, string, error) {
	if resolver := connectionOwnerResolver.Load(); resolver != nil {
		uid, path, err := (*resolver)(network, srcIP, srcPort, dstIP, dstPort)
		if err == nil && path != "" {
			return uid, path, nil
		}
		if errors.Is(err, ErrOwnerResolverIsFinal) {
			return 0, "", fmt.Errorf("%w: %w", ErrNotFound, err)
		}
	}
	return ownLookup(network, srcIP, srcPort)
}
