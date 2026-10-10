package clash

import (
	"errors"
	"net/netip"
	"sync/atomic"

	"github.com/ProjectClash/Clash/component/process"
)

type ConnectionOwner struct {
	UserId      int32
	UserName    string
	ProcessPath string
}

type ConnectionOwnerResolver interface {
	FindConnectionOwner(ipProtocol int32, sourceAddress string, sourcePort int32, destinationAddress string, destinationPort int32) (*ConnectionOwner, error)
}

type ownerResolverBox struct{ resolver ConnectionOwnerResolver }

var platformOwnerResolver atomic.Pointer[ownerResolverBox]

var errNoOwner = errors.New("the platform found no owner")

func SetConnectionOwnerResolver(resolver ConnectionOwnerResolver) {
	if resolver == nil {
		platformOwnerResolver.Store(nil)
		return
	}
	if _, ok := resolver.(bridgeSafeOwnerResolverDecorator); !ok {
		resolver = bridgeSafeOwnerResolverDecorator{resolver}
	}
	platformOwnerResolver.Store(&ownerResolverBox{resolver})
}

type bridgeSafeOwnerResolverDecorator struct{ ConnectionOwnerResolver }

func (d bridgeSafeOwnerResolverDecorator) FindConnectionOwner(ipProtocol int32, sourceAddress string, sourcePort int32, destinationAddress string, destinationPort int32) (*ConnectionOwner, error) {
	return d.ConnectionOwnerResolver.FindConnectionOwner(ipProtocol, bridgeSafeString(sourceAddress), sourcePort, bridgeSafeString(destinationAddress), destinationPort)
}

func init() {
	process.SetConnectionOwnerResolver(askPlatformForConnectionOwner)
}

func askPlatformForConnectionOwner(network string, srcIP netip.Addr, srcPort int, dstIP netip.Addr, dstPort int) (uint32, string, error) {
	box := platformOwnerResolver.Load()
	if box == nil || currentRuntimeProfile() != runtimeProfileMacOSPacketTunnel {
		return 0, "", errNoOwner
	}
	ipProtocol := int32(6)
	if network == process.UDP {
		ipProtocol = 17
	}
	owner, err := box.resolver.FindConnectionOwner(ipProtocol, srcIP.String(), int32(srcPort), dstIP.String(), int32(dstPort))
	if err != nil {
		return 0, "", err
	}
	if owner == nil || owner.ProcessPath == "" {
		return 0, "", errNoOwner
	}
	return uint32(owner.UserId), owner.ProcessPath, nil
}
