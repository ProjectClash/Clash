package statistic

import (
	"sync/atomic"

	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/log"
)


type egressTyped interface {
	EgressType() C.AdapterType
	Chains() C.Chain
}

func BucketForAdapterType(adapterType C.AdapterType) OutboundBucket {
	switch adapterType {
	case C.Direct, C.Compatible, C.Pass, C.Dns:
		return BucketDirect
	case C.Reject, C.RejectDrop:
		return BucketReject
	default:
		return BucketProxy
	}
}

var egressFallbackSaid atomic.Bool

const maxEgressUnwrap = 8

func BucketForConnection(conn C.Connection) OutboundBucket {
	finalOutbound := conn.Chains().Last()
	var layer any = conn
	for depth := 0; depth < maxEgressUnwrap; depth++ {
		if typed, ok := layer.(egressTyped); ok {
			if typed.Chains().Last() == finalOutbound {
				return BucketForAdapterType(typed.EgressType())
			}
			break
		}
		upstream, ok := layer.(interface{ Upstream() any })
		if !ok {
			break
		}
		layer = upstream.Upstream()
	}
	if _, reserved := reservedOutboundBuckets[finalOutbound]; !reserved && egressFallbackSaid.CompareAndSwap(false, true) {
		log.Debugln("[Statistic] %s is counted by name: its connection (%T) does not reach the outbound it left through", finalOutbound, conn)
	}
	return BucketForOutbound(finalOutbound)
}

func (m *Manager) PushUploadedInto(bucket OutboundBucket, size int64) {
	m.pushUploaded(bucket, size)
}

func (m *Manager) PushDownloadedInto(bucket OutboundBucket, size int64) {
	m.pushDownloaded(bucket, size)
}
