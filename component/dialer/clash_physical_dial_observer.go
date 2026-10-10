package dialer

import (
	"context"
	"strings"
	"sync/atomic"
)

type PhysicalDialEvent uint8

const (
	PhysicalDialStarted PhysicalDialEvent = iota
	PhysicalDialSucceeded
	PhysicalDialFailed
)

const (
	DialKindDirect = "direct"
	DialKindProxy  = "proxy"
	DialKindResolver = "resolver"
	DialKindProbe = "probe"
)

type dialKindKey struct{}

type connectKey struct{}

var connectSerial atomic.Uint64

func withConnect(ctx context.Context) context.Context {
	return context.WithValue(ctx, connectKey{}, connectSerial.Add(1))
}

func ConnectOf(ctx context.Context) uint64 {
	serial, _ := ctx.Value(connectKey{}).(uint64)
	return serial
}

func WithDialKind(ctx context.Context, kind string) context.Context {
	return context.WithValue(ctx, dialKindKey{}, kind)
}

func DialKindOf(ctx context.Context) string {
	kind, _ := ctx.Value(dialKindKey{}).(string)
	return kind
}

var physicalDialObserver atomic.Pointer[func(kind, network, address string, connect uint64, event PhysicalDialEvent, err error)]

func SetPhysicalDialObserver(observe func(kind, network, address string, connect uint64, event PhysicalDialEvent, err error)) {
	if observe == nil {
		physicalDialObserver.Store(nil)
		return
	}
	physicalDialObserver.Store(&observe)
}

func ObserveResolverQuestion(endpoint string, event PhysicalDialEvent, err error) {
	if observe := physicalDialObserver.Load(); observe != nil {
		(*observe)(DialKindResolver, "udp", endpoint, 0, event, err)
	}
}

func observePhysicalDial(ctx context.Context, network, address string, event PhysicalDialEvent, err error) {
	observe := physicalDialObserver.Load()
	if observe == nil || !strings.HasPrefix(network, "tcp") {
		return
	}
	(*observe)(DialKindOf(ctx), network, address, ConnectOf(ctx), event, err)
}
