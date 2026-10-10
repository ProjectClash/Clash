package clash

import (
	"net"
	"net/netip"
)

type StringIterator interface {
	Len() int32
	HasNext() bool
	Next() string
}

type RoutePrefix struct {
	address netip.Addr
	prefix  int
}

func newRoutePrefix(p netip.Prefix) *RoutePrefix {
	return &RoutePrefix{address: p.Addr(), prefix: p.Bits()}
}

func (p *RoutePrefix) Address() string {
	return bridgeSafeString(p.address.String())
}

func (p *RoutePrefix) Prefix() int32 {
	return int32(p.prefix)
}

func (p *RoutePrefix) Mask() string {
	bits := 32
	if p.address.Is6() {
		bits = 128
	}
	return bridgeSafeString(net.IP(net.CIDRMask(p.prefix, bits)).String())
}

func (p *RoutePrefix) String() string {
	if p == nil {
		return ""
	}
	return bridgeSafeString(netip.PrefixFrom(p.address, p.prefix).String())
}

type RoutePrefixIterator interface {
	Len() int32
	HasNext() bool
	Next() *RoutePrefix
}

type NetworkInterface struct {
	Index     int32
	MTU       int32
	Name      string
	Addresses StringIterator
	Flags     int32
	Type      int32
	Metered   bool
}

type NetworkInterfaceIterator interface {
	Len() int32
	HasNext() bool
	Next() *NetworkInterface
}

type StringBox struct {
	Value string
}

func WrapString(value string) *StringBox {
	return &StringBox{Value: bridgeSafeString(value)}
}

type iterator[T any] struct {
	values []T
}

func (i *iterator[T]) Len() int32 {
	return int32(len(i.values))
}

func (i *iterator[T]) HasNext() bool {
	return len(i.values) > 0
}

func (i *iterator[T]) Next() T {
	if len(i.values) == 0 {
		var zero T
		return zero
	}
	next := i.values[0]
	i.values = i.values[1:]
	return next
}

func newStringIterator(values []string) StringIterator {
	return &iterator[string]{values}
}

func newRoutePrefixIterator(values []*RoutePrefix) RoutePrefixIterator {
	return &iterator[*RoutePrefix]{values}
}

func mapRoutePrefix(prefixes []netip.Prefix) RoutePrefixIterator {
	out := make([]*RoutePrefix, 0, len(prefixes))
	for _, p := range prefixes {
		out = append(out, newRoutePrefix(p))
	}
	return newRoutePrefixIterator(out)
}

func newNetworkInterfaceIterator(values []*NetworkInterface) NetworkInterfaceIterator {
	return &iterator[*NetworkInterface]{values}
}
