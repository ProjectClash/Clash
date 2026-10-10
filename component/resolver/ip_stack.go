package resolver

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync/atomic"

	"github.com/metacubex/randv2"
)

type IPQueryPolicy uint32

const (
	IPQueryLegacy IPQueryPolicy = iota
	IPQueryIPv4Only
	IPQueryDualStack
	IPQueryPreferIPv4
	IPQueryPreferIPv6
	IPQueryIPv6Only
)

var startupIPQueryPolicy atomic.Uint32

func CurrentIPQueryPolicy() IPQueryPolicy { return IPQueryPolicy(startupIPQueryPolicy.Load()) }
func SetIPQueryPolicy(p IPQueryPolicy)    { startupIPQueryPolicy.Store(uint32(p)) }
func (p IPQueryPolicy) String() string {
	switch p {
	case IPQueryLegacy:
		return ""
	case IPQueryIPv4Only:
		return "ipv4-only"
	case IPQueryDualStack:
		return "dual-stack"
	case IPQueryPreferIPv4:
		return "prefer-ipv4"
	case IPQueryPreferIPv6:
		return "prefer-ipv6"
	case IPQueryIPv6Only:
		return "ipv6-only"
	}
	return "invalid"
}
func ParseIPQueryPolicy(value string) (IPQueryPolicy, error) {
	for p := IPQueryLegacy; p <= IPQueryIPv6Only; p++ {
		if p.String() == value {
			return p, nil
		}
	}
	return IPQueryLegacy, fmt.Errorf("unknown IP query mode %q", value)
}
func (p IPQueryPolicy) AllowsAddress(ip netip.Addr) bool {
	if !ip.IsValid() {
		return true
	}
	ip = ip.Unmap()
	return (p != IPQueryIPv4Only || ip.Is4()) && (p != IPQueryIPv6Only || ip.Is6())
}
func (p IPQueryPolicy) AllowsQueryType(qtype uint16) bool {
	return !(p == IPQueryIPv4Only && qtype == 28) && !(p == IPQueryIPv6Only && qtype == 1)
}

type familyAnswer struct {
	ips  []netip.Addr
	err  error
	ipv4 bool
}

func LookupIPWithPolicy(ctx context.Context, host string, r Resolver, p IPQueryPolicy) ([]netip.Addr, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if p == IPQueryLegacy {
		return LookupIPWithResolver(ctx, host, r)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		ip = ip.Unmap()
		if !p.AllowsAddress(ip) {
			return nil, ErrIPVersion
		}
		return []netip.Addr{ip}, nil
	}
	if p == IPQueryIPv4Only {
		return lookupPolicyFamily(ctx, host, r, true)
	}
	if p == IPQueryIPv6Only {
		return lookupPolicyFamily(ctx, host, r, false)
	}
	lookupCtx, cancel := context.WithTimeout(ctx, DefaultDNSTimeout)
	defer cancel()
	answers := make(chan familyAnswer, 2)
	for _, four := range []bool{true, false} {
		go func(four bool) {
			ips, err := lookupPolicyFamily(lookupCtx, host, r, four)
			answers <- familyAnswer{ips, err, four}
		}(four)
	}
	var a4, a6 familyAnswer
	for received := 0; received < 2; received++ {
		select {
		case a := <-answers:
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if a.ipv4 {
				a4 = a
			} else {
				a6 = a
			}
			if p == IPQueryDualStack && a.err == nil && len(a.ips) > 0 {
				return a.ips, nil
			}
		case <-lookupCtx.Done():
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if a4.err == nil && len(a4.ips) > 0 {
				return a4.ips, nil
			}
			if a6.err == nil && len(a6.ips) > 0 {
				return a6.ips, nil
			}
			return nil, lookupCtx.Err()
		}
	}
	if a4.err != nil {
		a4.ips = nil
	}
	if a6.err != nil {
		a6.ips = nil
	}
	if len(a4.ips)+len(a6.ips) == 0 {
		return nil, errors.Join(ErrIPNotFound, a4.err, a6.err)
	}
	if p == IPQueryPreferIPv6 {
		return append(a6.ips, a4.ips...), nil
	}
	return append(a4.ips, a6.ips...), nil
}

func ResolveIPWithPolicy(ctx context.Context, host string, r Resolver, p IPQueryPolicy) (netip.Addr, error) {
	ips, err := LookupIPWithPolicy(ctx, host, r, p)
	if err != nil {
		return netip.Addr{}, err
	}
	if len(ips) == 0 {
		return netip.Addr{}, ErrIPNotFound
	}
	family := ips[0].Unmap().Is4()
	choices := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if ip.Unmap().Is4() == family {
			choices = append(choices, ip)
		}
	}
	return choices[randv2.IntN(len(choices))], nil
}

func lookupPolicyFamily(ctx context.Context, host string, r Resolver, four bool) ([]netip.Addr, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if node, ok := DefaultHosts.Search(host, false); ok {
		filtered := make([]netip.Addr, 0, len(node.IPs))
		for _, ip := range node.IPs {
			if ip.IsValid() && ip.Unmap().Is4() == four {
				filtered = append(filtered, ip.Unmap())
			}
		}
		if len(filtered) == 0 {
			return nil, ErrIPVersion
		}
		return filtered, nil
	}
	var ips []netip.Addr
	var err error
	if four {
		ips, err = lookupIPv4WithResolver(ctx, host, r)
	} else {
		ips, err = lookupIPv6WithResolver(ctx, host, r)
	}
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	filtered := make([]netip.Addr, 0, len(ips))
	for _, ip := range ips {
		if ip.IsValid() && ip.Unmap().Is4() == four {
			filtered = append(filtered, ip.Unmap())
		}
	}
	if len(filtered) == 0 {
		return nil, ErrIPNotFound
	}
	return filtered, nil
}
