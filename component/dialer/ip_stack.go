package dialer

import (
	"context"
	"errors"
	"github.com/ProjectClash/Clash/component/resolver"
	"net"
	"net/netip"
	"strings"
	"time"
)

func dialWithIPStack(ctx context.Context, network, address string, opt option, policy resolver.IPQueryPolicy) (connection net.Conn, resultErr error) {
	defer func() {
		if err := ctx.Err(); err != nil {
			if connection != nil {
				_ = connection.Close()
			}
			connection, resultErr = nil, err
		}
	}()
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	family := opt.network
	switch network {
	case "tcp4", "udp4":
		if family == 0 {
			family = 4
		}
	case "tcp6", "udp6":
		if family == 0 {
			family = 6
		}
	case "tcp", "udp":
	default:
		return nil, ErrorInvalidedNetworkStack
	}
	network = strings.TrimSuffix(strings.TrimSuffix(network, "4"), "6")
	if (policy == resolver.IPQueryIPv4Only && family == 6) || (policy == resolver.IPQueryIPv6Only && family == 4) {
		return nil, resolver.ErrIPVersion
	}
	if policy == resolver.IPQueryIPv4Only {
		family = 4
	}
	if policy == resolver.IPQueryIPv6Only {
		family = 6
	}
	if family == 4 {
		policy = resolver.IPQueryIPv4Only
	}
	if family == 6 {
		policy = resolver.IPQueryIPv6Only
	}
	if family == 0 {
		if opt.prefer == 4 {
			policy = resolver.IPQueryPreferIPv4
		}
		if opt.prefer == 6 {
			policy = resolver.IPQueryPreferIPv6
		}
	}
	dialFn := serialDialContext
	if GetTcpConcurrent() {
		dialFn = parallelDialContext
	}
	if ip, e := netip.ParseAddr(host); e == nil {
		ip = ip.Unmap()
		if !policy.AllowsAddress(ip) {
			return nil, resolver.ErrIPVersion
		}
		return dialFn(ctx, network, []netip.Addr{ip}, port, opt)
	}
	r := opt.resolver
	if r == nil {
		r = resolver.ProxyServerHostResolver
	}
	if policy == resolver.IPQueryDualStack {
		return dialRacingIPFamilies(ctx, network, host, port, opt, r, dialFn)
	}
	ips, err := resolver.LookupIPWithPolicy(ctx, host, r, policy)
	if err != nil {
		return nil, err
	}
	if policy == resolver.IPQueryPreferIPv4 {
		opt.prefer = 4
	}
	if policy == resolver.IPQueryPreferIPv6 {
		opt.prefer = 6
	}
	if family != 0 {
		return dialFn(ctx, network, ips, port, opt)
	}
	return dualStackDialContext(ctx, dialFn, network, ips, port, opt)
}

type ipFamilyResolution struct {
	ips []netip.Addr
	err error
}
type ipFamilyDialResult struct {
	conn net.Conn
	err  error
}

func dialRacingIPFamilies(ctx context.Context, network, host, port string, opt option, r resolver.Resolver, dialFn dialFunc) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, DefaultTCPTimeout)
	defer cancel()
	resolved := make(chan ipFamilyResolution, 2)
	for _, p := range []resolver.IPQueryPolicy{resolver.IPQueryIPv4Only, resolver.IPQueryIPv6Only} {
		go func(p resolver.IPQueryPolicy) {
			ips, err := resolver.LookupIPWithPolicy(ctx, host, r, p)
			if err == nil && len(ips) == 0 {
				err = ErrorNoIpAddress
			}
			resolved <- ipFamilyResolution{ips, err}
		}(p)
	}
	results := make(chan ipFamilyDialResult)
	startDial := func(ips []netip.Addr) {
		go func() {
			conn, err := dialFn(ctx, network, ips, port, opt)
			if err == nil && conn == nil {
				err = ErrorNoIpAddress
			}
			select {
			case results <- ipFamilyDialResult{conn, err}:
			case <-ctx.Done():
				if conn != nil {
					conn.Close()
				}
			}
		}()
	}
	var timer *time.Timer
	var timerC <-chan time.Time
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	var pending []netip.Addr
	var failures []error
	remaining, active, started := 2, 0, 0
	releaseAlternate := false
	for {
		if remaining == 0 && active == 0 && len(pending) == 0 {
			return nil, errors.Join(append([]error{ErrorNoIpAddress}, failures...)...)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case answer := <-resolved:
			remaining--
			if answer.err != nil {
				failures = append(failures, answer.err)
				continue
			}
			if started == 0 {
				startDial(answer.ips)
				started++
				active++
				timer = time.NewTimer(dualStackFallbackTimeout)
				timerC = timer.C
			} else if releaseAlternate || active == 0 {
				startDial(answer.ips)
				active++
			} else {
				pending = answer.ips
			}
		case <-timerC:
			timerC = nil
			releaseAlternate = true
			if len(pending) > 0 {
				startDial(pending)
				pending = nil
				active++
			}
		case result := <-results:
			active--
			if result.err == nil {
				if err := ctx.Err(); err != nil {
					result.conn.Close()
					return nil, err
				}
				return result.conn, nil
			}
			if result.conn != nil {
				result.conn.Close()
			}
			failures = append(failures, result.err)
			releaseAlternate = true
			if len(pending) > 0 {
				startDial(pending)
				pending = nil
				active++
			}
		}
	}
}
