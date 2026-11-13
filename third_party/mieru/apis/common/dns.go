// Copyright (C) 2024  mieru authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package common

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

type DNSResolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

var _ DNSResolver = (*net.Resolver)(nil)

type NilDNSResolver struct{}

func (r NilDNSResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	return nil, fmt.Errorf("look up IP address of %s is not supported", host)
}

var _ DNSResolver = NilDNSResolver{}

func NormalizeDomainName(host string) string {
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

type HostMapResolver struct {
	Resolver DNSResolver
	Hosts    map[string]net.IP
}

var _ DNSResolver = HostMapResolver{}

func (r HostMapResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	ip, found := r.Hosts[NormalizeDomainName(host)]
	if found {
		switch network {
		case "", "ip":
			return []net.IP{append(net.IP(nil), ip...)}, nil
		case "ip4":
			if ipv4 := ip.To4(); ipv4 != nil {
				return []net.IP{append(net.IP(nil), ipv4...)}, nil
			}
			return nil, nil
		case "ip6":
			if ipv4 := ip.To4(); ipv4 == nil {
				return []net.IP{append(net.IP(nil), ip.To16()...)}, nil
			}
			return nil, nil
		default:
			return nil, net.UnknownNetworkError(network)
		}
	}
	if r.Resolver == nil {
		return nil, fmt.Errorf("look up IP address of %s is not supported", host)
	}
	return r.Resolver.LookupIP(ctx, network, host)
}

type ClientDNSConfig struct {
	BypassDialerDNS bool
}

func ResolveTCPAddr(ctx context.Context, r DNSResolver, network, address string) (*net.TCPAddr, error) {
	dnsQueryNetwork := "ip"
	switch network {
	case "tcp":
	case "tcp4":
		dnsQueryNetwork = "ip4"
	case "tcp6":
		dnsQueryNetwork = "ip6"
	case "":
		network = "tcp"
	default:
		return nil, net.UnknownNetworkError(network)
	}

	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	if host == "" {
		return &net.TCPAddr{Port: port}, nil
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return &net.TCPAddr{IP: net.IP(ip.AsSlice()), Port: port, Zone: ip.Zone()}, nil
	}

	ips, err := r.LookupIP(ctx, dnsQueryNetwork, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, &net.AddrError{Err: "IP address not found", Addr: address}
	}

	return &net.TCPAddr{IP: ips[0], Port: port}, nil
}

func ResolveUDPAddr(ctx context.Context, r DNSResolver, network, address string) (*net.UDPAddr, error) {
	dnsQueryNetwork := "ip"
	switch network {
	case "udp":
	case "udp4":
		dnsQueryNetwork = "ip4"
	case "udp6":
		dnsQueryNetwork = "ip6"
	case "":
		network = "udp"
	default:
		return nil, net.UnknownNetworkError(network)
	}

	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	if host == "" {
		return &net.UDPAddr{Port: port}, nil
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return &net.UDPAddr{IP: net.IP(ip.AsSlice()), Port: port, Zone: ip.Zone()}, nil
	}

	ips, err := r.LookupIP(ctx, dnsQueryNetwork, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, &net.AddrError{Err: "IP address not found", Addr: address}
	}

	return &net.UDPAddr{IP: ips[0], Port: port}, nil
}

func ForbidDefaultResolver() {
	net.DefaultResolver.PreferGo = true
	net.DefaultResolver.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		panic("Using net.DefaultResolver is forbidden")
	}
}
