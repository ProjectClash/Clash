// Copyright (C) 2022  mieru authors
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
	"net"
	"net/netip"
)

type DualStackPreference int32

const (
	USE_FIRST_IP DualStackPreference = 0
	PREFER_IPv4  DualStackPreference = 1
	PREFER_IPv6  DualStackPreference = 2
	ONLY_IPv4    DualStackPreference = 3
	ONLY_IPv6    DualStackPreference = 4
)

func LocalIPAddr() string {
	return "127.0.0.1"
}

func MaybeDecorateIPv6(addr string) string {
	if ip, err := netip.ParseAddr(addr); err == nil && ip.Is6() {
		return "[" + addr + "]"
	}
	return addr
}

func SelectIPFromList(ips []net.IP, strategy DualStackPreference) net.IP {
	if len(ips) == 0 {
		return nil
	}

	var ipv4, ipv6 net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			if ipv4 == nil {
				ipv4 = ip
			}
		} else {
			if ipv6 == nil {
				ipv6 = ip
			}
		}
	}

	switch strategy {
	case PREFER_IPv4:
		if ipv4 != nil {
			return ipv4
		}
		return ipv6
	case PREFER_IPv6:
		if ipv6 != nil {
			return ipv6
		}
		return ipv4
	case ONLY_IPv4:
		return ipv4
	case ONLY_IPv6:
		return ipv6
	default:
		return ips[0]
	}
}
