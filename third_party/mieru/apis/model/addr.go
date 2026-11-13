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

package model

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"

	"github.com/enfein/mieru/v3/apis/constant"
)

var (
	ErrUnrecognizedAddrType = errors.New("unrecognized address type")
)

type AddrSpec struct {
	FQDN string
	IP   net.IP
	Port int
}

func (a AddrSpec) String() string {
	if len(a.IP) != 0 {
		return net.JoinHostPort(a.IP.String(), strconv.Itoa(a.Port))
	}
	return net.JoinHostPort(a.FQDN, strconv.Itoa(a.Port))
}

func (a AddrSpec) AddrType() uint8 {
	if a.IP.To4() != nil {
		return constant.Socks5IPv4Address
	}
	if a.IP.To16() != nil {
		return constant.Socks5IPv6Address
	}
	if a.FQDN != "" {
		return constant.Socks5FQDNAddress
	}
	return 0
}

func (a *AddrSpec) From(addr string) error {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}
	if port < 0 || port > 65535 {
		return fmt.Errorf("port %d is out of range", port)
	}

	if ip := net.ParseIP(host); ip != nil {
		a.FQDN = ""
		a.IP = ip
		a.Port = port
		return nil
	}

	if len(host) > 255 {
		return fmt.Errorf("FQDN %q exceeds 255 bytes", host)
	}
	a.FQDN = host
	a.IP = nil
	a.Port = port
	return nil
}

func (a *AddrSpec) ReadFromSocks5(r io.Reader) error {
	addrType := []byte{0}
	if _, err := io.ReadFull(r, addrType); err != nil {
		return err
	}

	switch addrType[0] {
	case constant.Socks5IPv4Address:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(r, addr); err != nil {
			return err
		}
		a.IP = net.IP(addr)
	case constant.Socks5IPv6Address:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(r, addr); err != nil {
			return err
		}
		a.IP = net.IP(addr)
	case constant.Socks5FQDNAddress:
		addrLen := []byte{0}
		if _, err := io.ReadFull(r, addrLen); err != nil {
			return err
		}
		fqdn := make([]byte, int(addrLen[0]))
		if _, err := io.ReadFull(r, fqdn); err != nil {
			return err
		}
		a.FQDN = string(fqdn)
	default:
		return ErrUnrecognizedAddrType
	}

	port := []byte{0, 0}
	if _, err := io.ReadFull(r, port); err != nil {
		return err
	}
	a.Port = (int(port[0]) << 8) | int(port[1])

	return nil
}

func (a AddrSpec) WriteToSocks5(w io.Writer) error {
	var addrPort uint16
	var b bytes.Buffer

	switch {
	case a.IP.To4() != nil:
		b.WriteByte(constant.Socks5IPv4Address)
		b.Write(a.IP.To4())
	case a.IP.To16() != nil:
		b.WriteByte(constant.Socks5IPv6Address)
		b.Write(a.IP.To16())
	case a.FQDN != "":
		b.WriteByte(constant.Socks5FQDNAddress)
		b.WriteByte(byte(len(a.FQDN)))
		b.Write([]byte(a.FQDN))
	default:
		return ErrUnrecognizedAddrType
	}
	addrPort = uint16(a.Port)
	b.WriteByte(byte(addrPort >> 8))
	b.WriteByte(byte(addrPort & 0xff))

	_, err := w.Write(b.Bytes())
	return err
}

type NetAddrSpec struct {
	AddrSpec
	Net string
}

var _ net.Addr = NetAddrSpec{}
var _ net.Addr = &NetAddrSpec{}

func (n NetAddrSpec) Network() string {
	return n.Net
}

func (n *NetAddrSpec) From(addr net.Addr) error {
	if nas, ok := addr.(NetAddrSpec); ok {
		n.AddrSpec = nas.AddrSpec
		n.Net = nas.Net
		return nil
	}
	if nas, ok := addr.(*NetAddrSpec); ok {
		n.AddrSpec = nas.AddrSpec
		n.Net = nas.Net
		return nil
	}

	addrSpec := AddrSpec{}
	if err := addrSpec.From(addr.String()); err != nil {
		return err
	}
	n.AddrSpec = addrSpec
	n.Net = addr.Network()
	return nil
}
