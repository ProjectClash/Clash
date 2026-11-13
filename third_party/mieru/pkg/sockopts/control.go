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

package sockopts

import (
	"fmt"
	"net"
	"os"
	"syscall"
)

type Control = func(network, address string, c syscall.RawConn) error

type RawControl = func(fd uintptr)

type RawControlErr = func(fd uintptr) error

func ApplyTCPControl(l *net.TCPListener, controlFunc Control) error {
	rawConn, err := l.SyscallConn()
	if err != nil {
		return fmt.Errorf("SyscallConn() failed: %w", err)
	}
	return controlFunc(l.Addr().Network(), l.Addr().String(), rawConn)
}

func ApplyUDPControl(c *net.UDPConn, controlFunc Control) error {
	rawConn, err := c.SyscallConn()
	if err != nil {
		return fmt.Errorf("SyscallConn() failed: %w", err)
	}
	return controlFunc(c.LocalAddr().Network(), c.LocalAddr().String(), rawConn)
}

func DefaultDialerControl() Control {
	return func(network, address string, c syscall.RawConn) error {
		if err := c.Control(ReuseAddrPortRaw()); err != nil {
			return err
		}
		if path, found := os.LookupEnv("MIERU_PROTECT_PATH"); found {
			if err := c.Control(ProtectPathRaw(path)); err != nil {
				return err
			}
		}
		return nil
	}
}

func DefaultListenerControl() Control {
	return func(network, address string, c syscall.RawConn) error {
		return c.Control(ReuseAddrPortRaw())
	}
}
