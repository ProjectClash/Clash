// Copyright (C) 2023  mieru authors
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

package stderror

import (
	"errors"
	"io"
	"net"
	"strings"
)

func IsClosed(err error) bool {
	if errors.Is(err, io.ErrClosedPipe) {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "use of closed network connection")
}

func IsConnRefused(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "connection refused") || strings.Contains(s, "no connection could be made because the target machine actively refused it")
}

func IsEOF(err error) bool {
	return errors.Is(err, io.EOF)
}

func IsNotReady(err error) bool {
	return errors.Is(err, ErrNotReady)
}

func IsPermissionDenied(err error) bool {
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "permission denied")
}

func IsTimeout(err error) bool {
	if netErr, ok := err.(net.Error); ok {
		if netErr.Timeout() {
			return true
		}
	}
	return errors.Is(err, ErrTimeout)
}
