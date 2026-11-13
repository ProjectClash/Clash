// Copyright (C) 2025  mieru authors
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

package appctlcommon

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/enfein/mieru/v3/apis/constant"
	pb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
)

func ValidateServerListenIPAddress(address string) error {
	if address == "" {
		return nil
	}
	ip, err := netip.ParseAddr(address)
	if err != nil || ip.Zone() != "" {
		return fmt.Errorf("server listen IP address %q is invalid", address)
	}
	return nil
}

func ParseServerTCPIdleTimeout(value string) (time.Duration, error) {
	if value == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("TCP idle timeout %q is invalid: %w", value, err)
	}
	if d < time.Minute {
		return 0, fmt.Errorf("TCP idle timeout %q is less than 1 minute", value)
	}
	return d, nil
}

func ValidateServerConfigSingleUser(user *pb.User) error {
	if user.GetName() == "" {
		return fmt.Errorf("user name is not set")
	}
	if user.GetPassword() == "" && user.GetHashedPassword() == "" {
		return fmt.Errorf("user password is not set")
	}
	if len(user.GetName()) > constant.MaxUserNameLen {
		return fmt.Errorf("user name exceeds %d bytes", constant.MaxUserNameLen)
	}
	if user.GetPassword() != "" && len(user.GetPassword()) > 64 {
		return fmt.Errorf("user password exceeds 64 bytes")
	}
	for _, quota := range user.GetQuotas() {
		if quota.GetDays() <= 0 {
			return fmt.Errorf("quota: number of days %d is invalid", quota.GetDays())
		}
		if quota.GetMegabytes() <= 0 {
			return fmt.Errorf("quota: traffic volume in megabyte %d is invalid", quota.GetMegabytes())
		}
	}
	return nil
}
