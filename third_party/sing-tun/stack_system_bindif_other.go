//go:build !darwin

package tun

import (
	"errors"
	"net/netip"
	"syscall"

	"github.com/metacubex/sing/common/logger"
)

const bindListenerSupported = false

var errTunAddressNotPresent = errors.New("no up interface carries the tun address")

func interfaceIndexCarrying(netip.Addr) (index int, carriers int, err error) { return -1, 0, nil }

func bindListenerToInterfaceControl(int, logger.Logger) func(network, address string, conn syscall.RawConn) error {
	return nil
}
