package snell

import (
	"errors"
	"fmt"
	"net"

	"github.com/ProjectClash/Clash/adapter/inbound"
	C "github.com/ProjectClash/Clash/constant"
	LC "github.com/ProjectClash/Clash/listener/config"
)


const versionV6 = 6

type V6ConnHandler func(conn net.Conn, additions ...inbound.Addition)

var NewV6ConnHandler func(config LC.SnellServer, tunnel C.Tunnel) (V6ConnHandler, error)

func newV6ConnHandler(config LC.SnellServer, tunnel C.Tunnel) (V6ConnHandler, error) {
	if NewV6ConnHandler == nil {
		return nil, errors.New("snell inbound version 6 is not in this build")
	}
	if config.ObfsMode != "" {
		return nil, fmt.Errorf("snell inbound version 6 has no obfs (mode replaces it): %s", config.ObfsMode)
	}
	return NewV6ConnHandler(config, tunnel)
}
