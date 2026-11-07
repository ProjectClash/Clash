package sing_tun

import (
	"errors"

	tun "github.com/metacubex/sing-tun"
)

func getTunnelName(fd int32) (string, error) {
	if name, ok := tun.UtunControlName(int(fd)); ok {
		return name, nil
	}
	return "", errors.New("not a utun control socket")
}
