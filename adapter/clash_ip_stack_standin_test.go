package adapter

import (
	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/adapter/outbound/ipstacktest"
)

func init() {
	outbound.SetGoIPStackFactory(func(options outbound.GoIPStackOptions) (outbound.IPStack, error) {
		return ipstacktest.New(options.MTU), nil
	})
}
