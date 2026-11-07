package sing_tun

import (
	"context"
	"sync/atomic"
	"time"

	tun "github.com/metacubex/sing-tun"
	E "github.com/metacubex/sing/common/exceptions"
)

type GoStackOptions struct {
	Context           context.Context
	Device            tun.Tun
	TunOptions        tun.Options
	Handler           *ListenerHandler
	UDPTimeout        time.Duration
	ICMPTimeout       time.Duration
	CongestionControl string
}

type GoStackFactory func(options GoStackOptions) (tun.Stack, error)

var goStackFactory atomic.Pointer[GoStackFactory]

func SetGoStackFactory(factory GoStackFactory) {
	if factory == nil {
		goStackFactory.Store(nil)
		return
	}
	goStackFactory.Store(&factory)
}

func newGoStack(options GoStackOptions) (tun.Stack, error) {
	factory := goStackFactory.Load()
	if factory == nil {
		return nil, E.New("the go stack is not available in this build")
	}
	return (*factory)(options)
}

func startGoStack(options GoStackOptions) (tun.Stack, error) {
	stack, err := newGoStack(options)
	if err != nil {
		return nil, err
	}
	if err = stack.Start(); err != nil {
		_ = stack.Close()
		return nil, err
	}
	return stack, nil
}
