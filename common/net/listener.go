package net

import (
	"context"
	"net"
	"sync"
)

type handleContextListener struct {
	net.Listener
	ctx      context.Context
	cancel   context.CancelFunc
	conns    chan net.Conn
	done     chan struct{}
	err      error
	once     sync.Once
	handle   func(context.Context, net.Conn) (net.Conn, error)
	panicLog func(any)
}

func (l *handleContextListener) init() {
	go func() {
		for {
			c, err := l.Listener.Accept()
			if err != nil {
				l.err = err
				close(l.done)
				l.cancel()
				return
			}
			go func() {
				defer func() {
					if r := recover(); r != nil {
						if l.panicLog != nil {
							l.panicLog(r)
						}
						_ = c.Close()
					}
				}()
				if conn, err := l.handle(l.ctx, c); err == nil {
					select {
					case l.conns <- conn:
					case <-l.done:
						_ = conn.Close()
					case <-l.ctx.Done():
						_ = conn.Close()
					}
				} else {
					// handle failed, close the underlying connection.
					_ = c.Close()
				}
			}()
		}
	}()
}

func (l *handleContextListener) Accept() (net.Conn, error) {
	l.once.Do(l.init)
	select {
	case c := <-l.conns:
		if l.ctx.Err() != nil {
			_ = c.Close()
			return nil, net.ErrClosed
		}
		return c, nil
	case <-l.done:
		return nil, l.err
	case <-l.ctx.Done():
		select {
		case <-l.done:
			return nil, l.err
		default:
			return nil, net.ErrClosed
		}
	}
}

func (l *handleContextListener) Close() error {
	l.cancel()
	l.once.Do(func() {
		l.err = net.ErrClosed
		close(l.done)
	})
	return l.Listener.Close()
}

func NewHandleContextListener(ctx context.Context, l net.Listener, handle func(context.Context, net.Conn) (net.Conn, error), panicLog func(any)) net.Listener {
	ctx, cancel := context.WithCancel(ctx)
	return &handleContextListener{
		Listener: l,
		ctx:      ctx,
		cancel:   cancel,
		conns:    make(chan net.Conn),
		done:     make(chan struct{}),
		handle:   handle,
		panicLog: panicLog,
	}
}
