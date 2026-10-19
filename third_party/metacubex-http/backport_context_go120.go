//go:build !go1.21

package http

import (
	"context"
	"sync"
	"time"
)

func contextAfterFunc(ctx context.Context, f func()) (stop func() bool) {
	stopc := make(chan struct{})
	once := sync.Once{}
	if ctx.Done() != nil {
		go func() {
			select {
			case <-ctx.Done():
				once.Do(func() {
					go f()
				})
			case <-stopc:
			}
		}()
	}

	return func() bool {
		stopped := false
		once.Do(func() {
			stopped = true
			close(stopc)
		})
		return stopped
	}
}

func contextWithoutCancel(parent context.Context) context.Context {
	if parent == nil {
		panic("cannot create context from nil parent")
	}
	return withoutCancelCtx{parent}
}

type withoutCancelCtx struct {
	context.Context
}

func (withoutCancelCtx) Deadline() (deadline time.Time, ok bool) {
	return
}

func (withoutCancelCtx) Done() <-chan struct{} {
	return nil
}

func (withoutCancelCtx) Err() error {
	return nil
}
