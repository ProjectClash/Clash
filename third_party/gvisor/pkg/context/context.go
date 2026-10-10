// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package context

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/metacubex/gvisor/pkg/log"
	"github.com/metacubex/gvisor/pkg/waiter"
)

type Blocker interface {
	Interrupt()

	Interrupted() bool

	Killed() bool

	BlockOn(waiter.Waitable, waiter.EventMask) bool

	Block(C <-chan struct{}) error

	BlockWithTimeout(C chan struct{}, haveTimeout bool, timeout time.Duration) (time.Duration, error)

	BlockWithTimeoutOn(waiter.Waitable, waiter.EventMask, time.Duration) (time.Duration, bool)

	UninterruptibleSleepStart()

	UninterruptibleSleepFinish()
}

type NoTask struct {
	cancel chan struct{}
}

func (nt *NoTask) Interrupt() {
	select {
	case nt.cancel <- struct{}{}:
	default:
	}
}

func (nt *NoTask) Interrupted() bool {
	return len(nt.cancel) > 0
}

func (nt *NoTask) Killed() bool {
	return false
}

func (nt *NoTask) Block(C <-chan struct{}) error {
	if nt.cancel == nil {
		nt.cancel = make(chan struct{}, 1)
	}
	select {
	case <-nt.cancel:
		return errors.New("interrupted system call")
	case <-C:
		return nil
	}
}

func (nt *NoTask) BlockOn(w waiter.Waitable, mask waiter.EventMask) bool {
	if nt.cancel == nil {
		nt.cancel = make(chan struct{}, 1)
	}
	e, ch := waiter.NewChannelEntry(mask)
	w.EventRegister(&e)
	defer w.EventUnregister(&e)
	select {
	case <-nt.cancel:
		return false
	case _, ok := <-ch:
		return ok
	}
}

func (nt *NoTask) BlockWithTimeout(C chan struct{}, haveTimeout bool, timeout time.Duration) (time.Duration, error) {
	if !haveTimeout {
		return timeout, nt.Block(C)
	}

	if nt.cancel == nil {
		nt.cancel = make(chan struct{}, 1)
	}
	start := time.Now()
	remainingTimeout := func() time.Duration {
		rt := timeout - time.Since(start)
		if rt < 0 {
			rt = 0
		}
		return rt
	}
	select {
	case <-nt.cancel:
		return remainingTimeout(), errors.New("interrupted system call")
	case <-C:
		return remainingTimeout(), nil
	case <-time.After(timeout):
		return 0, errors.New("timeout expired")
	}
}

func (nt *NoTask) BlockWithTimeoutOn(w waiter.Waitable, mask waiter.EventMask, timeout time.Duration) (time.Duration, bool) {
	e, ch := waiter.NewChannelEntry(mask)
	w.EventRegister(&e)
	defer w.EventUnregister(&e)
	left, err := nt.BlockWithTimeout(ch, true, timeout)
	return left, err == nil
}

func (*NoTask) UninterruptibleSleepStart() {}

func (*NoTask) UninterruptibleSleepFinish() {}

type Context interface {
	context.Context
	log.Logger
	Blocker
}

type logContext struct {
	NoTask
	log.Logger
	context.Context
}

var bgContext Context
var bgOnce sync.Once

func Background() Context {
	bgOnce.Do(func() {
		bgContext = &logContext{
			Context: context.Background(),
			Logger:  log.Log(),
		}
	})
	return bgContext
}

func WithValue(parent Context, key, val any) Context {
	return &withValue{
		Context: parent,
		key:     key,
		val:     val,
	}
}

type withValue struct {
	Context
	key any
	val any
}

func (ctx *withValue) Value(key any) any {
	if key == ctx.key {
		return ctx.val
	}
	return ctx.Context.Value(key)
}

func WithValues(parent Context, values map[any]any) Context {
	if len(values) == 0 {
		return parent
	}
	return &withValues{
		Context: parent,
		values:  values,
	}
}

type withValues struct {
	Context
	values map[any]any
}

func (ctx *withValues) Value(key any) any {
	if val, ok := ctx.values[key]; ok {
		return val
	}
	return ctx.Context.Value(key)
}
