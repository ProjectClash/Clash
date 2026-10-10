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

package state

import (
	"context"
	"fmt"
	"io"
	"reflect"
	"runtime"

	"github.com/metacubex/gvisor/pkg/state/wire"
)

type objectID uint32

type typeID uint32

type ErrState struct {
	err error

	trace string
}

func (e *ErrState) Error() string {
	return fmt.Sprintf("%v:\n%s", e.err, e.trace)
}

func (e *ErrState) Unwrap() error {
	return e.err
}

func Save(ctx context.Context, w io.Writer, rootPtr any) (Stats, error) {
	es := encodeState{
		ctx:            ctx,
		w:              wire.Writer{Writer: w},
		types:          makeTypeEncodeDatabase(),
		zeroValues:     make(map[reflect.Type]*objectEncodeState),
		pending:        make(map[objectID]*objectEncodeState),
		encodedStructs: make(map[reflect.Value]*wire.Struct),
	}

	err := safely(func() {
		es.Save(reflect.ValueOf(rootPtr).Elem())
	})
	return es.stats, err
}

func Load(ctx context.Context, r io.Reader, rootPtr any) (Stats, error) {
	ds := decodeState{
		ctx:      ctx,
		r:        wire.Reader{Reader: r},
		types:    makeTypeDecodeDatabase(),
		deferred: make(map[objectID]wire.Object),
	}

	err := safely(func() {
		ds.Load(reflect.ValueOf(rootPtr).Elem())
	})
	return ds.stats, err
}

type Sink struct {
	internal objectEncoder
}

func (s Sink) Save(slot int, objPtr any) {
	s.internal.save(slot, reflect.ValueOf(objPtr).Elem())
}

func (s Sink) SaveValue(slot int, obj any) {
	s.internal.save(slot, reflect.ValueOf(obj))
}

func (s Sink) Context() context.Context {
	return s.internal.es.ctx
}

type Type interface {
	StateTypeName() string

	StateFields() []string
}

type SaverLoader interface {
	StateSave(Sink)

	StateLoad(context.Context, Source)
}

type Source struct {
	internal objectDecoder
}

func (s Source) Load(slot int, objPtr any) {
	s.internal.load(slot, reflect.ValueOf(objPtr), false, nil)
}

func (s Source) LoadWait(slot int, objPtr any) {
	s.internal.load(slot, reflect.ValueOf(objPtr), true, nil)
}

func (s Source) LoadValue(slot int, objPtr any, fn func(any)) {
	o := reflect.ValueOf(objPtr)
	s.internal.load(slot, o, true, func() { fn(o.Elem().Interface()) })
}

func (s Source) AfterLoad(fn func()) {
	s.internal.afterLoad(fn)
}

func (s Source) Context() context.Context {
	return s.internal.ds.ctx
}

func IsZeroValue(val any) bool {
	return val == nil || reflect.ValueOf(val).Elem().IsZero()
}

func Failf(fmtStr string, v ...any) {
	panic(fmt.Errorf(fmtStr, v...))
}

func safely(fn func()) (err error) {
	defer func() {
		if r := recover(); r != nil {
			if es, ok := r.(*ErrState); ok {
				err = es
				return
			}

			es := new(ErrState)
			if e, ok := r.(error); ok {
				es.err = e
			} else {
				es.err = fmt.Errorf("%v", r)
			}

			var stack []byte
			for sz := 1024; ; sz *= 2 {
				stack = make([]byte, sz)
				n := runtime.Stack(stack, false)
				if n < sz {
					es.trace = string(stack[:n])
					break
				}
			}

			err = es
		}
	}()

	fn()
	return nil
}
