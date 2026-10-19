// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httptrace

import (
	"context"
	"github.com/metacubex/tls"
	"net"
	"net/textproto"
	"reflect"
	"time"
)

type clientEventContextKey struct{}

func ContextClientTrace(ctx context.Context) *ClientTrace {
	trace, _ := ctx.Value(clientEventContextKey{}).(*ClientTrace)
	return trace
}

func WithClientTrace(ctx context.Context, trace *ClientTrace) context.Context {
	if trace == nil {
		panic("nil trace")
	}
	old := ContextClientTrace(ctx)
	trace.compose(old)

	ctx = context.WithValue(ctx, clientEventContextKey{}, trace)
	return ctx
}

type ClientTrace struct {
	GetConn func(hostPort string)

	GotConn func(GotConnInfo)

	PutIdleConn func(err error)

	GotFirstResponseByte func()

	Got100Continue func()

	Got1xxResponse func(code int, header textproto.MIMEHeader) error

	TLSHandshakeStart func()

	TLSHandshakeDone func(tls.ConnectionState, error)

	WroteHeaderField func(key string, value []string)

	WroteHeaders func()

	Wait100Continue func()

	WroteRequest func(WroteRequestInfo)
}

type WroteRequestInfo struct {
	Err error
}

func (t *ClientTrace) compose(old *ClientTrace) {
	if old == nil {
		return
	}
	tv := reflect.ValueOf(t).Elem()
	ov := reflect.ValueOf(old).Elem()
	structType := tv.Type()
	for i := 0; i < structType.NumField(); i++ {
		tf := tv.Field(i)
		hookType := tf.Type()
		if hookType.Kind() != reflect.Func {
			continue
		}
		of := ov.Field(i)
		if of.IsNil() {
			continue
		}
		if tf.IsNil() {
			tf.Set(of)
			continue
		}

		tfCopy := reflect.ValueOf(tf.Interface())

		newFunc := reflect.MakeFunc(hookType, func(args []reflect.Value) []reflect.Value {
			tfCopy.Call(args)
			return of.Call(args)
		})
		tv.Field(i).Set(newFunc)
	}
}

type DNSStartInfo struct {
	Host string
}

type DNSDoneInfo struct {
	Addrs []net.IPAddr

	Err error

	Coalesced bool
}

type GotConnInfo struct {
	Conn net.Conn

	Reused bool

	WasIdle bool

	IdleTime time.Duration
}
