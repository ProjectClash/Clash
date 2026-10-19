// Copyright 2024 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http2

import (
	"math"
	"time"

	"github.com/metacubex/http"
)

type http2Config struct {
	MaxConcurrentStreams         uint32
	StrictMaxConcurrentRequests  bool
	MaxDecoderHeaderTableSize    uint32
	MaxEncoderHeaderTableSize    uint32
	MaxReadFrameSize             uint32
	MaxUploadBufferPerConnection int32
	MaxUploadBufferPerStream     int32
	SendPingTimeout              time.Duration
	PingTimeout                  time.Duration
	WriteByteTimeout             time.Duration
	PermitProhibitedCipherSuites bool
	CountError                   func(errType string)
}

func configFromServer(h1 *http.Server, h2 *Server) http2Config {
	conf := http2Config{
		MaxConcurrentStreams:         h2.MaxConcurrentStreams,
		MaxEncoderHeaderTableSize:    h2.MaxEncoderHeaderTableSize,
		MaxDecoderHeaderTableSize:    h2.MaxDecoderHeaderTableSize,
		MaxReadFrameSize:             h2.MaxReadFrameSize,
		MaxUploadBufferPerConnection: h2.MaxUploadBufferPerConnection,
		MaxUploadBufferPerStream:     h2.MaxUploadBufferPerStream,
		SendPingTimeout:              h2.ReadIdleTimeout,
		PingTimeout:                  h2.PingTimeout,
		WriteByteTimeout:             h2.WriteByteTimeout,
		PermitProhibitedCipherSuites: h2.PermitProhibitedCipherSuites,
		CountError:                   h2.CountError,
	}
	fillNetHTTPConfig(&conf, h1.HTTP2)
	setConfigDefaults(&conf, true)
	return conf
}

func configFromTransport(h2 *Transport) http2Config {
	conf := http2Config{
		StrictMaxConcurrentRequests: h2.StrictMaxConcurrentStreams,
		MaxEncoderHeaderTableSize:   h2.MaxEncoderHeaderTableSize,
		MaxDecoderHeaderTableSize:   h2.MaxDecoderHeaderTableSize,
		MaxReadFrameSize:            h2.MaxReadFrameSize,
		SendPingTimeout:             h2.ReadIdleTimeout,
		PingTimeout:                 h2.PingTimeout,
		WriteByteTimeout:            h2.WriteByteTimeout,
	}

	if conf.MaxReadFrameSize < minMaxFrameSize {
		conf.MaxReadFrameSize = minMaxFrameSize
	} else if conf.MaxReadFrameSize > maxFrameSize {
		conf.MaxReadFrameSize = maxFrameSize
	}

	if h2.t1 != nil {
		fillNetHTTPConfig(&conf, h2.t1.HTTP2)
	}
	setConfigDefaults(&conf, false)
	return conf
}

func setDefault[T ~int | ~int32 | ~uint32 | ~int64](v *T, minval, maxval, defval T) {
	if *v < minval || *v > maxval {
		*v = defval
	}
}

func setConfigDefaults(conf *http2Config, server bool) {
	setDefault(&conf.MaxConcurrentStreams, 1, math.MaxUint32, defaultMaxStreams)
	setDefault(&conf.MaxEncoderHeaderTableSize, 1, math.MaxUint32, initialHeaderTableSize)
	setDefault(&conf.MaxDecoderHeaderTableSize, 1, math.MaxUint32, initialHeaderTableSize)
	if server {
		setDefault(&conf.MaxUploadBufferPerConnection, initialWindowSize, math.MaxInt32, 1<<20)
	} else {
		setDefault(&conf.MaxUploadBufferPerConnection, initialWindowSize, math.MaxInt32, transportDefaultConnFlow)
	}
	if server {
		setDefault(&conf.MaxUploadBufferPerStream, 1, math.MaxInt32, 1<<20)
	} else {
		setDefault(&conf.MaxUploadBufferPerStream, 1, math.MaxInt32, transportDefaultStreamFlow)
	}
	setDefault(&conf.MaxReadFrameSize, minMaxFrameSize, maxFrameSize, defaultMaxReadFrameSize)
	setDefault(&conf.PingTimeout, 1, math.MaxInt64, 15*time.Second)
}

func adjustHTTP1MaxHeaderSize(n int64) int64 {
	const perFieldOverhead = 32
	const typicalHeaders = 10
	return n + typicalHeaders*perFieldOverhead
}

func fillNetHTTPConfig(conf *http2Config, h2 *http.HTTP2Config) {
	if h2 == nil {
		return
	}
	if h2.MaxConcurrentStreams != 0 {
		conf.MaxConcurrentStreams = uint32(h2.MaxConcurrentStreams)
	}
	if http2ConfigStrictMaxConcurrentRequests(h2) {
		conf.StrictMaxConcurrentRequests = true
	}
	if h2.MaxEncoderHeaderTableSize != 0 {
		conf.MaxEncoderHeaderTableSize = uint32(h2.MaxEncoderHeaderTableSize)
	}
	if h2.MaxDecoderHeaderTableSize != 0 {
		conf.MaxDecoderHeaderTableSize = uint32(h2.MaxDecoderHeaderTableSize)
	}
	if h2.MaxConcurrentStreams != 0 {
		conf.MaxConcurrentStreams = uint32(h2.MaxConcurrentStreams)
	}
	if h2.MaxReadFrameSize != 0 {
		conf.MaxReadFrameSize = uint32(h2.MaxReadFrameSize)
	}
	if h2.MaxReceiveBufferPerConnection != 0 {
		conf.MaxUploadBufferPerConnection = int32(h2.MaxReceiveBufferPerConnection)
	}
	if h2.MaxReceiveBufferPerStream != 0 {
		conf.MaxUploadBufferPerStream = int32(h2.MaxReceiveBufferPerStream)
	}
	if h2.SendPingTimeout != 0 {
		conf.SendPingTimeout = h2.SendPingTimeout
	}
	if h2.PingTimeout != 0 {
		conf.PingTimeout = h2.PingTimeout
	}
	if h2.WriteByteTimeout != 0 {
		conf.WriteByteTimeout = h2.WriteByteTimeout
	}
	if h2.PermitProhibitedCipherSuites {
		conf.PermitProhibitedCipherSuites = true
	}
	if h2.CountError != nil {
		conf.CountError = h2.CountError
	}
}

func http2ConfigStrictMaxConcurrentRequests(h2 *http.HTTP2Config) bool {
	return h2.StrictMaxConcurrentRequests
}
