package adapter

import (
	"context"
	"errors"
	"net"
	"syscall"
)

type URLTestFailure struct {
	Kind string
	Errno string
	Message string
}

const (
	URLTestFailureTimeout  = "timeout"
	URLTestFailureCanceled = "canceled"
	URLTestFailureStatus   = "status"
	URLTestFailureUnknown  = "unknown"
)

func ClassifyURLTestFailure(err error, satisfied bool, status int) *URLTestFailure {
	if err == nil && satisfied {
		return nil
	}
	failure := &URLTestFailure{Kind: URLTestFailureUnknown}
	if err != nil {
		failure.Message = err.Error()
	}

	switch {
	case err == nil && !satisfied:
		failure.Kind = URLTestFailureStatus
		if failure.Message == "" {
			failure.Message = unexpectedStatusSentence(status)
		}
		return failure
	case errors.Is(err, context.DeadlineExceeded):
		failure.Kind = URLTestFailureTimeout
	case errors.Is(err, context.Canceled):
		failure.Kind = URLTestFailureCanceled
	default:
		var opErr *net.OpError
		if errors.As(err, &opErr) && opErr.Op != "" {
			failure.Kind = opErr.Op
		}
	}

	var errno syscall.Errno
	if errors.As(err, &errno) {
		failure.Errno = errnoName(errno)
	}
	return failure
}

func unexpectedStatusSentence(status int) string {
	return "unexpected HTTP status " + itoa(status) + " from URL test target"
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	negative := v < 0
	if negative {
		v = -v
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if negative {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
