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
	HTTPStatus int

	errno syscall.Errno
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
		failure.HTTPStatus = status
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
		failure.errno = errno
	}
	return failure
}

const (
	failureKindShift   = 12
	failurePayloadMask = 1<<failureKindShift - 1
)

var failureKinds = [...]string{"", URLTestFailureTimeout, URLTestFailureCanceled, URLTestFailureStatus, URLTestFailureUnknown, "dial", "read", "write"}

func (f *URLTestFailure) code() uint16 {
	if f == nil {
		return 0
	}
	kind := 4
	for i, known := range failureKinds {
		if i > 0 && known == f.Kind {
			kind = i
			break
		}
	}
	payload := uint16(f.errno)
	if f.Kind == URLTestFailureStatus {
		payload = uint16(f.HTTPStatus)
	}
	if int(payload) > failurePayloadMask {
		payload = 0
	}
	return uint16(kind)<<failureKindShift | payload
}

func failureOfCode(code uint16) *URLTestFailure {
	kind := int(code >> failureKindShift)
	if code == 0 || kind >= len(failureKinds) || kind == 0 {
		return nil
	}
	failure := &URLTestFailure{Kind: failureKinds[kind]}
	payload := int(code & failurePayloadMask)
	switch {
	case failure.Kind == URLTestFailureStatus:
		failure.HTTPStatus = payload
	case payload != 0:
		failure.errno = syscall.Errno(payload)
		failure.Errno = errnoName(failure.errno)
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
