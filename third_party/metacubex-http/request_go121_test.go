//go:build go1.21

package http

import (
	"errors"
	"testing"
)

func TestErrNotSupported(t *testing.T) {
	if !errors.Is(ErrNotSupported, errors.ErrUnsupported) {
		t.Error("errors.Is(ErrNotSupported, errors.ErrUnsupported) failed")
	}
}
