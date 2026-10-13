//go:build !go1.21

package realm

import "errors"

var ErrUnsupported = errors.New("unsupported operation")
