// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httputil

import (
	"github.com/metacubex/http/internal"
	"io"
)

func NewChunkedReader(r io.Reader) io.Reader {
	return internal.NewChunkedReader(r)
}

func NewChunkedWriter(w io.Writer) io.WriteCloser {
	return internal.NewChunkedWriter(w)
}

var ErrLineTooLong = internal.ErrLineTooLong
