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

package secio

import (
	"errors"
	"io"
)

var ErrReachedLimit = errors.New("reached limit")

type SectionReader struct {
	r     io.ReaderAt
	off   int64
	limit int64
}

func (r *SectionReader) Read(dst []byte) (int, error) {
	if r.limit >= 0 {
		if max := r.limit - r.off; max < int64(len(dst)) {
			dst = dst[:max]
		}
	}
	n, err := r.r.ReadAt(dst, r.off)
	r.off += int64(n)
	if err == nil && r.off == r.limit {
		err = ErrReachedLimit
	}
	return n, err
}

func NewOffsetReader(r io.ReaderAt, off int64) *SectionReader {
	return &SectionReader{r, off, -1}
}

func NewSectionReader(r io.ReaderAt, off int64, n int64) *SectionReader {
	return &SectionReader{r, off, off + n}
}

type SectionWriter struct {
	w     io.WriterAt
	off   int64
	limit int64
}

func (w *SectionWriter) Write(src []byte) (int, error) {
	if w.limit >= 0 {
		if max := w.limit - w.off; max < int64(len(src)) {
			src = src[:max]
		}
	}
	n, err := w.w.WriteAt(src, w.off)
	w.off += int64(n)
	if err == nil && w.off == w.limit {
		err = ErrReachedLimit
	}
	return n, err
}

func NewOffsetWriter(w io.WriterAt, off int64) *SectionWriter {
	return &SectionWriter{w, off, -1}
}

func NewSectionWriter(w io.WriterAt, off int64, n int64) *SectionWriter {
	return &SectionWriter{w, off, off + n}
}
