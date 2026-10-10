// Copyright 2019 The gVisor Authors.
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

package flipcall

import (
	"fmt"
	"io"
)

type DatagramReader struct {
	ep  *Endpoint
	off uint32
	end uint32
}

func (r *DatagramReader) Init(ep *Endpoint, dataLen uint32) {
	r.ep = ep
	r.Reset(dataLen)
}

func (r *DatagramReader) Reset(dataLen uint32) {
	if dataLen > r.ep.dataCap {
		panic(fmt.Sprintf("invalid dataLen (%d) > ep.dataCap (%d)", dataLen, r.ep.dataCap))
	}
	r.off = 0
	r.end = dataLen
}

func (ep *Endpoint) NewReader(dataLen uint32) *DatagramReader {
	r := &DatagramReader{}
	r.Init(ep, dataLen)
	return r
}

func (r *DatagramReader) Read(dst []byte) (int, error) {
	n := copy(dst, r.ep.Data()[r.off:r.end])
	r.off += uint32(n)
	if r.off == r.end {
		return n, io.EOF
	}
	return n, nil
}

type DatagramWriter struct {
	ep  *Endpoint
	off uint32
}

func (w *DatagramWriter) Init(ep *Endpoint) {
	w.ep = ep
}

func (w *DatagramWriter) Reset() {
	w.off = 0
}

func (ep *Endpoint) NewWriter() *DatagramWriter {
	w := &DatagramWriter{}
	w.Init(ep)
	return w
}

func (w *DatagramWriter) Write(src []byte) (int, error) {
	n := copy(w.ep.Data()[w.off:w.ep.dataCap], src)
	w.off += uint32(n)
	if n != len(src) {
		return n, fmt.Errorf("datagram would exceed maximum size of %d bytes", w.ep.dataCap)
	}
	return n, nil
}

func (w *DatagramWriter) Len() uint32 {
	return w.off
}
