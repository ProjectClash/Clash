// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http

import (
	"fmt"
	"io"
	"io/fs"
)

type fileTransport struct {
	fh fileHandler
}

func NewFileTransport(fs FileSystem) RoundTripper {
	return fileTransport{fileHandler{fs}}
}

func NewFileTransportFS(fsys fs.FS) RoundTripper {
	return NewFileTransport(FS(fsys))
}

func (t fileTransport) RoundTrip(req *Request) (resp *Response, err error) {
	rw, resc := newPopulateResponseWriter(req)
	go func() {
		t.fh.ServeHTTP(rw, req)
		rw.finish()
	}()
	return <-resc, nil
}

func newPopulateResponseWriter(req *Request) (*populateResponse, <-chan *Response) {
	pr, pw := io.Pipe()
	rw := &populateResponse{
		ch: make(chan *Response),
		pw: pw,
		res: &Response{
			Proto:      "HTTP/1.0",
			ProtoMajor: 1,
			Header:     make(Header),
			Close:      true,
			Body:       pr,
			Request:    req,
		},
	}
	return rw, rw.ch
}

type populateResponse struct {
	res          *Response
	ch           chan *Response
	wroteHeader  bool
	hasContent   bool
	sentResponse bool
	pw           *io.PipeWriter
}

func (pr *populateResponse) finish() {
	if !pr.wroteHeader {
		pr.WriteHeader(500)
	}
	if !pr.sentResponse {
		pr.sendResponse()
	}
	pr.pw.Close()
}

func (pr *populateResponse) sendResponse() {
	if pr.sentResponse {
		return
	}
	pr.sentResponse = true

	if pr.hasContent {
		pr.res.ContentLength = -1
	}
	pr.ch <- pr.res
}

func (pr *populateResponse) Header() Header {
	return pr.res.Header
}

func (pr *populateResponse) WriteHeader(code int) {
	if pr.wroteHeader {
		return
	}
	pr.wroteHeader = true

	pr.res.StatusCode = code
	pr.res.Status = fmt.Sprintf("%d %s", code, StatusText(code))
}

func (pr *populateResponse) Write(p []byte) (n int, err error) {
	if !pr.wroteHeader {
		pr.WriteHeader(StatusOK)
	}
	pr.hasContent = true
	if !pr.sentResponse {
		pr.sendResponse()
	}
	return pr.pw.Write(p)
}
