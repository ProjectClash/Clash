// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http

import (
	"io"
	"strings"
	"testing"
)

type respWriteTest struct {
	Resp Response
	Raw  string
}

func TestResponseWrite(t *testing.T) {
	respWriteTests := []respWriteTest{
		{
			Response{
				StatusCode:    503,
				ProtoMajor:    1,
				ProtoMinor:    0,
				Request:       dummyReq("GET"),
				Header:        Header{},
				Body:          io.NopCloser(strings.NewReader("abcdef")),
				ContentLength: 6,
			},

			"HTTP/1.0 503 Service Unavailable\r\n" +
				"Content-Length: 6\r\n\r\n" +
				"abcdef",
		},
		{
			Response{
				StatusCode:    200,
				ProtoMajor:    1,
				ProtoMinor:    0,
				Request:       dummyReq("GET"),
				Header:        Header{},
				Body:          io.NopCloser(strings.NewReader("abcdef")),
				ContentLength: -1,
			},
			"HTTP/1.0 200 OK\r\n" +
				"\r\n" +
				"abcdef",
		},
		{
			Response{
				StatusCode:    200,
				ProtoMajor:    1,
				ProtoMinor:    1,
				Request:       dummyReq("GET"),
				Header:        Header{},
				Body:          io.NopCloser(strings.NewReader("abcdef")),
				ContentLength: -1,
				Close:         true,
			},
			"HTTP/1.1 200 OK\r\n" +
				"Connection: close\r\n" +
				"\r\n" +
				"abcdef",
		},
		{
			Response{
				StatusCode:    200,
				ProtoMajor:    1,
				ProtoMinor:    1,
				Request:       dummyReq11("GET"),
				Header:        Header{},
				Body:          io.NopCloser(strings.NewReader("abcdef")),
				ContentLength: -1,
				Close:         false,
			},
			"HTTP/1.1 200 OK\r\n" +
				"Connection: close\r\n" +
				"\r\n" +
				"abcdef",
		},
		{
			Response{
				StatusCode:       200,
				ProtoMajor:       1,
				ProtoMinor:       1,
				Request:          dummyReq11("GET"),
				Header:           Header{},
				Body:             io.NopCloser(strings.NewReader("abcdef")),
				ContentLength:    -1,
				TransferEncoding: []string{"chunked"},
				Close:            false,
			},
			"HTTP/1.1 200 OK\r\n" +
				"Transfer-Encoding: chunked\r\n\r\n" +
				"6\r\nabcdef\r\n0\r\n\r\n",
		},
		{
			Response{
				StatusCode:    200,
				ProtoMajor:    1,
				ProtoMinor:    1,
				Request:       dummyReq11("GET"),
				Header:        Header{},
				Body:          nil,
				ContentLength: 0,
				Close:         false,
			},
			"HTTP/1.1 200 OK\r\n" +
				"Content-Length: 0\r\n" +
				"\r\n",
		},
		{
			Response{
				StatusCode:    200,
				ProtoMajor:    1,
				ProtoMinor:    1,
				Request:       dummyReq11("GET"),
				Header:        Header{},
				Body:          io.NopCloser(strings.NewReader("")),
				ContentLength: 0,
				Close:         false,
			},
			"HTTP/1.1 200 OK\r\n" +
				"Content-Length: 0\r\n" +
				"\r\n",
		},
		{
			Response{
				StatusCode:    200,
				ProtoMajor:    1,
				ProtoMinor:    1,
				Request:       dummyReq11("GET"),
				Header:        Header{},
				Body:          io.NopCloser(strings.NewReader("foo")),
				ContentLength: 0,
				Close:         false,
			},
			"HTTP/1.1 200 OK\r\n" +
				"Connection: close\r\n" +
				"\r\nfoo",
		},
		{
			Response{
				StatusCode:       200,
				ProtoMajor:       1,
				ProtoMinor:       1,
				Request:          dummyReq("GET"),
				Header:           Header{},
				Body:             io.NopCloser(strings.NewReader("abcdef")),
				ContentLength:    6,
				TransferEncoding: []string{"chunked"},
				Close:            true,
			},

			"HTTP/1.1 200 OK\r\n" +
				"Connection: close\r\n" +
				"Transfer-Encoding: chunked\r\n\r\n" +
				"6\r\nabcdef\r\n0\r\n\r\n",
		},

		{
			Response{
				StatusCode: 204,
				ProtoMajor: 1,
				ProtoMinor: 1,
				Request:    dummyReq("GET"),
				Header: Header{
					"Foo": []string{" Bar\nBaz "},
				},
				Body:             nil,
				ContentLength:    0,
				TransferEncoding: []string{"chunked"},
				Close:            true,
			},

			"HTTP/1.1 204 No Content\r\n" +
				"Connection: close\r\n" +
				"Foo: Bar Baz\r\n" +
				"\r\n",
		},

		{
			Response{
				StatusCode:       StatusOK,
				ProtoMajor:       1,
				ProtoMinor:       1,
				Request:          &Request{Method: "POST"},
				Header:           Header{},
				ContentLength:    0,
				TransferEncoding: nil,
				Body:             nil,
			},
			"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
		},

		{
			Response{
				StatusCode:    StatusOK,
				ProtoMajor:    1,
				ProtoMinor:    1,
				Request:       &Request{Method: "POST"},
				Header:        Header{},
				ContentLength: -1,
				Body:          io.NopCloser(strings.NewReader("abcdef")),
			},
			"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nabcdef",
		},

		{
			Response{
				StatusCode: 7,
				Status:     "license to violate specs",
				ProtoMajor: 1,
				ProtoMinor: 0,
				Request:    dummyReq("GET"),
				Header:     Header{},
				Body:       nil,
			},

			"HTTP/1.0 007 license to violate specs\r\nContent-Length: 0\r\n\r\n",
		},

		{
			Response{
				StatusCode: 123,
				Status:     "123 Sesame Street",
				ProtoMajor: 1,
				ProtoMinor: 0,
				Request:    dummyReq("GET"),
				Header:     Header{},
				Body:       nil,
			},

			"HTTP/1.0 123 Sesame Street\r\n\r\n",
		},

		{
			Response{
				StatusCode: 204,
				Status:     "No Content",
				ProtoMajor: 1,
				ProtoMinor: 0,
				Request:    dummyReq("GET"),
				Header:     Header{},
				Body:       nil,
			},

			"HTTP/1.0 204 No Content\r\n\r\n",
		},
	}

	for i := range respWriteTests {
		tt := &respWriteTests[i]
		var braw strings.Builder
		err := tt.Resp.Write(&braw)
		if err != nil {
			t.Errorf("error writing #%d: %s", i, err)
			continue
		}
		sraw := braw.String()
		if sraw != tt.Raw {
			t.Errorf("Test %d, expecting:\n%q\nGot:\n%q\n", i, tt.Raw, sraw)
			continue
		}
	}
}
