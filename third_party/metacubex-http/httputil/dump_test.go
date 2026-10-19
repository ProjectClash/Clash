// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package httputil

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"github.com/metacubex/http"
	"io"
	"math/rand"
	"net/url"
	"runtime"
	"runtime/pprof"
	"strings"
	"testing"
	"time"
)

type eofReader struct{}

func (n eofReader) Close() error { return nil }

func (n eofReader) Read([]byte) (int, error) { return 0, io.EOF }

type dumpTest struct {
	Req    *http.Request
	GetReq func() *http.Request

	Body any

	WantDump    string
	WantDumpOut string
	MustError   bool
	NoBody      bool
}

var dumpTests = []dumpTest{
	{
		Req: &http.Request{
			Method: "GET",
			URL: &url.URL{
				Scheme: "http",
				Host:   "www.google.com",
				Path:   "/search",
			},
			ProtoMajor:       1,
			ProtoMinor:       1,
			TransferEncoding: []string{"chunked"},
		},

		Body: []byte("abcdef"),

		WantDump: "GET /search HTTP/1.1\r\n" +
			"Host: www.google.com\r\n" +
			"Transfer-Encoding: chunked\r\n\r\n" +
			chunk("abcdef") + chunk(""),
	},

	{
		Req: &http.Request{
			Method:     "GET",
			URL:        mustParseURL("/foo"),
			ProtoMajor: 1,
			ProtoMinor: 0,
			Header: http.Header{
				"X-Foo": []string{"X-Bar"},
			},
		},

		WantDump: "GET /foo HTTP/1.0\r\n" +
			"X-Foo: X-Bar\r\n\r\n",
	},

	{
		Req: mustNewRequest("GET", "http://example.com/foo", nil),

		WantDumpOut: "GET /foo HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"User-Agent: Go-http-client/1.1\r\n" +
			"Accept-Encoding: gzip\r\n\r\n",
	},

	{
		Req: mustNewRequest("GET", "https://example.com/foo", nil),
		WantDumpOut: "GET /foo HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"User-Agent: Go-http-client/1.1\r\n" +
			"Accept-Encoding: gzip\r\n\r\n",
	},

	{
		Req: &http.Request{
			Method: "POST",
			URL: &url.URL{
				Scheme: "http",
				Host:   "post.tld",
				Path:   "/",
			},
			ContentLength: 6,
			ProtoMajor:    1,
			ProtoMinor:    1,
		},

		Body: []byte("abcdef"),

		WantDumpOut: "POST / HTTP/1.1\r\n" +
			"Host: post.tld\r\n" +
			"User-Agent: Go-http-client/1.1\r\n" +
			"Content-Length: 6\r\n" +
			"Accept-Encoding: gzip\r\n\r\n",

		NoBody: true,
	},

	{
		Req: &http.Request{
			Method: "POST",
			URL: &url.URL{
				Scheme: "http",
				Host:   "post.tld",
				Path:   "/",
			},
			Header: http.Header{
				"Content-Length": []string{"8193"},
			},

			ContentLength: 8193,
			ProtoMajor:    1,
			ProtoMinor:    1,
		},

		Body: bytes.Repeat([]byte("a"), 8193),

		WantDumpOut: "POST / HTTP/1.1\r\n" +
			"Host: post.tld\r\n" +
			"User-Agent: Go-http-client/1.1\r\n" +
			"Content-Length: 8193\r\n" +
			"Accept-Encoding: gzip\r\n\r\n" +
			strings.Repeat("a", 8193),
		WantDump: "POST / HTTP/1.1\r\n" +
			"Host: post.tld\r\n" +
			"Content-Length: 8193\r\n\r\n" +
			strings.Repeat("a", 8193),
	},

	{
		GetReq: func() *http.Request {
			return mustReadRequest("GET http://foo.com/ HTTP/1.1\r\n" +
				"User-Agent: blah\r\n\r\n")
		},
		NoBody: true,
		WantDump: "GET http://foo.com/ HTTP/1.1\r\n" +
			"User-Agent: blah\r\n\r\n",
	},

	{
		GetReq: func() *http.Request {
			return mustReadRequest("POST /v2/api/?login HTTP/1.1\r\n" +
				"Host: passport.myhost.com\r\n" +
				"Content-Length: 3\r\n" +
				"\r\nkey1=name1&key2=name2")
		},
		WantDump: "POST /v2/api/?login HTTP/1.1\r\n" +
			"Host: passport.myhost.com\r\n" +
			"Content-Length: 3\r\n" +
			"\r\nkey",
	},
	{
		GetReq: func() *http.Request {
			return mustReadRequest("POST /v2/api/?login HTTP/1.1\r\n" +
				"Host: passport.myhost.com\r\n" +
				"Content-Length: 0\r\n" +
				"\r\nkey1=name1&key2=name2")
		},
		WantDump: "POST /v2/api/?login HTTP/1.1\r\n" +
			"Host: passport.myhost.com\r\n" +
			"Content-Length: 0\r\n\r\n",
	},

	{
		GetReq: func() *http.Request {
			return mustReadRequest("POST /v2/api/?login HTTP/1.1\r\n" +
				"Host: passport.myhost.com\r\n" +
				"\r\nkey1=name1&key2=name2")
		},
		WantDump: "POST /v2/api/?login HTTP/1.1\r\n" +
			"Host: passport.myhost.com\r\n\r\n",
	},

	{
		Req: mustNewRequest("POST", "http://example.com/foo", http.NoBody),
		WantDumpOut: "POST /foo HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"User-Agent: Go-http-client/1.1\r\n" +
			"Content-Length: 0\r\n" +
			"Accept-Encoding: gzip\r\n\r\n",
	},

	{
		Req: &http.Request{
			Method: "PUT",
			URL: &url.URL{
				Scheme: "http",
				Host:   "post.tld",
				Path:   "/test",
			},
			ContentLength: 0,
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			Body:          &eofReader{},
		},
		NoBody: true,
		WantDumpOut: "PUT /test HTTP/1.1\r\n" +
			"Host: post.tld\r\n" +
			"User-Agent: Go-http-client/1.1\r\n" +
			"Transfer-Encoding: chunked\r\n" +
			"Accept-Encoding: gzip\r\n\r\n",
	},

	{
		GetReq: func() *http.Request {
			return mustReadRequest("GET / HTTP/1.1\r\n" +
				"Host: example.com\r\n" +
				"Connection: close\r\n\r\n")
		},
		NoBody: true,
		WantDump: "GET / HTTP/1.1\r\n" +
			"Host: example.com\r\n" +
			"Connection: close\r\n\r\n",
	},
}

func TestDumpRequest(t *testing.T) {
	dumpTests := dumpTests[:]
	for i := 0; i < 10; i++ {
		dumpTests = append(dumpTests, dumpTest{
			Req:       mustNewRequest("GET", "", nil),
			MustError: true,
		})
	}
	numg0 := runtime.NumGoroutine()
	for i, tt := range dumpTests {
		if tt.Req != nil && tt.GetReq != nil || tt.Req == nil && tt.GetReq == nil {
			t.Errorf("#%d: either .Req(%p) or .GetReq(%p) can be set/nil but not both", i, tt.Req, tt.GetReq)
			continue
		}

		freshReq := func(ti dumpTest) *http.Request {
			req := ti.Req
			if req == nil {
				req = ti.GetReq()
			}

			if req.Header == nil {
				req.Header = make(http.Header)
			}

			if ti.Body == nil {
				return req
			}
			switch b := ti.Body.(type) {
			case []byte:
				req.Body = io.NopCloser(bytes.NewReader(b))
			case func() io.ReadCloser:
				req.Body = b()
			default:
				t.Fatalf("Test %d: unsupported Body of %T", i, ti.Body)
			}
			return req
		}

		if tt.WantDump != "" {
			req := freshReq(tt)
			dump, err := DumpRequest(req, !tt.NoBody)
			if err != nil {
				t.Errorf("DumpRequest #%d: %s\nWantDump:\n%s", i, err, tt.WantDump)
				continue
			}
			if string(dump) != tt.WantDump {
				t.Errorf("DumpRequest %d, expecting:\n%s\nGot:\n%s\n", i, tt.WantDump, string(dump))
				continue
			}
		}

		if tt.MustError {
			req := freshReq(tt)
			_, err := DumpRequestOut(req, !tt.NoBody)
			if err == nil {
				t.Errorf("DumpRequestOut #%d: expected an error, got nil", i)
			}
			continue
		}

		if tt.WantDumpOut != "" {
			req := freshReq(tt)
			dump, err := DumpRequestOut(req, !tt.NoBody)
			if err != nil {
				t.Errorf("DumpRequestOut #%d: %s", i, err)
				continue
			}
			if string(dump) != tt.WantDumpOut {
				t.Errorf("DumpRequestOut %d, expecting:\n%s\nGot:\n%s\n", i, tt.WantDumpOut, string(dump))
				continue
			}
		}
	}

	var dg int
	dl := deadline(t, 5*time.Second, time.Second)
	for time.Now().Before(dl) {
		if dg = runtime.NumGoroutine() - numg0; dg <= 4 {
			return
		}

		runtime.Gosched()
	}

	buf := make([]byte, 4096)
	buf = buf[:runtime.Stack(buf, true)]
	t.Errorf("Unexpectedly large number of new goroutines: %d new: %s", dg, buf)
}

func deadline(t *testing.T, defaultDelay, needed time.Duration) time.Time {
	if dl, ok := t.Deadline(); ok {
		if dl = dl.Add(-needed); dl.After(time.Now()) {
			return dl
		}
	}

	return time.Now().Add(defaultDelay)
}

func chunk(s string) string {
	return fmt.Sprintf("%x\r\n%s\r\n", len(s), s)
}

func mustParseURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(fmt.Sprintf("Error parsing URL %q: %v", s, err))
	}
	return u
}

func mustNewRequest(method, url string, body io.Reader) *http.Request {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		panic(fmt.Sprintf("NewRequest(%q, %q, %p) err = %v", method, url, body, err))
	}
	return req
}

func mustReadRequest(s string) *http.Request {
	req, err := http.ReadRequest(bufio.NewReader(strings.NewReader(s)))
	if err != nil {
		panic(err)
	}
	return req
}

var dumpResTests = []struct {
	res  *http.Response
	body bool
	want string
}{
	{
		res: &http.Response{
			Status:        "200 OK",
			StatusCode:    200,
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			ContentLength: 50,
			Header: http.Header{
				"Foo": []string{"Bar"},
			},
			Body: io.NopCloser(strings.NewReader("foo")),
		},
		body: false,
		want: `HTTP/1.1 200 OK
Content-Length: 50
Foo: Bar`,
	},

	{
		res: &http.Response{
			Status:        "200 OK",
			StatusCode:    200,
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			ContentLength: 3,
			Body:          io.NopCloser(strings.NewReader("foo")),
		},
		body: true,
		want: `HTTP/1.1 200 OK
Content-Length: 3

foo`,
	},

	{
		res: &http.Response{
			Status:           "200 OK",
			StatusCode:       200,
			Proto:            "HTTP/1.1",
			ProtoMajor:       1,
			ProtoMinor:       1,
			ContentLength:    -1,
			Body:             io.NopCloser(strings.NewReader("foo")),
			TransferEncoding: []string{"chunked"},
		},
		body: true,
		want: `HTTP/1.1 200 OK
Transfer-Encoding: chunked

3
foo
0`,
	},
	{
		res: &http.Response{
			Status:        "200 OK",
			StatusCode:    200,
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			ContentLength: 0,
			Header: http.Header{
				"Foo1": []string{"Bar1"},
				"Foo2": []string{"Bar2"},
			},
			Body: nil,
		},
		body: false,
		want: `HTTP/1.1 200 OK
Foo1: Bar1
Foo2: Bar2
Content-Length: 0`,
	},
}

func TestDumpResponse(t *testing.T) {
	for i, tt := range dumpResTests {
		gotb, err := DumpResponse(tt.res, tt.body)
		if err != nil {
			t.Errorf("%d. DumpResponse = %v", i, err)
			continue
		}
		got := string(gotb)
		got = strings.TrimSpace(got)
		got = strings.ReplaceAll(got, "\r", "")

		if got != tt.want {
			t.Errorf("%d.\nDumpResponse got:\n%s\n\nWant:\n%s\n", i, got, tt.want)
		}
	}
}

func TestDumpRequestOutIssue38352(t *testing.T) {
	if testing.Short() {
		return
	}
	t.Parallel()

	timeout := 10 * time.Second
	if deadline, ok := t.Deadline(); ok {
		timeout = time.Until(deadline)
		timeout -= time.Second * 2
	}
	for i := 0; i < 1000; i++ {
		delay := time.Duration(rand.Intn(5)) * time.Millisecond
		ctx, cancel := context.WithTimeout(context.Background(), delay)
		defer cancel()

		r := bytes.NewBuffer(make([]byte, 10000))
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://example.com", r)
		if err != nil {
			t.Fatal(err)
		}

		out := make(chan error)
		go func() {
			_, err = DumpRequestOut(req, true)
			out <- err
		}()

		select {
		case <-out:
		case <-time.After(timeout):
			b := &strings.Builder{}
			fmt.Fprintf(b, "deadlock detected on iteration %d after %s with delay: %v\n", i, timeout, delay)
			pprof.Lookup("goroutine").WriteTo(b, 1)
			t.Fatal(b.String())
		}
	}
}
