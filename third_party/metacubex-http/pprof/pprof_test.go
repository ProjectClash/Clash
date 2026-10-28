// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pprof

import (
	"bytes"
	"fmt"
	"io"
	"runtime"
	"runtime/pprof"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/pprof/profile"

	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

func TestDescriptions(t *testing.T) {
	for _, p := range pprof.Profiles() {
		_, ok := profileDescriptions[p.Name()]
		if ok != true {
			t.Errorf("%s does not exist in profileDescriptions map\n", p.Name())
		}
	}
}

func TestHandlers(t *testing.T) {
	testCases := []struct {
		path               string
		handler            http.HandlerFunc
		statusCode         int
		contentType        string
		contentDisposition string
		resp               []byte
	}{
		{"/debug/pprof/<script>scripty<script>", Index, http.StatusNotFound, "text/plain; charset=utf-8", "", []byte("Unknown profile\n")},
		{"/debug/pprof/heap", Index, http.StatusOK, "application/octet-stream", `attachment; filename="heap"`, nil},
		{"/debug/pprof/heap?debug=1", Index, http.StatusOK, "text/plain; charset=utf-8", "", nil},
		{"/debug/pprof/cmdline", Cmdline, http.StatusOK, "text/plain; charset=utf-8", "", nil},
		{"/debug/pprof/profile?seconds=1", Profile, http.StatusOK, "application/octet-stream", `attachment; filename="profile"`, nil},
		{"/debug/pprof/symbol", Symbol, http.StatusOK, "text/plain; charset=utf-8", "", nil},
		{"/debug/pprof/trace", Trace, http.StatusOK, "application/octet-stream", `attachment; filename="trace"`, nil},
		{"/debug/pprof/mutex", Index, http.StatusOK, "application/octet-stream", `attachment; filename="mutex"`, nil},
		{"/debug/pprof/block?seconds=1", Index, http.StatusOK, "application/octet-stream", `attachment; filename="block-delta"`, nil},
		{"/debug/pprof/goroutine?seconds=1", Index, http.StatusOK, "application/octet-stream", `attachment; filename="goroutine-delta"`, nil},
		{"/debug/pprof/", Index, http.StatusOK, "text/html; charset=utf-8", "", []byte("Types of profiles available:")},
	}
	if !deltaProfilesServed {
		for i, tc := range testCases {
			if strings.Contains(tc.path, "seconds=") && !strings.HasPrefix(tc.path, "/debug/pprof/profile") {
				testCases[i].statusCode = http.StatusBadRequest
				testCases[i].contentType = "text/plain; charset=utf-8"
				testCases[i].contentDisposition = ""
				testCases[i].resp = []byte("\"seconds\" parameter is not supported in this build\n")
			}
		}
	}
	for _, tc := range testCases {
		t.Run(tc.path, func(t *testing.T) {
			req := httptest.NewRequest("GET", "http://example.com"+tc.path, nil)
			w := httptest.NewRecorder()
			tc.handler(w, req)

			resp := w.Result()
			if got, want := resp.StatusCode, tc.statusCode; got != want {
				t.Errorf("status code: got %d; want %d", got, want)
			}

			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Errorf("when reading response body, expected non-nil err; got %v", err)
			}
			if got, want := resp.Header.Get("X-Content-Type-Options"), "nosniff"; got != want {
				t.Errorf("X-Content-Type-Options: got %q; want %q", got, want)
			}
			if got, want := resp.Header.Get("Content-Type"), tc.contentType; got != want {
				t.Errorf("Content-Type: got %q; want %q", got, want)
			}
			if got, want := resp.Header.Get("Content-Disposition"), tc.contentDisposition; got != want {
				t.Errorf("Content-Disposition: got %q; want %q", got, want)
			}

			if resp.StatusCode == http.StatusOK {
				return
			}
			if got, want := resp.Header.Get("X-Go-Pprof"), "1"; got != want {
				t.Errorf("X-Go-Pprof: got %q; want %q", got, want)
			}
			if !bytes.Equal(body, tc.resp) {
				t.Errorf("response: got %q; want %q", body, tc.resp)
			}
		})
	}
}

var Sink uint32

func mutexHog1(mu1, mu2 *sync.Mutex, start time.Time, dt time.Duration) {
	atomic.AddUint32(&Sink, 1)
	for time.Since(start) < dt {
		t1 := time.Now()
		for time.Since(start) < dt && time.Since(t1) < 10*time.Millisecond {
			mu1.Lock()
			mu2.Lock()
			mu1.Unlock()
			mu2.Unlock()
		}
		if runtime.Compiler == "gccgo" {
			runtime.Gosched()
		}
	}
}

func mutexHog2(mu1, mu2 *sync.Mutex, start time.Time, dt time.Duration) {
	atomic.AddUint32(&Sink, 2)
	for time.Since(start) < dt {
		t1 := time.Now()
		for time.Since(start) < dt && time.Since(t1) < 10*time.Millisecond {
			mu1.Lock()
			mu2.Lock()
			mu1.Unlock()
			mu2.Unlock()
		}
		if runtime.Compiler == "gccgo" {
			runtime.Gosched()
		}
	}
}

func mutexHog(duration time.Duration, hogger func(mu1, mu2 *sync.Mutex, start time.Time, dt time.Duration)) {
	start := time.Now()
	mu1 := new(sync.Mutex)
	mu2 := new(sync.Mutex)
	var wg sync.WaitGroup
	wg.Add(10)
	for i := 0; i < 10; i++ {
		go func() {
			defer wg.Done()
			hogger(mu1, mu2, start, duration)
		}()
	}
	wg.Wait()
}

func TestDeltaProfile(t *testing.T) {
	if !deltaProfilesServed {
		t.Skip("a low-memory build serves no delta profiles")
	}
	if strings.HasPrefix(runtime.GOARCH, "arm") {
		t.Skipf("skipping known flaky test without the -flaky flag; see golang.org/issue/%d", 50218)
	}

	rate := runtime.SetMutexProfileFraction(1)
	defer func() {
		runtime.SetMutexProfileFraction(rate)
	}()

	mutexHog(20*time.Millisecond, mutexHog1)


	p, err := query("/debug/pprof/mutex")
	if err != nil {
		t.Skipf("mutex profile is unsupported: %v", err)
	}

	if !seen(p, "mutexHog1") {
		t.Skipf("mutex profile is not working: %v", p)
	}

	done := make(chan bool)
	go func() {
		for {
			mutexHog(20*time.Millisecond, mutexHog2)
			select {
			case <-done:
				done <- true
				return
			default:
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()
	defer func() {
		done <- true
		<-done
	}()

	for _, d := range []int{1, 4, 16, 32} {
		endpoint := fmt.Sprintf("/debug/pprof/mutex?seconds=%d", d)
		p, err := query(endpoint)
		if err != nil {
			t.Fatalf("failed to query %q: %v", endpoint, err)
		}
		if !seen(p, "mutexHog1") && seen(p, "mutexHog2") && p.DurationNanos > 0 {
			break
		}
		if d == 32 {
			t.Errorf("want mutexHog2 but no mutexHog1 in the profile, and non-zero p.DurationNanos, got %v", p)
		}
	}
	p, err = query("/debug/pprof/mutex")
	if err != nil {
		t.Fatalf("failed to query mutex profile: %v", err)
	}
	if !seen(p, "mutexHog1") || !seen(p, "mutexHog2") {
		t.Errorf("want both mutexHog1 and mutexHog2 in the profile, got %v", p)
	}
}

var srv = httptest.NewServer(nil)

func query(endpoint string) (*profile.Profile, error) {
	url := srv.URL + endpoint
	r, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch %q: %v", url, err)
	}
	if r.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch %q: %v", url, r.Status)
	}

	b, err := io.ReadAll(r.Body)
	r.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to read and parse the result from %q: %v", url, err)
	}
	return profile.Parse(bytes.NewBuffer(b))
}

func seen(p *profile.Profile, fname string) bool {
	locIDs := map[*profile.Location]bool{}
	for _, loc := range p.Location {
		for _, l := range loc.Line {
			if strings.Contains(l.Function.Name, fname) {
				locIDs[loc] = true
				break
			}
		}
	}
	for _, sample := range p.Sample {
		for _, loc := range sample.Location {
			if locIDs[loc] {
				return true
			}
		}
	}
	return false
}
