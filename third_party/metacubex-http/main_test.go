// Copyright 2013 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http_test

import (
	"fmt"
	"github.com/metacubex/http"
	"golang.org/x/exp/slices"
	"io"
	"log"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

var quietLog = log.New(io.Discard, "", 0)

func TestMain(m *testing.M) {
	*http.MaxWriteWaitBeforeConnReuse = 60 * time.Minute
	v := m.Run()
	if v == 0 && goroutineLeaked() {
		os.Exit(1)
	}
	os.Exit(v)
}

func interestingGoroutines() (gs []string) {
	buf := make([]byte, 2<<20)
	buf = buf[:runtime.Stack(buf, true)]
	for _, g := range strings.Split(string(buf), "\n\n") {
		_, stack, _ := strings.Cut(g, "\n")
		stack = strings.TrimSpace(stack)
		if stack == "" ||
			strings.Contains(stack, "testing.(*M).before.func1") ||
			strings.Contains(stack, "os/signal.signal_recv") ||
			strings.Contains(stack, "created by net.startServer") ||
			strings.Contains(stack, "created by testing.RunTests") ||
			strings.Contains(stack, "closeWriteAndWait") ||
			strings.Contains(stack, "testing.Main(") ||
			strings.Contains(stack, "runtime.goexit") ||
			strings.Contains(stack, "created by runtime.gc") ||
			strings.Contains(stack, "interestingGoroutines") ||
			strings.Contains(stack, "runtime.MHeap_Scavenger") {
			continue
		}
		gs = append(gs, stack)
	}
	slices.Sort(gs)
	return
}

func goroutineLeaked() bool {
	if testing.Short() || runningBenchmarks() {
		return false
	}

	var stackCount map[string]int
	for i := 0; i < 5; i++ {
		n := 0
		stackCount = make(map[string]int)
		gs := interestingGoroutines()
		for _, g := range gs {
			stackCount[g]++
			n++
		}
		if n == 0 {
			return false
		}
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Fprintf(os.Stderr, "Too many goroutines running after net/http test(s).\n")
	for stack, count := range stackCount {
		fmt.Fprintf(os.Stderr, "%d instances of:\n%s\n", count, stack)
	}
	return true
}

func setParallel(t *testing.T) {
	if strings.Contains(t.Name(), "HTTP2") {
		http.CondSkipHTTP2(t)
	}
	if testing.Short() {
		t.Parallel()
	}
}

func runningBenchmarks() bool {
	for i, arg := range os.Args {
		if strings.HasPrefix(arg, "-test.bench=") && !strings.HasSuffix(arg, "=") {
			return true
		}
		if arg == "-test.bench" && i < len(os.Args)-1 && os.Args[i+1] != "" {
			return true
		}
	}
	return false
}

var leakReported bool

func afterTest(t testing.TB) {
	http.DefaultTransport.(*http.Transport).CloseIdleConnections()
	if testing.Short() {
		return
	}
	if leakReported {
		return
	}

	leakReported = true

	var bad string
	badSubstring := map[string]string{
		").readLoop(":  "a Transport",
		").writeLoop(": "a Transport",
		"created by net/http/httptest.(*Server).Start": "an httptest.Server",
		"timeoutHandler":        "a TimeoutHandler",
		"net.(*netFD).connect(": "a timing out dial",
		").noteClientGone(":     "a closenotifier sender",
	}
	var stacks string
	for i := 0; i < 2500; i++ {
		bad = ""
		stacks = strings.Join(interestingGoroutines(), "\n\n")
		for substr, what := range badSubstring {
			if strings.Contains(stacks, substr) {
				bad = what
			}
		}
		if bad == "" {
			leakReported = false
			return
		}
		time.Sleep(1 * time.Millisecond)
	}
	t.Errorf("Test appears to have leaked %s:\n%s", bad, stacks)
}

func waitCondition(t testing.TB, delay time.Duration, fn func(time.Duration) bool) {
	t.Helper()
	start := time.Now()
	var since time.Duration
	for !fn(since) {
		time.Sleep(delay)
		delay = 2*delay - (delay / 2)
		since = time.Since(start)
	}
}
