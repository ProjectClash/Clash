// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package pprof

import (
	"bufio"
	"bytes"
	"fmt"
	"html"
	"io"
	"log"
	"net/url"
	"os"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/metacubex/http"
)

func init() {
	prefix := "GET "
	http.HandleFunc(prefix+"/debug/pprof/", Index)
	http.HandleFunc(prefix+"/debug/pprof/cmdline", Cmdline)
	http.HandleFunc(prefix+"/debug/pprof/profile", Profile)
	http.HandleFunc(prefix+"/debug/pprof/symbol", Symbol)
	http.HandleFunc(prefix+"/debug/pprof/trace", Trace)
}

func Cmdline(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, strings.Join(os.Args, "\x00"))
}

func sleep(r *http.Request, d time.Duration) {
	select {
	case <-time.After(d):
	case <-r.Context().Done():
	}
}

func configureWriteDeadline(w http.ResponseWriter, r *http.Request, seconds float64) {
	srv, ok := r.Context().Value(http.ServerContextKey).(*http.Server)
	if ok && srv.WriteTimeout > 0 {
		timeout := srv.WriteTimeout + time.Duration(seconds*float64(time.Second))

		rc := http.NewResponseController(w)
		rc.SetWriteDeadline(time.Now().Add(timeout))
	}
}

func serveError(w http.ResponseWriter, status int, txt string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Go-Pprof", "1")
	w.Header().Del("Content-Disposition")
	w.WriteHeader(status)
	fmt.Fprintln(w, txt)
}

func Profile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	sec, err := strconv.ParseInt(r.FormValue("seconds"), 10, 64)
	if sec <= 0 || err != nil {
		sec = 30
	}

	configureWriteDeadline(w, r, float64(sec))

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="profile"`)
	if err := pprof.StartCPUProfile(w); err != nil {
		serveError(w, http.StatusInternalServerError,
			fmt.Sprintf("Could not enable CPU profiling: %s", err))
		return
	}
	sleep(r, time.Duration(sec)*time.Second)
	pprof.StopCPUProfile()
}

func Trace(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	sec, err := strconv.ParseFloat(r.FormValue("seconds"), 64)
	if sec <= 0 || err != nil {
		sec = 1
	}

	configureWriteDeadline(w, r, sec)

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="trace"`)
	if err := trace.Start(w); err != nil {
		serveError(w, http.StatusInternalServerError,
			fmt.Sprintf("Could not enable tracing: %s", err))
		return
	}
	sleep(r, time.Duration(sec*float64(time.Second)))
	trace.Stop()
}

func Symbol(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	var buf bytes.Buffer

	fmt.Fprintf(&buf, "num_symbols: 1\n")

	var b *bufio.Reader
	if r.Method == "POST" {
		b = bufio.NewReader(r.Body)
	} else {
		b = bufio.NewReader(strings.NewReader(r.URL.RawQuery))
	}

	for {
		word, err := b.ReadSlice('+')
		if err == nil {
			word = word[0 : len(word)-1]
		}
		pc, _ := strconv.ParseUint(string(word), 0, 64)
		if pc != 0 {
			f := runtime.FuncForPC(uintptr(pc))
			if f != nil {
				fmt.Fprintf(&buf, "%#x %s\n", pc, f.Name())
			}
		}

		if err != nil {
			if err != io.EOF {
				fmt.Fprintf(&buf, "reading request: %v\n", err)
			}
			break
		}
	}

	w.Write(buf.Bytes())
}

func Handler(name string) http.Handler {
	return handler(name)
}

type handler string

func (name handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	p := pprof.Lookup(string(name))
	if p == nil {
		serveError(w, http.StatusNotFound, "Unknown profile")
		return
	}
	if sec := r.FormValue("seconds"); sec != "" {
		name.serveDeltaProfile(w, r, p, sec)
		return
	}
	gc, _ := strconv.Atoi(r.FormValue("gc"))
	if name == "heap" && gc > 0 {
		runtime.GC()
	}
	debug, _ := strconv.Atoi(r.FormValue("debug"))
	if debug != 0 {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, name))
	}
	p.WriteTo(w, debug)
}

var profileSupportsDelta = map[handler]bool{
	"allocs":        true,
	"block":         true,
	"goroutineleak": true,
	"goroutine":     true,
	"heap":          true,
	"mutex":         true,
	"threadcreate":  true,
}

var profileDescriptions = map[string]string{
	"allocs":        "A sampling of all past memory allocations",
	"block":         "Stack traces that led to blocking on synchronization primitives",
	"cmdline":       "The command line invocation of the current program",
	"goroutine":     "Stack traces of all current goroutines. Use debug=2 as a query parameter to export in the same format as an unrecovered panic.",
	"heap":          "A sampling of memory allocations of live objects. You can specify the gc GET parameter to run GC before taking the heap sample.",
	"mutex":         "Stack traces of holders of contended mutexes",
	"profile":       "CPU profile. You can specify the duration in the seconds GET parameter. After you get the profile file, use the go tool pprof command to investigate the profile.",
	"symbol":        "Maps given program counters to function names. Counters can be specified in a GET raw query or POST body, multiple counters are separated by '+'.",
	"threadcreate":  "Stack traces that led to the creation of new OS threads",
	"trace":         "A trace of execution of the current program. You can specify the duration in the seconds GET parameter. After you get the trace file, use the go tool trace command to investigate the trace.",
	"goroutineleak": "Stack traces of all leaked goroutines. Use debug=2 as a query parameter to export in the same format as an unrecovered panic.",
}

type profileEntry struct {
	Name  string
	Href  string
	Desc  string
	Count int
}

func Index(w http.ResponseWriter, r *http.Request) {
	if name, found := strings.CutPrefix(r.URL.Path, "/debug/pprof/"); found {
		if name != "" {
			handler(name).ServeHTTP(w, r)
			return
		}
	}

	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	var profiles []profileEntry
	for _, p := range pprof.Profiles() {
		profiles = append(profiles, profileEntry{
			Name:  p.Name(),
			Href:  p.Name(),
			Desc:  profileDescriptions[p.Name()],
			Count: p.Count(),
		})
	}

	for _, p := range []string{"cmdline", "profile", "symbol", "trace"} {
		profiles = append(profiles, profileEntry{
			Name: p,
			Href: p,
			Desc: profileDescriptions[p],
		})
	}

	sort.Slice(profiles, func(i, j int) bool {
		return profiles[i].Name < profiles[j].Name
	})

	if err := indexTmplExecute(w, profiles); err != nil {
		log.Print(err)
	}
}

func indexTmplExecute(w io.Writer, profiles []profileEntry) error {
	var b bytes.Buffer
	b.WriteString(`<html>
<head>
<title>/debug/pprof/</title>
<style>
.profile-name{
	display:inline-block;
	width:6rem;
}
</style>
</head>
<body>
/debug/pprof/
<br>
<p>Set debug=1 as a query parameter to export in legacy text format</p>
<br>
Types of profiles available:
<table>
<thead><td>Count</td><td>Profile</td></thead>
`)

	for _, profile := range profiles {
		link := &url.URL{Path: profile.Href, RawQuery: "debug=1"}
		fmt.Fprintf(&b, "<tr><td>%d</td><td><a href='%s'>%s</a></td></tr>\n", profile.Count, link, html.EscapeString(profile.Name))
	}

	b.WriteString(`</table>
<a href="goroutine?debug=2">full goroutine stack dump</a>
<br>
<p>
Profile Descriptions:
<ul>
`)
	for _, profile := range profiles {
		fmt.Fprintf(&b, "<li><div class=profile-name>%s: </div> %s</li>\n", html.EscapeString(profile.Name), html.EscapeString(profile.Desc))
	}
	b.WriteString(`</ul>
</p>
</body>
</html>`)

	_, err := w.Write(b.Bytes())
	return err
}
