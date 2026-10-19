// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build ignore

package main

import (
	"expvar"
	"flag"
	"fmt"
	"github.com/metacubex/http"
	"io"
	"log"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

var helloRequests = expvar.NewInt("hello-requests")

func HelloServer(w http.ResponseWriter, req *http.Request) {
	helloRequests.Add(1)
	io.WriteString(w, "hello, world!\n")
}

type Counter struct {
	mu sync.Mutex
	n  int
}

func (ctr *Counter) String() string {
	ctr.mu.Lock()
	defer ctr.mu.Unlock()
	return strconv.Itoa(ctr.n)
}

func (ctr *Counter) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	ctr.mu.Lock()
	defer ctr.mu.Unlock()
	switch req.Method {
	case "GET":
		ctr.n++
	case "POST":
		var buf strings.Builder
		io.Copy(&buf, req.Body)
		body := buf.String()
		if n, err := strconv.Atoi(body); err != nil {
			fmt.Fprintf(w, "bad POST: %v\nbody: [%v]\n", err, body)
		} else {
			ctr.n = n
			fmt.Fprint(w, "counter reset\n")
		}
	}
	fmt.Fprintf(w, "counter = %d\n", ctr.n)
}

var booleanflag = flag.Bool("boolean", true, "another flag for testing")

func FlagServer(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprint(w, "Flags:\n")
	flag.VisitAll(func(f *flag.Flag) {
		if f.Value.String() != f.DefValue {
			fmt.Fprintf(w, "%s = %s [default = %s]\n", f.Name, f.Value.String(), f.DefValue)
		} else {
			fmt.Fprintf(w, "%s = %s\n", f.Name, f.Value.String())
		}
	})
}

func ArgServer(w http.ResponseWriter, req *http.Request) {
	for _, s := range os.Args {
		fmt.Fprint(w, s, " ")
	}
}

type Chan chan int

func ChanCreate() Chan {
	c := make(Chan)
	go func(c Chan) {
		for x := 0; ; x++ {
			c <- x
		}
	}(c)
	return c
}

func (ch Chan) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	io.WriteString(w, fmt.Sprintf("channel send #%d\n", <-ch))
}

func DateServer(rw http.ResponseWriter, req *http.Request) {
	rw.Header().Set("Content-Type", "text/plain; charset=utf-8")

	date, err := exec.Command("/bin/date").Output()
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	rw.Write(date)
}

func Logger(w http.ResponseWriter, req *http.Request) {
	log.Print(req.URL)
	http.Error(w, "oops", http.StatusNotFound)
}

var webroot = flag.String("root", "", "web root directory")

func main() {
	flag.Parse()

	ctr := new(Counter)
	expvar.Publish("counter", ctr)
	http.Handle("/counter", ctr)
	http.Handle("/", http.HandlerFunc(Logger))
	if *webroot != "" {
		http.Handle("/go/", http.StripPrefix("/go/", http.FileServer(http.Dir(*webroot))))
	}
	http.Handle("/chan", ChanCreate())
	http.HandleFunc("/flags", FlagServer)
	http.HandleFunc("/args", ArgServer)
	http.HandleFunc("/go/hello", HelloServer)
	http.HandleFunc("/date", DateServer)
	log.Fatal(http.ListenAndServe("localhost:12345", nil))
}
