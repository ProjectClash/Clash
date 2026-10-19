// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
	"github.com/metacubex/http/pprof"
	"log"
	"runtime"
)

func main() {
	runtime.SetMutexProfileFraction(0)

	h := pprof.Handler("mutex")

	req := httptest.NewRequest("GET", "/debug/pprof/mutex?seconds=1", nil)
	rec := httptest.NewRecorder()
	rec.Body = new(bytes.Buffer)

	h.ServeHTTP(rec, req)
	resp := rec.Result()
	if resp.StatusCode != http.StatusOK {
		log.Fatalf("Request failed: %s\n%s", resp.Status, rec.Body)
	}

	fmt.Print(rec.Body)
}
