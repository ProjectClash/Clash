// Copyright 2010 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !with_low_memory

package pprof

import (
	"bytes"
	"context"
	"fmt"
	"runtime/pprof"
	"strconv"
	"time"

	"github.com/google/pprof/profile"
	"github.com/metacubex/http"
)

const deltaProfilesServed = true

func (name handler) serveDeltaProfile(w http.ResponseWriter, r *http.Request, p *pprof.Profile, secStr string) {
	sec, err := strconv.ParseInt(secStr, 10, 64)
	if err != nil || sec <= 0 {
		serveError(w, http.StatusBadRequest, `invalid value for "seconds" - must be a positive integer`)
		return
	}
	if !profileSupportsDelta[name] {
		serveError(w, http.StatusBadRequest, `"seconds" parameter is not supported for this profile type`)
		return
	}

	configureWriteDeadline(w, r, float64(sec))

	debug, _ := strconv.Atoi(r.FormValue("debug"))
	if debug != 0 {
		serveError(w, http.StatusBadRequest, "seconds and debug params are incompatible")
		return
	}
	p0, err := collectProfile(p)
	if err != nil {
		serveError(w, http.StatusInternalServerError, "failed to collect profile")
		return
	}

	t := time.NewTimer(time.Duration(sec) * time.Second)
	defer t.Stop()

	select {
	case <-r.Context().Done():
		err := r.Context().Err()
		if err == context.DeadlineExceeded {
			serveError(w, http.StatusRequestTimeout, err.Error())
		} else {
			serveError(w, http.StatusInternalServerError, err.Error())
		}
		return
	case <-t.C:
	}

	p1, err := collectProfile(p)
	if err != nil {
		serveError(w, http.StatusInternalServerError, "failed to collect profile")
		return
	}
	ts := p1.TimeNanos
	dur := p1.TimeNanos - p0.TimeNanos

	p0.Scale(-1)

	p1, err = profile.Merge([]*profile.Profile{p0, p1})
	if err != nil {
		serveError(w, http.StatusInternalServerError, "failed to compute delta")
		return
	}

	p1.TimeNanos = ts
	p1.DurationNanos = dur

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s-delta"`, name))
	p1.Write(w)
}

func collectProfile(p *pprof.Profile) (*profile.Profile, error) {
	var buf bytes.Buffer
	if err := p.WriteTo(&buf, 0); err != nil {
		return nil, err
	}
	ts := time.Now().UnixNano()
	p0, err := profile.Parse(&buf)
	if err != nil {
		return nil, err
	}
	p0.TimeNanos = ts
	return p0, nil
}
