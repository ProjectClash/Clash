// Copyright 2025 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http

import (
	"errors"
	"fmt"
	"net/url"
	"sync"
	"sync/atomic"
)

type CrossOriginProtection struct {
	bypass    atomic.Pointer[ServeMux]
	trustedMu sync.RWMutex
	trusted   map[string]bool
	deny      atomic.Pointer[Handler]
}

func NewCrossOriginProtection() *CrossOriginProtection {
	return &CrossOriginProtection{}
}

func (c *CrossOriginProtection) AddTrustedOrigin(origin string) error {
	u, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("invalid origin %q: %w", origin, err)
	}
	if u.Scheme == "" {
		return fmt.Errorf("invalid origin %q: scheme is required", origin)
	}
	if u.Host == "" {
		return fmt.Errorf("invalid origin %q: host is required", origin)
	}
	if u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("invalid origin %q: path, query, and fragment are not allowed", origin)
	}
	c.trustedMu.Lock()
	defer c.trustedMu.Unlock()
	if c.trusted == nil {
		c.trusted = make(map[string]bool)
	}
	c.trusted[origin] = true
	return nil
}

type noopHandler struct{}

func (noopHandler) ServeHTTP(ResponseWriter, *Request) {}

var sentinelHandler Handler = &noopHandler{}

func (c *CrossOriginProtection) AddInsecureBypassPattern(pattern string) {
	var bypass *ServeMux

	for {
		bypass = c.bypass.Load()
		if bypass != nil {
			break
		}
		bypass = NewServeMux()
		if c.bypass.CompareAndSwap(nil, bypass) {
			break
		}
	}

	bypass.Handle(pattern, sentinelHandler)
}

func (c *CrossOriginProtection) SetDenyHandler(h Handler) {
	if h == nil {
		c.deny.Store(nil)
		return
	}
	c.deny.Store(&h)
}

func (c *CrossOriginProtection) Check(req *Request) error {
	switch req.Method {
	case "GET", "HEAD", "OPTIONS":
		return nil
	}

	switch req.Header.Get("Sec-Fetch-Site") {
	case "":
	case "same-origin", "none":
		return nil
	default:
		if c.isRequestExempt(req) {
			return nil
		}
		return errCrossOriginRequest
	}

	origin := req.Header.Get("Origin")
	if origin == "" {
		return nil
	}

	if o, err := url.Parse(origin); err == nil && o.Host == req.Host {
		return nil
	}

	if c.isRequestExempt(req) {
		return nil
	}
	return errCrossOriginRequestFromOldBrowser
}

var (
	errCrossOriginRequest               = errors.New("cross-origin request detected from Sec-Fetch-Site header")
	errCrossOriginRequestFromOldBrowser = errors.New("cross-origin request detected, and/or browser is out of date: " +
		"Sec-Fetch-Site is missing, and Origin does not match Host")
)

func (c *CrossOriginProtection) isRequestExempt(req *Request) bool {
	if bypass := c.bypass.Load(); bypass != nil {
		if h, _ := bypass.Handler(req); h == sentinelHandler {
			return true
		}
	}

	c.trustedMu.RLock()
	defer c.trustedMu.RUnlock()
	origin := req.Header.Get("Origin")
	return origin != "" && c.trusted[origin]
}

func (c *CrossOriginProtection) Handler(h Handler) Handler {
	return HandlerFunc(func(w ResponseWriter, r *Request) {
		if err := c.Check(r); err != nil {
			if deny := c.deny.Load(); deny != nil {
				(*deny).ServeHTTP(w, r)
				return
			}
			Error(w, err.Error(), StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})
}
