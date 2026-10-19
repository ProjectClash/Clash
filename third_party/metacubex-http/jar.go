// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package http

import (
	"net/url"
)

type CookieJar interface {
	SetCookies(u *url.URL, cookies []*Cookie)

	Cookies(u *url.URL) []*Cookie
}
