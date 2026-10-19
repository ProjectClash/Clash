//go:build go1.21

package http

import "context"

var contextAfterFunc = context.AfterFunc
var contextWithoutCancel = context.WithoutCancel
