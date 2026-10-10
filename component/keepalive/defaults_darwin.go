//go:build darwin

package keepalive

import "time"

const (
	defaultKeepAliveIdle     = 5 * time.Minute
	defaultKeepAliveInterval = 75 * time.Second
)
