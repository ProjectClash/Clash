package hysteria2

import (
	"time"
)

const (
	DefaultStreamReceiveWindow = 8388608
	DefaultConnReceiveWindow   = DefaultStreamReceiveWindow * 5 / 2
	DefaultMaxIdleTimeout      = 30 * time.Second
	DefaultKeepAlivePeriod     = 10 * time.Second
)
