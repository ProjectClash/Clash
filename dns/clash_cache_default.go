package dns

import "sync/atomic"

var clashDefaultCacheMaxSize atomic.Int64

func ClashSetDefaultCacheMaxSize(n int) { clashDefaultCacheMaxSize.Store(int64(n)) }

func ClashDefaultCacheMaxSize() int {
	if n := clashDefaultCacheMaxSize.Load(); n > 0 {
		return int(n)
	}
	return 4096
}
