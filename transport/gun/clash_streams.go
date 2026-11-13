package gun

import "sync/atomic"

var streamsOpen atomic.Int64

func StreamsOpen() int64 { return streamsOpen.Load() }
