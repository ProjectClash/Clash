package smux

import (
	"sync"
	"sync/atomic"
)

var liveSessions sync.Map

func UnreadBytes() (bytes int64, sessions int) {
	liveSessions.Range(func(key, _ any) bool {
		s := key.(*Session)
		sessions++
		if held := int64(s.config.MaxReceiveBuffer) - int64(atomic.LoadInt32(&s.bucket)); held > 0 {
			bytes += held
		}
		return true
	})
	return bytes, sessions
}
