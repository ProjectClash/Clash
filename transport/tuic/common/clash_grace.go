package common

import (
	"time"
	"weak"
)

func AfterGrace[T any](d time.Duration, conn *T, fn func(*T)) {
	held := weak.Make(conn)
	time.AfterFunc(d, func() { fn(held.Value()) })
}
