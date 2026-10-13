package provider

import (
	"context"
	"sync/atomic"
	"time"
)

var backgroundRoundHold atomic.Pointer[func(ctx context.Context) error]

func SetBackgroundRoundHold(hold func(ctx context.Context) error) {
	if hold == nil {
		backgroundRoundHold.Store(nil)
		return
	}
	backgroundRoundHold.Store(&hold)
}

func holdBackgroundRound(ctx context.Context) bool {
	hold := backgroundRoundHold.Load()
	if hold == nil {
		return true
	}
	return (*hold)(ctx) == nil && ctx.Err() == nil
}

func scheduledRoundBegan(ctx context.Context, asked time.Time) (time.Time, bool) {
	if backgroundRoundHold.Load() == nil {
		return asked, true
	}
	if !holdBackgroundRound(ctx) {
		return time.Time{}, false
	}
	return time.Now(), true
}

var roundLimit atomic.Pointer[func() int]

func SetRoundConcurrency(limit func() int) {
	if limit == nil {
		roundLimit.Store(nil)
		return
	}
	roundLimit.Store(&limit)
}

func roundConcurrency() int {
	if limit := roundLimit.Load(); limit != nil {
		if n := (*limit)(); n > 0 {
			return n
		}
	}
	return 10
}

func RoundConcurrencyForTest() int { return roundConcurrency() }
