package mipstack

import (
	"math"
	"time"
)

type cubicCongestionControl struct {
	epochStart         time.Time
	lastSend           time.Time
	applicationLimited time.Time
	lastMaximum        float64
	priorWindow        float64
	estimate           float64
	origin             float64
	k                  float64
	credit             float64
	afterTimeout       bool
	recovery cubicRecoveryCheckpoint
}

type cubicRecoveryCheckpoint struct {
	epochStart         time.Time
	lastSend           time.Time
	applicationLimited time.Time
	lastMaximum        float64
	priorWindow        float64
	estimate           float64
	origin             float64
	k                  float64
	credit             float64
	afterTimeout       bool
	valid              bool
}

func newCUBICCongestionControl() *cubicCongestionControl {
	return &cubicCongestionControl{}
}

func (c *cubicCongestionControl) HandleCongestionEvent(event *CongestionEvent) {
	switch event.Type {
	case CongestionEventACK:
		event.State.CongestionWindow = c.increaseOnACK(
			event.State.CongestionWindow,
			event.Acknowledged,
			event.State.MaximumSegmentSize,
			event.Time,
			event.State.SmoothedRTT,
			event.State.BytesInFlight,
			event.State.SlowStartThreshold,
		)
	case CongestionEventLoss:
		event.State.SlowStartThreshold = c.onCongestion(event.State.CongestionWindow, event.State.MaximumSegmentSize)
	case CongestionEventECN:
		threshold := c.onECN(event.State.CongestionWindow, event.State.MaximumSegmentSize)
		event.State.SlowStartThreshold = threshold
		event.State.CongestionWindow = threshold
	case CongestionEventTimeout:
		event.State.SlowStartThreshold = c.onTimeout(event.State.CongestionWindow, event.State.MaximumSegmentSize)
	case CongestionEventPacketSent:
		c.onSend(event.Time, event.State.BytesInFlight)
	case CongestionEventRecovery:
		switch event.Recovery.Stage {
		case CongestionRecoveryCheckpoint:
			c.saveRecoveryCheckpoint()
		case CongestionRecoveryUndo:
			c.restoreRecoveryCheckpoint()
		}
	case CongestionEventMTUChanged:
		*c = cubicCongestionControl{}
	}
}

func (c *cubicCongestionControl) increaseOnACK(window, acknowledged uint32, mss int, now time.Time, smoothedRTT time.Duration, flight, slowStartThreshold uint32) uint32 {
	if !congestionWindowLimited(window, flight, mss) {
		c.onApplicationLimited(now)
		return window
	}
	window, acknowledged = applySlowStart(window, acknowledged, slowStartThreshold)
	if acknowledged == 0 {
		return window
	}
	return c.onACK(window, acknowledged, mss, now, smoothedRTT)
}

func (c *cubicCongestionControl) saveRecoveryCheckpoint() {
	c.recovery = cubicRecoveryCheckpoint{
		epochStart: c.epochStart, lastSend: c.lastSend, applicationLimited: c.applicationLimited,
		lastMaximum: c.lastMaximum, priorWindow: c.priorWindow, estimate: c.estimate,
		origin: c.origin, k: c.k, credit: c.credit, afterTimeout: c.afterTimeout, valid: true,
	}
}

func (c *cubicCongestionControl) restoreRecoveryCheckpoint() {
	checkpoint := c.recovery
	if !checkpoint.valid {
		return
	}
	c.epochStart = checkpoint.epochStart
	c.lastSend = checkpoint.lastSend
	c.applicationLimited = checkpoint.applicationLimited
	c.lastMaximum = checkpoint.lastMaximum
	c.priorWindow = checkpoint.priorWindow
	c.estimate = checkpoint.estimate
	c.origin = checkpoint.origin
	c.k = checkpoint.k
	c.credit = checkpoint.credit
	c.afterTimeout = checkpoint.afterTimeout
	c.recovery.valid = false
}

func (c *cubicCongestionControl) onSend(now time.Time, flight uint32) {
	if !c.applicationLimited.IsZero() {
		if !c.epochStart.IsZero() && now.After(c.applicationLimited) {
			c.epochStart = c.epochStart.Add(now.Sub(c.applicationLimited))
		}
		c.applicationLimited = time.Time{}
	} else if flight == 0 && !c.epochStart.IsZero() && !c.lastSend.IsZero() && now.After(c.lastSend) {
		c.epochStart = c.epochStart.Add(now.Sub(c.lastSend))
	}
	c.lastSend = now
}

func (c *cubicCongestionControl) onApplicationLimited(now time.Time) {
	if c.applicationLimited.IsZero() {
		c.applicationLimited = now
	}
}

func (c *cubicCongestionControl) onCongestion(window uint32, mss int) uint32 {
	return c.reduce(window, mss, 2)
}

func (c *cubicCongestionControl) onECN(window uint32, mss int) uint32 {
	return c.reduce(window, mss, 1)
}

func (c *cubicCongestionControl) reduce(window uint32, mss, minimumSegments int) uint32 {
	current := float64(window) / float64(mss)
	if c.lastMaximum != 0 && current < c.lastMaximum {
		c.lastMaximum = current * 0.85
	} else {
		c.lastMaximum = current
	}
	c.epochStart = time.Time{}
	c.applicationLimited = time.Time{}
	c.priorWindow = current
	c.estimate = 0
	c.credit = 0
	c.afterTimeout = false
	return congestionThresholdWithFloor(window, mss, 7, 10, minimumSegments)
}

func (c *cubicCongestionControl) onTimeout(window uint32, mss int) uint32 {
	c.epochStart = time.Time{}
	c.lastSend = time.Time{}
	c.applicationLimited = time.Time{}
	c.lastMaximum = 0
	c.priorWindow = float64(window) / float64(mss)
	c.estimate = 0
	c.origin = 0
	c.k = 0
	c.credit = 0
	c.afterTimeout = true
	return congestionThreshold(window, mss, 7, 10)
}

func (c *cubicCongestionControl) onACK(window, acknowledged uint32, mss int, now time.Time, smoothedRTT time.Duration) uint32 {
	if window == 0 || acknowledged == 0 || mss < 1 {
		return window
	}
	current := float64(window) / float64(mss)
	if c.epochStart.IsZero() {
		c.epochStart = now
		c.estimate = current
		if c.afterTimeout {
			c.lastMaximum = current
			c.origin = current
			c.k = 0
			c.afterTimeout = false
		} else if c.lastMaximum > current {
			c.origin = c.lastMaximum
			c.k = math.Cbrt((c.lastMaximum - current) / 0.4)
		} else {
			c.origin = current
			c.k = 0
		}
	}
	alpha := float64(9) / 17
	if c.priorWindow > 0 && c.estimate >= c.priorWindow {
		alpha = 1
	}
	c.estimate += alpha * float64(acknowledged) / float64(window)
	elapsed := now.Sub(c.epochStart).Seconds()
	curve := 0.4*math.Pow(elapsed-c.k, 3) + c.origin
	target := 0.4*math.Pow(elapsed+smoothedRTT.Seconds()-c.k, 3) + c.origin
	if target < current {
		target = current
	} else if maximum := 1.5 * current; target > maximum {
		target = maximum
	}
	increment := float64(0)
	if curve < c.estimate {
		increment = (c.estimate - current) * float64(mss)
	} else if target > current {
		increment = float64(acknowledged) * (target - current) / current
	}
	return applyCongestionIncrease(window, &c.credit, increment)
}
