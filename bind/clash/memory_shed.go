package clash

import (
	"time"
)

const (
	shedReleaseEnterMargins = 4
	shedReleaseExitMargins  = 5
	shedPaceEnterMargins    = 2
	shedPaceExitMargins     = 3
	shedLineMargins         = 1
	shedExitHalfMargins     = 3
	shedHardGap             = 1 << 20

	shedReleaseEvery  = 10 * time.Second
	shedReleaseGrowth = 1 << 20
	shedReleaseClosed = 4

	shedBatch           = 4
	shedSettle          = 300 * time.Millisecond
	shedEpisodeShare    = 4
	shedPaidShare       = 2
	shedNodeResetWait   = 10 * time.Second
	shedCooldown        = 2 * time.Second
	shedCooldownMax     = time.Minute
	shedCloseStreak     = 2
	shedCloseBackoffMin = 10 * time.Second
	shedCloseBackoffMax = time.Minute
)

type shedLines struct {
	mode                      thresholdMode
	releaseEnter, releaseExit uint64
	paceEnter, paceExit, shed uint64
	shedExit, hard            uint64
}

func computeShedLines(mode thresholdMode, limit uint64) shedLines {
	lines := shedLines{mode: mode}
	if mode != thresholdModeLimit || limit == 0 {
		return lines
	}
	under := func(gap uint64) uint64 {
		if gap < limit {
			return limit - gap
		}
		return 0
	}
	below := func(margins uint64) uint64 { return under(margins * pressureSafetyMargin) }
	lines.releaseEnter, lines.releaseExit = below(shedReleaseEnterMargins), below(shedReleaseExitMargins)
	lines.paceEnter, lines.paceExit = below(shedPaceEnterMargins), below(shedPaceExitMargins)
	lines.shed = below(shedLineMargins)
	lines.shedExit = under(shedExitHalfMargins * pressureSafetyMargin / 2)
	lines.hard = under(shedHardGap)
	return lines
}

func (l shedLines) at(sample pressureSample, line uint64) bool {
	return l.mode == thresholdModeLimit && line > 0 && sample.usage >= line
}

type shedLadder struct {
	release, pace    bool
	lastRelease      time.Time
	lastReleaseUsage uint64
	lastReleaseConns int
	cooldownUntil    time.Time
	backoff          time.Duration
	lastEpisode      time.Time
	closeStreak      int
	closeAfter       time.Time
	closeBackoff     time.Duration
}

type shedStep struct {
	release, pace               bool
	releaseChanged, paceChanged bool
	freeMemory                  bool
	shed                        bool
	mayClose                    bool
}

func (l *shedLadder) step(lines shedLines, sample pressureSample, predicted bool, now time.Time) shedStep {
	var out shedStep
	switch {
	case !l.release && lines.at(sample, lines.releaseEnter):
		l.release, out.releaseChanged, out.freeMemory = true, true, true
		l.lastRelease, l.lastReleaseUsage, l.lastReleaseConns = now, sample.usage, sample.connections
	case l.release && !lines.at(sample, lines.releaseExit):
		l.release, out.releaseChanged = false, true
	case l.release && lines.at(sample, lines.releaseEnter) && now.Sub(l.lastRelease) >= shedReleaseEvery &&
		(sample.usage >= l.lastReleaseUsage+shedReleaseGrowth || sample.connections <= l.lastReleaseConns-shedReleaseClosed):
		out.freeMemory = true
		l.lastRelease, l.lastReleaseUsage, l.lastReleaseConns = now, sample.usage, sample.connections
	}
	switch {
	case !l.pace && lines.at(sample, lines.paceEnter):
		l.pace, out.paceChanged = true, true
	case l.pace && !lines.at(sample, lines.paceExit):
		l.pace, out.paceChanged = false, true
		l.cooldownUntil, l.backoff = time.Time{}, 0
		l.resetCloseBackoff()
	}
	if !lines.at(sample, lines.shedExit) {
		l.resetCloseBackoff()
	}
	ready := !now.Before(l.cooldownUntil) || (lines.at(sample, lines.hard) && now.Sub(l.lastEpisode) >= shedCooldown)
	if (lines.at(sample, lines.shed) || (predicted && lines.mode == thresholdModeLimit)) && ready {
		out.shed = true
		out.mayClose = !now.Before(l.closeAfter)
	}
	out.release, out.pace = l.release, l.pace
	return out
}

func (l *shedLadder) resetCloseBackoff() {
	l.closeStreak, l.closeBackoff, l.closeAfter = 0, 0, time.Time{}
}

func (l *shedLadder) episodeDone(result shedEpisodeResult, now time.Time) {
	l.lastEpisode = now
	switch {
	case result.reason == shedReasonNodeReset:
		l.backoff = 0
		l.resetCloseBackoff()
		l.cooldownUntil = now.Add(shedNodeResetWait)
	case result.closed > 0 && result.closesPaid:
		l.backoff = 0
		l.resetCloseBackoff()
		l.cooldownUntil = now.Add(shedCooldown)
	case result.closed > 0:
		l.closeStreak++
		if l.closeStreak >= shedCloseStreak {
			l.closeBackoff = min(max(shedCloseBackoffMin, l.closeBackoff*2), shedCloseBackoffMax)
			l.closeAfter = now.Add(l.closeBackoff)
		}
		l.cooldownUntil = now.Add(max(shedCooldown, l.backoff))
	case result.reason == shedReasonReleased:
		l.cooldownUntil = now.Add(shedCooldown)
	default:
		if l.backoff == 0 {
			l.backoff = shedCooldown
		} else {
			l.backoff = min(l.backoff*2, shedCooldownMax)
		}
		l.cooldownUntil = now.Add(max(shedCooldown, l.backoff))
	}
}

type shedEpisodeDeps struct {
	sample     func() pressureSample
	candidates func() []shedCandidate
	closeOne   func(shedCandidate)
	resetNode  func(node string)
	free       func()
	settle     func(time.Duration) bool
}

type shedEpisodeResult struct {
	present    int
	closed     int
	nodesReset int
	freed      int64
	closesPaid bool
	reason     string
}

const (
	shedReasonUnderLine        = "back under the line"
	shedReasonCap              = "episode cap (a quarter of the connections)"
	shedReasonTooLittle        = "the batch freed too little"
	shedReasonNoCandidate      = "no candidates"
	shedReasonStopped          = "stopped"
	shedReasonReportOnly       = "report only"
	shedReasonReleased         = "a release alone got under the line"
	shedReasonCloseBackoff     = "closes did not pay recently; released only"
	shedReasonNotInConnections = "the connections hold less than the excess"
	shedReasonNodeReset        = "a wedged node was shed whole and its session reset"
)

func (r shedEpisodeResult) ineffective() bool {
	if r.closed > 0 {
		return !r.closesPaid
	}
	return r.reason != shedReasonReleased
}

func runShedEpisode(lines shedLines, deps shedEpisodeDeps, mayClose bool) shedEpisodeResult {
	var result shedEpisodeResult
	deps.free()
	first := deps.sample()
	if !lines.at(first, lines.shed) {
		result.reason = shedReasonReleased
		return result
	}
	if !mayClose && !lines.at(first, lines.hard) {
		result.reason = shedReasonCloseBackoff
		return result
	}
	before := first
	candidates := deps.candidates()
	result.present = len(candidates)
	budget := (result.present + shedEpisodeShare - 1) / shedEpisodeShare
	if !anyStalled(candidates) {
		var total int64
		for _, candidate := range candidates {
			total += candidate.weight
		}
		if over := int64(first.usage) - int64(lines.shed); total < over && len(candidates) > 0 {
			result.reason = shedReasonNotInConnections
			return result
		}
	}
	closed := map[string]bool{}
	ordinary := 0
	for {
		batch := nextShedBatch(candidates, closed, budget-ordinary)
		if len(batch) == 0 {
			if ordinary > 0 && ordinary >= budget {
				result.reason = shedReasonCap
			} else {
				result.reason = shedReasonNoCandidate
			}
			break
		}
		var weight int64
		for _, candidate := range batch {
			closed[candidate.id] = true
			deps.closeOne(candidate)
			weight += candidate.weight
			if candidate.group == "" {
				ordinary++
			}
		}
		group := batch[0].group
		if group != "" && deps.resetNode != nil {
			deps.resetNode(group)
			result.nodesReset++
		}
		result.closed += len(batch)
		if !deps.settle(shedSettle) {
			result.reason = shedReasonStopped
			break
		}
		deps.free()
		after := deps.sample()
		result.freed = signedDiff(first, after)
		if group != "" {
			result.closesPaid = true
			result.reason = shedReasonNodeReset
			break
		}
		paid := signedDiff(before, after) >= weight/shedPaidShare
		if paid {
			result.closesPaid = true
		}
		if !lines.at(after, lines.shed) {
			result.reason = shedReasonUnderLine
			break
		}
		if !paid && !anyStalled(batch) {
			result.reason = shedReasonTooLittle
			break
		}
		before = after
		candidates = deps.candidates()
	}
	return result
}

func nextShedBatch(candidates []shedCandidate, closed map[string]bool, capLeft int) []shedCandidate {
	var head *shedCandidate
	for i := range candidates {
		if !closed[candidates[i].id] {
			head = &candidates[i]
			break
		}
	}
	if head == nil {
		return nil
	}
	var batch []shedCandidate
	if head.group != "" {
		for _, candidate := range candidates {
			if !closed[candidate.id] && candidate.group == head.group {
				batch = append(batch, candidate)
			}
		}
		return batch
	}
	for _, candidate := range candidates {
		if len(batch) == shedBatch || len(batch) >= capLeft {
			break
		}
		if !closed[candidate.id] && candidate.group == "" {
			batch = append(batch, candidate)
		}
	}
	return batch
}

func anyStalled(batch []shedCandidate) bool {
	for _, candidate := range batch {
		if candidate.stalled() {
			return true
		}
	}
	return false
}

func signedDiff(before, after pressureSample) int64 {
	return int64(before.usage) - int64(after.usage)
}
