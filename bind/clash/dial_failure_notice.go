package clash

import (
	"errors"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ProjectClash/Clash/log"
	"github.com/ProjectClash/Clash/tunnel"
)

const consecutiveDialFailuresBeforeNotice = 20

var dialFailureWatch struct {
	sync.Mutex
	consecutive int
	firstError  string
	firstErr    error
	firstAt     time.Time
	announced   bool
}

func init() {
	tunnel.SetDialOutcomeObserver(observeDialOutcomeForNotice)
}

func observeDialOutcomeForNotice(err error) {
	dialFailureWatch.Lock()
	defer dialFailureWatch.Unlock()

	if err == nil {
		dialFailureWatch.consecutive = 0
		dialFailureWatch.firstError = ""
		dialFailureWatch.firstErr = nil
		dialFailureWatch.firstAt = time.Time{}
		dialFailureWatch.announced = false
		return
	}

	reason := err.Error()
	if dialFailureWatch.consecutive == 0 {
		dialFailureWatch.firstError = reason
		dialFailureWatch.firstErr = err
		dialFailureWatch.firstAt = time.Now()
	} else if !sameDialFailure(dialFailureWatch.firstError, reason) {
		dialFailureWatch.firstError = reason
		dialFailureWatch.firstErr = err
		dialFailureWatch.firstAt = time.Now()
		dialFailureWatch.consecutive = 1
		return
	}

	dialFailureWatch.consecutive++
	if dialFailureWatch.consecutive < consecutiveDialFailuresBeforeNotice || dialFailureWatch.announced {
		return
	}
	dialFailureWatch.announced = true

	log.Warnln("[Apple] %d outbound connections in a row failed and none succeeded: %s. %s",
		dialFailureWatch.consecutive, reason, dialFailureAdvice(err))
}

func DialHealthJSON() string {
	dialFailureWatch.Lock()
	defer dialFailureWatch.Unlock()

	health := map[string]any{
		"consecutive": dialFailureWatch.consecutive,
		"announced":   dialFailureWatch.announced,
	}
	if dialFailureWatch.firstErr != nil {
		health["firstError"] = dialFailureWatch.firstError
		health["advice"] = dialFailureAdvice(dialFailureWatch.firstErr)
	}
	if !dialFailureWatch.firstAt.IsZero() {
		health["sinceUnix"] = dialFailureWatch.firstAt.Unix()
	}
	return bridgeSafeString(mustJSON(health))
}

func sameDialFailure(first, second string) bool {
	return dialFailureTail(first) == dialFailureTail(second)
}

func dialFailureTail(reason string) string {
	if index := strings.LastIndex(reason, ": "); index >= 0 {
		return reason[index+2:]
	}
	return reason
}

func dialFailureAdvice(err error) string {
	switch {
	case errors.Is(err, syscall.EPERM):
		return "the operating system is refusing this process permission to connect, which on " +
			"Apple platforms usually means the app extension is missing the client-network " +
			"entitlement, or a local firewall is blocking it"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "the destinations are reachable but refusing the connection"
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
		return "no route to the destinations; check whether the device has network access at all"
	default:
		return "the tunnel reports itself connected, so this is happening after the tunnel came up"
	}
}
