package outboundgroup

import (
	"slices"
	"sync"

	P "github.com/ProjectClash/Clash/constant/provider"
)

func healthCheckAfterDialFailures(pd P.ProxyProvider, failed []string) {
	if windowed, ok := pd.(interface{ HealthCheckAfterDialFailures(failed ...string) }); ok {
		windowed.HealthCheckAfterDialFailures(failed...)
		return
	}
	pd.HealthCheck()
}

const failedMembersLimit = 16

type failedMembers struct {
	mu    sync.Mutex
	names []string
}

func (f *failedMembers) note(name string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.names = slices.DeleteFunc(f.names, func(known string) bool { return known == name })
	f.names = append(f.names, name)
	if extra := len(f.names) - failedMembersLimit; extra > 0 {
		f.names = slices.Delete(f.names, 0, extra)
	}
}

func (f *failedMembers) take() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	names := f.names
	f.names = nil
	return names
}
