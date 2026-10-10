package clash

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ProjectClash/Clash/config"
	"github.com/ProjectClash/Clash/hub/executor"
)

var startupPhaseFailure string

func StartupPhaseDiagnostic() string {
	phaseMu.Lock()
	diagnostic := "path=" + setupStartupPhaseLogPath + " err=" + startupPhaseFailure
	phaseMu.Unlock()
	return bridgeSafeString(diagnostic)
}

var startupProbing atomic.Bool

func startupStage(name string) {
	startupStageNaming(name, "")
}

func startupStageNaming(name string, resource string) {
	startupStageNamingPeak(name, resource, 0)
}

func startupStageNamingPeak(name string, resource string, peakBytes int64) {
	if startupProbing.Load() {
		startupPhaseWithPeak(name, peakBytes)
	}
	if breadcrumbRecording.Load() {
		recordStartupStageNaming(name, resource)
	}
}

func startupStageCounting(name string, count int64) {
	if startupProbing.Load() {
		startupPhaseLine(name, 0, count)
	}
	if breadcrumbRecording.Load() {
		recordStartupStageCounting(name, count)
	}
}

func nodeListBegin(section string) (nodes int64, ok bool) {
	rest, matched := strings.CutPrefix(section, "proxies-begin:")
	if !matched {
		return 0, false
	}
	nodes, err := strconv.ParseInt(rest, 10, 64)
	return nodes, err == nil
}

func providerStepKind(step string) (resource string, begin bool, ok bool) {
	for _, candidate := range []struct {
		prefix string
		kind   string
		begin  bool
	}{
		{"rule-provider-begin:", "rule-provider:", true},
		{"proxy-provider-begin:", "proxy-provider:", true},
		{"rule-provider:", "rule-provider:", false},
		{"proxy-provider:", "proxy-provider:", false},
	} {
		if rest, matched := strings.CutPrefix(step, candidate.prefix); matched {
			return candidate.kind + rest, candidate.begin, true
		}
	}
	return "", false, false
}

func armStartupProbes() func() {
	startupProbing.Store(true)
	config.StartupProbe = func(section string) {
		if nodes, ok := nodeListBegin(section); ok {
			startupStageCounting("parse:proxies-begin", nodes)
			return
		}
		startupStage("parse:" + section)
	}
	executor.StartupProbe = func(step string) {
		resource, begin, isProvider := providerStepKind(step)
		switch {
		case isProvider && begin:
			startupStageNaming("apply:"+step, resource)
			startProviderPeakSampling(resource)
		case isProvider:
			peak := stopProviderPeakSampling(resource)
			startupStageNamingPeak("apply:"+step, resource, peak)
		default:
			startupStage("apply:" + step)
		}
	}
	executor.SerializeProviderLoads = func() bool {
		return startupPhaseLogPath() != ""
	}
	return func() {
		startupProbing.Store(false)
		config.StartupProbe = nil
		executor.StartupProbe = nil
		stopAnyProviderPeakSampling()
	}
}

var breadcrumbRecording atomic.Bool

func setStartupBreadcrumbRecording(on bool) { breadcrumbRecording.Store(on) }

func StartupPhaseTrace() string {
	phaseMu.Lock()
	defer phaseMu.Unlock()
	return bridgeSafeString(strings.Join(phaseTrace, "\n"))
}

var (
	phaseMu                 sync.Mutex
	phaseTrace              []string
	phaseEpoch              = newStartupPhaseEpoch()
	phaseLogGeneration      uint64
	phaseDiagnosticRevision int64
	phaseFailureSequence    int64
)

func startupPhase(name string) {
	startupPhaseWithPeak(name, 0)
}

func startupPhaseWithPeak(name string, peakBytes int64) {
	startupPhaseLine(name, peakBytes, 0)
}

func startupPhaseLine(name string, peakBytes int64, count int64) {
	line := fmt.Sprintf("%s  go-phase=%-24s fp=%.1fMiB",
		time.Now().Format("15:04:05.000"),
		name, float64(MemoryFootprint())/(1024*1024))
	if peakBytes > 0 {
		line += fmt.Sprintf(" peak=%.1fMiB", float64(peakBytes)/(1024*1024))
	}
	if count > 0 {
		line += fmt.Sprintf(" count=%d", count)
	}
	phaseMu.Lock()
	phaseTrace = append(phaseTrace, line)
	sequence := int64(len(phaseTrace))
	path := setupStartupPhaseLogPath
	generation := phaseLogGeneration
	phaseMu.Unlock()
	if path == "" {
		return
	}
	stamped := line + "\n"
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		recordStartupPhaseFailure(generation, sequence, fmt.Errorf("open: %w", err))
		return
	}
	if err := writeStartupPhaseRecord(file, stamped); err != nil {
		recordStartupPhaseFailure(generation, sequence, err)
	}
}

func startupPhaseLogPath() string {
	phaseMu.Lock()
	defer phaseMu.Unlock()
	return setupStartupPhaseLogPath
}

func configureStartupPhaseLogPath(path string) {
	phaseMu.Lock()
	defer phaseMu.Unlock()
	phaseLogGeneration++
	setupStartupPhaseLogPath = path
	startupPhaseFailure = ""
	phaseFailureSequence = 0
	phaseDiagnosticRevision++
}

func recordStartupPhaseFailure(generation uint64, sequence int64, err error) {
	phaseMu.Lock()
	defer phaseMu.Unlock()
	if generation != phaseLogGeneration {
		return
	}
	startupPhaseFailure = err.Error()
	phaseFailureSequence = sequence
	phaseDiagnosticRevision++
}

func writeStartupPhaseRecord(file io.WriteCloser, line string) error {
	written, err := io.WriteString(file, line)
	if err == nil && written != len(line) {
		err = io.ErrShortWrite
	}
	closeErr := file.Close()
	if err != nil {
		if closeErr != nil {
			return fmt.Errorf("write: %v; close: %w", err, closeErr)
		}
		return fmt.Errorf("write: %w", err)
	}
	if closeErr != nil {
		return fmt.Errorf("close: %w", closeErr)
	}
	return nil
}
