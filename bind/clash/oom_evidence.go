package clash

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ProjectClash/Clash/tunnel/statistic"
	tun "github.com/metacubex/sing-tun"
)

const (
	oomEvidenceSchemaVersion = 3
	oomEvidenceFileName      = "clash-oom-evidence.json"
	oomEvidenceMaxBytes      = 4 << 10
	oomEvidenceMinInterval   = time.Hour
)

type oomEvidence struct {
	SchemaVersion                  int    `json:"schemaVersion"`
	RecordedAtUnix                 int64  `json:"recordedAtUnix"`
	PressureLevel                  string `json:"pressureLevel"`
	ProcessIdentifier              int    `json:"processIdentifier"`
	PossibleSystemKill             bool   `json:"possibleSystemKill"`
	PhysicalMemoryBytes            int64  `json:"physicalMemoryBytes"`
	SoftMemoryLimit                int64  `json:"softMemoryLimit,omitempty"`
	GCPercent                      int    `json:"gcPercent"`
	CoreState                      string `json:"coreState"`
	CoreStartTimeUnix              int64  `json:"coreStartTimeUnix"`
	InboundCount                   int32  `json:"inboundCount"`
	OutboundCount                  int32  `json:"outboundCount"`
	ConnectionCount                int32  `json:"connectionCount"`
	GoroutineCount                 int    `json:"goroutineCount"`
	HeapAllocBytes                 uint64 `json:"heapAllocBytes"`
	HeapInuseBytes                 uint64 `json:"heapInuseBytes"`
	StackInuseBytes                uint64 `json:"stackInuseBytes"`
	NumGC                          uint32 `json:"numGC"`
	GVisorReceiveOccupancyP50Bytes int    `json:"gvisorReceiveOccupancyP50Bytes"`
	GVisorReceiveOccupancyP95Bytes int    `json:"gvisorReceiveOccupancyP95Bytes"`
	GVisorReceiveOccupancyMaxBytes int    `json:"gvisorReceiveOccupancyMaxBytes"`
	GVisorSegmentQueueDropped      uint64 `json:"gvisorSegmentQueueDropped"`
	ReloadPhase                    string `json:"reloadPhase,omitempty"`
	ReloadStartedUnix              int64  `json:"reloadStartedUnix,omitempty"`
	ReloadNeededBytes              int64  `json:"reloadNeededBytes,omitempty"`
	ReloadAvailableBytes           int64  `json:"reloadAvailableBytes,omitempty"`
}

var (
	oomEvidenceMu        sync.Mutex
	oomEvidenceLastWrite atomic.Int64
	oomCoreRunning       atomic.Bool
	oomCoreStartTimeUnix atomic.Int64
	oomCoreInboundCount  atomic.Int32
	oomCoreOutboundCount atomic.Int32

	oomEvidenceWrites uint64

	reloadEvidence struct {
		ticket            uint64
		phase             string
		startedUnix       int64
		needed, available int64
		footprint         int64
		markerWritten     bool
		markerAtWrite     uint64
	}
)

const (
	reloadPhaseParse = "parse"
	reloadPhaseApply = "apply"
)

func setOOMEvidenceCoreState(running bool, startTimeUnix int64, inboundCount, outboundCount int32) {
	oomCoreStartTimeUnix.Store(startTimeUnix)
	oomCoreInboundCount.Store(inboundCount)
	oomCoreOutboundCount.Store(outboundCount)
	oomCoreRunning.Store(running)
}

func RecordMemoryPressureEvidence() error {
	oomEvidenceMu.Lock()
	defer oomEvidenceMu.Unlock()

	now := time.Now()
	if lastNanos := oomEvidenceLastWrite.Load(); lastNanos != 0 {
		if now.Sub(time.Unix(0, lastNanos)) < oomEvidenceMinInterval {
			return nil
		}
	}

	path, runtimeSetup, err := oomEvidenceRuntimeState()
	if err != nil {
		return bridgeSafeError(err)
	}
	report := currentOOMEvidenceLocked(now, "critical", physFootprint(), runtimeSetup)
	if err := writeOOMEvidenceAt(path, report, os.Rename); err != nil {
		return bridgeSafeError(err)
	}
	oomEvidenceLastWrite.Store(now.UnixNano())
	oomEvidenceWrites++
	return nil
}

func currentOOMEvidenceLocked(now time.Time, level string, footprint int64, runtimeSetup runtimeSetupState) oomEvidence {
	var connectionCount int32
	statistic.DefaultManager.Range(func(statistic.Tracker) bool {
		connectionCount++
		return true
	})
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	coreState := "stopped"
	if oomCoreRunning.Load() {
		coreState = "running"
	}
	report := oomEvidence{
		SchemaVersion:        oomEvidenceSchemaVersion,
		RecordedAtUnix:       now.Unix(),
		PressureLevel:        level,
		ProcessIdentifier:    os.Getpid(),
		PossibleSystemKill:   true,
		PhysicalMemoryBytes:  footprint,
		SoftMemoryLimit:      runtimeSetup.softMemoryLimit,
		GCPercent:            runtimeSetup.gcPercent,
		CoreState:            coreState,
		CoreStartTimeUnix:    oomCoreStartTimeUnix.Load(),
		InboundCount:         oomCoreInboundCount.Load(),
		OutboundCount:        oomCoreOutboundCount.Load(),
		ConnectionCount:      connectionCount,
		GoroutineCount:       runtime.NumGoroutine(),
		HeapAllocBytes:       memory.HeapAlloc,
		HeapInuseBytes:       memory.HeapInuse,
		StackInuseBytes:      memory.StackInuse,
		NumGC:                memory.NumGC,
		ReloadPhase:          reloadEvidence.phase,
		ReloadStartedUnix:    reloadEvidence.startedUnix,
		ReloadNeededBytes:    reloadEvidence.needed,
		ReloadAvailableBytes: reloadEvidence.available,
	}
	if snapshot := tun.GVisorTCPWindowSnapshot; snapshot != nil {
		window := snapshot()
		report.GVisorReceiveOccupancyP50Bytes = window.ReceiveOccupancyP50Bytes
		report.GVisorReceiveOccupancyP95Bytes = window.ReceiveOccupancyP95Bytes
		report.GVisorReceiveOccupancyMaxBytes = window.ReceiveOccupancyMaxBytes
		report.GVisorSegmentQueueDropped = window.SegmentQueueDroppedTotal
	}
	return report
}

func beginReloadEvidence(verdict reloadMemoryVerdict) uint64 {
	oomEvidenceMu.Lock()
	defer oomEvidenceMu.Unlock()
	reloadEvidence.ticket++
	reloadEvidence.phase = reloadPhaseParse
	reloadEvidence.startedUnix = time.Now().Unix()
	reloadEvidence.needed = verdict.NeededBytes
	reloadEvidence.available = verdict.AvailableBytes
	reloadEvidence.footprint = verdict.FootprintBytes
	reloadEvidence.markerWritten = false
	path, runtimeSetup, err := oomEvidenceRuntimeState()
	if err != nil {
		return reloadEvidence.ticket
	}
	if _, statErr := os.Stat(path); statErr == nil || !os.IsNotExist(statErr) {
		return reloadEvidence.ticket
	}
	if err := writeOOMEvidenceAt(path, currentOOMEvidenceLocked(time.Now(), "reload", verdict.FootprintBytes, runtimeSetup), os.Rename); err == nil {
		reloadEvidence.markerWritten = true
		reloadEvidence.markerAtWrite = oomEvidenceWrites
	}
	return reloadEvidence.ticket
}

func reloadEvidenceOwnsFileLocked() bool {
	return reloadEvidence.markerWritten && oomEvidenceWrites == reloadEvidence.markerAtWrite
}

func advanceReloadEvidence(ticket uint64, phase string) {
	oomEvidenceMu.Lock()
	defer oomEvidenceMu.Unlock()
	if ticket != reloadEvidence.ticket {
		return
	}
	reloadEvidence.phase = phase
	if !reloadEvidenceOwnsFileLocked() {
		return
	}
	path, runtimeSetup, err := oomEvidenceRuntimeState()
	if err != nil {
		return
	}
	_ = writeOOMEvidenceAt(path, currentOOMEvidenceLocked(time.Now(), "reload", reloadEvidence.footprint, runtimeSetup), os.Rename)
}

func endReloadEvidence(ticket uint64) {
	oomEvidenceMu.Lock()
	defer oomEvidenceMu.Unlock()
	if ticket != reloadEvidence.ticket {
		return
	}
	if reloadEvidenceOwnsFileLocked() {
		if path, _, err := oomEvidenceRuntimeState(); err == nil {
			_ = os.Remove(path)
		}
	}
	reloadEvidence.phase = ""
	reloadEvidence.startedUnix, reloadEvidence.needed, reloadEvidence.available, reloadEvidence.footprint = 0, 0, 0, 0
	reloadEvidence.markerWritten = false
}

func oomEvidenceRuntimeState() (string, runtimeSetupState, error) {
	setupMu.Lock()
	defer setupMu.Unlock()
	if !setupDone || setupOOMEvidencePath == "" {
		return "", runtimeSetupState{}, errors.New("clash: OOM evidence before Setup")
	}
	return setupOOMEvidencePath, currentRuntimeSetup, nil
}

func writeOOMEvidenceAt(path string, report oomEvidence, rename func(string, string) error) error {
	data, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("clash: encode OOM evidence: %w", err)
	}
	if len(data) > oomEvidenceMaxBytes {
		return fmt.Errorf("clash: OOM evidence is %d bytes; limit is %d", len(data), oomEvidenceMaxBytes)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("clash: create OOM evidence directory: %w", err)
	}
	temporary := path + ".tmp"
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("clash: create OOM evidence temporary file: %w", err)
	}
	cleanup := true
	defer func() {
		_ = file.Close()
		if cleanup {
			_ = os.Remove(temporary)
		}
	}()
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fmt.Errorf("clash: write OOM evidence: %w", err)
	}
	if err := rename(temporary, path); err != nil {
		return fmt.Errorf("clash: commit OOM evidence: %w", err)
	}
	cleanup = false
	if directory, err := os.Open(filepath.Dir(path)); err == nil {
		_ = directory.Sync()
		_ = directory.Close()
	}
	return nil
}

func ConsumeOOMEvidence() (*StringBox, error) {
	oomEvidenceMu.Lock()
	defer oomEvidenceMu.Unlock()
	path, _, err := oomEvidenceRuntimeState()
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	if reloadEvidenceOwnsFileLocked() {
		return nil, bridgeSafeError(os.ErrNotExist)
	}
	data, err := readBoundedFile(path, oomEvidenceMaxBytes)
	if err != nil {
		if !os.IsNotExist(err) {
			_ = os.Remove(path)
		}
		return nil, bridgeSafeError(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var report oomEvidence
	if err := decoder.Decode(&report); err != nil {
		_ = os.Remove(path)
		return nil, bridgeSafeError(fmt.Errorf("clash: invalid OOM evidence: %w", err))
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		_ = os.Remove(path)
		return nil, bridgeSafeError(errors.New("clash: invalid OOM evidence trailing data"))
	}
	if report.SchemaVersion != oomEvidenceSchemaVersion ||
		(report.PressureLevel != "critical" && report.PressureLevel != "reload") || !report.PossibleSystemKill {
		_ = os.Remove(path)
		return nil, bridgeSafeError(errors.New("clash: invalid OOM evidence schema or pressure state"))
	}
	normalized, err := json.Marshal(report)
	if err != nil {
		return nil, bridgeSafeError(fmt.Errorf("clash: normalize OOM evidence: %w", err))
	}
	if err := os.Remove(path); err != nil {
		return nil, bridgeSafeError(fmt.Errorf("clash: consume OOM evidence: %w", err))
	}
	return WrapString(string(normalized)), nil
}

func readBoundedFile(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("clash: stat OOM evidence: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("clash: OOM evidence is not a regular file")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, fmt.Errorf("clash: read OOM evidence: %w", err)
	}
	if int64(len(data)) > maximum {
		return nil, fmt.Errorf("clash: OOM evidence exceeds %d bytes", maximum)
	}
	return data, nil
}

func abandonReloadEvidenceStateForTest() {
	oomEvidenceMu.Lock()
	defer oomEvidenceMu.Unlock()
	reloadEvidence.ticket++
	reloadEvidence.phase = ""
	reloadEvidence.startedUnix, reloadEvidence.needed, reloadEvidence.available, reloadEvidence.footprint = 0, 0, 0, 0
	reloadEvidence.markerWritten = false
}
