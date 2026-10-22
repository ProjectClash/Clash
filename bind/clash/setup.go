package clash

import (
	"errors"
	"fmt"
	"github.com/ProjectClash/Clash/dns"
	"io"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "time/tzdata"

	"github.com/ProjectClash/Clash/component/ca"
	"github.com/ProjectClash/Clash/component/profile/cachefile"
	"github.com/ProjectClash/Clash/component/resource"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/listener/sing_tun"
	"github.com/ProjectClash/Clash/log"
	ruleprovider "github.com/ProjectClash/Clash/rules/provider"
	tun "github.com/metacubex/sing-tun"
	"github.com/sirupsen/logrus"
)

type SetupOptions struct {
	IPQueryMode              string
	TunIPv6Mode              string
	BasePath                 string
	WorkingPath              string
	TempPath                 string
	TimeZone                 string
	RuntimeProfile           string
	LogMaxLines              int
	MemoryLimit              int64
	TunMTU                   int
	StartupPhaseLogPath      string
	DisablePersistentCache   bool
	PersistentCacheDirectory string
	MaxProcs                 int
	CertificateStore         string
	IncludeAllNetworks       bool
	MemoryPressureShed       bool
	SystemDNSServerLines     string
}

var (
	setupMu                    sync.Mutex
	setupDone                  bool
	setupCacheDisabled         bool
	setupStartupPhaseLogPath   string
	setupClashAPIPath          string
	setupOOMEvidencePath       string
	setupGoCrashReportBasePath string
	setupGoCrashReportRole     goCrashRole
	budgetSetGCPercent         bool
	gcPercentBeforeBudget      int
	timeZoneMu                 sync.Mutex
	configuredTimeZone         string
	configuredLocation         atomic.Pointer[time.Location]

	tracebackOnce sync.Once
)

const gVisorTCPBufferOverrideFile = "clash-gvisor-tcp-buffer-bytes"

func applyGVisorTCPBufferOverride(basePath string) {
	data, err := os.ReadFile(filepath.Join(basePath, gVisorTCPBufferOverrideFile))
	if err != nil {
		return
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || n <= 0 {
		return
	}
	tun.GVisorTCPBufferBytes = n
	logrus.Warnf("[iOS] gVisor TCP window overridden to %d bytes via %s (benchmark knob)", n, gVisorTCPBufferOverrideFile)
}

func Setup(options *SetupOptions) error {
	appParseMu.Lock()
	defer appParseMu.Unlock()
	setupMu.Lock()
	defer setupMu.Unlock()
	defer holdSetupLogs()()

	if options == nil {
		return bridgeSafeError(errors.New("clash: Setup called with nil options"))
	}
	if options.BasePath == "" || options.WorkingPath == "" || options.TempPath == "" {
		return bridgeSafeError(errors.New("clash: SetupOptions.BasePath, WorkingPath and TempPath are required"))
	}
	requestedIPStack, err := parseIPStackSettings(options.IPQueryMode, options.TunIPv6Mode)
	if err != nil {
		return bridgeSafeError(err)
	}
	if activeCoreCount.Load() > 0 && requestedIPStack != currentIPStackSettings() {
		return bridgeSafeError(fmt.Errorf("clash: changing IP Stack requires restart"))
	}
	requestedRuntimeProfile, err := normalizeRuntimeProfile(options.RuntimeProfile)
	if err != nil {
		return bridgeSafeError(err)
	}
	systemResolvers, err := parseSystemDNSServerLines(options.SystemDNSServerLines)
	if err != nil {
		return bridgeSafeError(fmt.Errorf("clash: SetupOptions.SystemDNSServerLines: %w", err))
	}
	if activeCoreCount.Load() > 0 && requestedRuntimeProfile != currentRuntimeProfile() {
		return bridgeSafeError(fmt.Errorf(
			"clash: changing RuntimeProfile from %q to %q requires restart",
			currentRuntimeProfile().String(),
			requestedRuntimeProfile.String(),
		))
	}
	if activeCoreCount.Load() > 0 && options.IncludeAllNetworks != includeAllNetworksRequested.Load() {
		return bridgeSafeError(fmt.Errorf(
			"clash: changing IncludeAllNetworks from %v to %v requires restart",
			includeAllNetworksRequested.Load(),
			options.IncludeAllNetworks,
		))
	}
	includeAllNetworksRequested.Store(options.IncludeAllNetworks)
	sing_tun.IncludeAllNetworks = options.IncludeAllNetworks
	systemDNSSubstitutes.Store(&systemResolvers)
	dns.SetSystemResolverDefaults(systemResolvers)
	startupPhase("setup:entered")
	requestedCertificateStore, err := ca.ParseStore(options.CertificateStore)
	if err != nil {
		return bridgeSafeError(fmt.Errorf("clash: SetupOptions.CertificateStore: %w", err))
	}
	ca.SetStore(requestedCertificateStore)

	startupPhase("setup:cert-store")
	applyGVisorTCPBufferOverride(options.BasePath)
	resource.DeferRemoteInitialFetch = true
	resource.DefaultRemoteSizeLimit = int64(maximumProviderResourceBytes)
	if err := resource.SetAtomicCacheDirectory(filepath.Join(options.WorkingPath, "tv-rule-cache")); err != nil {
		return bridgeSafeError(err)
	}
	resource.SetFirstLoadConcurrency(5)
	ruleprovider.UseLowMemoryMrsEncoder()
	if options.DisablePersistentCache {
		if err := cachefile.DisablePersistentCache(); err != nil {
			return bridgeSafeError(fmt.Errorf("clash: disable persistent cache: %w", err))
		}
		setupCacheDisabled = true
	}
	if err := validateTunMTU(options.TunMTU); err != nil {
		return bridgeSafeError(err)
	}
	requestedTunMTU := normalizedTunMTU(options.TunMTU)
	if activeCoreCount.Load() > 0 && requestedTunMTU != effectiveTunMTU() {
		return bridgeSafeError(fmt.Errorf("clash: changing TunMTU from %d to %d requires restart", effectiveTunMTU(), requestedTunMTU))
	}

	startupPhase("setup:mtu-checked")
	if options.TimeZone != "" {
		if err := applyTimeZone(options.TimeZone); err != nil {
			return bridgeSafeError(fmt.Errorf("clash: apply timezone %q: %w", options.TimeZone, err))
		}
	}

	startupPhase("setup:timezone")
	tracebackOnce.Do(func() {
		debug.SetTraceback("all")
	})

	if options.MemoryLimit > 0 {
		softLimit := options.MemoryLimit * 3 / 4
		debug.SetMemoryLimit(softLimit)
		previousGC := debug.SetGCPercent(10)
		if !budgetSetGCPercent {
			budgetSetGCPercent, gcPercentBeforeBudget = true, previousGC
		}
		currentRuntimeSetup.softMemoryLimit = softLimit
		currentRuntimeSetup.softMemoryLimitIsPacingDefault = false
		currentRuntimeSetup.gcPercent = 10
	} else {
		currentRuntimeSetup.softMemoryLimit = 0
		currentRuntimeSetup.softMemoryLimitIsPacingDefault = false
		debug.SetMemoryLimit(math.MaxInt64)
		if budgetSetGCPercent {
			debug.SetGCPercent(gcPercentBeforeBudget)
			budgetSetGCPercent = false
			currentRuntimeSetup.gcPercent = 0
		}
	}

	if procs := effectiveMaxProcs(options); procs > 0 {
		runtime.GOMAXPROCS(procs)
	}

	startupPhase("setup:runtime-tuned")
	C.SetHomeDir(options.WorkingPath)
	C.SetConfig(filepath.Join(options.WorkingPath, "config.yaml"))
	phaseLogPath := options.StartupPhaseLogPath
	if phaseLogPath == "" {
		phaseLogPath = filepath.Join(options.WorkingPath, "clash-core-phases.log")
	}
	configureStartupPhaseLogPath(phaseLogPath)
	setupClashAPIPath = filepath.Join(options.BasePath, clashAPISocketName)
	setupOOMEvidencePath = filepath.Join(options.BasePath, oomEvidenceFileName)
	setupGoCrashReportBasePath = options.BasePath
	setupGoCrashReportRole = currentGoCrashRole()
	legacyClashAPIPath := filepath.Join(options.WorkingPath, clashAPISocketName)
	if runtimePolicyFor(requestedRuntimeProfile, true).bindsUnixControlSocket &&
		legacyClashAPIPath != setupClashAPIPath {
		_ = os.Remove(legacyClashAPIPath)
	}

	startupPhase("setup:paths-wired")
	for _, dir := range []string{
		options.WorkingPath,
		options.TempPath,
		filepath.Join(options.WorkingPath, "providers"),
		filepath.Join(options.WorkingPath, "geodata"),
	} {
		if err := probeDir(dir); err != nil {
			return bridgeSafeError(err)
		}
	}

	if err := placePersistentCache(options); err != nil {
		return bridgeSafeError(err)
	}

	startupPhase("setup:dirs-probed")
	if err := armGoCrashOutputAt(options.BasePath, setupGoCrashReportRole); err != nil {
		logrus.Warnf("[iOS] Go crash output unavailable, a panic will leave no readable traceback: %v", err)
	}

	startupPhase("setup:crash-armed")
	logMaxLines := options.LogMaxLines
	if logMaxLines <= 0 {
		logMaxLines = defaultLogMaxLines
	}
	recentLogs.setMax(logMaxLines)
	currentRuntimeSetup.logMaxLines = logMaxLines
	setIPStackSettings(requestedIPStack)
	setTunMTU(requestedTunMTU)
	setupRuntimeProfile.Store(uint32(requestedRuntimeProfile))
	applyXHTTPTunnelReuse(requestedRuntimeProfile)
	armMemoryPressureMonitorForRuntime(
		requestedRuntimeProfile,
		options.DisablePersistentCache,
		startMemoryPressureMonitor,
	)
	armMemoryPressureMonitorForRuntime(
		requestedRuntimeProfile,
		options.DisablePersistentCache,
		func() {
			startPressureThresholdMonitor(options.MemoryLimit, true)
		},
	)
	startupPhase("setup:monitors-armed")
	setupDone = true
	return nil
}

func effectiveMaxProcs(options *SetupOptions) int {
	const constrainedCap = 4
	procs := options.MaxProcs
	if procs <= 0 {
		if options.MemoryLimit <= 0 {
			return 0
		}
		procs = constrainedCap
	}
	if n := runtime.NumCPU(); procs > n {
		procs = n
	}
	return procs
}

func placePersistentCache(options *SetupOptions) error {
	if options.PersistentCacheDirectory == "" || options.DisablePersistentCache {
		return nil
	}
	if err := probeDir(options.PersistentCacheDirectory); err != nil {
		return err
	}
	target := filepath.Join(options.PersistentCacheDirectory, "cache.db")
	if err := cachefile.SetPersistentCachePath(target); err != nil {
		return fmt.Errorf("clash: persistent cache at %s: %w", target, err)
	}
	moveLegacyPersistentCache(filepath.Join(options.WorkingPath, "cache.db"), target)
	return nil
}

func moveLegacyPersistentCache(legacy, target string) {
	info, err := os.Lstat(legacy)
	if err != nil {
		return
	}
	if !info.Mode().IsRegular() {
		log.Warnln("[Apple] %s is not a regular file; left where it is", legacy)
		return
	}
	if _, err := os.Lstat(target); err == nil {
		if err := os.Remove(legacy); err != nil {
			log.Warnln("[Apple] remove stale %s: %v", legacy, err)
		}
		return
	}
	renameErr := os.Rename(legacy, target)
	if renameErr == nil {
		log.Infoln("[Apple] cache.db moved from %s to %s", legacy, target)
		return
	}
	if err := copyLegacyPersistentCache(legacy, target); err != nil {
		log.Warnln("[Apple] cache.db not moved from %s (rename: %v, copy: %v); starting from an empty one", legacy, renameErr, err)
		return
	}
	if err := os.Remove(legacy); err != nil {
		log.Warnln("[Apple] remove %s after copying it: %v", legacy, err)
	}
	log.Infoln("[Apple] cache.db copied from %s to %s", legacy, target)
}

func copyLegacyPersistentCache(legacy, target string) error {
	source, err := os.Open(legacy)
	if err != nil {
		return err
	}
	defer source.Close()
	partial := target + ".moving"
	destination, err := os.OpenFile(partial, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = io.Copy(destination, source)
	if syncErr := destination.Sync(); err == nil {
		err = syncErr
	}
	if closeErr := destination.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(partial, target)
	}
	if err != nil {
		_ = os.Remove(partial)
	}
	return err
}

func probeDir(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("clash: create %s: %w", dir, err)
	}
	probe := filepath.Join(dir, ".clash-probe")
	if err := os.WriteFile(probe, []byte("ok"), 0o600); err != nil {
		return fmt.Errorf("clash: %s is not writable: %w", dir, err)
	}
	if err := os.Remove(probe); err != nil {
		return fmt.Errorf("clash: cleanup probe in %s: %w", dir, err)
	}
	return nil
}

func applyTimeZone(id string) error {
	loc, err := time.LoadLocation(id)
	if err != nil {
		return err
	}
	timeZoneMu.Lock()
	defer timeZoneMu.Unlock()
	if configuredTimeZone == id {
		return nil
	}
	previous := configuredTimeZone
	configuredLocation.Store(loc)
	configuredTimeZone = id
	if previous != "" {
		log.Infoln("[Apple] timezone %s -> %s", previous, id)
	}
	return nil
}

func clashLocalTime(value time.Time) time.Time {
	if location := configuredLocation.Load(); location != nil {
		return value.In(location)
	}
	return value
}

const logChannelSize = 1024

const logQueueMaxBytes = 4 << 20

type logLine struct {
	message   string
	delivered chan struct{}
}

const startupDeliveryBudget = 500 * time.Millisecond

type platformLogWriter struct {
	platform        PlatformInterface
	ch              chan logLine
	done            chan struct{}
	stopped         chan struct{}
	close           sync.Once
	dropped         atomic.Int64
	queuedBytes     atomic.Int64
	startingUp      atomic.Bool
	platformStalled atomic.Bool
}

func (w *platformLogWriter) Write(p []byte) (int, error) {
	if msg := strings.TrimRight(string(p), "\n"); msg != "" {
		recentLogs.add(msg)
		select {
		case <-w.done:
			return len(p), nil
		default:
		}
		if w.startingUp.Load() && !w.platformStalled.Load() {
			w.writeStartup(msg)
			return len(p), nil
		}
		size := int64(len(msg))
		if queued := w.queuedBytes.Load(); queued > 0 && queued+size > logQueueMaxBytes {
			w.dropped.Add(1)
			return len(p), nil
		}
		w.queuedBytes.Add(size)
		select {
		case w.ch <- logLine{message: msg}:
		case <-w.done:
			w.queuedBytes.Add(-size)
		default:
			w.queuedBytes.Add(-size)
			w.dropped.Add(1)
		}
	}
	return len(p), nil
}

func (w *platformLogWriter) writeStartup(msg string) {
	delivered := make(chan struct{})
	budget := time.NewTimer(startupDeliveryBudget)
	defer budget.Stop()
	size := int64(len(msg))
	w.queuedBytes.Add(size)
	select {
	case w.ch <- logLine{message: msg, delivered: delivered}:
	case <-budget.C:
		w.queuedBytes.Add(-size)
		w.platformStalled.Store(true)
		w.dropped.Add(1)
		return
	case <-w.done:
		w.queuedBytes.Add(-size)
		return
	}
	select {
	case <-delivered:
	case <-budget.C:
		w.platformStalled.Store(true)
	case <-w.done:
	}
}

func (w *platformLogWriter) drain() {
	defer close(w.stopped)
	batch := make([]logLine, 0, logBatchMax)
	for {
		select {
		case line := <-w.ch:
			w.queuedBytes.Add(-int64(len(line.message)))
			if sink := logBatchWriter.Load(); sink != nil {
				batch = append(batch[:0], line)
				size := len(line.message)
			collect:
				for len(batch) < logBatchMax && size < logBatchBytes {
					select {
					case next := <-w.ch:
						w.queuedBytes.Add(-int64(len(next.message)))
						batch = append(batch, next)
						size += len(next.message)
					default:
						break collect
					}
				}
				writeLogBatch(*sink, batch)
				for _, sent := range batch {
					if sent.delivered != nil {
						close(sent.delivered)
					}
				}
				continue
			}
			w.platform.WriteLog(line.message)
			if line.delivered != nil {
				close(line.delivered)
			}
		case <-w.done:
			if dropped := w.dropped.Load(); dropped > 0 {
				recentLogs.add(fmt.Sprintf("[clash] dropped %d log lines due to platform backpressure", dropped))
			}
			return
		}
	}
}

func (w *platformLogWriter) Close() {
	w.close.Do(func() { close(w.done) })
}

var (
	logRedirectMu         sync.Mutex
	activeLogWriter       *platformLogWriter
	localLogFormatterOnce sync.Once
	heldSetupLogs         *setupLogHold
)

const setupLogHoldMax = 64

type setupLogHold struct {
	mu       sync.Mutex
	previous io.Writer
	lines    [][]byte
}

func (hold *setupLogHold) Write(p []byte) (int, error) {
	hold.mu.Lock()
	if len(hold.lines) < setupLogHoldMax {
		hold.lines = append(hold.lines, append([]byte(nil), p...))
	}
	hold.mu.Unlock()
	return hold.previous.Write(p)
}

func holdSetupLogs() (release func()) {
	logRedirectMu.Lock()
	defer logRedirectMu.Unlock()
	if activeLogWriter != nil {
		return func() {}
	}
	useLocalLogFormatter()
	logger := logrus.StandardLogger()
	hold := &setupLogHold{previous: logger.Out}
	heldSetupLogs = hold
	logger.SetOutput(hold)
	return func() {
		logRedirectMu.Lock()
		defer logRedirectMu.Unlock()
		if activeLogWriter == nil {
			logger.SetOutput(hold.previous)
		}
	}
}

func takeSetupLogs() [][]byte {
	logRedirectMu.Lock()
	hold := heldSetupLogs
	heldSetupLogs = nil
	logRedirectMu.Unlock()
	if hold == nil {
		return nil
	}
	hold.mu.Lock()
	defer hold.mu.Unlock()
	lines := hold.lines
	hold.lines = nil
	return lines
}

func useLocalLogFormatter() {
	localLogFormatterOnce.Do(func() {
		logger := logrus.StandardLogger()
		logger.SetFormatter(&localLogFormatter{delegate: logger.Formatter})
	})
}

type localLogFormatter struct {
	delegate logrus.Formatter
}

func (formatter *localLogFormatter) Format(entry *logrus.Entry) ([]byte, error) {
	localized := *entry
	localized.Time = clashLocalTime(entry.Time)
	return formatter.delegate.Format(&localized)
}

func redirectLogs(platform PlatformInterface) *platformLogWriter {
	w := &platformLogWriter{
		platform: platform,
		ch:       make(chan logLine, logChannelSize),
		done:     make(chan struct{}),
		stopped:  make(chan struct{}),
	}
	w.startingUp.Store(true)
	go w.drain()
	useLocalLogFormatter()
	for _, line := range takeSetupLogs() {
		_, _ = w.Write(line)
	}

	logRedirectMu.Lock()
	previous := activeLogWriter
	activeLogWriter = w
	logrus.SetOutput(w)
	logRedirectMu.Unlock()
	if previous != nil {
		previous.Close()
	}
	return w
}

func stopLogRedirect(w *platformLogWriter) {
	if w == nil {
		return
	}
	logRedirectMu.Lock()
	if activeLogWriter == w {
		activeLogWriter = nil
		logrus.SetOutput(io.Discard)
	}
	logRedirectMu.Unlock()
	w.Close()
}

func (w *platformLogWriter) markTunnelEstablished() {
	if w != nil {
		w.startingUp.Store(false)
	}
}
