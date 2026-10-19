package clash

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"runtime"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ProjectClash/Clash/component/pause"
	"github.com/ProjectClash/Clash/component/resolver"
	"github.com/ProjectClash/Clash/config"
	constant "github.com/ProjectClash/Clash/constant"
	provider "github.com/ProjectClash/Clash/constant/provider"
	"github.com/ProjectClash/Clash/dns"
	"github.com/ProjectClash/Clash/hub/executor"
	coreListener "github.com/ProjectClash/Clash/listener"
	LC "github.com/ProjectClash/Clash/listener/config"
	"github.com/ProjectClash/Clash/listener/inner"
	"github.com/ProjectClash/Clash/log"
	"github.com/ProjectClash/Clash/tunnel"
	"github.com/ProjectClash/Clash/tunnel/statistic"
	tun "github.com/metacubex/sing-tun"
	"golang.org/x/sys/unix"
)

var errNotImplemented = errors.New("clash: not implemented yet")

var activeCoreCount atomic.Int32

type BoxService struct {
	mu                       sync.Mutex
	routingMu                sync.Mutex
	platform                 PlatformInterface
	running                  bool
	stunMu                   sync.Mutex
	stunClosing              bool
	stunNextID               uint64
	stunSessions             map[uint64]context.CancelFunc
	stunWG                   sync.WaitGroup
	tunFd                    int
	liveTunFd                int
	liveTun                  LC.Tun
	hasLiveTun               bool
	ifaceListener            InterfaceUpdateListener
	logWriter                *platformLogWriter
	clashAPIPath             string
	startTimeUnix            int64
	inboundCount             int32
	outboundCount            int32
	dnsTransports            dnsTransportSnapshot
	providerRuntime          *providerRuntime
	refresher                *providerRefresher
	refreshGeneration        uint64
	refreshCancel            context.CancelFunc
	sessionSweepCancel       context.CancelFunc
	orphanedProviderRuntimes []*providerRuntime
	proxyShare               *proxyShareRuntime
	pauseCount               atomic.Uint64
	wakeCount                atomic.Uint64

	startFootprintBytes    int64
	configLength           int
	runningConfigSHA256    string
	providerBytes          int64
	candidateProviderBytes int64
	reloadVerdict          reloadMemoryVerdict

	endPauseMu    sync.Mutex
	endPauseTimer *time.Timer
}

func NewService(platform PlatformInterface) (*BoxService, error) {
	if platform == nil {
		return nil, bridgeSafeError(errors.New("clash: NewService requires a platform"))
	}
	setupMu.Lock()
	ok := setupDone
	cacheDisabled := setupCacheDisabled
	setupMu.Unlock()
	if !ok {
		return nil, bridgeSafeError(errors.New("clash: call Setup before NewService"))
	}
	if cacheDisabled {
		return nil, bridgeSafeError(errors.New("clash: NewService is unavailable after App-only DisablePersistentCache Setup"))
	}
	tunnelProcess.Store(true)
	if platform.UnderNetworkExtension() {
		config.ClashRuleIndexesVerified.Store(true)
	}
	platform = bridgeSafePlatform(platform)
	logWriter := redirectLogs(platform)
	armNEPacingForService(platform)
	armNodeCatalog(platform)
	installSocketHook(platform)
	setUnscopedResolversArePhysical(!platform.UnderNetworkExtension())
	installLocalZoneResolver(true)
	installNetworkInterfaceProvider(platform)
	installListenerScopeHooks(platform.UnderNetworkExtension())
	return &BoxService{platform: platform, tunFd: -1, liveTunFd: -1, logWriter: logWriter}, nil
}

func logFootprint(stage string) {
	footprint := MemoryFootprint()
	if footprint <= 0 {
		return
	}
	log.Infoln("[mem] %s: %.1f MiB of the extension's budget",
		stage, float64(footprint)/(1<<20))
}

func (s *BoxService) Start(configContent string) error {
	return bridgeSafeError(s.start(configContent))
}

func (s *BoxService) start(configContent string) (startErr error) {
	defer func() { recordStartupFailure(startErr) }()
	startupPhase("start-first-statement")
	defer armStartupProbes()()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.running {
		return errors.New("clash: service already started")
	}
	armProviderCache()
	startupPhase("validated")
	setupMu.Lock()
	activeCoreCount.Add(1)
	setupMu.Unlock()
	startupPhase("core-count-bumped")
	defer func() {
		if !s.running {
			activeCoreCount.Add(-1)
		}
	}()
	if s.logWriter == nil {
		s.logWriter = redirectLogs(s.platform)
	}
	startupPhase("logs-redirected")
	logFootprint("before the interface monitor")
	startupPhase("pre-iface-monitor")
	listener, err := startInterfaceMonitor(s.platform)
	if err != nil {
		return fmt.Errorf("clash: start default interface monitor: %w", err)
	}
	s.ifaceListener = listener
	startupPhase("iface-monitor-up")

	setStartupBreadcrumbRecording(currentRuntimePolicy(s.platform.UnderNetworkExtension()).networkExtension)
	startupStageCounting("bind:unmarshal-begin", int64(len(configContent)))
	var startedDNSTransports dnsTransportSnapshot
	var startedProviderRuntime *providerRuntime
	done := make(chan error, 1)
	var pendingTunOpen chan tunOpenResult
	var applying atomic.Bool
	previousTunnelPrefixes := currentTunnelPrefixes()
	go func() {
		defer func() {
			if r := recover(); r != nil {
				executor.WaitBeforeTunAttach = nil
				shutdownCore()
				stopClashAPI(s.clashAPIPath)
				s.clashAPIPath = ""
				closeFDIfOpen(s.tunFd)
				s.resetTunState()
				reapUnclaimedTunOpen(pendingTunOpen)
				if startedProviderRuntime != nil {
					startedProviderRuntime.close()
					startedProviderRuntime = nil
				}
				log.Errorln("[Apple] the start panicked and the tunnel did not come up: %v", r)
				class := CoreOutcomeConfig
				if applying.Load() {
					class = CoreOutcomeUnknown
				}
				done <- classify(class, fmt.Errorf("clash: start panicked: %v", r))
			}
		}()
		startupPhase("pre-config-parse")
		debug.FreeOSMemory()
		s.startFootprintBytes = readFootprintForReload()
		s.configLength = len(configContent)
		logFootprint("before parsing the configuration")
		decoded := decodeConfigText(configContent)
		s.providerBytes = decoded.providerBytes()
		cfg, runtime, err := parseDecodedConfigForIOSRuntime(configContent, decoded, s.platform.UnderNetworkExtension(), deviationEntryStart)
		decoded = nil
		logFootprint("after parsing the configuration")
		startupPhase("config-parsed")
		if err != nil {
			startupPhase("config-refused")
			log.Errorln("[Apple] the configuration was refused and the tunnel did not start: %v", err)
			done <- classify(CoreOutcomeConfig, err)
			return
		}
		startedProviderRuntime = runtime
		fail := func(err error) {
			log.Errorln("[Apple] the tunnel did not start: %v", err)
			if startedProviderRuntime != nil {
				startedProviderRuntime.close()
				startedProviderRuntime = nil
			}
			done <- err
		}

		underNE := s.platform.UnderNetworkExtension()
		finalizeConfigForApple(cfg, currentRuntimePolicy(underNE))
		startedDNSTransports = snapshotDNSTransports(cfg)
		startupPhase("config-finalized")

		if cfg.General.Tun.Enable {
			startupPhase("tun-open-dispatched")
			pendingTunOpen = dispatchTunOpen(s.platform, &cfg.General.Tun)
			executor.WaitBeforeTunAttach = func(applied *config.Config) {
				result := <-pendingTunOpen
				pendingTunOpen = nil
				if result.err != nil {
					panic(fmt.Sprintf("clash: OpenTun: %v", result.err))
				}
				s.tunFd = result.fd
				s.liveTunFd = result.fd
				applied.General.Tun.FileDescriptor = result.fd
				startupPhase("tun-fd-ready")
			}
		}

		startupPhase("pre-apply-config")
		logFootprint("before applying it (providers load here)")
		applying.Store(true)
		executor.ApplyConfig(cfg, true)
		executor.WaitBeforeTunAttach = nil
		logFootprint("after applying it")
		startupPhase("apply-config-done")
		s.logWriter.markTunnelEstablished()
		pendingTunFd := s.tunFd
		s.tunFd = -1
		if cfg.General.Tun.Enable {
			if err := verifyTunStarted(cfg.General.Tun); err != nil {
				shutdownCore()
				closeFDIfOpen(pendingTunFd)
				s.resetTunState()
				fail(err)
				return
			}
			startupPhase("tun-verified")
		}
		if cfg.General.Tun.Enable {
			s.liveTun = cfg.General.Tun
			s.hasLiveTun = true
			publishTunSourceAddress(cfg.General.Tun)
		}
		if underNE {
			s.clashAPIPath = APIPath()
			if err := startControlPlane(cfg, s.clashAPIPath); err != nil {
				shutdownCore()
				s.resetTunState()
				s.clashAPIPath = ""
				fail(err)
				return
			}
			startupPhase("clash-api-up")
		} else {
			applyExternalController(cfg)
		}
		done <- nil
	}()
	if err := <-done; err != nil {
		if !applying.Load() {
			setConfiguredTunnelPrefixes(previousTunnelPrefixes)
		}
		s.closeInterfaceMonitor()
		return err
	}

	startupPhase("start-return-begin")
	s.running = true
	s.runningConfigSHA256 = configurationSHA256(configContent)
	markStartupComplete()
	s.resumeSTUNSessions()
	s.startTimeUnix = time.Now().Unix()
	s.inboundCount = runtimeInboundCount()
	s.outboundCount = int32(len(tunnel.Proxies()) + runningNodeCount())
	s.dnsTransports = startedDNSTransports
	s.providerRuntime = startedProviderRuntime
	s.startProviderRefreshLocked()
	s.startSessionSweepLocked()
	refreshNodeCatalog()
	setOOMEvidenceCoreState(true, s.startTimeUnix, s.inboundCount, s.outboundCount)
	publishCoreService(s)
	startupPhase("start-return-done")
	return nil
}

type tunOpenResult struct {
	fd  int
	err error
}

func dispatchTunOpen(platform PlatformInterface, tun *LC.Tun) chan tunOpenResult {
	results := make(chan tunOpenResult, 1)
	options := tun
	go func() {
		fd, err := prepareTunBridgeFD(platform, options)
		results <- tunOpenResult{fd: fd, err: err}
	}()
	return results
}

func reapUnclaimedTunOpen(pending chan tunOpenResult) {
	if pending == nil {
		return
	}
	go func() {
		if result := <-pending; result.err == nil {
			closeFDIfOpen(result.fd)
		}
	}()
}

func prepareTunBridgeFD(platform PlatformInterface, tun *LC.Tun) (int, error) {
	fd, err := platform.OpenTun(newTunOptions(tun))
	if err != nil {
		return -1, fmt.Errorf("clash: OpenTun: %w", err)
	}
	if fd < 0 {
		return -1, fmt.Errorf("clash: OpenTun returned invalid bridge fd %d", fd)
	}
	dupFd, err := unix.Dup(int(fd))
	if err != nil {
		return -1, fmt.Errorf("clash: dup PacketFlow bridge fd %d: %w", fd, err)
	}
	return dupFd, nil
}

func verifyTunStarted(expected LC.Tun) error {
	actual := coreListener.GetTunConf()
	if !actual.Enable {
		return errors.New("clash: tun listener failed to start; inspect preceding core log for the underlying error")
	}
	if actual.FileDescriptor != expected.FileDescriptor {
		return fmt.Errorf("clash: tun listener fd mismatch: live=%d expected=%d", actual.FileDescriptor, expected.FileDescriptor)
	}
	return nil
}

func closeFDIfOpen(fd int) {
	if fd < 0 {
		return
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err == nil {
		_ = unix.Close(fd)
	}
}

func (s *BoxService) resetTunState() {
	s.tunFd = -1
	s.liveTunFd = -1
	s.liveTun = LC.Tun{}
	s.hasLiveTun = false
	publishTunSourceAddress(LC.Tun{})
}

func (s *BoxService) Reload(configContent string) error {
	err := s.reload(configContent)
	var classified *classifiedError
	if errors.As(err, &classified) && classified.class == CoreOutcomeCommitted {
		return nil
	}
	return bridgeSafeError(err)
}

func (s *BoxService) reload(configContent string) error {
	s.stopSTUNSessions()
	defer s.resumeSTUNSessions()
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return classify(CoreOutcomeRestart, errors.New("clash: Reload before Start"))
	}
	verdict, decoded := s.judgeReloadAgainstTheCeiling(configContent)
	if verdict.Reason == reloadRefusedMemory {
		return classify(CoreOutcomeMemory, reloadMemoryRefusal(verdict))
	}
	ticket := beginReloadEvidence(verdict)
	defer endReloadEvidence(ticket)
	done := make(chan error, 1)
	var applying atomic.Bool
	var orphaned *providerRuntime
	previousTunnelPrefixes := currentTunnelPrefixes()
	go func() {
		var nextProviderRuntime *providerRuntime
		committedProviderRuntime := false
		defer func() {
			if r := recover(); r != nil {
				if !committedProviderRuntime && nextProviderRuntime != nil {
					if applying.Load() {
						orphaned = nextProviderRuntime
					} else {
						nextProviderRuntime.close()
					}
					nextProviderRuntime = nil
				}
				class := CoreOutcomeConfig
				if applying.Load() {
					class = CoreOutcomeUnknown
				}
				log.Errorln("[Apple] the reload panicked and the tunnel did not come up: %v", r)
				done <- classify(class, fmt.Errorf("clash: reload panicked: %v", r))
			}
		}()
		underNE := s.platform.UnderNetworkExtension()
		if decoded == nil {
			decoded = decodeConfigText(configContent)
		}
		providerSources := decoded.providerSources
		cfg, runtime, err := parseDecodedConfigForIOSRuntime(configContent, decoded, underNE, deviationEntryReload)
		decoded = nil
		if hook := reloadTestAfterParse; hook != nil {
			hook()
		}
		if err != nil {
			log.Errorln("[Apple] the replacement configuration was refused and the running one is unchanged: %v", err)
			done <- classify(CoreOutcomeConfig, err)
			return
		}
		nextProviderRuntime = runtime
		if reloadTestPanicBeforeCommit.Load() {
			panic("clash test: deliberate panic before the reload commits")
		}
		fail := func(err error) {
			log.Errorln("[Apple] the reload did not complete and the running configuration is unchanged: %v", err)
			if nextProviderRuntime != nil {
				nextProviderRuntime.close()
				nextProviderRuntime = nil
			}
			done <- classify(CoreOutcomeRestart, err)
		}
		finalizeConfigForApple(cfg, currentRuntimePolicy(underNE))
		if cfg.General.Tun.Enable {
			if s.liveTunFd < 0 {
				fail(errors.New("clash: reload enables tun but no live fd from Start"))
				return
			}
			cfg.General.Tun.FileDescriptor = s.liveTunFd
		}
		if cfg.General.Tun.Enable != s.hasLiveTun {
			fail(errors.New("clash: reload cannot enable or disable the live tun; restart the appex"))
			return
		}
		if s.hasLiveTun && !tunConfigurationsEqual(s.liveTun, cfg.General.Tun) {
			fail(errors.New("clash: reload changes the effective tun; restart the appex instead of rebuilding utun"))
			return
		}
		advanceReloadEvidence(ticket, reloadPhaseApply)
		applying.Store(true)
		s.runningConfigSHA256 = ""
		if reloadTestPanicAfterApplyBegins.Load() {
			panic("clash test: deliberate panic after the reload began applying")
		}
		func() {
			s.routingMu.Lock()
			defer s.routingMu.Unlock()
			executor.ApplyConfig(cfg, true)
			applyExternalController(cfg)
		}()
		s.runningConfigSHA256 = configurationSHA256(configContent)
		var attachmentFailure error
		if err := s.reapplyProxyShareLocked(); err != nil {
			log.Errorln("[iOS] proxy share closed after reload: %v", err)
			_ = s.stopProxyShareLocked()
			attachmentFailure = classify(CoreOutcomeCommitted, fmt.Errorf("clash: proxy share closed after reload: %w", err))
		}
		previousProviderRuntime := s.providerRuntime
		s.providerRuntime = nextProviderRuntime
		committedProviderRuntime = true
		if previousProviderRuntime != nil {
			previousProviderRuntime.close()
		}
		s.startProviderRefreshLocked()
		refreshNodeCatalog()
		s.inboundCount = s.runtimeInboundCountLocked()
		s.outboundCount = int32(len(tunnel.Proxies()) + runningNodeCount())
		s.dnsTransports = snapshotDNSTransports(cfg)
		s.configLength = len(configContent)
		if s.candidateProviderBytes >= 0 {
			s.providerBytes = s.candidateProviderBytes
		} else {
			s.providerBytes = providerSources.bytes()
		}
		setOOMEvidenceCoreState(true, s.startTimeUnix, s.inboundCount, s.outboundCount)
		debug.FreeOSMemory()
		done <- attachmentFailure
	}()
	err := <-done
	if err != nil && !applying.Load() {
		setConfiguredTunnelPrefixes(previousTunnelPrefixes)
	}
	if orphaned != nil {
		s.orphanedProviderRuntimes = append(s.orphanedProviderRuntimes, orphaned)
	} else if applying.Load() && (err == nil || coreOutcomeOf(err).ErrorClass == CoreOutcomeCommitted) {
		s.closeOrphanedProviderRuntimesLocked()
	}
	return err
}

func runtimeInboundCount() int32 {
	count := coreListener.InboundListenerCount()
	ports := coreListener.GetPorts()
	for _, port := range []int{ports.Port, ports.SocksPort, ports.RedirPort, ports.TProxyPort, ports.MixedPort} {
		if port != 0 {
			count++
		}
	}
	if ports.ShadowSocksConfig != "" {
		count++
	}
	if ports.VmessConfig != "" {
		count++
	}
	if coreListener.GetTuicConf().Enable {
		count++
	}
	if coreListener.GetTunConf().Enable {
		count++
	}
	return int32(count)
}

func runGuardedTeardown(teardown func()) {
	defer func() {
		if r := recover(); r != nil {
			log.Warnln("[iOS] core teardown recovered from panic: %v", r)
		}
	}()
	teardown()
}

func (s *BoxService) Close() error {
	var refresherDone <-chan struct{}
	defer func() { awaitProviderRefreshExit(refresherDone) }()
	s.stopSTUNSessions()
	s.releasePauseOnClose()
	s.mu.Lock()
	defer s.mu.Unlock()
	unpublishCoreService(s)
	refresherDone = s.stopProviderRefreshLocked()
	if !s.running {
		s.stopProxyShareLocked()
		s.closeInterfaceMonitor()
		stopClashAPI(s.clashAPIPath)
		s.clashAPIPath = ""
		stopLogRedirect(s.logWriter)
		s.logWriter = nil
		if s.providerRuntime != nil {
			s.providerRuntime.close()
			s.providerRuntime = nil
		}
		s.closeOrphanedProviderRuntimesLocked()
		return nil
	}
	s.stopProxyShareLocked()
	s.closeInterfaceMonitor()
	stopClashAPI(s.clashAPIPath)
	s.clashAPIPath = ""
	done := make(chan struct{})
	go func() {
		defer close(done)
		runGuardedTeardown(func() {
			shutdownCore()
			debug.FreeOSMemory()
		})
	}()
	<-done
	if s.providerRuntime != nil {
		s.providerRuntime.close()
		s.providerRuntime = nil
	}
	s.closeOrphanedProviderRuntimesLocked()
	if s.tunFd >= 0 {
		_ = unix.Close(s.tunFd)
		s.tunFd = -1
	}
	s.resetTunState()
	s.stopSessionSweepLocked()
	s.running = false
	s.runningConfigSHA256 = ""
	s.startTimeUnix = 0
	s.inboundCount = 0
	s.outboundCount = 0
	s.dnsTransports = dnsTransportSnapshot{}
	activeCoreCount.Add(-1)
	setOOMEvidenceCoreState(false, 0, 0, 0)
	stopLogRedirect(s.logWriter)
	s.logWriter = nil
	return nil
}

func (s *BoxService) closeInterfaceMonitor() {
	if s.ifaceListener == nil {
		return
	}
	listener := s.ifaceListener
	s.ifaceListener = nil
	if updater, ok := listener.(*interfaceUpdater); ok {
		updater.stopSettling()
	}
	dns.SetSystemSubstituteRefresh(nil)
	installLocalZoneResolver(false)
	if err := s.platform.CloseDefaultInterfaceMonitor(listener); err != nil {
		log.Warnln("[iOS] close interface monitor: %v", err)
	}
	pause.NetworkWake()
	publishedInterfaceIndex.Store(0)
}

func shutdownCore() {
	inner.CloseTCPConnections()
	CloseAllConnections()

	proxies := tunnel.Proxies()
	providers := tunnel.Providers()
	ruleProviders := tunnel.RuleProviders()
	tunnel.UpdateProxiesRulesAndRouting(map[string]constant.Proxy{}, map[string]provider.ProxyProvider{}, nil, map[string][]constant.Rule{}, map[string]provider.RuleProvider{}, nil, constant.ClashRouting{})
	tun.SetIPRewrite(nil)

	executor.Shutdown()
	closeConfiguredInbounds()
	resolver.ResetConnection()
	resolver.CloseQueries()

	for _, current := range providers {
		if closer, ok := any(current).(io.Closer); ok {
			_ = closer.Close()
		}
	}
	for _, current := range ruleProviders {
		if closer, ok := any(current).(io.Closer); ok {
			_ = closer.Close()
		}
	}
	for _, current := range proxies {
		_ = current.Close()
	}
}

func (s *BoxService) RuntimeDiagnosticsJSON() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	connectionCount := int32(0)
	statistic.DefaultManager.Range(func(statistic.Tracker) bool {
		connectionCount++
		return true
	})
	runtimeSetup := runtimeSetupSnapshot()
	memory := currentRuntimeMemorySnapshot()
	nat64 := nat64DiagnosticsSnapshot()
	admission := tunnel.TCPConnectionAdmissionSnapshot()
	udpAdmission := tunnel.UDPSessionAdmissionSnapshot()
	endpointKinds, endpointKindsUnnamed := s.outboundEndpointKindsLocked()
	diagnostics := map[string]any{
		"processIdentifier":                   os.Getpid(),
		"startTimeUnix":                       s.startTimeUnix,
		"goroutines":                          runtime.NumGoroutine(),
		"inboundCount":                        s.inboundCount,
		"outboundCount":                       s.outboundCount,
		"dnsMainTransportTypes":               s.dnsTransports.main,
		"dnsFallbackTransportTypes":           s.dnsTransports.fallback,
		"dnsDefaultTransportTypes":            s.dnsTransports.defaults,
		"dnsProxyTransportTypes":              s.dnsTransports.proxyServer,
		"dnsDirectTransportTypes":             s.dnsTransports.direct,
		"dnsPolicyTransportTypes":             s.dnsTransports.policy,
		"outboundEndpointKinds":               endpointKinds,
		"outboundEndpointKindsUnnamed":        endpointKindsUnnamed,
		"connectionCount":                     connectionCount,
		"tcpConnectionAdmissionLimit":         admission.Limit,
		"tcpConnectionAdmissionActive":        admission.Active,
		"tcpConnectionAdmissionRejectedTotal": admission.Rejected,
		"tcpConnectionAdmissionEvictedTotal":  admission.Evicted,
		"udpSessionAdmissionLimit":            udpAdmission.Limit,
		"udpSessionAdmissionActive":           udpAdmission.Active,
		"udpSessionAdmissionRejectedTotal":    udpAdmission.Rejected,
		"udpSessionAdmissionEvictedTotal":     udpAdmission.Evicted,
		"running":                             s.running,
		"pauseCount":                          s.pauseCount.Load(),
		"wakeCount":                           s.wakeCount.Load(),
		"gcPercent":                           runtimeSetup.gcPercent,
		"logMaxLines":                         runtimeSetup.logMaxLines,
		"availableMemoryBytes":                memory.availableBytes,
		"physicalMemoryBytes":                 memory.physicalBytes,
		"goRuntimeResidentBytes":              memory.goResidentBytes,
		"nonGoPhysicalEstimateBytes":          memory.nonGoPhysicalEstimate,
		"goHeapAllocBytes":                    memory.heapAllocBytes,
		"goHeapInuseBytes":                    memory.heapInuseBytes,
		"goStackInuseBytes":                   memory.stackInuseBytes,
		"goGCCount":                           memory.gcCount,
		"goGCPauseTotalNanoseconds":           memory.gcPauseTotalNanoseconds,
		"processCPUTimeNanoseconds":           processCPUTimeNanoseconds(),
		"goMaxProcs":                          runtime.GOMAXPROCS(0),
		"memoryPressureEventCount":            memoryPressureEventCount.Load(),
		"physicalPathSupportsIPv4":            nat64.supportsIPv4,
		"physicalPathSupportsIPv6":            nat64.supportsIPv6,
		"nat64SynthesisAttempts":              nat64.attempts,
		"nat64SynthesisApplied":               nat64.applied,
		"nat64SynthesisFailures":              nat64.failures,
	}
	if runtimeSetup.softMemoryLimit > 0 {
		diagnostics["softMemoryLimit"] = runtimeSetup.softMemoryLimit
	}
	if counts := probeAdmissionCounts.Load(); counts != nil {
		interactive, background, interactiveWaiting, backgroundWaiting := (*counts)()
		diagnostics["probeAdmission"] = map[string]int{
			"interactiveInFlight": interactive, "backgroundInFlight": background,
			"interactiveWaiting": interactiveWaiting, "backgroundWaiting": backgroundWaiting,
		}
	}
	if conf := coreListener.GetTunConf(); conf.Enable {
		diagnostics["tunStack"] = conf.Stack.String()
	}
	if s.reloadVerdict.Reason != "" {
		diagnostics["reloadVerdict"] = s.reloadVerdict
	}
	for key, value := range pressureThresholdDiagnostics() {
		diagnostics[key] = value
	}
	if snapshot := tun.GVisorTCPWindowSnapshot; snapshot != nil {
		window := snapshot()
		diagnostics["gvisorTCPWindowMinBytes"] = window.MinBytes
		diagnostics["gvisorTCPWindowDefaultBytes"] = window.DefaultBytes
		diagnostics["gvisorTCPWindowMaxBytes"] = window.MaxBytes
		diagnostics["gvisorTCPWindowConnections"] = window.TCPConnections
		diagnostics["gvisorTCPReceiveOccupancyP50Bytes"] = window.ReceiveOccupancyP50Bytes
		diagnostics["gvisorTCPReceiveOccupancyP95Bytes"] = window.ReceiveOccupancyP95Bytes
		diagnostics["gvisorTCPReceiveOccupancyMaxBytes"] = window.ReceiveOccupancyMaxBytes
		diagnostics["gvisorTCPConnectionsNearReceiveMax"] = window.ConnectionsNearReceiveMax
		diagnostics["gvisorTCPSegmentQueueDroppedTotal"] = window.SegmentQueueDroppedTotal
	}
	if updater, ok := s.ifaceListener.(*interfaceUpdater); ok {
		path := updater.snapshot()
		diagnostics["physicalPathUpdatesReceived"] = path.received
		diagnostics["physicalPathUpdatesApplied"] = path.applied
		diagnostics["physicalPathIdentityChanges"] = path.identityChanges
		diagnostics["physicalPathConnectionResets"] = path.connectionResets
	}
	if snapshot := tun.GVisorPacketIOSnapshot; snapshot != nil {
		packetIO := snapshot()
		diagnostics["corePacketIngressReadCalls"] = packetIO.IngressReadCalls
		diagnostics["corePacketIngressReadWouldBlock"] = packetIO.IngressReadWouldBlock
		diagnostics["corePacketIngressReadPackets"] = packetIO.IngressReadPackets
		diagnostics["corePacketIngressReadBytes"] = packetIO.IngressReadBytes
		diagnostics["corePacketIngressReadErrors"] = packetIO.IngressReadErrors
		diagnostics["corePacketIngressDispatchPackets"] = packetIO.IngressDispatchPackets
		diagnostics["corePacketIngressDispatchBytes"] = packetIO.IngressDispatchBytes
		diagnostics["corePacketProcessorQueueDepth"] = packetIO.ProcessorQueueDepth
		diagnostics["corePacketProcessorQueuePeak"] = packetIO.ProcessorQueuePeak
		diagnostics["corePacketEgressWriteCalls"] = packetIO.EgressWriteCalls
		diagnostics["corePacketEgressWritePackets"] = packetIO.EgressWritePackets
		diagnostics["corePacketEgressWriteBytes"] = packetIO.EgressWriteBytes
		diagnostics["corePacketEgressWriteErrors"] = packetIO.EgressWriteErrors
		diagnostics["corePacketEgressWriteWaits"] = packetIO.EgressWriteWaits
		diagnostics["corePacketEgressWriteWaitExhausted"] = packetIO.EgressWriteWaitExhausted
	}
	tunEgress := tun.TunEgressSnapshot()
	diagnostics["coreTunEgressWriteWaits"] = tunEgress.WriteWaits
	diagnostics["coreTunEgressWriteWaitExhausted"] = tunEgress.WriteWaitExhausted
	deferred := tun.DeferredHandshakeSnapshot()
	diagnostics["coreDeferredHandshakes"] = deferred.Deferred
	diagnostics["coreDeferredHandshakesBudgetSpent"] = deferred.BudgetSpent
	diagnostics["coreDeferredHandshakesCompleted"] = deferred.Completed
	diagnostics["coreDeferredHandshakesCompletedLate"] = deferred.CompletedLate
	diagnostics["coreDeferredHandshakesNotCompleted"] = deferred.NotCompleted
	diagnostics["coreDeferredHandshakesRefused"] = deferred.Refused
	diagnostics["coreDeferredHandshakesPending"] = deferred.Pending
	return bridgeSafeString(mustJSON(diagnostics))
}

func finalizeConfigForIOS(cfg *config.Config, underNE bool) {
	finalizeConfigForApple(cfg, runtimePolicyFor(runtimeProfileIOSPacketTunnel, underNE))
}

func finalizeConfigForApple(cfg *config.Config, policy appleRuntimePolicy) {
	if policy.networkExtension && policy.packetTunnel {
		ensureTunEnabled(&cfg.General.Tun)
	}
	overrideForAppleConfig(cfg, policy)
	if policy.networkExtension {
		overrideForNetworkExtension(cfg)
	}
}

func tunConfigurationsEqual(left, right LC.Tun) bool {
	left = cloneTunSlices(left)
	right = cloneTunSlices(right)
	clearTunFieldsDarwinNeverReads(&left)
	clearTunFieldsDarwinNeverReads(&right)
	left.Sort()
	right.Sort()
	sortTunFieldsMissingFromUpstream(&left)
	sortTunFieldsMissingFromUpstream(&right)
	return left.Equal(right) &&
		slices.Equal(left.LoopbackAddress, right.LoopbackAddress) &&
		slices.Equal(left.ExcludeSrcPort, right.ExcludeSrcPort) &&
		slices.Equal(left.ExcludeSrcPortRange, right.ExcludeSrcPortRange) &&
		slices.Equal(left.ExcludeDstPort, right.ExcludeDstPort) &&
		slices.Equal(left.ExcludeDstPortRange, right.ExcludeDstPortRange)
}

func clearTunFieldsDarwinNeverReads(tun *LC.Tun) {
	tun.IncludeInterface, tun.ExcludeInterface = nil, nil
	tun.IncludeUID, tun.IncludeUIDRange, tun.ExcludeUID, tun.ExcludeUIDRange = nil, nil, nil, nil
	tun.ExcludeSrcPort, tun.ExcludeSrcPortRange = nil, nil
	tun.ExcludeDstPort, tun.ExcludeDstPortRange = nil, nil
	tun.IncludeMACAddress, tun.ExcludeMACAddress = nil, nil
	tun.IncludeAndroidUser, tun.IncludePackage, tun.ExcludePackage = nil, nil, nil
	tun.AutoRedirect = false
	tun.AutoRedirectInputMark, tun.AutoRedirectOutputMark = 0, 0
	tun.AutoRedirectIPRoute2FallbackRuleIndex = 0
	tun.IPRoute2TableIndex, tun.IPRoute2RuleIndex = 0, 0
}

func cloneTunSlices(tun LC.Tun) LC.Tun {
	tun.DNSHijack = slices.Clone(tun.DNSHijack)
	tun.Inet4Address = slices.Clone(tun.Inet4Address)
	tun.Inet6Address = slices.Clone(tun.Inet6Address)
	tun.LoopbackAddress = slices.Clone(tun.LoopbackAddress)
	tun.RouteAddress = slices.Clone(tun.RouteAddress)
	tun.RouteAddressSet = slices.Clone(tun.RouteAddressSet)
	tun.RouteExcludeAddress = slices.Clone(tun.RouteExcludeAddress)
	tun.RouteExcludeAddressSet = slices.Clone(tun.RouteExcludeAddressSet)
	tun.IncludeInterface = slices.Clone(tun.IncludeInterface)
	tun.ExcludeInterface = slices.Clone(tun.ExcludeInterface)
	tun.IncludeUID = slices.Clone(tun.IncludeUID)
	tun.IncludeUIDRange = slices.Clone(tun.IncludeUIDRange)
	tun.ExcludeUID = slices.Clone(tun.ExcludeUID)
	tun.ExcludeUIDRange = slices.Clone(tun.ExcludeUIDRange)
	tun.ExcludeSrcPort = slices.Clone(tun.ExcludeSrcPort)
	tun.ExcludeSrcPortRange = slices.Clone(tun.ExcludeSrcPortRange)
	tun.ExcludeDstPort = slices.Clone(tun.ExcludeDstPort)
	tun.ExcludeDstPortRange = slices.Clone(tun.ExcludeDstPortRange)
	tun.IncludeAndroidUser = slices.Clone(tun.IncludeAndroidUser)
	tun.IncludePackage = slices.Clone(tun.IncludePackage)
	tun.ExcludePackage = slices.Clone(tun.ExcludePackage)
	tun.IncludeMACAddress = slices.Clone(tun.IncludeMACAddress)
	tun.ExcludeMACAddress = slices.Clone(tun.ExcludeMACAddress)
	tun.Inet4RouteAddress = slices.Clone(tun.Inet4RouteAddress)
	tun.Inet6RouteAddress = slices.Clone(tun.Inet6RouteAddress)
	tun.Inet4RouteExcludeAddress = slices.Clone(tun.Inet4RouteExcludeAddress)
	tun.Inet6RouteExcludeAddress = slices.Clone(tun.Inet6RouteExcludeAddress)
	return tun
}

func sortTunFieldsMissingFromUpstream(tun *LC.Tun) {
	slices.SortFunc(tun.LoopbackAddress, func(left, right netip.Addr) int {
		return left.Compare(right)
	})
	slices.Sort(tun.ExcludeSrcPort)
	slices.Sort(tun.ExcludeSrcPortRange)
	slices.Sort(tun.ExcludeDstPort)
	slices.Sort(tun.ExcludeDstPortRange)
}

func (s *BoxService) Status() string {
	return bridgeSafeString(tunnel.Status().String())
}

func (s *BoxService) Mode() string {
	s.routingMu.Lock()
	defer s.routingMu.Unlock()
	return bridgeSafeString(tunnel.Mode().String())
}

func (s *BoxService) SetMode(mode string) error {
	m, ok := tunnel.ModeMapping[strings.ToLower(mode)]
	if !ok {
		return bridgeSafeError(fmt.Errorf("clash: unknown mode %q", mode))
	}
	s.routingMu.Lock()
	defer s.routingMu.Unlock()
	tunnel.SetMode(m)
	return nil
}

const endPauseTimeout = time.Minute

func (s *BoxService) releasePauseOnClose() {
	s.endPauseMu.Lock()
	if s.endPauseTimer != nil {
		s.endPauseTimer.Stop()
	}
	s.endPauseMu.Unlock()

	if s.pauseCount.Load() > s.wakeCount.Load() {
		pause.DeviceWake()
	}
}

func (s *BoxService) Pause() {
	s.pauseCount.Add(1)
	pause.DevicePause()
	s.armEndPauseTimer()
	debug.FreeOSMemory()
}

func (s *BoxService) armEndPauseTimer() {
	if !currentRuntimeProfile().inheritsIOSPacketTunnelBehavior() {
		return
	}
	s.endPauseMu.Lock()
	defer s.endPauseMu.Unlock()
	if s.endPauseTimer == nil {
		s.endPauseTimer = time.AfterFunc(endPauseTimeout, pause.DeviceWake)
		return
	}
	s.endPauseTimer.Reset(endPauseTimeout)
}

func (s *BoxService) Wake() {
	s.wakeCount.Add(1)
	pause.DeviceWake()
	resolver.ResetConnection()
}

func (s *BoxService) closeOrphanedProviderRuntimesLocked() {
	for _, runtime := range s.orphanedProviderRuntimes {
		runtime.close()
	}
	s.orphanedProviderRuntimes = nil
}

func configurationSHA256(configContent string) string {
	sum := sha256.Sum256([]byte(configContent))
	return hex.EncodeToString(sum[:])
}

func (s *BoxService) runningConfigurationSHA256() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.runningConfigSHA256
}
