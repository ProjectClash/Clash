package tunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	syncatomic "sync/atomic"

	"github.com/ProjectClash/Clash/common/atomic"
	"github.com/ProjectClash/Clash/common/lru"
	N "github.com/ProjectClash/Clash/common/net"
	"github.com/ProjectClash/Clash/common/utils"
	"github.com/ProjectClash/Clash/component/dialer"
	"github.com/ProjectClash/Clash/component/loopback"
	"github.com/ProjectClash/Clash/component/mitm"
	"github.com/ProjectClash/Clash/component/nat"
	"github.com/ProjectClash/Clash/component/pause"
	"github.com/ProjectClash/Clash/component/process"
	"github.com/ProjectClash/Clash/component/proxydialer"
	"github.com/ProjectClash/Clash/component/resolver"
	"github.com/ProjectClash/Clash/component/slowdown"
	"github.com/ProjectClash/Clash/component/sniffer"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/constant/features"
	P "github.com/ProjectClash/Clash/constant/provider"
	icontext "github.com/ProjectClash/Clash/context"
	"github.com/ProjectClash/Clash/log"
	"github.com/ProjectClash/Clash/tunnel/statistic"

	"golang.org/x/exp/slices"
)

const (
	queueCapacity  = 64  // chan capacity tcpQueue and udpQueue
	senderCapacity = 128 // chan capacity of PacketSender
)

var (
	status    = atomic.NewInt32Enum(Suspend)
	udpInit   sync.Once
	udpQueues []chan C.PacketAdapter
	natTable  = nat.New()
	published syncatomic.Pointer[runtimeVersion]
	configMux sync.RWMutex

	// for compatibility, lazy init
	tcpQueue  chan C.ConnContext
	tcpInOnce sync.Once
	udpQueue  chan C.PacketAdapter
	udpInOnce sync.Once

	// default timeout for UDP session
	udpTimeout = 60 * time.Second

	findProcessMode = atomic.NewInt32Enum(process.FindProcessStrict)

	snifferDispatcher syncatomic.Pointer[sniffer.Dispatcher]
	sniffingEnable    syncatomic.Bool

	mitmDispatcher syncatomic.Pointer[mitm.Dispatcher]

	ruleUpdateCallback = utils.NewCallback[P.RuleProvider]()
)

type tunnel struct{}

var Tunnel = tunnel{}
var _ C.Tunnel = Tunnel
var _ P.Tunnel = Tunnel
var _ proxydialer.Tunnel = Tunnel

func (t tunnel) HandleTCPConn(conn net.Conn, metadata *C.Metadata) {
	connCtx := icontext.NewConnContext(conn, metadata)
	handleTCPConn(connCtx)
}

func (t tunnel) HandleTCPConnContext(ctx context.Context, conn net.Conn, metadata *C.Metadata) {
	handleTCPConnContext(ctx, icontext.NewConnContext(conn, metadata))
}

func initUDP() {
	numUDPWorkers := 4
	if num := runtime.GOMAXPROCS(0); num > numUDPWorkers {
		numUDPWorkers = num
	}

	udpQueues = make([]chan C.PacketAdapter, numUDPWorkers)
	for i := 0; i < numUDPWorkers; i++ {
		queue := make(chan C.PacketAdapter, queueCapacity)
		udpQueues[i] = queue
		go processUDP(queue)
	}
}

func (t tunnel) HandleUDPPacket(packet C.UDPPacket, metadata *C.Metadata) {
	udpInit.Do(initUDP)

	packetAdapter := C.NewPacketAdapter(packet, metadata)
	key := packetAdapter.Key()

	hash := utils.MapHash(key)
	queueNo := uint(hash) % uint(len(udpQueues))

	select {
	case udpQueues[queueNo] <- packetAdapter:
	default:
		packet.Drop()
	}
}

func (t tunnel) NatTable() C.NatTable {
	return natTable
}

func (t tunnel) Proxies() map[string]C.Proxy {
	return loadProxies()
}

func (t tunnel) LookupProxy(name string) (C.Proxy, bool) {
	return LookupProxy(name)
}

func (t tunnel) Providers() map[string]P.ProxyProvider {
	return loadProviders()
}

func (t tunnel) RuleProviders() map[string]P.RuleProvider {
	return loadRuleProviders()
}

func (t tunnel) RuleUpdateCallback() *utils.Callback[P.RuleProvider] {
	return ruleUpdateCallback
}

func OnSuspend() {
	status.Store(Suspend)
}

func OnInnerLoading() {
	status.Store(Inner)
}

func OnRunning() {
	status.Store(Running)
}

func Status() TunnelStatus {
	return status.Load()
}

func SetSniffing(b bool) {
	if snifferDispatcher.Load().Enable() {
		configMux.Lock()
		sniffingEnable.Store(b)
		configMux.Unlock()
	}
}

func IsSniffing() bool {
	return sniffingEnable.Load()
}

// TCPIn return fan-in queue
// Deprecated: using Tunnel instead
func TCPIn() chan<- C.ConnContext {
	tcpInOnce.Do(func() {
		tcpQueue = make(chan C.ConnContext, queueCapacity)
		go func() {
			for connCtx := range tcpQueue {
				go handleTCPConn(connCtx)
			}
		}()
	})
	return tcpQueue
}

// UDPIn return fan-in udp queue
// Deprecated: using Tunnel instead
func UDPIn() chan<- C.PacketAdapter {
	udpInOnce.Do(func() {
		udpQueue = make(chan C.PacketAdapter, queueCapacity)
		go func() {
			for packet := range udpQueue {
				Tunnel.HandleUDPPacket(packet, packet.Metadata())
			}
		}()
	})
	return udpQueue
}

// NatTable return nat table
func NatTable() C.NatTable {
	return natTable
}

// Rules return all rules
func Rules() []C.Rule {
	return loadRules()
}

func Listeners() map[string]C.InboundListener {
	return loadListeners()
}

// UpdateRules handle update rules
func UpdateRules(newRules []C.Rule, newSubRule map[string][]C.Rule, rp map[string]P.RuleProvider) {
	publish(func(v *runtimeVersion) {
		v.rules, v.subRules, v.ruleProviders = newRules, newSubRule, rp
	})
}

// Proxies return all proxies
func Proxies() map[string]C.Proxy {
	return loadProxies()
}

// Providers return all compatible providers
func Providers() map[string]P.ProxyProvider {
	return loadProviders()
}

type runtimeVersion struct {
	mode          TunnelMode
	proxies       map[string]C.Proxy
	providers     map[string]P.ProxyProvider
	rules         []C.Rule
	subRules      map[string][]C.Rule
	ruleProviders map[string]P.RuleProvider
	listeners     map[string]C.InboundListener
	proxyTable uint64
	library C.ProxyLibrary
}

func (v *runtimeVersion) lookup(name string) (C.Proxy, bool) {
	if proxy, ok := v.proxies[name]; ok {
		return proxy, true
	}
	if v.library != nil {
		return v.library.Lookup(name)
	}
	return nil, false
}

func LookupProxy(name string) (C.Proxy, bool) {
	return loadVersion().lookup(name)
}

func ProxyLibrary() C.ProxyLibrary {
	return loadVersion().library
}

func RangeProxies(f func(name string, proxy C.Proxy) bool) {
	v := loadVersion()
	for name, proxy := range v.proxies {
		if !f(name, proxy) {
			return
		}
	}
	if v.library != nil {
		for i := 0; i < v.library.Len(); i++ {
			node := v.library.At(i)
			if !f(node.Name(), node) {
				return
			}
		}
	}
}

var initialVersion = runtimeVersion{mode: Rule, proxies: map[string]C.Proxy{}, listeners: map[string]C.InboundListener{}}

func loadVersion() *runtimeVersion {
	if v := published.Load(); v != nil {
		return v
	}
	return &initialVersion
}

func publish(change func(*runtimeVersion)) {
	configMux.Lock()
	defer configMux.Unlock()
	next := *loadVersion()
	change(&next)
	published.Store(&next)
}

func ProxyTable() (map[string]C.Proxy, map[string]P.ProxyProvider, uint64) {
	v := loadVersion()
	return v.proxies, v.providers, v.proxyTable
}

func loadProxies() map[string]C.Proxy              { return loadVersion().proxies }
func loadProviders() map[string]P.ProxyProvider    { return loadVersion().providers }
func loadRules() []C.Rule                          { return loadVersion().rules }
func loadRuleProviders() map[string]P.RuleProvider { return loadVersion().ruleProviders }
func loadListeners() map[string]C.InboundListener  { return loadVersion().listeners }

func (v *runtimeVersion) proxy(name string) (C.Proxy, error) {
	if proxy, _ := v.lookup(name); proxy != nil {
		return proxy, nil
	}
	return nil, fmt.Errorf("proxy %s not found", name)
}

// RuleProviders return all loaded rule providers
func RuleProviders() map[string]P.RuleProvider {
	return loadRuleProviders()
}

// UpdateProxies handle update proxies
func UpdateProxies(newProxies map[string]C.Proxy, newProviders map[string]P.ProxyProvider, library ...C.ProxyLibrary) {
	publish(func(v *runtimeVersion) {
		v.proxies, v.providers, v.proxyTable = newProxies, newProviders, v.proxyTable+1
		v.library = lastLibrary(library)
	})
}

func lastLibrary(library []C.ProxyLibrary) C.ProxyLibrary {
	if len(library) == 0 {
		return nil
	}
	return library[len(library)-1]
}

func UpdateProxiesAndRules(newProxies map[string]C.Proxy, newProviders map[string]P.ProxyProvider, newRules []C.Rule, newSubRule map[string][]C.Rule, rp map[string]P.RuleProvider, library ...C.ProxyLibrary) {
	publish(func(v *runtimeVersion) {
		v.proxies, v.providers, v.proxyTable = newProxies, newProviders, v.proxyTable+1
		v.library = lastLibrary(library)
		v.rules, v.subRules, v.ruleProviders = newRules, newSubRule, rp
	})
}

func UpdateListeners(newListeners map[string]C.InboundListener) {
	publish(func(v *runtimeVersion) { v.listeners = newListeners })
}

func UpdateSniffer(dispatcher *sniffer.Dispatcher) {
	configMux.Lock()
	snifferDispatcher.Store(dispatcher)
	sniffingEnable.Store(dispatcher.Enable())
	configMux.Unlock()
}

// UpdateMITM swaps the MITM dispatcher used by the TCP hot path; nil
// disables interception.
func UpdateMITM(dispatcher *mitm.Dispatcher) {
	configMux.Lock()
	mitmDispatcher.Store(dispatcher)
	configMux.Unlock()
}

// Mode return current mode
func Mode() TunnelMode {
	return loadVersion().mode
}

var modeObserver syncatomic.Pointer[func(TunnelMode)]

func SetModeObserver(observe func(TunnelMode)) {
	if observe == nil {
		modeObserver.Store(nil)
		return
	}
	modeObserver.Store(&observe)
}

// SetMode change the mode of tunnel
func SetMode(m TunnelMode) {
	publish(func(v *runtimeVersion) { v.mode = m })
	if observe := modeObserver.Load(); observe != nil {
		(*observe)(m)
	}
}

func FindProcessMode() process.FindProcessMode {
	return findProcessMode.Load()
}

// SetFindProcessMode replace SetAlwaysFindProcess
// always find process info if legacyAlways = true or mode.Always() = true, may be increase many memory
func SetFindProcessMode(mode process.FindProcessMode) {
	findProcessMode.Store(mode)
}

func isHandle(t C.Type) bool {
	status := status.Load()
	return status == Running || (status == Inner && t == C.INNER)
}

func fixMetadata(metadata *C.Metadata) {
	// first unmap dstIP
	metadata.DstIP = metadata.DstIP.Unmap()
	// handle IP string on host
	if ip, err := netip.ParseAddr(metadata.Host); err == nil {
		metadata.DstIP = ip.Unmap()
		metadata.Host = ""
	}
}

func needLookupIP(metadata *C.Metadata) bool {
	return resolver.MappingEnabled() && metadata.Host == "" && metadata.DstIP.IsValid()
}

type fakeRecordMissing struct{ ip netip.Addr }

func (e fakeRecordMissing) Error() string {
	return fmt.Sprintf("fake DNS record %s missing", e.ip)
}

func logPreHandleError(metadata *C.Metadata, err error) {
	var missing fakeRecordMissing
	if errors.As(err, &missing) {
		if missingRecordReport(missing.ip) {
			log.Warnln("[Metadata PreHandle] %s --> %s: %s", metadata.SourceDetail(), metadata.RemoteAddress(), err)
		} else {
			log.Debugln("[Metadata PreHandle] error: %s", err)
		}
		return
	}
	log.Debugln("[Metadata PreHandle] error: %s", err)
}

var missingRecordReports = lru.New[netip.Addr, struct{}](
	lru.WithSize[netip.Addr, struct{}](256),
	lru.WithAge[netip.Addr, struct{}](10),
)

func missingRecordReport(ip netip.Addr) bool {
	if _, seen := missingRecordReports.Get(ip); seen {
		return false
	}
	missingRecordReports.Set(ip, struct{}{})
	return true
}

func preHandleMetadata(metadata *C.Metadata) error {
	if !resolver.IsFakeIP(metadata.DstIP) && !resolver.CurrentIPQueryPolicy().AllowsAddress(metadata.DstIP) {
		return resolver.ErrIPVersion
	}
	// preprocess enhanced-mode metadata
	if needLookupIP(metadata) {
		host, exist := resolver.FindHostByIP(metadata.DstIP)
		if exist {
			metadata.Host = host
			metadata.DNSMode = C.DNSMapping
			if resolver.IsFakeIP(metadata.DstIP) {
				// only clear dstIP if it is confirmed to be a fake IP
				metadata.DstIP = netip.Addr{}
				metadata.DNSMode = C.DNSFakeIP
			} else if node, ok := resolver.DefaultHosts.Search(host, false); ok {
				// redir-host should lookup the hosts
				metadata.DstIP, _ = ipStackHostAddress(node)
			} else if node != nil && node.IsDomain {
				metadata.Host = node.Domain
			}
		} else if resolver.IsFakeIP(metadata.DstIP) {
			return fakeRecordMissing{metadata.DstIP}
		}
	} else if node, ok := resolver.DefaultHosts.Search(metadata.Host, true); ok {
		// try use domain mapping
		metadata.Host = node.Domain
	}

	return nil
}

func ownerLookupUsesPackageName(cmfa bool, goos string) bool {
	return cmfa && goos == "android"
}

var resolvesOwnerByPackageName = ownerLookupUsesPackageName(features.CMFA, runtime.GOOS)

func lookupProxy(name string) (C.Proxy, error) {
	return loadVersion().proxy(name)
}

func resolveMetadata(metadata *C.Metadata) (proxy C.Proxy, rule C.Rule, err error) {
	return resolveMetadataContext(context.Background(), metadata)
}

func resolveMetadataContext(parent context.Context, metadata *C.Metadata) (proxy C.Proxy, rule C.Rule, err error) {
	return resolveMetadataInVersion(parent, metadata, loadVersion())
}

func resolveMetadataInVersion(parent context.Context, metadata *C.Metadata, version *runtimeVersion) (proxy C.Proxy, rule C.Rule, err error) {
	if metadata.SpecialProxy != "" {
		proxy, err = version.proxy(metadata.SpecialProxy)
		return
	}
	flow := &flowMatch{
		metadata:             metadata,
		version:              version,
		attemptProcessLookup: metadata.Type != C.INNER && !metadata.SourceIdentityKnown,
	}

	if node, ok := resolver.DefaultHosts.Search(metadata.Host, false); ok {
		metadata.DstIP, _ = ipStackHostAddress(node)
		flow.resolved = true
	}

	helper := C.RuleMatchHelper{
		ResolveIP: func() {
			metadata := flow.metadata
			if !flow.resolved && metadata.Host != "" && !metadata.Resolved() {
				ctx, cancel := context.WithTimeout(parent, resolver.DefaultDNSTimeout)
				defer cancel()
				ip, err := resolver.ResolveIP(ctx, metadata.Host)
				if err != nil {
					log.Debugln("[DNS] resolve %s error: %s", metadata.Host, err.Error())
				} else {
					log.Debugln("[DNS] %s --> %s", metadata.Host, ip.String())
					metadata.DstIP = ip
				}
				flow.resolved = true
			}
		},
		FindProcess: func() {
			metadata := flow.metadata
			if flow.attemptProcessLookup {
				flow.attemptProcessLookup = false
				if !resolvesOwnerByPackageName {
					// normal check for process
					ownerDstIP, ownerDstPort := ownerDestination(metadata)
					uid, path, err := process.FindConnectionOwner(metadata.NetWork.String(), metadata.SrcIP, int(metadata.SrcPort), ownerDstIP, ownerDstPort)
					if err != nil {
						log.Debugln("[Process] find process error for %s: %v", metadata.String(), err)
					} else {
						metadata.Process = filepath.Base(path)
						metadata.ProcessPath = path
						metadata.Uid = uid
						metadata.UidKnown = true
						metadata.SourceIdentityKnown = true

						if pkg, err := process.FindPackageName(metadata); err == nil { // for android (not CMFA) package names
							metadata.Process = pkg
						}
					}
				} else {
					// check package names
					pkg, err := process.FindPackageName(metadata)
					if err != nil {
						log.Debugln("[Process] find process error for %s: %v", metadata.String(), err)
					} else {
						metadata.Process = pkg
					}
				}
			}
		},
		CheckPassRule: func(adapterName string) bool {
			metadata := flow.metadata
			adapter, ok := flow.version.lookup(adapterName)
			if !ok {
				return false
			}
			for a := adapter; a != nil; a = a.Unwrap(metadata, false) {
				if a.Type() == C.PassRule {
					return true
				}
			}
			return false
		},
		RuleProviders: version.ruleProviders,
	}

	switch FindProcessMode() {
	case process.FindProcessAlways:
		helper.FindProcess()
		helper.FindProcess = nil
	case process.FindProcessOff:
		helper.FindProcess = nil
	}

	switch version.mode {
	case Direct:
		proxy, err = version.proxy("DIRECT")
	case Global:
		proxy, err = version.proxy("GLOBAL")
	// Rule
	default:
		proxy, rule, err = match(metadata, helper, version)
	}
	return
}

// processUDP starts a loop to handle udp packet
func processUDP(queue chan C.PacketAdapter) {
	for conn := range queue {
		handleUDPConn(conn)
	}
}

func handleUDPConn(packet C.PacketAdapter) {
	if !isHandle(packet.Metadata().Type) {
		packet.Drop()
		return
	}

	metadata := packet.Metadata()
	if !metadata.Valid() {
		packet.Drop()
		log.Warnln("[Metadata] not valid: %#v", metadata)
		return
	}
	fixMetadata(metadata) // fix some metadata not set via metadata.SetRemoteAddr or metadata.SetRemoteAddress

	if err := preHandleMetadata(metadata.Clone()); err != nil { // precheck without modify metadata
		packet.Drop()
		logPreHandleError(metadata, err)
		return
	}

	key := packet.Key()
	sender, loaded := natTable.GetOrCreate(key, withUDPQuota(func() C.PacketSender {
		sender := newPacketSender()
		if dispatcher := snifferDispatcher.Load(); sniffingEnable.Load() && dispatcher.Enable() {
			return dispatcher.UDPSniff(packet, sender)
		}
		return sender
	}))
	if !loaded {
		dial := func() (C.PacketConn, C.WriteBackProxy, error) {
			originMetadata := metadata  // save origin metadata
			metadata = metadata.Clone() // don't modify PacketAdapter's metadata

			if err := sender.DoSniff(metadata); err != nil {
				log.Warnln("[UDP] DoSniff error: %s", err.Error())
				return nil, nil, err
			}

			if err := preHandleMetadata(metadata); err != nil {
				return nil, nil, err
			}

			proxy, rule, err := resolveMetadata(metadata)
			if err != nil {
				log.Warnln("[UDP] Parse metadata failed: %s", err.Error())
				return nil, nil, err
			}

			dialMetadata := metadata.Pure()
			ctx, cancel := context.WithTimeout(context.Background(), C.DefaultUDPTimeout)
			defer cancel()
			dialMetadata, err = ipStackDialMetadata(ctx, dialMetadata, !proxy.IsL3Protocol(dialMetadata))
			if err != nil {
				return nil, nil, err
			}
			rawPc, err := retry(ctx, func(ctx context.Context) (C.PacketConn, error) {
				return proxy.ListenPacketContext(ctx, dialMetadata)
			}, func(err error) {
				logMetadataErr(metadata, rule, proxy, err)
			})
			if err != nil {
				return nil, nil, err
			}
			logMetadata(metadata, rule, rawPc)
			if terminalAdapterType(proxy, dialMetadata) == C.Reject {
				reportUDPUnreachable(packet, metadata, "rejected by rule")
			}

			pc := statistic.NewUDPTracker(rawPc, statistic.DefaultManager, metadata, rule, 0, 0, true)

			sender.AddMapping(originMetadata, dialMetadata)
			oAddrPort := dialMetadata.AddrPort()
			writeBackProxy := nat.NewWriteBackProxy(packet)

			go handleUDPToLocal(writeBackProxy, pc, sender, key, oAddrPort)
			return pc, writeBackProxy, nil
		}

		go func() {
			if !admitUDPSession(context.Background(), sender) {
				reportUDPUnreachable(packet, metadata, "the UDP session quota is full")
				sender.Close()
				natTable.Delete(key)
				return
			}
			pc, proxy, err := dial()
			if err != nil {
				reportUDPUnreachable(packet, metadata, "the outbound could not be opened")
				sender.Close()
				natTable.Delete(key)
				return
			}
			sender.Process(pc, proxy)
		}()
	}
	sender.Send(packet) // nonblocking
}

func handleTCPConn(connCtx C.ConnContext) {
	handleTCPConnContext(context.Background(), connCtx)
}

func handleTCPConnContext(parent context.Context, connCtx C.ConnContext) {
	if !isHandle(connCtx.Metadata().Type) {
		_ = connCtx.Conn().Close()
		return
	}
	waitNewSessionGate(parent, C.TCP)
	if !admitTCPConnection() {
		_ = connCtx.Conn().Close()
		return
	}
	defer releaseTCPConnectionSlot()

	defer func(conn net.Conn) {
		_ = conn.Close()
	}(connCtx.Conn())

	metadata := connCtx.Metadata()
	if !metadata.Valid() {
		log.Warnln("[Metadata] not valid: %#v", metadata)
		return
	}
	fixMetadata(metadata) // fix some metadata not set via metadata.SetRemoteAddr or metadata.SetRemoteAddress

	preHandleFailed := false
	if err := preHandleMetadata(metadata); err != nil {
		logPreHandleError(metadata, err)
		if errors.Is(err, resolver.ErrIPVersion) {
			return
		}
		preHandleFailed = true
	}

	conn := connCtx.Conn()
	conn.ResetPeeked() // reset before sniffer
	if dispatcher := snifferDispatcher.Load(); sniffingEnable.Load() && dispatcher.Enable() && !sniffingStandsAside(conn, metadata) {
		// Try to sniff a domain when `preHandleMetadata` failed, this is usually
		// caused by a "Fake DNS record missing" error when enhanced-mode is fake-ip.
		if dispatcher.TCPSniff(conn, metadata) {
			// we now have a domain name
			preHandleFailed = false
		}
	}

	// If both trials have failed, we can do nothing but give up
	if preHandleFailed {
		log.Debugln("[Metadata PreHandle] failed to sniff a domain for connection %s --> %s, give up",
			metadata.SourceDetail(), metadata.RemoteAddress())
		return
	}

	peekMutex := sync.Mutex{}
	if !conn.Peeked() && !N.HandshakePending(conn) {
		peekMutex.Lock()
		go func() {
			defer peekMutex.Unlock()
			_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			_, _ = conn.Peek(1)
			_ = conn.SetReadDeadline(time.Time{})
		}()
	}

	proxy, rule, err := resolveMetadataContext(parent, metadata)
	if err != nil {
		log.Warnln("[Metadata] parse failed: %s", err.Error())
		return
	}

	// MITM interception: when the dispatcher claims this connection it is
	// served to completion (TLS terminated, requests rewritten and forwarded
	// through the same rule-resolved proxy), and handleTCPConnContext closes
	// it without running the byte-pipe below. A decline returns the conn
	// with peeked bytes intact and the normal path proceeds.
	//
	// dialCtx carries the short TCP dial deadline for the gate/peek phase
	// only. Once the dispatcher claims the conn it switches to a long-lived
	// context (values kept, cancellation dropped), and every upstream dial
	// inside it runs under a fresh DefaultTCPTimeout budget so keep-alive
	// requests seconds or minutes later still dial.
	if d := mitm.ActiveDispatcher(); d != nil && d.Enable() {
		dialCtx, dialCancel := context.WithTimeout(parent, C.DefaultTCPTimeout)
		// A dedicated metadata copy per dial: metadata.Pure() can alias
		// the original in some DNS modes, and mutating a shared struct
		// would corrupt the outer conn's metadata.
		mitmDial := func(ctx context.Context, host string, port uint16) (net.Conn, error) {
			dialMeta := &C.Metadata{
				NetWork: metadata.NetWork,
				Type:    metadata.Type,
				SrcIP:   metadata.SrcIP,
				SrcPort: metadata.SrcPort,
				InIP:    metadata.InIP,
				InPort:  metadata.InPort,
				InName:  metadata.InName,
				InUser:  metadata.InUser,
				Host:    host,
				DstPort: port,
				DNSMode: C.DNSNormal,
			}
			return proxy.DialContext(ctx, dialMeta)
		}
		claimed := mitm.TrafficMatch(dialCtx, conn, metadata, mitmDial)
		dialCancel()
		if claimed {
			if N.HandshakePending(conn) {
				// The interceptor answers inline; the outer proxy
				// conn is never dialed, so the deferred handshake
				// resolves as success to whoever waits on it.
				_ = N.ReportDeferredHandshake(conn, nil)
			}
			// Gated conns never reach logMetadata below; leave the
			// same style of trace so interception is visible.
			log.Infoln("[%s] %s --> %s intercepted[MITM] using %s",
				strings.ToUpper(metadata.NetWork.String()), metadata.SourceDetail(), metadata.RemoteAddress(), proxy.Name())
			return
		}
	}

	dialMetadata := metadata
	if len(metadata.Host) > 0 {
		if node, ok := resolver.DefaultHosts.Search(metadata.Host, false); ok {
			if dstIp, _ := ipStackHostAddress(node); !resolver.IsFakeIP(dstIp) {
				dialMetadata.DstIP = dstIp
				dialMetadata.DNSMode = C.DNSHosts
				dialMetadata = dialMetadata.Pure()
			}
		}
	}

	var peekBytes []byte
	var peekLen int

	ctx, cancel := context.WithTimeout(parent, C.DefaultTCPTimeout)
	defer cancel()
	dialMetadata, err = ipStackDialMetadata(ctx, dialMetadata, !proxy.IsL3Protocol(dialMetadata))
	if err != nil {
		logMetadataErr(metadata, rule, proxy, err)
		return
	}
	deferred := N.HandshakePending(conn)
	ctx = dialer.WithDialKind(ctx, dialKindOf(proxy, dialMetadata))
	remoteConn, err := retry(ctx, func(ctx context.Context) (remoteConn C.Conn, err error) {
		remoteConn, err = proxy.DialContext(ctx, dialMetadata)
		if err != nil {
			if deferred && errors.Is(err, syscall.ECONNREFUSED) && terminalAdapterType(proxy, dialMetadata) == C.Direct {
				err = finalDialError{err}
			}
			return
		}

		if N.NeedHandshake(remoteConn) {
			handshakeConn := remoteConn
			stop := context.AfterFunc(ctx, func() { _ = handshakeConn.Close() })
			defer stop()
			defer func() {
				if err != nil {
					_ = remoteConn.Close()
					for _, chain := range remoteConn.Chains() {
						if chain == "REJECT" {
							err = nil
							return
						}
					}
					remoteConn = nil
				}
			}()
			if N.HandshakePending(conn) && !N.TransportPending(remoteConn) {
				if reportErr := N.ReportDeferredHandshake(conn, nil); reportErr != nil {
					err = clientLeftError{reportErr}
					return
				}
				if !serverSpeaksFirst(metadata.DstPort) {
					_ = conn.SetReadDeadline(time.Now().Add(firstBytesWait))
					_, _ = conn.Peek(1)
					_ = conn.SetReadDeadline(time.Time{})
				}
			}
			peekMutex.Lock()
			defer peekMutex.Unlock()
			peekBytes, _ = conn.Peek(conn.Buffered())
			_, err = remoteConn.Write(peekBytes)
			if err != nil {
				return
			}
			if peekLen = len(peekBytes); peekLen > 0 {
				_, _ = conn.Discard(peekLen)
			}
		}
		return
	}, func(err error) {
		var left clientLeftError
		if !errors.As(err, &left) {
			logMetadataErr(metadata, rule, proxy, err)
		}
	})
	var left clientLeftError
	if errors.As(err, &left) {
		log.Debugln("[TCP] %s --> %s handshake with the client failed after the dial: %s", metadata.SourceDetail(), metadata.RemoteAddress(), left.error)
		return
	}
	if err != nil {
		if N.HandshakePending(conn) {
			log.Debugln("[TCP] %s --> %s reset before its handshake: the dial failed", metadata.SourceDetail(), metadata.RemoteAddress())
		}
		_ = N.ReportDeferredHandshake(conn, err)
		return
	}
	tracked := false
	defer func(remoteConn C.Conn) {
		if !tracked {
			_ = remoteConn.Close()
		}
	}(remoteConn)

	if N.HandshakePending(conn) && terminalAdapterType(proxy, dialMetadata) == C.Reject {
		logMetadata(metadata, rule, remoteConn)
		log.Debugln("[TCP] %s --> %s reset before its handshake: rejected by rule", metadata.SourceDetail(), metadata.RemoteAddress())
		_ = N.ReportDeferredHandshake(conn, errRejectedByRule)
		return
	}

	if err = N.ReportDeferredHandshake(conn, nil); err != nil {
		log.Debugln("[TCP] %s --> %s handshake with the client failed after the dial: %s", metadata.SourceDetail(), metadata.RemoteAddress(), err)
		return
	}

	logMetadata(metadata, rule, remoteConn)

	remoteConn = statistic.NewTCPTracker(remoteConn, statistic.DefaultManager, metadata, rule, int64(peekLen), 0, true)
	tracked = true
	trackInbound(remoteConn, conn)
	defer func(remoteConn C.Conn) {
		_ = remoteConn.Close()
	}(remoteConn)

	_ = conn.SetReadDeadline(time.Now()) // stop unfinished peek
	peekMutex.Lock()
	defer peekMutex.Unlock()
	_ = conn.SetReadDeadline(time.Time{}) // reset
	handleSocket(conn, remoteConn)
}

var dialOutcomeObserver syncatomic.Pointer[func(error)]

func dialKindOf(proxy C.ProxyAdapter, metadata *C.Metadata) string {
	if adapter, ok := proxy.(C.Proxy); ok && terminalAdapterType(adapter, metadata) == C.Direct {
		return dialer.DialKindDirect
	}
	return dialer.DialKindProxy
}

func SetDialOutcomeObserver(observe func(error)) {
	if observe == nil {
		dialOutcomeObserver.Store(nil)
		return
	}
	dialOutcomeObserver.Store(&observe)
}

func observeDialOutcome(err error) {
	if observe := dialOutcomeObserver.Load(); observe != nil {
		(*observe)(err)
	}
}

func logMetadataErr(metadata *C.Metadata, rule C.Rule, proxy C.ProxyAdapter, err error) {
	observeDialOutcome(err)
	if rule == nil {
		log.Warnln("[%s] dial %s %s --> %s error: %s", strings.ToUpper(metadata.NetWork.String()), proxy.Name(), metadata.SourceDetail(), metadata.RemoteAddress(), err.Error())
	} else {
		log.Warnln("[%s] dial %s (match %s/%s) %s --> %s error: %s", strings.ToUpper(metadata.NetWork.String()), proxy.Name(), rule.RuleType().String(), rule.Payload(), metadata.SourceDetail(), metadata.RemoteAddress(), err.Error())
	}
}

func logMetadata(metadata *C.Metadata, rule C.Rule, remoteConn C.Connection) {
	observeDialOutcome(nil)
	switch {
	case metadata.SpecialProxy != "":
		log.Infoln("[%s] %s --> %s using %s", strings.ToUpper(metadata.NetWork.String()), metadata.SourceDetail(), metadata.RemoteAddress(), remoteConn.Chains().String())
	case rule != nil:
		if rule.Payload() != "" {
			log.Infoln("[%s] %s --> %s match %s using %s", strings.ToUpper(metadata.NetWork.String()), metadata.SourceDetail(), metadata.RemoteAddress(), fmt.Sprintf("%s(%s)", rule.RuleType().String(), rule.Payload()), remoteConn.Chains().String())
		} else {
			log.Infoln("[%s] %s --> %s match %s using %s", strings.ToUpper(metadata.NetWork.String()), metadata.SourceDetail(), metadata.RemoteAddress(), rule.RuleType().String(), remoteConn.Chains().String())
		}
	case Mode() == Global:
		log.Infoln("[%s] %s --> %s using GLOBAL", strings.ToUpper(metadata.NetWork.String()), metadata.SourceDetail(), metadata.RemoteAddress())
	case Mode() == Direct:
		log.Infoln("[%s] %s --> %s using DIRECT", strings.ToUpper(metadata.NetWork.String()), metadata.SourceDetail(), metadata.RemoteAddress())
	default:
		log.Infoln("[%s] %s --> %s doesn't match any rule using %s", strings.ToUpper(metadata.NetWork.String()), metadata.SourceDetail(), metadata.RemoteAddress(), remoteConn.Chains().String())
	}
}

type flowMatch struct {
	metadata             *C.Metadata
	version              *runtimeVersion
	resolved             bool
	attemptProcessLookup bool
}

func match(metadata *C.Metadata, helper C.RuleMatchHelper, version *runtimeVersion) (C.Proxy, C.Rule, error) {
	var rematchChain []string
	for {
		var rematchProxy C.Proxy
		var rematchRule C.Rule
	GetRules:
		for _, rule := range getRules(metadata, version) {
			if matched, ada := rule.Match(metadata, helper); matched {
				adapter, ok := version.lookup(ada)
				if !ok || adapter == nil {
					continue
				}

				// parse multi-layer nesting
				for adapter := adapter; adapter != nil; adapter = adapter.Unwrap(metadata, false) {
					if adapter.Type() == C.Pass {
						log.Debugln("%s match Pass rule", adapter.Name())
						continue GetRules
					}
					if adapter.Type() == C.Rematch {
						log.Debugln("%s match Rematch rule", adapter.Name())
						rematchProxy = adapter
						rematchRule = rule
						break GetRules
					}
				}

				if metadata.NetWork == C.UDP && !adapter.SupportUDP() {
					log.Debugln("%s UDP is not supported", adapter.Name())
					continue
				}

				return adapter, rule, nil
			}
		}
		if rematchProxy != nil {
			if slices.Contains(rematchChain, rematchProxy.Name()) {
				log.Warnln("[Rule] rematch cycle detected on %s", rematchProxy.Name())
				return rematchProxy, rematchRule, nil
			}
			rematchChain = append(rematchChain, rematchProxy.Name())
			conn, err := rematchProxy.DialContext(context.Background(), metadata) // not a real connection, just for metadata update
			if conn != nil {
				_ = conn.Close()
			}
			if err != nil {
				log.Warnln("[Rule] rematch proxy %s failed to update metadata: %s", rematchProxy.Name(), err)
				return rematchProxy, rematchRule, nil
			}
			log.Debugln("[Rule] rematch proxy %s update metadata to rematch-name=%q sub-rule=%q", rematchProxy.Name(), metadata.InName, metadata.SpecialRules)
			continue
		}
		proxy, err := version.proxy("DIRECT")
		return proxy, nil, err
	}
}

func getRules(metadata *C.Metadata, version *runtimeVersion) []C.Rule {
	if sr, ok := version.subRules[metadata.SpecialRules]; ok {
		log.Debugln("[Rule] use %s rules", metadata.SpecialRules)
		return sr
	} else {
		log.Debugln("[Rule] use default rules")
		return version.rules
	}
}

func sniffingStandsAside(conn any, metadata *C.Metadata) bool {
	return metadata.Host == "" &&
		dialer.IsPhysicalGlobalIPv6(metadata.DstIP) &&
		N.HandshakePending(conn) &&
		WouldDialPhysically(metadata)
}

var errRejectedByRule = errors.New("rejected by rule")

const firstBytesWait = 50 * time.Millisecond

func serverSpeaksFirst(port uint16) bool {
	switch port {
	case 21, 22, 25, 110, 143, 587, 3306:
		return true
	}
	return false
}

type clientLeftError struct{ error }

func (e clientLeftError) Unwrap() error { return e.error }

type finalDialError struct{ error }

func (e finalDialError) Unwrap() error { return e.error }

func terminalAdapterType(proxy C.Proxy, metadata *C.Metadata) C.AdapterType {
	adapterType := proxy.Type()
	for adapter := proxy.Unwrap(metadata, false); adapter != nil; adapter = adapter.Unwrap(metadata, false) {
		adapterType = adapter.Type()
	}
	return adapterType
}

func reportUDPUnreachable(packet C.UDPPacket, metadata *C.Metadata, why string) {
	if pause.IsNetworkPaused() {
		return
	}
	if err := C.ReportUDPUnreachable(packet); err != nil {
		log.Debugln("[UDP] %s --> %s could not be answered unreachable: %s", metadata.SourceDetail(), metadata.RemoteAddress(), err)
		return
	}
	if metadata.Type == C.TUN {
		log.Debugln("[UDP] %s --> %s answered port unreachable: %s", metadata.SourceDetail(), metadata.RemoteAddress(), why)
	}
}

func shouldStopRetry(err error) bool {
	var final finalDialError
	if errors.As(err, &final) {
		return true
	}
	var left clientLeftError
	if errors.As(err, &left) {
		return true
	}
	if errors.Is(err, resolver.ErrIPNotFound) {
		return true
	}
	if errors.Is(err, resolver.ErrIPVersion) {
		return true
	}
	if errors.Is(err, resolver.ErrIPv6Disabled) {
		return true
	}
	if errors.Is(err, loopback.ErrReject) {
		return true
	}
	return false
}

func retry[T any](ctx context.Context, ft func(context.Context) (T, error), fe func(err error)) (t T, err error) {
	s := slowdown.New()
	for i := 0; i < 10; i++ {
		t, err = ft(ctx)
		if err != nil {
			if fe != nil {
				fe(err)
			}
			if shouldStopRetry(err) {
				return
			}
			if s.Wait(ctx) == nil {
				continue
			} else {
				return
			}
		} else {
			break
		}
	}
	return
}
