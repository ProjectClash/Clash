package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/ProjectClash/Clash/common/atomic"
	"github.com/ProjectClash/Clash/component/keepalive"
	"github.com/ProjectClash/Clash/component/mptcp"
)


type NetworkStrategy int

const (
	NetworkStrategyDefault NetworkStrategy = iota
	NetworkStrategyFallback
	NetworkStrategyHybrid
)

var networkStrategyNames = map[NetworkStrategy]string{
	NetworkStrategyDefault:  "default",
	NetworkStrategyFallback: "fallback",
	NetworkStrategyHybrid:   "hybrid",
}

func (s NetworkStrategy) String() string {
	if name, ok := networkStrategyNames[s]; ok {
		return name
	}
	return "unknown"
}

func ParseNetworkStrategy(value string) (NetworkStrategy, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "default":
		return NetworkStrategyDefault, nil
	case "fallback":
		return NetworkStrategyFallback, nil
	case "hybrid":
		return NetworkStrategyHybrid, nil
	default:
		return NetworkStrategyDefault, errors.New("unknown network strategy: " + value)
	}
}

type InterfaceType int

const (
	InterfaceTypeOther InterfaceType = iota
	InterfaceTypeWIFI
	InterfaceTypeCellular
	InterfaceTypeWired
	InterfaceTypeLoopback
	InterfaceTypeTunnel
)

var interfaceTypeNames = map[InterfaceType]string{
	InterfaceTypeOther:    "other",
	InterfaceTypeWIFI:     "wifi",
	InterfaceTypeCellular: "cellular",
	InterfaceTypeWired:    "wired",
	InterfaceTypeLoopback: "loopback",
	InterfaceTypeTunnel:   "tunnel",
}

func (t InterfaceType) String() string {
	if name, ok := interfaceTypeNames[t]; ok {
		return name
	}
	return "other"
}

func ParseInterfaceType(value string) (InterfaceType, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "wifi", "wi-fi":
		return InterfaceTypeWIFI, nil
	case "cellular":
		return InterfaceTypeCellular, nil
	case "wired", "ethernet":
		return InterfaceTypeWired, nil
	case "other":
		return InterfaceTypeOther, nil
	default:
		return InterfaceTypeOther, errors.New("unknown interface type: " + value)
	}
}

type NetworkInterface struct {
	Index     int
	Name      string
	Type      InterfaceType
	Available bool
	Default   bool
	OwnTunnel bool
	Metered   bool
}

var (
	NetworkStrategyValue = atomic.NewTypedValue[NetworkStrategy](NetworkStrategyDefault)
	NetworkTypeValue         = atomic.NewTypedValue[[]InterfaceType](nil)
	FallbackNetworkTypeValue = atomic.NewTypedValue[[]InterfaceType](nil)
	NetworkInterfaceProvider = atomic.NewTypedValue[func() []NetworkInterface](nil)

	networkLastFallback = atomic.NewTypedValue[time.Time](time.Time{})
)

const (
	networkFallbackDelay = 300 * time.Millisecond
	networkFastFallbackWindow = 15 * time.Second
)

func SetNetworkStrategy(strategy NetworkStrategy, primary, fallback []InterfaceType) {
	NetworkStrategyValue.Store(strategy)
	NetworkTypeValue.Store(primary)
	FallbackNetworkTypeValue.Store(fallback)
}

func networkStrategyActive() bool {
	if NetworkInterfaceProvider.Load() == nil {
		return false
	}
	return NetworkStrategyValue.Load() != NetworkStrategyDefault ||
		len(NetworkTypeValue.Load()) != 0
}

func candidateInterfaces() (primary, fallback []NetworkInterface) {
	provider := NetworkInterfaceProvider.Load()
	if provider == nil {
		return nil, nil
	}
	var usable []NetworkInterface
	for _, candidate := range provider() {
		if candidate.OwnTunnel || candidate.Type == InterfaceTypeLoopback || !candidate.Available {
			continue
		}
		if candidate.Index <= 0 || candidate.Name == "" {
			continue
		}
		usable = append(usable, candidate)
	}
	strategy := NetworkStrategyValue.Load()
	primaryTypes := NetworkTypeValue.Load()
	fallbackTypes := FallbackNetworkTypeValue.Load()
	switch strategy {
	case NetworkStrategyHybrid:
		if len(primaryTypes) == 0 {
			primary = usable
		} else {
			primary = filterInterfaceTypes(usable, primaryTypes)
		}
	case NetworkStrategyFallback:
		if len(primaryTypes) == 0 {
			primary = defaultInterfaceOnly(usable)
		} else {
			primary = filterInterfaceTypes(usable, primaryTypes)
		}
		if len(fallbackTypes) == 0 {
			fallback = exceptInterfaces(usable, primary)
		} else {
			fallback = exceptInterfaces(filterInterfaceTypes(usable, fallbackTypes), primary)
		}
	default:
		if len(primaryTypes) == 0 {
			primary = defaultInterfaceOnly(usable)
		} else {
			primary = filterInterfaceTypes(usable, primaryTypes)
		}
	}
	sortInterfaces(primary)
	sortInterfaces(fallback)
	return primary, fallback
}

func defaultInterfaceOnly(interfaces []NetworkInterface) []NetworkInterface {
	for _, candidate := range interfaces {
		if candidate.Default {
			return []NetworkInterface{candidate}
		}
	}
	return interfaces
}

func filterInterfaceTypes(interfaces []NetworkInterface, types []InterfaceType) []NetworkInterface {
	var out []NetworkInterface
	for _, candidate := range interfaces {
		for _, want := range types {
			if candidate.Type == want {
				out = append(out, candidate)
				break
			}
		}
	}
	return out
}

func exceptInterfaces(interfaces, exclude []NetworkInterface) []NetworkInterface {
	var out []NetworkInterface
	for _, candidate := range interfaces {
		excluded := false
		for _, other := range exclude {
			if candidate.Index == other.Index {
				excluded = true
				break
			}
		}
		if !excluded {
			out = append(out, candidate)
		}
	}
	return out
}

func sortInterfaces(interfaces []NetworkInterface) {
	sort.SliceStable(interfaces, func(i, j int) bool {
		if interfaces[i].Default != interfaces[j].Default {
			return interfaces[i].Default
		}
		return interfaces[i].Index < interfaces[j].Index
	})
}

func strategyOwnsThisSocket(opt option) bool {
	if opt.interfaceName != "" {
		return false
	}
	switch opt.netDialer.(type) {
	case nil, *net.Dialer:
		return true
	default:
		return false
	}
}

type strategyDialResult struct {
	conn    net.Conn
	err     error
	primary bool
}

func dialStrategyContext(ctx context.Context, network string, destination netip.Addr, address string, opt option) (net.Conn, bool, error) {
	if !networkStrategyActive() || !strategyOwnsThisSocket(opt) {
		return nil, false, nil
	}
	primary, fallback := candidateInterfaces()
	if len(primary)+len(fallback) == 0 {
		return nil, false, nil
	}
	fastFallback := time.Since(networkLastFallback.Load()) < networkFastFallbackWindow

	if len(primary)+len(fallback) == 1 {
		only := primary
		isPrimary := true
		if len(only) == 0 {
			only = fallback
			isPrimary = false
		}
		conn, err := dialOverInterface(ctx, network, destination, address, only[0], opt)
		if err != nil {
			return nil, true, err
		}
		if !fastFallback && !isPrimary {
			networkLastFallback.Store(time.Now())
		}
		return conn, true, nil
	}

	var (
		conn      net.Conn
		isPrimary bool
		err       error
	)
	if fastFallback {
		conn, isPrimary, err = dialParallelInterfaceFastFallback(ctx, network, destination, address, primary, fallback, opt)
	} else {
		conn, isPrimary, err = dialParallelInterface(ctx, network, destination, address, primary, fallback, opt)
	}
	if err != nil {
		return nil, true, err
	}
	if !fastFallback && !isPrimary {
		networkLastFallback.Store(time.Now())
	}
	return conn, true, nil
}

func startInterfaceRacer(
	ctx context.Context,
	network string,
	destination netip.Addr,
	address string,
	candidate NetworkInterface,
	isPrimary bool,
	opt option,
	results chan<- strategyDialResult,
	returned <-chan struct{},
	onLateLoss func(primary bool),
) {
	conn, err := dialOverInterface(ctx, network, destination, address, candidate, opt)
	if err != nil {
		select {
		case results <- strategyDialResult{err: dialInterfaceError(err, candidate), primary: isPrimary}:
		case <-returned:
		}
		return
	}
	select {
	case results <- strategyDialResult{conn: conn, primary: isPrimary}:
	case <-returned:
		if onLateLoss != nil {
			onLateLoss(isPrimary)
		}
		_ = conn.Close()
	}
}

func dialInterfaceError(err error, candidate NetworkInterface) error {
	return fmt.Errorf("dial %s (%d): %w", candidate.Name, candidate.Index, err)
}

func dialParallelInterface(ctx context.Context, network string, destination netip.Addr, address string, primary, fallback []NetworkInterface, opt option) (net.Conn, bool, error) {
	returned := make(chan struct{})
	defer close(returned)
	results := make(chan strategyDialResult)
	primaryCtx, primaryCancel := context.WithCancel(ctx)
	defer primaryCancel()
	for _, candidate := range primary {
		go startInterfaceRacer(primaryCtx, network, destination, address, candidate, true, opt, results, returned, nil)
	}
	var (
		fallbackTimer *time.Timer
		fallbackChan  <-chan time.Time
		fallbackCtx   context.Context
	)
	if len(fallback) != 0 {
		delay := networkFallbackDelay
		if len(primary) == 0 {
			delay = 0
		}
		fallbackTimer = time.NewTimer(delay)
		defer fallbackTimer.Stop()
		fallbackChan = fallbackTimer.C
		var fallbackCancel context.CancelFunc
		fallbackCtx, fallbackCancel = context.WithCancel(ctx)
		defer fallbackCancel()
	}
	var errs []error
	for {
		select {
		case <-fallbackChan:
			fallbackChan = nil
			for _, candidate := range fallback {
				go startInterfaceRacer(fallbackCtx, network, destination, address, candidate, false, opt, results, returned, nil)
			}
		case result := <-results:
			if result.err == nil {
				return result.conn, result.primary, nil
			}
			errs = append(errs, result.err)
			if len(errs) == len(primary)+len(fallback) {
				return nil, false, errors.Join(errs...)
			}
			if result.primary && fallbackTimer != nil && fallbackTimer.Stop() {
				fallbackTimer.Reset(0)
			}
		case <-ctx.Done():
			return nil, false, ctx.Err()
		}
	}
}

func dialParallelInterfaceFastFallback(ctx context.Context, network string, destination netip.Addr, address string, primary, fallback []NetworkInterface, opt option) (net.Conn, bool, error) {
	returned := make(chan struct{})
	defer close(returned)
	results := make(chan strategyDialResult)
	startAt := time.Now()
	onLateLoss := func(isPrimary bool) { closeWindowOnLatePrimary(isPrimary, startAt) }
	for _, candidate := range primary {
		go startInterfaceRacer(ctx, network, destination, address, candidate, true, opt, results, returned, onLateLoss)
	}
	fallbackCtx, fallbackCancel := context.WithCancel(ctx)
	defer fallbackCancel()
	for _, candidate := range fallback {
		go startInterfaceRacer(fallbackCtx, network, destination, address, candidate, false, opt, results, returned, onLateLoss)
	}
	var errs []error
	for {
		select {
		case result := <-results:
			if result.err == nil {
				return result.conn, result.primary, nil
			}
			errs = append(errs, result.err)
			if len(errs) == len(primary)+len(fallback) {
				return nil, false, errors.Join(errs...)
			}
		case <-ctx.Done():
			return nil, false, ctx.Err()
		}
	}
}

func closeWindowOnLatePrimary(isPrimary bool, startAt time.Time) {
	if isPrimary && time.Since(startAt) <= networkFallbackDelay {
		networkLastFallback.Store(time.Time{})
	}
}

func listenStrategyPacket(ctx context.Context, network, address string, rAddrPort netip.AddrPort, opt option) (net.PacketConn, bool, error) {
	if !networkStrategyActive() || !strategyOwnsThisSocket(opt) {
		return nil, false, nil
	}
	primary, fallback := candidateInterfaces()
	if len(primary)+len(fallback) == 0 {
		return nil, false, nil
	}
	var errs []error
	for _, candidate := range append(append([]NetworkInterface(nil), primary...), fallback...) {
		conn, err := listenPacketOverInterface(ctx, network, address, rAddrPort, candidate, opt)
		if err == nil {
			return conn, true, nil
		}
		errs = append(errs, fmt.Errorf("listen %s (%d): %w", candidate.Name, candidate.Index, err))
	}
	return nil, true, errors.Join(errs...)
}

func dialOverInterface(ctx context.Context, network string, destination netip.Addr, address string, candidate NetworkInterface, opt option) (net.Conn, error) {
	var netDialer net.Dialer
	if existing, ok := opt.netDialer.(*net.Dialer); ok && existing != nil {
		netDialer = *existing
	}
	dialer := &netDialer
	keepalive.SetNetDialer(dialer)
	mptcp.SetNetDialer(dialer, opt.mpTcp)
	if err := bindStrategyInterface(candidate, dialer, network, destination, opt); err != nil {
		return nil, err
	}
	routingMark := opt.routingMark
	if routingMark == 0 {
		routingMark = int(DefaultRoutingMark.Load())
	}
	if routingMark != 0 {
		bindMarkToDialer(routingMark, dialer, network, destination)
	}
	return dialer.DialContext(ctx, network, address)
}

func bindStrategyInterface(candidate NetworkInterface, dialer *net.Dialer, network string, destination netip.Addr, opt option) error {
	bind := bindIfaceToDialer
	if opt.fallbackBind {
		bind = fallbackBindIfaceToDialer
	}
	return bind(candidate.Name, dialer, network, destination)
}

func listenPacketOverInterface(ctx context.Context, network, address string, rAddrPort netip.AddrPort, candidate NetworkInterface, opt option) (net.PacketConn, error) {
	lc := &net.ListenConfig{}
	if opt.addrReuse {
		addrReuseToListenConfig(lc)
	}
	bind := bindIfaceToListenConfig
	if opt.fallbackBind {
		bind = fallbackBindIfaceToListenConfig
	}
	bound, err := bind(candidate.Name, lc, network, address, rAddrPort)
	if err != nil {
		return nil, err
	}
	address = bound
	routingMark := opt.routingMark
	if routingMark == 0 {
		routingMark = int(DefaultRoutingMark.Load())
	}
	if routingMark != 0 {
		bindMarkToListenConfig(routingMark, lc, network, address)
	}
	return lc.ListenPacket(ctx, network, address)
}
