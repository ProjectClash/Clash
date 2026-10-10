package mipstack

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"syscall"
)

const (
	rxChecksumOffloadIPv4Header uint32 = 1 << iota
	rxChecksumOffloadTCP
	rxChecksumOffloadUDP
	rxChecksumOffloadICMPv4
	rxChecksumOffloadICMPv6
	rxChecksumOffloadIGMP
)

const rxChecksumOffloadGenerated = rxChecksumOffloadIPv4Header | rxChecksumOffloadTCP | rxChecksumOffloadUDP |
	rxChecksumOffloadICMPv4 | rxChecksumOffloadICMPv6 | rxChecksumOffloadIGMP

type RXChecksumOffload struct {
	flags uint32
}

func (o *RXChecksumOffload) SetIPv4Header(enabled bool) *RXChecksumOffload {
	if enabled {
		o.flags |= rxChecksumOffloadIPv4Header
	} else {
		o.flags &^= rxChecksumOffloadIPv4Header
	}
	return o
}

func (o RXChecksumOffload) IPv4Header() bool { return o.flags&rxChecksumOffloadIPv4Header != 0 }

func (o *RXChecksumOffload) SetTCP(enabled bool) *RXChecksumOffload {
	if enabled {
		o.flags |= rxChecksumOffloadTCP
	} else {
		o.flags &^= rxChecksumOffloadTCP
	}
	return o
}

func (o RXChecksumOffload) TCP() bool { return o.flags&rxChecksumOffloadTCP != 0 }

func (o *RXChecksumOffload) SetUDP(enabled bool) *RXChecksumOffload {
	if enabled {
		o.flags |= rxChecksumOffloadUDP
	} else {
		o.flags &^= rxChecksumOffloadUDP
	}
	return o
}

func (o RXChecksumOffload) UDP() bool { return o.flags&rxChecksumOffloadUDP != 0 }

func (o *RXChecksumOffload) SetICMPv4(enabled bool) *RXChecksumOffload {
	if enabled {
		o.flags |= rxChecksumOffloadICMPv4
	} else {
		o.flags &^= rxChecksumOffloadICMPv4
	}
	return o
}

func (o RXChecksumOffload) ICMPv4() bool { return o.flags&rxChecksumOffloadICMPv4 != 0 }

func (o *RXChecksumOffload) SetICMPv6(enabled bool) *RXChecksumOffload {
	if enabled {
		o.flags |= rxChecksumOffloadICMPv6
	} else {
		o.flags &^= rxChecksumOffloadICMPv6
	}
	return o
}

func (o RXChecksumOffload) ICMPv6() bool { return o.flags&rxChecksumOffloadICMPv6 != 0 }

func (o *RXChecksumOffload) SetIGMP(enabled bool) *RXChecksumOffload {
	if enabled {
		o.flags |= rxChecksumOffloadIGMP
	} else {
		o.flags &^= rxChecksumOffloadIGMP
	}
	return o
}

func (o RXChecksumOffload) IGMP() bool { return o.flags&rxChecksumOffloadIGMP != 0 }

func (s *Stack) SetRXChecksumOffload(offload RXChecksumOffload) {
	s.rxChecksumOffload.Store(offload.flags)
}

func (s *Stack) RXChecksumOffload() RXChecksumOffload {
	return RXChecksumOffload{flags: s.rxChecksumOffload.Load()}
}

type AddressProperties struct {
	Deprecated bool
	Temporary bool
}

type Route struct {
	Destination netip.Prefix
	Source netip.Addr
	Metric uint32
}

type networkState struct {
	mtu               int
	maxTCPConnections int
	promiscuous       bool
	tcpDefaults       TCPSocketDefaults
	udpDefaults       UDPSocketDefaults
	ipDefaults        IPSocketDefaults
	local             map[netip.Addr]struct{}
	broadcast         map[netip.Addr]struct{}
	sources           []netip.Addr
	sourcePrefixBits  []int
	localPrefixes     []netip.Prefix
	routes            []Route
	addressProperties map[netip.Addr]AddressProperties
	preferTemporary   bool
}

func (state *networkState) samePathConfiguration(other *networkState) bool {
	if state == nil || other == nil || state.mtu != other.mtu ||
		len(state.sources) != len(other.sources) || len(state.localPrefixes) != len(other.localPrefixes) || len(state.routes) != len(other.routes) ||
		!state.sameSourceProperties(other) {
		return false
	}
	for index := range state.sources {
		if state.sources[index] != other.sources[index] {
			return false
		}
	}
	for index := range state.localPrefixes {
		if state.localPrefixes[index] != other.localPrefixes[index] {
			return false
		}
	}
	for index := range state.routes {
		if state.routes[index] != other.routes[index] {
			return false
		}
	}
	return true
}

func (state *networkState) sameMulticastConfiguration(other *networkState) bool {
	if state == nil || other == nil || len(state.sources) != len(other.sources) || len(state.localPrefixes) != len(other.localPrefixes) ||
		!state.sameSourceProperties(other) {
		return false
	}
	for index := range state.sources {
		if state.sources[index] != other.sources[index] {
			return false
		}
	}
	for index := range state.localPrefixes {
		if state.localPrefixes[index] != other.localPrefixes[index] {
			return false
		}
	}
	return true
}

func (state *networkState) sameSourceProperties(other *networkState) bool {
	if state.preferTemporary != other.preferTemporary || len(state.addressProperties) != len(other.addressProperties) {
		return false
	}
	for address, properties := range state.addressProperties {
		otherProperties, exists := other.addressProperties[address]
		if !exists || otherProperties != properties {
			return false
		}
	}
	return true
}

func buildNetworkState(config Config) (*networkState, error) {
	mtu := int(config.MTU)
	if mtu == 0 {
		mtu = defaultMTU
	}
	if mtu < 68 || mtu > 65535 {
		return nil, errors.New("mipstack: MTU must be between 68 and 65535")
	}
	if config.MaxTCPConnections < 0 {
		return nil, errors.New("mipstack: maximum TCP connections cannot be negative")
	}
	tcpDefaults, err := normalizeTCPSocketDefaults(config.TCP)
	if err != nil {
		return nil, err
	}
	udpDefaults, err := normalizeUDPSocketDefaults(config.UDP)
	if err != nil {
		return nil, errors.New("mipstack: invalid UDP socket defaults: " + err.Error())
	}
	ipDefaults, err := normalizeIPSocketDefaults(config.IP)
	if err != nil {
		return nil, errors.New("mipstack: invalid IP socket defaults: " + err.Error())
	}
	state := &networkState{
		mtu: mtu, maxTCPConnections: config.MaxTCPConnections, promiscuous: config.Promiscuous,
		tcpDefaults: tcpDefaults, udpDefaults: udpDefaults, ipDefaults: ipDefaults,
		local: make(map[netip.Addr]struct{}, len(config.LocalAddresses)), sources: make([]netip.Addr, 0, len(config.LocalAddresses)),
		preferTemporary: config.PreferTemporaryAddresses,
	}
	configuredPrefixes := make(map[netip.Prefix]struct{}, len(config.LocalAddresses))
	for _, prefix := range config.LocalAddresses {
		address := prefix.Addr().Unmap()
		if !prefix.IsValid() || !address.IsValid() || address.IsUnspecified() || address.IsMulticast() || address.Zone() != "" {
			return nil, errors.New("mipstack: invalid local address")
		}
		bits := prefix.Bits()
		if prefix.Addr().Is6() && address.Is4() {
			bits -= 96
		}
		if bits < 0 || bits > address.BitLen() {
			return nil, errors.New("mipstack: invalid local prefix")
		}
		if address.Is4() && isIPv4Broadcast(prefix, address, bits) {
			return nil, errors.New("mipstack: IPv4 broadcast address cannot be local")
		}
		configuredPrefix := netip.PrefixFrom(address, bits)
		if _, duplicate := configuredPrefixes[configuredPrefix]; duplicate {
			continue
		}
		configuredPrefixes[configuredPrefix] = struct{}{}
		if _, exists := state.local[address]; !exists {
			state.local[address] = struct{}{}
			state.sources = append(state.sources, address)
			state.sourcePrefixBits = append(state.sourcePrefixBits, bits)
		} else {
			for index, source := range state.sources {
				if source == address {
					if bits > state.sourcePrefixBits[index] {
						state.sourcePrefixBits[index] = bits
					}
					break
				}
			}
		}
		masked := netip.PrefixFrom(address, bits).Masked()
		state.localPrefixes = append(state.localPrefixes, masked)
		if broadcast, ok := ipv4BroadcastAddress(masked); ok {
			if state.broadcast == nil {
				state.broadcast = make(map[netip.Addr]struct{}, len(config.LocalAddresses))
			}
			state.broadcast[broadcast] = struct{}{}
		}
	}
	for address := range state.local {
		if _, broadcast := state.broadcast[address]; broadcast {
			return nil, errors.New("mipstack: IPv4 broadcast address cannot be local")
		}
	}
	if len(config.AddressProperties) != 0 {
		state.addressProperties = make(map[netip.Addr]AddressProperties, len(config.AddressProperties))
		for address, properties := range config.AddressProperties {
			normalized := address.Unmap()
			if !address.IsValid() || address.Zone() != "" || !normalized.IsValid() || normalized.IsUnspecified() || normalized.IsMulticast() {
				return nil, errors.New("mipstack: invalid address-properties key")
			}
			if _, local := state.local[normalized]; !local {
				return nil, errors.New("mipstack: address properties refer to a nonlocal address")
			}
			if properties.Temporary && normalized.Is4() {
				return nil, errors.New("mipstack: temporary source property requires IPv6")
			}
			if existing, duplicate := state.addressProperties[normalized]; duplicate && existing != properties {
				return nil, errors.New("mipstack: conflicting address properties")
			}
			state.addressProperties[normalized] = properties
		}
	}
	addressless := len(state.local) == 0
	if addressless && !state.promiscuous {
		return nil, errors.New("mipstack: at least one local address is required")
	}
	var haveLocal4, haveLocal6 bool
	for _, source := range state.sources {
		if source.Is4() {
			haveLocal4 = true
		} else {
			haveLocal6 = true
		}
	}
	state.routes = make([]Route, 0, len(config.Routes)+2)
	haveIPv6Output := haveLocal6
	for _, route := range config.Routes {
		destination, err := normalizeRoutePrefix(route.Destination)
		if err != nil {
			return nil, err
		}
		source := route.Source.Unmap()
		if route.Source.IsValid() {
			if !source.IsValid() || source.IsUnspecified() || source.IsMulticast() || source.Zone() != "" || source.Is6() != destination.Addr().Is6() {
				return nil, errors.New("mipstack: invalid route source")
			}
			if _, exists := state.local[source]; !exists {
				return nil, errors.New("mipstack: route source is not local")
			}
		} else {
			source = netip.Addr{}
		}
		familyAvailable := haveLocal4
		if destination.Addr().Is6() {
			familyAvailable = haveLocal6
			haveIPv6Output = true
		}
		if !familyAvailable && !state.promiscuous {
			return nil, errors.New("mipstack: route has no local address in its family")
		}
		state.routes = append(state.routes, Route{Destination: destination, Source: source, Metric: route.Metric})
	}
	if config.Routes == nil {
		default4, default6 := haveLocal4, haveLocal6
		if addressless {
			default4, default6 = true, true
		}
		if default4 {
			state.routes = append(state.routes, Route{Destination: netip.PrefixFrom(netip.IPv4Unspecified(), 0)})
		}
		if default6 {
			state.routes = append(state.routes, Route{Destination: netip.PrefixFrom(netip.IPv6Unspecified(), 0)})
			haveIPv6Output = true
		}
	}
	if mtu < ipv6MinimumMTU && haveIPv6Output {
		return nil, errors.New("mipstack: IPv6 requires an MTU of at least 1280")
	}
	return state, nil
}

func normalizeUDPSocketDefaults(value UDPSocketDefaults) (UDPSocketDefaults, error) {
	defaults, err := normalizeDatagramSocketDefaults(value.DatagramSocketDefaults, udpDefaultReceiveCapacity, udpDatagramMetadataSize)
	if err != nil {
		return UDPSocketDefaults{}, err
	}
	value.DatagramSocketDefaults = defaults
	return value, nil
}

func normalizeIPSocketDefaults(value IPSocketDefaults) (IPSocketDefaults, error) {
	defaults, err := normalizeDatagramSocketDefaults(value.DatagramSocketDefaults, ipDefaultReceiveCapacity, ipDatagramMetadataSize)
	if err != nil {
		return IPSocketDefaults{}, err
	}
	value.DatagramSocketDefaults = defaults
	return value, nil
}

func (state *networkState) acceptsInboundDestination(address netip.Addr) bool {
	address = address.Unmap()
	if _, local := state.local[address]; local {
		return true
	}
	return state.acceptsNonlocalDestination(address)
}

func (state *networkState) acceptsNonlocalDestination(address netip.Addr) bool {
	address = address.Unmap()
	if !state.promiscuous || !address.IsValid() || address.IsUnspecified() || address.IsMulticast() || address.IsLoopback() {
		return false
	}
	return !state.broadcastDestination(address)
}

func normalizeTCPSocketDefaults(value TCPSocketDefaults) (TCPSocketDefaults, error) {
	if value.CongestionControlFactory != nil {
		if value.CongestionControl != "" {
			return TCPSocketDefaults{}, errors.New("mipstack: TCP congestion control name and factory are mutually exclusive")
		}
		if !value.CongestionControlFactory.valid() {
			return TCPSocketDefaults{}, errors.New("mipstack: invalid TCP congestion control factory")
		}
	} else {
		if value.CongestionControl == "" {
			value.CongestionControl = CongestionControlCUBIC
		}
		factory, exists := registeredCongestionControlFactory(value.CongestionControl)
		if !exists {
			return TCPSocketDefaults{}, errors.New("mipstack: unsupported congestion control")
		}
		value.CongestionControl = ""
		value.CongestionControlFactory = factory
	}
	if value.ReceiveBuffer < 0 || value.MaximumReceiveBuffer < 0 || value.SendBuffer < 0 || value.MaximumSendBuffer < 0 ||
		value.AcceptQueue < 0 || value.SYNBacklog < 0 || value.IdleTimeout < 0 || value.UserTimeout < 0 {
		return TCPSocketDefaults{}, errors.New("mipstack: TCP socket defaults cannot be negative")
	}
	if value.FlowLabel > ipv6MaximumFlowLabel {
		return TCPSocketDefaults{}, errors.New("mipstack: TCP flow label exceeds 20 bits")
	}
	if value.ReceiveBuffer == 0 {
		value.ReceiveBuffer = tcpReceiveCapacity
	}
	if value.MaximumReceiveBuffer == 0 {
		value.MaximumReceiveBuffer = tcpMaximumReceiveCapacity
	}
	if value.SendBuffer == 0 {
		value.SendBuffer = tcpSendCapacity
	}
	if value.MaximumSendBuffer == 0 {
		value.MaximumSendBuffer = tcpMaximumSendCapacity
	}
	if value.MaximumReceiveBuffer < value.ReceiveBuffer || value.MaximumSendBuffer < value.SendBuffer {
		return TCPSocketDefaults{}, errors.New("mipstack: TCP automatic buffer maximum is below its initial size")
	}
	if uint64(value.MaximumReceiveBuffer) > uint64(tcpMaximumScaledWindow) {
		return TCPSocketDefaults{}, errors.New("mipstack: TCP receive buffer maximum exceeds the RFC 7323 window limit")
	}
	if value.AcceptQueue == 0 {
		value.AcceptQueue = tcpAcceptQueue
	}
	if value.SYNBacklog == 0 {
		value.SYNBacklog = tcpSYNBacklog
	}
	if value.KeepAliveConfig.Idle == 0 {
		value.KeepAliveConfig.Idle = tcpDefaultKeepAliveIdle
	}
	if value.KeepAliveConfig.Interval == 0 {
		value.KeepAliveConfig.Interval = tcpDefaultKeepAliveInterval
	}
	if value.KeepAliveConfig.Count == 0 {
		value.KeepAliveConfig.Count = tcpDefaultKeepAliveCount
	}
	if value.KeepAliveConfig.Idle < 0 || value.KeepAliveConfig.Interval < 0 || value.KeepAliveConfig.Count < 0 {
		return TCPSocketDefaults{}, errors.New("mipstack: TCP keepalive defaults cannot be negative")
	}
	value.TrafficClass &= 0xfc
	return value, nil
}

func normalizeDatagramSocketDefaults(value DatagramSocketDefaults, defaultReceiveBuffer, minimumReceiveBuffer int) (DatagramSocketDefaults, error) {
	if value.ReceiveBuffer < 0 || value.HopLimit < 0 || value.HopLimit > 255 || value.MulticastHopLimit < 0 || value.MulticastHopLimit > 255 {
		return DatagramSocketDefaults{}, errors.New("receive buffer and hop limit must be valid")
	}
	if !value.PathMTUDiscovery.valid() {
		return DatagramSocketDefaults{}, errors.New("unsupported path MTU discovery mode")
	}
	if value.FlowLabel > ipv6MaximumFlowLabel {
		return DatagramSocketDefaults{}, errors.New("flow label exceeds 20 bits")
	}
	if value.ReceiveBuffer == 0 {
		value.ReceiveBuffer = defaultReceiveBuffer
	} else if value.ReceiveBuffer < minimumReceiveBuffer {
		value.ReceiveBuffer = minimumReceiveBuffer
	}
	if value.HopLimit == 0 {
		value.HopLimit = 64
	}
	if value.MulticastHopLimit == 0 {
		value.MulticastHopLimit = 1
	}
	return value, nil
}

func (state *networkState) invalidInboundSource(address netip.Addr) bool {
	_, broadcast := state.broadcast[address.Unmap()]
	return broadcast
}

func (state *networkState) broadcastDestination(address netip.Addr) bool {
	address = address.Unmap()
	if !address.Is4() {
		return false
	}
	if address == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return true
	}
	_, broadcast := state.broadcast[address]
	return broadcast
}

func ipv4BroadcastAddress(prefix netip.Prefix) (netip.Addr, bool) {
	if !prefix.IsValid() || !prefix.Addr().Is4() || prefix.Addr().IsLoopback() || prefix.Bits() >= 31 {
		return netip.Addr{}, false
	}
	networkBytes := prefix.Masked().Addr().As4()
	network := binary.BigEndian.Uint32(networkBytes[:])
	hostMask := uint32((uint64(1) << (32 - prefix.Bits())) - 1)
	var address [4]byte
	binary.BigEndian.PutUint32(address[:], network|hostMask)
	return netip.AddrFrom4(address), true
}

func isIPv4Broadcast(prefix netip.Prefix, address netip.Addr, bits int) bool {
	addressBytes := address.As4()
	value := binary.BigEndian.Uint32(addressBytes[:])
	if value == ^uint32(0) {
		return true
	}
	if bits >= 31 {
		return false
	}
	networkBytes := prefix.Masked().Addr().Unmap().As4()
	network := binary.BigEndian.Uint32(networkBytes[:])
	hostMask := uint32((uint64(1) << (32 - bits)) - 1)
	return value == network|hostMask
}

func normalizeRoutePrefix(prefix netip.Prefix) (netip.Prefix, error) {
	if !prefix.IsValid() || prefix.Addr().Zone() != "" {
		return netip.Prefix{}, errors.New("mipstack: invalid route destination")
	}
	address := prefix.Addr().Unmap()
	bits := prefix.Bits()
	if prefix.Addr().Is6() && address.Is4() {
		bits -= 96
	}
	if bits < 0 || bits > address.BitLen() {
		return netip.Prefix{}, errors.New("mipstack: invalid route destination")
	}
	return netip.PrefixFrom(address, bits).Masked(), nil
}

func (state *networkState) routeFor(destination netip.Addr) (Route, bool) {
	destination = destination.Unmap()
	if _, local := state.local[destination]; local {
		return Route{Destination: netip.PrefixFrom(destination, destination.BitLen()), Source: destination}, true
	}
	var selected Route
	selectedIndex := -1
	for index, route := range state.routes {
		if route.Destination.Addr().Is6() != destination.Is6() || !route.Destination.Contains(destination) {
			continue
		}
		if selectedIndex < 0 || route.Destination.Bits() > selected.Destination.Bits() ||
			route.Destination.Bits() == selected.Destination.Bits() && route.Metric < selected.Metric {
			selected, selectedIndex = route, index
		}
	}
	return selected, selectedIndex >= 0
}

func (state *networkState) sourceForUnicast(destination, requested netip.Addr) (netip.Addr, error) {
	destination = destination.Unmap()
	if !destination.IsValid() || destination.IsUnspecified() || destination.IsMulticast() || destination.Zone() != "" {
		return netip.Addr{}, syscall.EINVAL
	}
	route, exists := state.routeFor(destination)
	if !exists {
		return netip.Addr{}, syscall.ENETUNREACH
	}
	if destination.IsLoopback() {
		if _, local := state.local[destination]; !local {
			return netip.Addr{}, syscall.ENETUNREACH
		}
	}
	requested = requested.Unmap()
	if requested.IsValid() && !requested.IsUnspecified() {
		if requested.Is6() != destination.Is6() {
			return netip.Addr{}, syscall.EAFNOSUPPORT
		}
		if _, local := state.local[requested]; !local {
			return netip.Addr{}, syscall.EADDRNOTAVAIL
		}
		return requested, nil
	}
	if route.Source.IsValid() {
		return route.Source, nil
	}
	var selected netip.Addr
	selectedPrefixBits := 0
	for index, candidate := range state.sources {
		if candidate.Is6() != destination.Is6() {
			continue
		}
		candidatePrefixBits := state.sourcePrefixBits[index]
		if !selected.IsValid() || state.preferSource(candidate, candidatePrefixBits, selected, selectedPrefixBits, destination) {
			selected = candidate
			selectedPrefixBits = candidatePrefixBits
		}
	}
	if !selected.IsValid() {
		return netip.Addr{}, syscall.EADDRNOTAVAIL
	}
	return selected, nil
}

func (state *networkState) sourceForNonUnicast(destination, requested netip.Addr) (netip.Addr, error) {
	destination = destination.Unmap()
	if !destination.IsValid() || destination.IsUnspecified() || destination.Zone() != "" ||
		!destination.IsMulticast() && !state.broadcastDestination(destination) {
		return netip.Addr{}, syscall.EINVAL
	}
	if destination.IsMulticast() && !validMulticastGroup(destination) {
		return netip.Addr{}, syscall.EINVAL
	}
	requested = requested.Unmap()
	if requested.IsValid() && !requested.IsUnspecified() {
		if requested.Zone() != "" || requested.IsMulticast() || requested.Is6() != destination.Is6() {
			return netip.Addr{}, syscall.EAFNOSUPPORT
		}
		if _, local := state.local[requested]; !local {
			return netip.Addr{}, syscall.EADDRNOTAVAIL
		}
		if state.broadcastDestination(destination) && requested.IsLoopback() {
			return netip.Addr{}, syscall.ENETUNREACH
		}
		if destination.IsMulticast() && !sourceScopeUsable(requested, destination) {
			return netip.Addr{}, syscall.ENETUNREACH
		}
		return requested, nil
	}
	if state.broadcastDestination(destination) {
		if destination != netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
			for _, prefix := range state.localPrefixes {
				if !prefix.Addr().Is4() || !isIPv4Broadcast(prefix, destination, prefix.Bits()) {
					continue
				}
				for _, candidate := range state.sources {
					if candidate.Is4() && !candidate.IsLoopback() && prefix.Contains(candidate) {
						return candidate, nil
					}
				}
			}
		}
		for _, candidate := range state.sources {
			if candidate.Is4() && !candidate.IsLoopback() {
				return candidate, nil
			}
		}
		return netip.Addr{}, syscall.EADDRNOTAVAIL
	}
	if destination.Is4() {
		for _, candidate := range state.sources {
			if candidate.Is4() && !candidate.IsLoopback() {
				return candidate, nil
			}
		}
		return netip.Addr{}, syscall.EADDRNOTAVAIL
	}
	var selected netip.Addr
	selectedPrefixBits := 0
	for index, candidate := range state.sources {
		if candidate.Is6() != destination.Is6() {
			continue
		}
		candidatePrefixBits := state.sourcePrefixBits[index]
		if !selected.IsValid() || state.preferSource(candidate, candidatePrefixBits, selected, selectedPrefixBits, destination) {
			selected = candidate
			selectedPrefixBits = candidatePrefixBits
		}
	}
	if !selected.IsValid() {
		return netip.Addr{}, syscall.EADDRNOTAVAIL
	}
	return selected, nil
}

func (state *networkState) inboundIPv4PacketInfoSource(source, destination netip.Addr) netip.Addr {
	source, destination = source.Unmap(), destination.Unmap()
	if !destination.Is4() {
		return netip.Addr{}
	}
	if _, local := state.local[destination]; local {
		return destination
	}
	if source.Is4() && !source.IsUnspecified() {
		if selected, err := state.sourceForUnicast(source, netip.Addr{}); err == nil {
			return selected
		}
		for index, candidate := range state.sources {
			if !candidate.Is4() || candidate.IsLoopback() || index >= len(state.sourcePrefixBits) {
				continue
			}
			prefix := netip.PrefixFrom(candidate, state.sourcePrefixBits[index])
			if prefix.Contains(source) {
				return candidate
			}
		}
	}
	for _, candidate := range state.sources {
		if candidate.Is4() && !candidate.IsLoopback() {
			return candidate
		}
	}
	return netip.Addr{}
}

func (state *networkState) hasOutputPath(destination netip.Addr) bool {
	destination = destination.Unmap()
	if destination.IsMulticast() || state.broadcastDestination(destination) {
		return networkStateHasFamily(state, destination.Is6())
	}
	_, routed := state.routeFor(destination)
	return routed
}

func (state *networkState) preferSource(candidate netip.Addr, candidatePrefixBits int, current netip.Addr, currentPrefixBits int, destination netip.Addr) bool {
	if candidate == destination || current == destination {
		return candidate == destination
	}
	candidateScope, currentScope, destinationScope := addressScope(candidate), addressScope(current), addressScope(destination)
	if candidateScope != currentScope {
		candidateAppropriate := candidateScope >= destinationScope
		currentAppropriate := currentScope >= destinationScope
		if candidateAppropriate != currentAppropriate {
			return candidateAppropriate
		}
		if candidateAppropriate {
			return candidateScope < currentScope
		}
		return candidateScope > currentScope
	}
	candidateProperties, currentProperties := state.addressProperties[candidate], state.addressProperties[current]
	if candidateProperties.Deprecated != currentProperties.Deprecated {
		return !candidateProperties.Deprecated
	}
	if (addressLabel(candidate) == addressLabel(destination)) != (addressLabel(current) == addressLabel(destination)) {
		return addressLabel(candidate) == addressLabel(destination)
	}
	if candidateProperties.Temporary != currentProperties.Temporary {
		return candidateProperties.Temporary == state.preferTemporary
	}
	return commonPrefixBits(candidate, destination, candidatePrefixBits) > commonPrefixBits(current, destination, currentPrefixBits)
}

func sourceScopeUsable(source, destination netip.Addr) bool {
	return addressScope(source) >= addressScope(destination) || destination.IsLoopback()
}

func validMulticastGroup(address netip.Addr) bool {
	address = address.Unmap()
	if !address.IsValid() || !address.IsMulticast() || address.Zone() != "" {
		return false
	}
	if address.Is4() {
		return true
	}
	raw := address.As16()
	flags, scope := raw[1]>>4, raw[1]&0x0f
	if scope == 0 || scope == 0x0f || flags&8 != 0 {
		return false
	}
	transient, prefixBased, embeddedRP := flags&1 != 0, flags&2 != 0, flags&4 != 0
	if prefixBased && !transient || embeddedRP && !prefixBased {
		return false
	}
	return true
}

func isInterfaceLocalMulticast(address netip.Addr) bool {
	address = address.Unmap()
	return address.Is6() && address.IsMulticast() && address.As16()[1]&0x0f == 1
}

func addressScope(address netip.Addr) uint8 {
	address = address.Unmap()
	if address.IsLoopback() {
		return 2
	}
	if address.IsMulticast() {
		if address.Is4() {
			value := address.As4()
			if value[0] == 224 && value[1] == 0 && value[2] == 0 {
				return 2
			}
			if value[0] == 239 && value[1] == 255 {
				return 3
			}
			if value[0] == 239 && value[1]&0xfc == 192 {
				return 8
			}
			return 14
		}
		return address.As16()[1] & 0x0f
	}
	if address.IsLinkLocalUnicast() {
		return 2
	}
	if address.Is6() {
		value := address.As16()
		if value[0] == 0xfe && value[1]&0xc0 == 0xc0 {
			return 5
		}
	}
	return 14
}

func addressLabel(address netip.Addr) uint8 {
	address = address.Unmap()
	if address.Is4() {
		return 4
	}
	if address.IsLoopback() {
		return 0
	}
	value := address.As16()
	if value[0] == 0x20 && value[1] == 0x02 {
		return 2
	}
	if value[0] == 0x20 && value[1] == 0x01 && value[2] == 0 && value[3] == 0 {
		return 5
	}
	if value[0]&0xfe == 0xfc {
		return 13
	}
	if value[0] == 0xfe && value[1]&0xc0 == 0xc0 {
		return 11
	}
	if value[0] == 0x3f && value[1] == 0xfe {
		return 12
	}
	if binary.BigEndian.Uint64(value[:8]) == 0 && binary.BigEndian.Uint32(value[8:12]) == 0 {
		return 3
	}
	return 1
}

func commonPrefixBits(left, right netip.Addr, limit int) int {
	left, right = left.Unmap(), right.Unmap()
	if !left.IsValid() || !right.IsValid() || left.Is4() != right.Is4() || limit <= 0 {
		return 0
	}
	leftValue, rightValue := left.As16(), right.As16()
	start := 0
	if left.Is4() {
		start = 12
	}
	leftBytes, rightBytes := leftValue[start:], rightValue[start:]
	result := 0
	for index := range leftBytes {
		difference := leftBytes[index] ^ rightBytes[index]
		if difference == 0 {
			result += 8
			continue
		}
		for mask := byte(0x80); difference&mask == 0; mask >>= 1 {
			result++
		}
		break
	}
	if result > limit {
		return limit
	}
	return result
}
