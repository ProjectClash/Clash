package mipstack

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"syscall"
	"time"
)

type SocketOption interface {
	apply(socketOptionSet, socketOptionUse) (socketOptionSet, error)
}

type SocketOptionFactory uint8

const SocketOptions SocketOptionFactory = 0

type socketOptionBoolOverride uint8

const (
	socketOptionBoolOverrideUnset socketOptionBoolOverride = iota
	socketOptionBoolOverrideDisabled
	socketOptionBoolOverrideEnabled
)

func newSocketOptionBoolOverride(enabled bool) socketOptionBoolOverride {
	if enabled {
		return socketOptionBoolOverrideEnabled
	}
	return socketOptionBoolOverrideDisabled
}

func (override socketOptionBoolOverride) valid() bool {
	return override <= socketOptionBoolOverrideEnabled
}

type socketOptionOverride[T any] struct {
	value T
	set   bool
}

type reuseAddressSocketOption socketOptionBoolOverride

type reusePortSocketOption socketOptionBoolOverride

type ipHeaderIncludedOnWriteSocketOption socketOptionBoolOverride

type ipHeaderIncludedOnReadSocketOption socketOptionBoolOverride

type icmpV4FilterSocketOption socketOptionOverride[ICMPv4Filter]

type icmpV6FilterSocketOption socketOptionOverride[ICMPv6Filter]

type ipv6ChecksumPolicy struct {
	enabled bool
	offset  int
}

type ipv6ChecksumSocketOption socketOptionOverride[ipv6ChecksumPolicy]

type readBufferSocketOption socketOptionOverride[int]

type trafficClassSocketOption socketOptionOverride[int]

type flowLabelSocketOption socketOptionOverride[uint32]

type writeBufferSocketOption socketOptionOverride[int]

type keepAliveSocketOption socketOptionBoolOverride

type keepAliveConfigSocketOption socketOptionOverride[KeepAliveConfig]

type noDelaySocketOption socketOptionBoolOverride

type idleTimeoutSocketOption socketOptionOverride[time.Duration]

type userTimeoutSocketOption socketOptionOverride[time.Duration]

type congestionControlSocketOption struct {
	name string
	set  bool
}

type congestionControlFactorySocketOption socketOptionOverride[*CongestionControlFactory]

type maximumPacingRateSocketOption socketOptionOverride[uint64]

type acceptQueueSocketOption socketOptionOverride[int]

type synBacklogSocketOption socketOptionOverride[int]

type receiveErrorsSocketOption socketOptionBoolOverride

type pathMTUDiscoverySocketOption socketOptionOverride[PathMTUDiscovery]

type hopLimitSocketOption socketOptionOverride[int]

type broadcastSocketOption socketOptionBoolOverride

type multicastHopLimitSocketOption socketOptionOverride[int]

type multicastLoopbackSocketOption socketOptionBoolOverride

func (SocketOptionFactory) ReadBuffer(bytes int) SocketOption {
	return readBufferSocketOption{value: bytes, set: true}
}

func (SocketOptionFactory) UnsetReadBuffer() SocketOption {
	return readBufferSocketOption{}
}

func (option readBufferSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	value := socketOptionOverride[int](option)
	if value.set && value.value <= 0 {
		return set, syscall.EINVAL
	}
	if use.isTCP() {
		set.tcp.readBuffer = value
	} else if use.isDatagram() {
		set.datagram.readBuffer = value
	} else {
		return set, syscall.ENOPROTOOPT
	}
	return set, nil
}

func (SocketOptionFactory) TrafficClass(value int) SocketOption {
	return trafficClassSocketOption{value: value, set: true}
}

func (SocketOptionFactory) UnsetTrafficClass() SocketOption {
	return trafficClassSocketOption{}
}

func (option trafficClassSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	value := socketOptionOverride[int](option)
	if value.set && (value.value < 0 || value.value > 255) {
		return set, syscall.EINVAL
	}
	if use.isTCP() {
		set.tcp.trafficClass = value
	} else if use.isDatagram() {
		set.datagram.trafficClass = value
	} else {
		return set, syscall.ENOPROTOOPT
	}
	return set, nil
}

func (SocketOptionFactory) FlowLabel(label uint32) SocketOption {
	return flowLabelSocketOption{value: label, set: true}
}

func (SocketOptionFactory) UnsetFlowLabel() SocketOption {
	return flowLabelSocketOption{}
}

func (option flowLabelSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	value := socketOptionOverride[uint32](option)
	if value.set && value.value > ipv6MaximumFlowLabel {
		return set, syscall.EINVAL
	}
	if use.isTCP() {
		set.tcp.flowLabel = value
	} else if use.isDatagram() {
		set.datagram.flowLabel = value
	} else {
		return set, syscall.ENOPROTOOPT
	}
	return set, nil
}

func (SocketOptionFactory) WriteBuffer(bytes int) SocketOption {
	return writeBufferSocketOption{value: bytes, set: true}
}

func (SocketOptionFactory) UnsetWriteBuffer() SocketOption {
	return writeBufferSocketOption{}
}

func (option writeBufferSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	value := socketOptionOverride[int](option)
	if !value.set {
		set.tcp.writeBuffer = value
		return set, nil
	}
	if !use.isTCP() {
		return set, syscall.ENOPROTOOPT
	}
	if value.value <= 0 {
		return set, syscall.EINVAL
	}
	set.tcp.writeBuffer = value
	return set, nil
}

func (SocketOptionFactory) KeepAlive(enabled bool) SocketOption {
	return keepAliveSocketOption(newSocketOptionBoolOverride(enabled))
}

func (SocketOptionFactory) UnsetKeepAlive() SocketOption {
	return keepAliveSocketOption(socketOptionBoolOverrideUnset)
}

func (option keepAliveSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	override := socketOptionBoolOverride(option)
	if !override.valid() {
		return set, syscall.EINVAL
	}
	if override == socketOptionBoolOverrideUnset {
		set.tcp.keepAlive = override
		return set, nil
	}
	if !use.isTCP() {
		return set, syscall.ENOPROTOOPT
	}
	set.tcp.keepAlive = override
	return set, nil
}

func (SocketOptionFactory) KeepAliveConfig(config KeepAliveConfig) SocketOption {
	return keepAliveConfigSocketOption{value: config, set: true}
}

func (SocketOptionFactory) UnsetKeepAliveConfig() SocketOption {
	return keepAliveConfigSocketOption{}
}

func (option keepAliveConfigSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	value := socketOptionOverride[KeepAliveConfig](option)
	if !value.set {
		set.tcp.keepAliveConfig = value
		return set, nil
	}
	if !use.isTCP() {
		return set, syscall.ENOPROTOOPT
	}
	if value.value.Idle <= 0 || value.value.Interval <= 0 || value.value.Count <= 0 {
		return set, syscall.EINVAL
	}
	set.tcp.keepAliveConfig = value
	return set, nil
}

func (SocketOptionFactory) NoDelay(enabled bool) SocketOption {
	return noDelaySocketOption(newSocketOptionBoolOverride(enabled))
}

func (SocketOptionFactory) UnsetNoDelay() SocketOption {
	return noDelaySocketOption(socketOptionBoolOverrideUnset)
}

func (option noDelaySocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	override := socketOptionBoolOverride(option)
	if !override.valid() {
		return set, syscall.EINVAL
	}
	if override == socketOptionBoolOverrideUnset {
		set.tcp.noDelay = override
		return set, nil
	}
	if !use.isTCP() {
		return set, syscall.ENOPROTOOPT
	}
	set.tcp.noDelay = override
	return set, nil
}

func (SocketOptionFactory) IdleTimeout(timeout time.Duration) SocketOption {
	return idleTimeoutSocketOption{value: timeout, set: true}
}

func (SocketOptionFactory) UnsetIdleTimeout() SocketOption {
	return idleTimeoutSocketOption{}
}

func (option idleTimeoutSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	value := socketOptionOverride[time.Duration](option)
	if !value.set {
		set.tcp.idleTimeout = value
		return set, nil
	}
	if !use.isTCP() {
		return set, syscall.ENOPROTOOPT
	}
	if value.value < 0 {
		return set, syscall.EINVAL
	}
	set.tcp.idleTimeout = value
	return set, nil
}

func (SocketOptionFactory) UserTimeout(timeout time.Duration) SocketOption {
	return userTimeoutSocketOption{value: timeout, set: true}
}

func (SocketOptionFactory) UnsetUserTimeout() SocketOption {
	return userTimeoutSocketOption{}
}

func (option userTimeoutSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	value := socketOptionOverride[time.Duration](option)
	if !value.set {
		set.tcp.userTimeout = value
		return set, nil
	}
	if !use.isTCP() {
		return set, syscall.ENOPROTOOPT
	}
	if value.value < 0 {
		return set, syscall.EINVAL
	}
	set.tcp.userTimeout = value
	return set, nil
}

func (SocketOptionFactory) CongestionControl(algorithm string) SocketOption {
	return congestionControlSocketOption{name: algorithm, set: true}
}

func (SocketOptionFactory) UnsetCongestionControl() SocketOption {
	return congestionControlSocketOption{}
}

func (option congestionControlSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	if !option.set {
		set.tcp.congestionControl = socketOptionOverride[*CongestionControlFactory]{}
		return set, nil
	}
	if !use.isTCP() {
		return set, syscall.ENOPROTOOPT
	}
	factory, exists := registeredCongestionControlFactory(option.name)
	if !exists {
		return set, syscall.EINVAL
	}
	set.tcp.congestionControl = socketOptionOverride[*CongestionControlFactory]{value: factory, set: true}
	return set, nil
}

func (SocketOptionFactory) CongestionControlFactory(factory *CongestionControlFactory) SocketOption {
	return congestionControlFactorySocketOption{value: factory, set: true}
}

func (option congestionControlFactorySocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	value := socketOptionOverride[*CongestionControlFactory](option)
	if !value.set {
		set.tcp.congestionControl = value
		return set, nil
	}
	if !use.isTCP() {
		return set, syscall.ENOPROTOOPT
	}
	if !value.value.valid() {
		return set, syscall.EINVAL
	}
	set.tcp.congestionControl = value
	return set, nil
}

func (SocketOptionFactory) MaximumPacingRate(bytesPerSecond uint64) SocketOption {
	return maximumPacingRateSocketOption{value: bytesPerSecond, set: true}
}

func (SocketOptionFactory) UnsetMaximumPacingRate() SocketOption {
	return maximumPacingRateSocketOption{}
}

func (option maximumPacingRateSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	value := socketOptionOverride[uint64](option)
	if !value.set {
		set.tcp.maximumPacingRate = value
		return set, nil
	}
	if !use.isTCP() {
		return set, syscall.ENOPROTOOPT
	}
	set.tcp.maximumPacingRate = value
	return set, nil
}

func (SocketOptionFactory) AcceptQueue(capacity int) SocketOption {
	return acceptQueueSocketOption{value: capacity, set: true}
}

func (SocketOptionFactory) UnsetAcceptQueue() SocketOption {
	return acceptQueueSocketOption{}
}

func (option acceptQueueSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	value := socketOptionOverride[int](option)
	if !value.set {
		set.tcp.acceptQueue = value
		return set, nil
	}
	if use != socketOptionTCPListen {
		return set, syscall.ENOPROTOOPT
	}
	if value.value < 0 {
		return set, syscall.EINVAL
	}
	set.tcp.acceptQueue = value
	return set, nil
}

func (SocketOptionFactory) SYNBacklog(capacity int) SocketOption {
	return synBacklogSocketOption{value: capacity, set: true}
}

func (SocketOptionFactory) UnsetSYNBacklog() SocketOption {
	return synBacklogSocketOption{}
}

func (option synBacklogSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	value := socketOptionOverride[int](option)
	if !value.set {
		set.tcp.synBacklog = value
		return set, nil
	}
	if use != socketOptionTCPListen {
		return set, syscall.ENOPROTOOPT
	}
	if value.value < 0 {
		return set, syscall.EINVAL
	}
	set.tcp.synBacklog = value
	return set, nil
}

func (SocketOptionFactory) ReceiveErrors(enabled bool) SocketOption {
	return receiveErrorsSocketOption(newSocketOptionBoolOverride(enabled))
}

func (SocketOptionFactory) UnsetReceiveErrors() SocketOption {
	return receiveErrorsSocketOption(socketOptionBoolOverrideUnset)
}

func (option receiveErrorsSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	override := socketOptionBoolOverride(option)
	if !override.valid() {
		return set, syscall.EINVAL
	}
	if override == socketOptionBoolOverrideUnset {
		set.datagram.receiveErrors = override
		return set, nil
	}
	if !use.isDatagram() {
		return set, syscall.ENOPROTOOPT
	}
	set.datagram.receiveErrors = override
	return set, nil
}

func (SocketOptionFactory) PathMTUDiscovery(mode PathMTUDiscovery) SocketOption {
	return pathMTUDiscoverySocketOption{value: mode, set: true}
}

func (SocketOptionFactory) UnsetPathMTUDiscovery() SocketOption {
	return pathMTUDiscoverySocketOption{}
}

func (option pathMTUDiscoverySocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	value := socketOptionOverride[PathMTUDiscovery](option)
	if !value.set {
		set.datagram.pathMTUDiscovery = value
		return set, nil
	}
	if !use.isDatagram() {
		return set, syscall.ENOPROTOOPT
	}
	if !value.value.valid() {
		return set, syscall.EINVAL
	}
	set.datagram.pathMTUDiscovery = value
	return set, nil
}

func (SocketOptionFactory) HopLimit(hopLimit int) SocketOption {
	return hopLimitSocketOption{value: hopLimit, set: true}
}

func (SocketOptionFactory) UnsetHopLimit() SocketOption {
	return hopLimitSocketOption{}
}

func (option hopLimitSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	value := socketOptionOverride[int](option)
	if !value.set {
		set.datagram.hopLimit = value
		return set, nil
	}
	if !use.isDatagram() {
		return set, syscall.ENOPROTOOPT
	}
	if value.value < 0 || value.value > 255 {
		return set, syscall.EINVAL
	}
	set.datagram.hopLimit = value
	return set, nil
}

func (SocketOptionFactory) Broadcast(enabled bool) SocketOption {
	return broadcastSocketOption(newSocketOptionBoolOverride(enabled))
}

func (SocketOptionFactory) UnsetBroadcast() SocketOption {
	return broadcastSocketOption(socketOptionBoolOverrideUnset)
}

func (option broadcastSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	override := socketOptionBoolOverride(option)
	if !override.valid() {
		return set, syscall.EINVAL
	}
	if override == socketOptionBoolOverrideUnset {
		set.datagram.broadcast = override
		return set, nil
	}
	if !use.isDatagram() {
		return set, syscall.ENOPROTOOPT
	}
	set.datagram.broadcast = override
	return set, nil
}

func (SocketOptionFactory) MulticastHopLimit(hopLimit int) SocketOption {
	return multicastHopLimitSocketOption{value: hopLimit, set: true}
}

func (SocketOptionFactory) UnsetMulticastHopLimit() SocketOption {
	return multicastHopLimitSocketOption{}
}

func (option multicastHopLimitSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	value := socketOptionOverride[int](option)
	if !value.set {
		set.datagram.multicastHopLimit = value
		return set, nil
	}
	if !use.isDatagram() {
		return set, syscall.ENOPROTOOPT
	}
	if value.value < 0 || value.value > 255 {
		return set, syscall.EINVAL
	}
	set.datagram.multicastHopLimit = value
	return set, nil
}

func (SocketOptionFactory) MulticastLoopback(enabled bool) SocketOption {
	return multicastLoopbackSocketOption(newSocketOptionBoolOverride(enabled))
}

func (SocketOptionFactory) UnsetMulticastLoopback() SocketOption {
	return multicastLoopbackSocketOption(socketOptionBoolOverrideUnset)
}

func (option multicastLoopbackSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	override := socketOptionBoolOverride(option)
	if !override.valid() {
		return set, syscall.EINVAL
	}
	if override == socketOptionBoolOverrideUnset {
		set.datagram.multicastLoopback = override
		return set, nil
	}
	if !use.isDatagram() {
		return set, syscall.ENOPROTOOPT
	}
	set.datagram.multicastLoopback = override
	return set, nil
}

func (SocketOptionFactory) ReuseAddress(enabled bool) SocketOption {
	return reuseAddressSocketOption(newSocketOptionBoolOverride(enabled))
}

func (SocketOptionFactory) UnsetReuseAddress() SocketOption {
	return reuseAddressSocketOption(socketOptionBoolOverrideUnset)
}

func (option reuseAddressSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	override := socketOptionBoolOverride(option)
	if !override.valid() {
		return set, syscall.EINVAL
	}
	if override == socketOptionBoolOverrideUnset {
		set.reuseAddress = use == socketOptionTCPListen
		return set, nil
	}
	if use != socketOptionTCPListen && use != socketOptionUDPListen {
		return set, syscall.ENOPROTOOPT
	}
	set.reuseAddress = override == socketOptionBoolOverrideEnabled
	return set, nil
}

func (SocketOptionFactory) ReusePort(enabled bool) SocketOption {
	return reusePortSocketOption(newSocketOptionBoolOverride(enabled))
}

func (SocketOptionFactory) UnsetReusePort() SocketOption {
	return reusePortSocketOption(socketOptionBoolOverrideUnset)
}

func (option reusePortSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	override := socketOptionBoolOverride(option)
	if !override.valid() {
		return set, syscall.EINVAL
	}
	if override == socketOptionBoolOverrideUnset {
		set.reusePort = false
		return set, nil
	}
	if use != socketOptionTCPListen && use != socketOptionUDPListen {
		return set, syscall.ENOPROTOOPT
	}
	set.reusePort = override == socketOptionBoolOverrideEnabled
	return set, nil
}

func (SocketOptionFactory) IPHeaderIncludedOnWrite(enabled bool) SocketOption {
	return ipHeaderIncludedOnWriteSocketOption(newSocketOptionBoolOverride(enabled))
}

func (SocketOptionFactory) UnsetIPHeaderIncludedOnWrite() SocketOption {
	return ipHeaderIncludedOnWriteSocketOption(socketOptionBoolOverrideUnset)
}

func (option ipHeaderIncludedOnWriteSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	override := socketOptionBoolOverride(option)
	if !override.valid() {
		return set, syscall.EINVAL
	}
	if override == socketOptionBoolOverrideUnset {
		set.ip.headerIncludedOnWrite = override
		return set, nil
	}
	if use != socketOptionIPListen && use != socketOptionIPDial {
		return set, syscall.ENOPROTOOPT
	}
	set.ip.headerIncludedOnWrite = override
	return set, nil
}

func (SocketOptionFactory) IPHeaderIncludedOnRead(enabled bool) SocketOption {
	return ipHeaderIncludedOnReadSocketOption(newSocketOptionBoolOverride(enabled))
}

func (SocketOptionFactory) UnsetIPHeaderIncludedOnRead() SocketOption {
	return ipHeaderIncludedOnReadSocketOption(socketOptionBoolOverrideUnset)
}

func (option ipHeaderIncludedOnReadSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	override := socketOptionBoolOverride(option)
	if !override.valid() {
		return set, syscall.EINVAL
	}
	if override == socketOptionBoolOverrideUnset {
		set.ip.headerIncludedOnRead = override
		return set, nil
	}
	if use != socketOptionIPListen && use != socketOptionIPDial {
		return set, syscall.ENOPROTOOPT
	}
	set.ip.headerIncludedOnRead = override
	return set, nil
}

func (SocketOptionFactory) ICMPv4Filter(filter ICMPv4Filter) SocketOption {
	return icmpV4FilterSocketOption{value: filter, set: true}
}

func (SocketOptionFactory) UnsetICMPv4Filter() SocketOption {
	return icmpV4FilterSocketOption{}
}

func (option icmpV4FilterSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	value := socketOptionOverride[ICMPv4Filter](option)
	if !value.set {
		set.ip.icmpV4Filter = value
		return set, nil
	}
	if use != socketOptionIPListen && use != socketOptionIPDial {
		return set, syscall.ENOPROTOOPT
	}
	set.ip.icmpV4Filter = value
	return set, nil
}

func (SocketOptionFactory) ICMPv6Filter(filter ICMPv6Filter) SocketOption {
	return icmpV6FilterSocketOption{value: filter, set: true}
}

func (SocketOptionFactory) UnsetICMPv6Filter() SocketOption {
	return icmpV6FilterSocketOption{}
}

func (option icmpV6FilterSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	value := socketOptionOverride[ICMPv6Filter](option)
	if !value.set {
		set.ip.icmpV6Filter = value
		return set, nil
	}
	if use != socketOptionIPListen && use != socketOptionIPDial {
		return set, syscall.ENOPROTOOPT
	}
	set.ip.icmpV6Filter = value
	return set, nil
}

func (SocketOptionFactory) IPv6Checksum(enabled bool, offset int) SocketOption {
	return ipv6ChecksumSocketOption{
		value: ipv6ChecksumPolicy{enabled: enabled, offset: offset},
		set:   true,
	}
}

func (SocketOptionFactory) UnsetIPv6Checksum() SocketOption {
	return ipv6ChecksumSocketOption{}
}

func (option ipv6ChecksumSocketOption) apply(set socketOptionSet, use socketOptionUse) (socketOptionSet, error) {
	value := socketOptionOverride[ipv6ChecksumPolicy](option)
	if !value.set {
		set.ip.ipv6Checksum = value
		return set, nil
	}
	if use != socketOptionIPListen && use != socketOptionIPDial {
		return set, syscall.ENOPROTOOPT
	}
	if value.value.enabled && (value.value.offset < 0 || value.value.offset&1 != 0) {
		return set, syscall.EINVAL
	}
	set.ip.ipv6Checksum = value
	return set, nil
}

type tcpSocketOptionSet struct {
	readBuffer        socketOptionOverride[int]
	writeBuffer       socketOptionOverride[int]
	keepAlive         socketOptionBoolOverride
	keepAliveConfig   socketOptionOverride[KeepAliveConfig]
	noDelay           socketOptionBoolOverride
	idleTimeout       socketOptionOverride[time.Duration]
	userTimeout       socketOptionOverride[time.Duration]
	congestionControl socketOptionOverride[*CongestionControlFactory]
	maximumPacingRate socketOptionOverride[uint64]
	trafficClass      socketOptionOverride[int]
	flowLabel         socketOptionOverride[uint32]
	acceptQueue       socketOptionOverride[int]
	synBacklog        socketOptionOverride[int]
}

type datagramSocketOptionSet struct {
	readBuffer        socketOptionOverride[int]
	receiveErrors     socketOptionBoolOverride
	pathMTUDiscovery  socketOptionOverride[PathMTUDiscovery]
	hopLimit          socketOptionOverride[int]
	broadcast         socketOptionBoolOverride
	multicastHopLimit socketOptionOverride[int]
	multicastLoopback socketOptionBoolOverride
	trafficClass      socketOptionOverride[int]
	flowLabel         socketOptionOverride[uint32]
}

type ipSocketOptionSet struct {
	headerIncludedOnWrite socketOptionBoolOverride
	headerIncludedOnRead  socketOptionBoolOverride
	icmpV4Filter          socketOptionOverride[ICMPv4Filter]
	icmpV6Filter          socketOptionOverride[ICMPv6Filter]
	ipv6Checksum          socketOptionOverride[ipv6ChecksumPolicy]
}

type socketOptionSet struct {
	tcp          tcpSocketOptionSet
	datagram     datagramSocketOptionSet
	ip           ipSocketOptionSet
	reuseAddress bool
	reusePort    bool
}

type socketOptionUse uint8

const (
	socketOptionTCPListen socketOptionUse = iota
	socketOptionUDPListen
	socketOptionIPListen
	socketOptionTCPDial
	socketOptionUDPDial
	socketOptionIPDial
)

func (use socketOptionUse) isTCP() bool {
	return use == socketOptionTCPListen || use == socketOptionTCPDial
}

func (use socketOptionUse) isDatagram() bool {
	return use == socketOptionUDPListen || use == socketOptionUDPDial || use == socketOptionIPListen || use == socketOptionIPDial
}

func (set socketOptionSet) validateFamily(use socketOptionUse, ipv6, dual bool) error {
	flowLabel := set.datagram.flowLabel
	if use.isTCP() {
		flowLabel = set.tcp.flowLabel
	}
	if flowLabel.set && !ipv6 && !dual {
		return syscall.EAFNOSUPPORT
	}
	if use.isDatagram() && set.datagram.hopLimit.set && set.datagram.hopLimit.value == 0 && (!ipv6 || dual) {
		return syscall.EINVAL
	}
	return nil
}

func (set socketOptionSet) validateIPSocket(protocol byte, ipv6, dual bool) error {
	hasIPv4 := !ipv6 || dual
	if set.ip.icmpV4Filter.set {
		if !hasIPv4 {
			return syscall.EAFNOSUPPORT
		}
		if protocol != ProtocolICMPv4 {
			return syscall.ENOPROTOOPT
		}
	}
	if set.ip.icmpV6Filter.set {
		if !ipv6 {
			return syscall.EAFNOSUPPORT
		}
		if protocol != ProtocolICMPv6 {
			return syscall.ENOPROTOOPT
		}
	}
	if set.ip.ipv6Checksum.set {
		if !ipv6 {
			return syscall.EAFNOSUPPORT
		}
		if protocol == ProtocolICMPv6 {
			return syscall.EINVAL
		}
	}
	return nil
}

func applyDatagramSocketOptions(defaults DatagramSocketDefaults, options datagramSocketOptionSet, minimumReceiveBuffer int) DatagramSocketDefaults {
	if options.readBuffer.set {
		defaults.ReceiveBuffer = options.readBuffer.value
		if defaults.ReceiveBuffer < minimumReceiveBuffer {
			defaults.ReceiveBuffer = minimumReceiveBuffer
		}
	}
	if options.receiveErrors != socketOptionBoolOverrideUnset {
		defaults.ReceiveErrors = options.receiveErrors == socketOptionBoolOverrideEnabled
	}
	if options.pathMTUDiscovery.set {
		defaults.PathMTUDiscovery = options.pathMTUDiscovery.value
	}
	if options.hopLimit.set {
		defaults.HopLimit = options.hopLimit.value
	}
	if options.broadcast != socketOptionBoolOverrideUnset {
		defaults.DisableBroadcast = options.broadcast == socketOptionBoolOverrideDisabled
	}
	if options.multicastHopLimit.set {
		defaults.MulticastHopLimit = options.multicastHopLimit.value
	}
	if options.multicastLoopback != socketOptionBoolOverrideUnset {
		defaults.DisableMulticastLoopback = options.multicastLoopback == socketOptionBoolOverrideDisabled
	}
	if options.trafficClass.set {
		defaults.TrafficClass = uint8(options.trafficClass.value)
	}
	if options.flowLabel.set {
		defaults.FlowLabel = options.flowLabel.value
	}
	return defaults
}

func parseSocketOptions(options []SocketOption, use socketOptionUse) (socketOptionSet, error) {
	set := socketOptionSet{reuseAddress: use == socketOptionTCPListen}
	for _, option := range options {
		if option == nil {
			return socketOptionSet{}, syscall.ENOPROTOOPT
		}
		var err error
		set, err = option.apply(set, use)
		if err != nil {
			return socketOptionSet{}, err
		}
	}
	return set, nil
}

type ListenConfig struct {
	Options []SocketOption
}

func (config *ListenConfig) ListenTCP(ctx context.Context, stack *Stack, network string, local netip.AddrPort) (net.Listener, error) {
	if stack == nil {
		return nil, socketOperationError("listen", network, nil, net.TCPAddrFromAddrPort(local), errors.New("mipstack: nil Stack"))
	}
	options, err := parseSocketOptions(listenConfigOptions(config), socketOptionTCPListen)
	if err != nil {
		return nil, socketOperationError("listen", network, nil, net.TCPAddrFromAddrPort(local), err)
	}
	var binding tcpListenerBinding = exclusiveTCPListenerBinding{reuseAddress: options.reuseAddress}
	if options.reusePort {
		binding = reuseTCPListenerBinding{reuseAddress: options.reuseAddress}
	}
	return stack.listenTCP(ctx, network, local, binding, options.tcp)
}

func (config *ListenConfig) ListenUDP(ctx context.Context, stack *Stack, network string, local netip.AddrPort) (net.PacketConn, error) {
	if stack == nil {
		return nil, socketOperationError("listen", network, nil, net.UDPAddrFromAddrPort(local), errors.New("mipstack: nil Stack"))
	}
	options, err := parseSocketOptions(listenConfigOptions(config), socketOptionUDPListen)
	if err != nil {
		return nil, socketOperationError("listen", network, nil, net.UDPAddrFromAddrPort(local), err)
	}
	var binding udpSocketBinding = exclusiveUDPSocketBinding{}
	if options.reusePort {
		binding = reuseUDPSocketBinding{reuseAddress: options.reuseAddress}
	} else if options.reuseAddress {
		binding = reuseAddressUDPSocketBinding{}
	}
	return stack.listenUDP(ctx, network, local, binding, options.datagram)
}

func (config *ListenConfig) ListenIP(ctx context.Context, stack *Stack, network string, local netip.Addr) (net.PacketConn, error) {
	if stack == nil {
		return nil, socketOperationError("listen", network, nil, ipNetAddr(local), errors.New("mipstack: nil Stack"))
	}
	options, err := parseSocketOptions(listenConfigOptions(config), socketOptionIPListen)
	if err != nil {
		return nil, socketOperationError("listen", network, nil, ipNetAddr(local), err)
	}
	return stack.listenIP(ctx, network, local, options)
}

func listenConfigOptions(config *ListenConfig) []SocketOption {
	if config == nil {
		return nil
	}
	return config.Options
}

type Dialer struct {
	Options []SocketOption
}

func (dialer *Dialer) DialTCP(ctx context.Context, stack *Stack, network string, source, remote netip.AddrPort) (net.Conn, error) {
	if stack == nil {
		return nil, socketOperationError("dial", network, net.TCPAddrFromAddrPort(source), net.TCPAddrFromAddrPort(remote), errors.New("mipstack: nil Stack"))
	}
	options, err := parseSocketOptions(dialerOptions(dialer), socketOptionTCPDial)
	if err != nil {
		return nil, socketOperationError("dial", network, net.TCPAddrFromAddrPort(source), net.TCPAddrFromAddrPort(remote), err)
	}
	return stack.dialTCP(ctx, network, source, remote, options.tcp)
}

func (dialer *Dialer) DialUDP(ctx context.Context, stack *Stack, network string, source, remote netip.AddrPort) (net.Conn, error) {
	if stack == nil {
		return nil, socketOperationError("dial", network, net.UDPAddrFromAddrPort(source), net.UDPAddrFromAddrPort(remote), errors.New("mipstack: nil Stack"))
	}
	options, err := parseSocketOptions(dialerOptions(dialer), socketOptionUDPDial)
	if err != nil {
		return nil, socketOperationError("dial", network, net.UDPAddrFromAddrPort(source), net.UDPAddrFromAddrPort(remote), err)
	}
	return stack.dialUDP(ctx, network, source, remote, options.datagram)
}

func (dialer *Dialer) DialIP(ctx context.Context, stack *Stack, network string, source, remote netip.Addr) (net.Conn, error) {
	if stack == nil {
		return nil, socketOperationError("dial", network, ipNetAddr(source), ipNetAddr(remote), errors.New("mipstack: nil Stack"))
	}
	options, err := parseSocketOptions(dialerOptions(dialer), socketOptionIPDial)
	if err != nil {
		return nil, socketOperationError("dial", network, ipNetAddr(source), ipNetAddr(remote), err)
	}
	return stack.dialIP(ctx, network, source, remote, options)
}

func dialerOptions(dialer *Dialer) []SocketOption {
	if dialer == nil {
		return nil
	}
	return dialer.Options
}
