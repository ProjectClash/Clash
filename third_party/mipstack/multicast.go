package mipstack

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	multicastDefaultRobustness = 2
	multicastDefaultQueryInterval = 125 * time.Second
	multicastDefaultResponseInterval = 10 * time.Second
	multicastUnsolicitedReportInterval = time.Second
	multicastMaximumQuerySources = 4096
)

const (
	igmpMembershipQuery = 0x11
	igmpV1MembershipReport = 0x12
	igmpV2MembershipReport = 0x16
	igmpV2LeaveGroup = 0x17
	igmpV3MembershipReport = 0x22
	mldMembershipQuery = 130
	mldV1MembershipReport = 131
	mldV1ListenerDone = 132
	mldV2MembershipReport = 143

	multicastRecordModeIsInclude = 1
	multicastRecordModeIsExclude = 2
	multicastRecordChangeToIncludeMode = 3
	multicastRecordChangeToExcludeMode = 4
	multicastRecordAllowNewSources = 5
	multicastRecordBlockOldSources = 6
)

type MulticastSourceFilterMode uint8

const (
	MulticastSourceFilterExclude MulticastSourceFilterMode = iota
	MulticastSourceFilterInclude
)

type MulticastSourceFilter struct {
	Mode MulticastSourceFilterMode
	Sources []netip.Addr
}

type multicastFilterMode uint8

const (
	multicastFilterInclude multicastFilterMode = iota
	multicastFilterExclude
)

type multicastMembershipOperation uint8

const (
	multicastJoinAnySource multicastMembershipOperation = iota
	multicastLeaveGroup
	multicastJoinSource
	multicastLeaveSource
	multicastExcludeSource
	multicastIncludeSource
)

type multicastFilter struct {
	mode    multicastFilterMode
	sources map[netip.Addr]struct{}
}

type multicastEndpoint interface {
	multicastEndpoint()
}

type multicastEndpoints interface {
	acceptsDestination(netip.Addr) bool
	acceptsSource(netip.Addr, netip.Addr) bool
	deliverUDP(ipPacket, uint16, uint16)
	deliverIP(ipPacket) bool
	deliverImplicitIP(ipPacket, ipEndpoints) bool
	handleControl(ipPacket, time.Time, bool)
	removeEndpoint(multicastEndpoint)
	updateConfig(*networkState)
	close()
}

type multicastGroupState struct {
	members   map[multicastEndpoint]*multicastFilter
	aggregate multicastFilter
	dispatch  atomic.Pointer[multicastDispatchGroup]
	query     multicastPendingQuery
	lastReporter bool
}

type multicastDispatchSnapshot struct {
	groups map[netip.Addr]*multicastGroupState
}

type multicastDispatchGroup struct {
	filter multicastFilter
	udp    []multicastUDPDispatch
	ip     []multicastIPDispatch
}

type multicastUDPDispatch struct {
	connection *UDPConn
	filter     multicastFilter
}

type multicastIPDispatch struct {
	connection *IPConn
	filter     multicastFilter
}

type multicastPendingQuery struct {
	deadline    time.Time
	sources     map[netip.Addr]struct{}
	sourceQuery bool
}

type multicastQuery struct {
	v6            bool
	version       uint8
	group         netip.Addr
	sources       []netip.Addr
	maximum       time.Duration
	legacyMaximum time.Duration
	robustness    uint8
	queryInterval time.Duration
}

type multicastRetransmission struct {
	filter        multicastFilter
	exists        bool
	lastReporter  bool
	modeRemaining uint8
	allow         map[netip.Addr]uint8
	block         map[netip.Addr]uint8
	due           time.Time
}

type multicastReportRecord struct {
	recordType byte
	group      netip.Addr
	sources    []netip.Addr
}

type multicastReportBatch struct {
	v6           bool
	legacy       uint8
	group        netip.Addr
	exists       bool
	lastReporter bool
	records      []multicastReportRecord
	cancel       <-chan struct{}
}

type multicastQuerierState struct {
	robustness       [2]uint8
	queryInterval    [2]time.Duration
	responseInterval [2]time.Duration
	compatibility    [2]uint8
	igmpV1Until      time.Time
	igmpV2Until      time.Time
	mldV1Until       time.Time
}

type multicastQuerierSeed struct {
	multicastQuerierState
}

type multicastState struct {
	stack *Stack

	multicastQuerierState
	mu              sync.Mutex
	groups          map[netip.Addr]*multicastGroupState
	retransmissions map[netip.Addr]*multicastRetransmission
	familyGroups    [2]int
	generalQuery    [2]time.Time
	random          uint64
	wake            chan struct{}
	done            chan struct{}
	closeOnce       sync.Once
	closed          bool
	dispatch        atomic.Pointer[multicastDispatchSnapshot]
	reportCancel    [2]chan struct{}
}

func defaultMulticastQuerierState() multicastQuerierState {
	return multicastQuerierState{
		robustness:       [2]uint8{multicastDefaultRobustness, multicastDefaultRobustness},
		queryInterval:    [2]time.Duration{multicastDefaultQueryInterval, multicastDefaultQueryInterval},
		responseInterval: [2]time.Duration{multicastDefaultResponseInterval, multicastDefaultResponseInterval},
		compatibility:    [2]uint8{3, 2},
	}
}

func newMulticastState(stack *Stack) *multicastState {
	querier := defaultMulticastQuerierState()
	if stack.multicastSeed != nil {
		querier = stack.multicastSeed.multicastQuerierState
		querier.refresh(time.Now())
		stack.multicastSeed = nil
	}
	state := &multicastState{
		stack: stack, groups: make(map[netip.Addr]*multicastGroupState), retransmissions: make(map[netip.Addr]*multicastRetransmission),
		multicastQuerierState: querier,
		random:                uint64(time.Now().UnixNano()) ^ sipHash24(stack.flowLabelSecret, []byte("multicast-report")),
		wake:                  make(chan struct{}, 1), done: make(chan struct{}),
		reportCancel: [2]chan struct{}{make(chan struct{}), make(chan struct{})},
	}
	state.dispatch.Store(&multicastDispatchSnapshot{groups: make(map[netip.Addr]*multicastGroupState)})
	go state.run()
	return state
}

func (s *Stack) ListenMulticastUDP(ctx context.Context, network string, group netip.AddrPort) (*UDPConn, error) {
	group = netip.AddrPortFrom(group.Addr().Unmap(), group.Port())
	target := net.UDPAddrFromAddrPort(group)
	wrap := func(err error) (*UDPConn, error) {
		return nil, socketOperationError("listen", network, nil, target, err)
	}
	if !group.IsValid() || !validMulticastGroup(group.Addr()) {
		return wrap(syscall.EINVAL)
	}
	if err := validateListenNetwork(network, "udp", group.Addr()); err != nil {
		return wrap(err)
	}
	localAddress := netip.IPv4Unspecified()
	listenNetwork := network
	if group.Addr().Is6() {
		localAddress = netip.IPv6Unspecified()
		if network == "udp" {
			listenNetwork = "udp6"
		}
	} else if network == "udp" {
		listenNetwork = "udp4"
	}
	listenConfig := ListenConfig{Options: []SocketOption{SocketOptions.ReuseAddress(true)}}
	packetConnection, err := listenConfig.ListenUDP(ctx, s, listenNetwork, netip.AddrPortFrom(localAddress, group.Port()))
	if err != nil {
		return nil, err
	}
	connection := packetConnection.(*UDPConn)
	if err = connection.SetMulticastLoopback(false); err == nil {
		err = connection.JoinGroup(group.Addr())
	}
	if err != nil {
		_ = connection.Close()
		return wrap(err)
	}
	return connection, nil
}

func (c *UDPConn) JoinGroup(group netip.Addr) error {
	return c.changeMulticastMembership(multicastJoinAnySource, group, netip.Addr{})
}

func (c *UDPConn) LeaveGroup(group netip.Addr) error {
	return c.changeMulticastMembership(multicastLeaveGroup, group, netip.Addr{})
}

func (c *UDPConn) JoinSourceSpecificGroup(group, source netip.Addr) error {
	return c.changeMulticastMembership(multicastJoinSource, group, source)
}

func (c *UDPConn) LeaveSourceSpecificGroup(group, source netip.Addr) error {
	return c.changeMulticastMembership(multicastLeaveSource, group, source)
}

func (c *UDPConn) ExcludeSourceSpecificGroup(group, source netip.Addr) error {
	return c.changeMulticastMembership(multicastExcludeSource, group, source)
}

func (c *UDPConn) IncludeSourceSpecificGroup(group, source netip.Addr) error {
	return c.changeMulticastMembership(multicastIncludeSource, group, source)
}

func (c *UDPConn) SetBroadcast(enabled bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return c.setOperationError(net.ErrClosed)
	default:
		c.broadcast = enabled
		return nil
	}
}

func (c *UDPConn) Broadcast() (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return false, c.setOperationError(net.ErrClosed)
	default:
		return c.broadcast, nil
	}
}

func (c *UDPConn) SetMulticastHopLimit(hopLimit int) error {
	if hopLimit < 0 || hopLimit > 255 {
		return c.setOperationError(syscall.EINVAL)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return c.setOperationError(net.ErrClosed)
	default:
		c.multicastHopLimit = byte(hopLimit)
		return nil
	}
}

func (c *UDPConn) MulticastHopLimit() (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return 0, c.setOperationError(net.ErrClosed)
	default:
		return int(c.multicastHopLimit), nil
	}
}

func (c *UDPConn) SetMulticastLoopback(enabled bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return c.setOperationError(net.ErrClosed)
	default:
		c.multicastLoopback = enabled
		return nil
	}
}

func (c *UDPConn) MulticastLoopback() (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return false, c.setOperationError(net.ErrClosed)
	default:
		return c.multicastLoopback, nil
	}
}

func (c *UDPConn) SetMulticastSourceFilter(group netip.Addr, filter MulticastSourceFilter) error {
	if c == nil || c.stack == nil {
		return net.ErrClosed
	}
	if err := c.stack.setMulticastSourceFilter(c, group, filter); err != nil {
		return c.setOperationError(err)
	}
	return nil
}

func (c *UDPConn) MulticastSourceFilter(group netip.Addr) (MulticastSourceFilter, error) {
	if c == nil || c.stack == nil {
		return MulticastSourceFilter{}, net.ErrClosed
	}
	filter, err := c.stack.multicastSourceFilter(c, group)
	if err != nil {
		return MulticastSourceFilter{}, c.setOperationError(err)
	}
	return filter, nil
}

func (c *IPConn) JoinGroup(group netip.Addr) error {
	return c.changeMulticastMembership(multicastJoinAnySource, group, netip.Addr{})
}

func (c *IPConn) LeaveGroup(group netip.Addr) error {
	return c.changeMulticastMembership(multicastLeaveGroup, group, netip.Addr{})
}

func (c *IPConn) JoinSourceSpecificGroup(group, source netip.Addr) error {
	return c.changeMulticastMembership(multicastJoinSource, group, source)
}

func (c *IPConn) LeaveSourceSpecificGroup(group, source netip.Addr) error {
	return c.changeMulticastMembership(multicastLeaveSource, group, source)
}

func (c *IPConn) ExcludeSourceSpecificGroup(group, source netip.Addr) error {
	return c.changeMulticastMembership(multicastExcludeSource, group, source)
}

func (c *IPConn) IncludeSourceSpecificGroup(group, source netip.Addr) error {
	return c.changeMulticastMembership(multicastIncludeSource, group, source)
}

func (c *IPConn) SetBroadcast(enabled bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return c.setOperationError(net.ErrClosed)
	default:
		c.broadcast = enabled
		return nil
	}
}

func (c *IPConn) Broadcast() (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return false, c.setOperationError(net.ErrClosed)
	default:
		return c.broadcast, nil
	}
}

func (c *IPConn) SetMulticastHopLimit(hopLimit int) error {
	if hopLimit < 0 || hopLimit > 255 {
		return c.setOperationError(syscall.EINVAL)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return c.setOperationError(net.ErrClosed)
	default:
		c.multicastHopLimit = byte(hopLimit)
		return nil
	}
}

func (c *IPConn) MulticastHopLimit() (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return 0, c.setOperationError(net.ErrClosed)
	default:
		return int(c.multicastHopLimit), nil
	}
}

func (c *IPConn) SetMulticastLoopback(enabled bool) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return c.setOperationError(net.ErrClosed)
	default:
		c.multicastLoopback = enabled
		return nil
	}
}

func (c *IPConn) MulticastLoopback() (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
		return false, c.setOperationError(net.ErrClosed)
	default:
		return c.multicastLoopback, nil
	}
}

func (c *IPConn) SetMulticastSourceFilter(group netip.Addr, filter MulticastSourceFilter) error {
	if c == nil || c.stack == nil {
		return net.ErrClosed
	}
	if err := c.stack.setMulticastSourceFilter(c, group, filter); err != nil {
		return c.setOperationError(err)
	}
	return nil
}

func (c *IPConn) MulticastSourceFilter(group netip.Addr) (MulticastSourceFilter, error) {
	if c == nil || c.stack == nil {
		return MulticastSourceFilter{}, net.ErrClosed
	}
	filter, err := c.stack.multicastSourceFilter(c, group)
	if err != nil {
		return MulticastSourceFilter{}, c.setOperationError(err)
	}
	return filter, nil
}

func (*UDPConn) multicastEndpoint() {}

func (*IPConn) multicastEndpoint() {}

func (c *UDPConn) changeMulticastMembership(operation multicastMembershipOperation, group, source netip.Addr) error {
	if c == nil || c.stack == nil {
		return net.ErrClosed
	}
	if err := c.stack.changeMulticastMembership(c, operation, group, source); err != nil {
		return c.setOperationError(err)
	}
	return nil
}

func (c *IPConn) changeMulticastMembership(operation multicastMembershipOperation, group, source netip.Addr) error {
	if c == nil || c.stack == nil {
		return net.ErrClosed
	}
	if err := c.stack.changeMulticastMembership(c, operation, group, source); err != nil {
		return c.setOperationError(err)
	}
	return nil
}

func (s *Stack) changeMulticastMembership(endpoint multicastEndpoint, operation multicastMembershipOperation, group, source netip.Addr) error {
	group, source = group.Unmap(), source.Unmap()
	if !validMulticastGroup(group) {
		return syscall.EINVAL
	}
	if isSourceSpecificMulticast(group) &&
		(operation == multicastJoinAnySource || operation == multicastExcludeSource || operation == multicastIncludeSource) {
		return syscall.EINVAL
	}
	if source.IsValid() && !validMulticastSourceSyntax(source, group.Is6()) {
		return syscall.EINVAL
	}
	if operation >= multicastJoinSource && !source.IsValid() {
		return syscall.EINVAL
	}
	s.mu.Lock()
	if s.closed || !s.multicastEndpointRegisteredLocked(endpoint) {
		s.mu.Unlock()
		return net.ErrClosed
	}
	if !multicastEndpointSupportsGroup(endpoint, group) {
		s.mu.Unlock()
		return syscall.EAFNOSUPPORT
	}
	if source.IsValid() && !validMulticastSourceAddress(s.network.Load(), source, group.Is6()) {
		s.mu.Unlock()
		return syscall.EINVAL
	}
	state, ok := s.multicast.(*multicastState)
	if !ok {
		switch operation {
		case multicastJoinAnySource, multicastJoinSource:
		case multicastLeaveGroup:
			s.mu.Unlock()
			return syscall.EADDRNOTAVAIL
		default:
			s.mu.Unlock()
			return syscall.EINVAL
		}
		state = newMulticastState(s)
		s.multicast = state
	}
	err := state.change(endpoint, operation, group, source)
	s.mu.Unlock()
	if err == nil {
		s.pruneFragments(s.network.Load())
	}
	return err
}

func (s *Stack) setMulticastSourceFilter(endpoint multicastEndpoint, group netip.Addr, filter MulticastSourceFilter) error {
	group = group.Unmap()
	if !validMulticastGroup(group) ||
		filter.Mode != MulticastSourceFilterInclude && filter.Mode != MulticastSourceFilterExclude {
		return syscall.EINVAL
	}
	if filter.Mode == MulticastSourceFilterExclude && isSourceSpecificMulticast(group) {
		return syscall.EINVAL
	}
	sources := make(map[netip.Addr]struct{}, len(filter.Sources))
	for _, source := range filter.Sources {
		source = source.Unmap()
		if !validMulticastSourceSyntax(source, group.Is6()) {
			return syscall.EINVAL
		}
		sources[source] = struct{}{}
	}
	mode := multicastFilterInclude
	if filter.Mode == MulticastSourceFilterExclude {
		mode = multicastFilterExclude
	}
	s.mu.Lock()
	if s.closed || !s.multicastEndpointRegisteredLocked(endpoint) {
		s.mu.Unlock()
		return net.ErrClosed
	}
	if !multicastEndpointSupportsGroup(endpoint, group) {
		s.mu.Unlock()
		return syscall.EAFNOSUPPORT
	}
	network := s.network.Load()
	for source := range sources {
		if !validMulticastSourceAddress(network, source, group.Is6()) {
			s.mu.Unlock()
			return syscall.EINVAL
		}
	}
	state, ok := s.multicast.(*multicastState)
	if !ok {
		s.mu.Unlock()
		if mode == multicastFilterInclude && len(sources) == 0 {
			return syscall.EADDRNOTAVAIL
		}
		return syscall.EINVAL
	}
	err := state.set(endpoint, group, mode, sources)
	s.mu.Unlock()
	if err == nil {
		s.pruneFragments(s.network.Load())
	}
	return err
}

func validMulticastSourceAddress(network *networkState, source netip.Addr, v6 bool) bool {
	if !validMulticastSourceSyntax(source, v6) {
		return false
	}
	source = source.Unmap()
	if source.Is4() && network.broadcastDestination(source) {
		return false
	}
	return true
}

func validMulticastSourceSyntax(source netip.Addr, v6 bool) bool {
	source = source.Unmap()
	return source.IsValid() && !source.IsUnspecified() && !source.IsMulticast() && source.Zone() == "" && source.Is6() == v6
}

func isSourceSpecificMulticast(group netip.Addr) bool {
	group = group.Unmap()
	if !group.IsMulticast() {
		return false
	}
	if group.Is4() {
		return group.As4()[0] == 232
	}
	raw := group.As16()
	return raw[1]>>4 == 3 && raw[2] == 0 && raw[3] == 0
}

func (s *Stack) multicastSourceFilter(endpoint multicastEndpoint, group netip.Addr) (MulticastSourceFilter, error) {
	group = group.Unmap()
	if !validMulticastGroup(group) {
		return MulticastSourceFilter{}, syscall.EINVAL
	}
	s.mu.RLock()
	if s.closed || !s.multicastEndpointRegisteredLocked(endpoint) {
		s.mu.RUnlock()
		return MulticastSourceFilter{}, net.ErrClosed
	}
	state, ok := s.multicast.(*multicastState)
	if !ok {
		s.mu.RUnlock()
		return MulticastSourceFilter{}, syscall.EADDRNOTAVAIL
	}
	state.mu.Lock()
	s.mu.RUnlock()
	groupState := state.groups[group]
	var current *multicastFilter
	if groupState != nil {
		current = groupState.members[endpoint]
	}
	if current == nil {
		state.mu.Unlock()
		return MulticastSourceFilter{}, syscall.EADDRNOTAVAIL
	}
	mode := MulticastSourceFilterInclude
	if current.mode == multicastFilterExclude {
		mode = MulticastSourceFilterExclude
	}
	result := MulticastSourceFilter{Mode: mode, Sources: make([]netip.Addr, 0, len(current.sources))}
	for source := range current.sources {
		result.Sources = append(result.Sources, source)
	}
	state.mu.Unlock()
	sort.Slice(result.Sources, func(left, right int) bool { return result.Sources[left].Compare(result.Sources[right]) < 0 })
	return result, nil
}

func (s *Stack) multicastEndpointRegisteredLocked(endpoint multicastEndpoint) bool {
	switch connection := endpoint.(type) {
	case *UDPConn:
		key := udpKey{address: connection.local, port: connection.port}
		if s.udp[key] == connection {
			return true
		}
		flow := udpFlowKey{local: netip.AddrPortFrom(connection.local, connection.port), remote: connection.remote}
		if s.udpForwarded[flow] == connection {
			return true
		}
		return s.udpReuse != nil && s.udpReuse.contains(connection)
	case *IPConn:
		state, ok := s.ip.(*ipEndpointState)
		return ok && state.contains(connection)
	}
	return false
}

func multicastEndpointSupportsGroup(endpoint multicastEndpoint, group netip.Addr) bool {
	switch connection := endpoint.(type) {
	case *UDPConn:
		return connection.dual || connection.v6 == group.Is6()
	case *IPConn:
		return connection.dual || connection.v6 == group.Is6()
	default:
		return false
	}
}

func (s *multicastState) change(endpoint multicastEndpoint, operation multicastMembershipOperation, group, source netip.Addr) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	groupState := s.groups[group]
	old, oldExists := multicastInterfaceFilter(groupState)
	oldLastReporter := groupState != nil && groupState.lastReporter
	filter := (*multicastFilter)(nil)
	if groupState != nil {
		filter = groupState.members[endpoint]
	}
	existingFilter := filter != nil
	switch operation {
	case multicastJoinAnySource:
		if filter != nil {
			return syscall.EADDRINUSE
		}
		filter = &multicastFilter{mode: multicastFilterExclude, sources: make(map[netip.Addr]struct{})}
	case multicastLeaveGroup:
		if filter == nil {
			return syscall.EADDRNOTAVAIL
		}
	case multicastJoinSource:
		if filter == nil {
			filter = &multicastFilter{mode: multicastFilterInclude, sources: make(map[netip.Addr]struct{})}
		} else if filter.mode != multicastFilterInclude {
			return syscall.EINVAL
		}
		if _, exists := filter.sources[source]; exists {
			return syscall.EADDRINUSE
		}
	case multicastLeaveSource:
		if filter == nil || filter.mode != multicastFilterInclude {
			return syscall.EINVAL
		}
		if _, exists := filter.sources[source]; !exists {
			return syscall.EADDRNOTAVAIL
		}
	case multicastExcludeSource:
		if filter == nil || filter.mode != multicastFilterExclude {
			return syscall.EINVAL
		}
		if _, exists := filter.sources[source]; exists {
			return syscall.EADDRINUSE
		}
	case multicastIncludeSource:
		if filter == nil || filter.mode != multicastFilterExclude {
			return syscall.EINVAL
		}
		if _, exists := filter.sources[source]; !exists {
			return syscall.EADDRNOTAVAIL
		}
	default:
		return syscall.EINVAL
	}
	if existingFilter && operation != multicastLeaveGroup {
		copied := cloneMulticastFilter(*filter)
		if copied.sources == nil {
			copied.sources = make(map[netip.Addr]struct{})
		}
		filter = &copied
	}
	if groupState == nil {
		groupState = &multicastGroupState{members: make(map[multicastEndpoint]*multicastFilter)}
		s.groups[group] = groupState
		if multicastGroupNeedsReport(group) {
			s.familyGroups[multicastFamilyIndex(group)]++
		}
	}
	switch operation {
	case multicastLeaveGroup:
		delete(groupState.members, endpoint)
	case multicastJoinSource, multicastExcludeSource:
		filter.sources[source] = struct{}{}
		groupState.members[endpoint] = filter
	case multicastLeaveSource:
		delete(filter.sources, source)
		if len(filter.sources) == 0 {
			delete(groupState.members, endpoint)
		} else {
			groupState.members[endpoint] = filter
		}
	case multicastIncludeSource:
		delete(filter.sources, source)
		groupState.members[endpoint] = filter
	default:
		groupState.members[endpoint] = filter
	}
	if len(groupState.members) == 0 {
		s.removeGroupLocked(group)
	} else {
		groupState.aggregate = aggregateMulticastFilter(groupState.members)
	}
	s.interfaceStateChangedLocked(group, old, oldExists, oldLastReporter)
	s.rebuildGroupDispatchLocked(group)
	return nil
}

func (s *multicastState) set(endpoint multicastEndpoint, group netip.Addr, mode multicastFilterMode, sources map[netip.Addr]struct{}) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	groupState := s.groups[group]
	if groupState == nil || groupState.members[endpoint] == nil {
		if mode == multicastFilterInclude && len(sources) == 0 {
			return syscall.EADDRNOTAVAIL
		}
		return syscall.EINVAL
	}
	old, oldExists := multicastInterfaceFilter(groupState)
	oldLastReporter := groupState.lastReporter
	if mode == multicastFilterInclude && len(sources) == 0 {
		delete(groupState.members, endpoint)
		if len(groupState.members) == 0 {
			s.removeGroupLocked(group)
		} else {
			groupState.aggregate = aggregateMulticastFilter(groupState.members)
		}
		s.interfaceStateChangedLocked(group, old, oldExists, oldLastReporter)
		s.rebuildGroupDispatchLocked(group)
		return nil
	}
	groupState.members[endpoint] = &multicastFilter{mode: mode, sources: sources}
	groupState.aggregate = aggregateMulticastFilter(groupState.members)
	s.interfaceStateChangedLocked(group, old, oldExists, oldLastReporter)
	s.rebuildGroupDispatchLocked(group)
	return nil
}

func (s *multicastState) removeEndpoint(endpoint multicastEndpoint) {
	s.mu.Lock()
	indexChanged := false
	for group, groupState := range s.groups {
		if _, exists := groupState.members[endpoint]; !exists {
			continue
		}
		old, oldExists := multicastInterfaceFilter(groupState)
		oldLastReporter := groupState.lastReporter
		delete(groupState.members, endpoint)
		removed := len(groupState.members) == 0
		if removed {
			s.removeGroupLocked(group)
			indexChanged = true
		} else {
			groupState.aggregate = aggregateMulticastFilter(groupState.members)
		}
		s.interfaceStateChangedLocked(group, old, oldExists, oldLastReporter)
		if !removed {
			s.rebuildGroupDispatchLocked(group)
		}
	}
	if indexChanged {
		s.rebuildDispatchIndexLocked()
	}
	s.mu.Unlock()
}

func (s *multicastState) removeGroupLocked(group netip.Addr) {
	if state := s.groups[group]; state != nil {
		state.dispatch.Store(nil)
	}
	delete(s.groups, group)
	if multicastGroupNeedsReport(group) {
		s.familyGroups[multicastFamilyIndex(group)]--
	}
}

func aggregateMulticastFilter(members map[multicastEndpoint]*multicastFilter) multicastFilter {
	if len(members) == 1 {
		for _, filter := range members {
			return *filter
		}
	}
	result := multicastFilter{mode: multicastFilterInclude}
	firstExclude := true
	var include map[netip.Addr]struct{}
	for _, filter := range members {
		if filter.mode == multicastFilterInclude {
			for source := range filter.sources {
				if include == nil {
					include = make(map[netip.Addr]struct{})
				}
				include[source] = struct{}{}
			}
			continue
		}
		result.mode = multicastFilterExclude
		if firstExclude {
			if len(filter.sources) != 0 {
				result.sources = make(map[netip.Addr]struct{}, len(filter.sources))
				for source := range filter.sources {
					result.sources[source] = struct{}{}
				}
			}
			firstExclude = false
			continue
		}
		for source := range result.sources {
			if _, exists := filter.sources[source]; !exists {
				delete(result.sources, source)
			}
		}
	}
	if result.mode == multicastFilterInclude {
		result.sources = include
		return result
	}
	for source := range include {
		delete(result.sources, source)
	}
	return result
}

func multicastInterfaceFilter(state *multicastGroupState) (multicastFilter, bool) {
	if state == nil || len(state.members) == 0 {
		return multicastFilter{mode: multicastFilterInclude}, false
	}
	return state.aggregate, true
}

func cloneMulticastFilter(filter multicastFilter) multicastFilter {
	if len(filter.sources) == 0 {
		return multicastFilter{mode: filter.mode}
	}
	result := multicastFilter{mode: filter.mode, sources: make(map[netip.Addr]struct{}, len(filter.sources))}
	for source := range filter.sources {
		result.sources[source] = struct{}{}
	}
	return result
}

func multicastFiltersEqual(left multicastFilter, leftExists bool, right multicastFilter, rightExists bool) bool {
	if leftExists != rightExists || left.mode != right.mode || len(left.sources) != len(right.sources) {
		return false
	}
	for source := range left.sources {
		if _, exists := right.sources[source]; !exists {
			return false
		}
	}
	return true
}

func (s *multicastState) interfaceStateChangedLocked(group netip.Addr, old multicastFilter, oldExists, oldLastReporter bool) {
	groupState := s.groups[group]
	current, currentExists := multicastInterfaceFilter(groupState)
	if multicastFiltersEqual(old, oldExists, current, currentExists) || !multicastGroupNeedsReport(group) {
		return
	}
	now := time.Now()
	s.refreshCompatibilityLocked(now)
	index := multicastFamilyIndex(group)
	latest := uint8(3)
	if group.Is6() {
		latest = 2
	}
	if s.compatibility[index] < latest && oldExists == currentExists {
		return
	}
	robustness := s.robustness[index]
	if robustness == 0 {
		robustness = multicastDefaultRobustness
	}
	pending := s.retransmissions[group]
	if pending == nil {
		pending = &multicastRetransmission{}
		s.retransmissions[group] = pending
	}
	pending.filter, pending.exists = current, currentExists
	if currentExists {
		pending.lastReporter = groupState.lastReporter
	} else {
		pending.lastReporter = oldLastReporter
	}
	if old.mode != current.mode {
		pending.modeRemaining = robustness
		pending.allow, pending.block = nil, nil
	} else {
		var allow, block map[netip.Addr]struct{}
		if current.mode == multicastFilterInclude {
			allow = multicastSourceDifference(current.sources, old.sources)
			block = multicastSourceDifference(old.sources, current.sources)
		} else {
			allow = multicastSourceDifference(old.sources, current.sources)
			block = multicastSourceDifference(current.sources, old.sources)
		}
		for source := range allow {
			if pending.allow == nil {
				pending.allow = make(map[netip.Addr]uint8)
			}
			pending.allow[source] = robustness
			delete(pending.block, source)
		}
		for source := range block {
			if pending.block == nil {
				pending.block = make(map[netip.Addr]uint8)
			}
			pending.block[source] = robustness
			delete(pending.allow, source)
		}
	}
	pending.due = now
	s.wakeLocked()
}

func multicastSourceDifference(left, right map[netip.Addr]struct{}) map[netip.Addr]struct{} {
	var result map[netip.Addr]struct{}
	for source := range left {
		if _, exists := right[source]; !exists {
			if result == nil {
				result = make(map[netip.Addr]struct{})
			}
			result[source] = struct{}{}
		}
	}
	return result
}

func (s *multicastState) wakeLocked() {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func multicastFamilyIndex(address netip.Addr) int {
	if address.Is6() {
		return 1
	}
	return 0
}

func isAllHostsGroup(group netip.Addr) bool {
	if group.Is4() {
		return group == netip.AddrFrom4([4]byte{224, 0, 0, 1})
	}
	value := group.As16()
	return value[0] == 0xff && (value[1] == 1 || value[1] == 2) &&
		value[2] == 0 && value[3] == 0 && value[4] == 0 && value[5] == 0 && value[6] == 0 && value[7] == 0 &&
		value[8] == 0 && value[9] == 0 && value[10] == 0 && value[11] == 0 && value[12] == 0 && value[13] == 0 && value[14] == 0 && value[15] == 1
}

func multicastGroupNeedsReport(group netip.Addr) bool {
	group = group.Unmap()
	if !validMulticastGroup(group) {
		return false
	}
	if group.Is4() {
		return group != netip.AddrFrom4([4]byte{224, 0, 0, 1})
	}
	value := group.As16()
	return value[1]&0x0f > 1 && !isAllHostsGroup(group)
}

func (s *multicastState) rebuildGroupDispatchLocked(address netip.Addr) {
	state := s.groups[address]
	if state == nil {
		s.rebuildDispatchIndexLocked()
		return
	}
	group := &multicastDispatchGroup{filter: state.aggregate}
	for endpoint, filter := range state.members {
		switch connection := endpoint.(type) {
		case *UDPConn:
			group.udp = append(group.udp, multicastUDPDispatch{connection: connection, filter: *filter})
		case *IPConn:
			group.ip = append(group.ip, multicastIPDispatch{connection: connection, filter: *filter})
		}
	}
	state.dispatch.Store(group)
	snapshot := s.dispatch.Load()
	if snapshot == nil || snapshot.groups[address] != state {
		s.rebuildDispatchIndexLocked()
	}
}

func (s *multicastState) rebuildDispatchIndexLocked() {
	snapshot := &multicastDispatchSnapshot{groups: make(map[netip.Addr]*multicastGroupState, len(s.groups))}
	for address, state := range s.groups {
		snapshot.groups[address] = state
	}
	s.dispatch.Store(snapshot)
}

func (s *multicastState) loadDispatchGroup(address netip.Addr) *multicastDispatchGroup {
	snapshot := s.dispatch.Load()
	if snapshot == nil {
		return nil
	}
	state := snapshot.groups[address]
	if state == nil {
		return nil
	}
	return state.dispatch.Load()
}

func (s *multicastState) acceptsSource(group, source netip.Addr) bool {
	group, source = group.Unmap(), source.Unmap()
	if isAllHostsGroup(group) {
		return true
	}
	state := s.loadDispatchGroup(group)
	return state != nil && state.filter.accepts(source)
}

func (s *multicastState) acceptsDestination(group netip.Addr) bool {
	group = group.Unmap()
	if !networkStateHasFamily(s.stack.network.Load(), group.Is6()) {
		return false
	}
	state := s.loadDispatchGroup(group)
	return state != nil && (len(state.udp) != 0 || len(state.ip) != 0)
}

func (s *multicastState) deliverUDP(packet ipPacket, sourcePort, targetPort uint16) {
	group := s.loadDispatchGroup(packet.target)
	if group == nil {
		return
	}
	options := ipPacketOptions{hopLimit: packet.hopLimit, trafficClass: packet.trafficClass, flowLabel: packet.flowLabel}
	remote := netip.AddrPortFrom(packet.source, sourcePort)
	for _, endpoint := range group.udp {
		connection := endpoint.connection
		if !connection.local.IsUnspecified() || connection.port != targetPort || connection.remote.IsValid() && connection.remote != remote || !endpoint.filter.accepts(packet.source) {
			continue
		}
		connection.enqueue(packet.payload[udpHeaderSize:], remote, packet.target, options)
	}
}

func (s *multicastState) deliverIP(packet ipPacket) bool {
	group := s.loadDispatchGroup(packet.target)
	if group == nil {
		return false
	}
	options := ipPacketOptions{hopLimit: packet.hopLimit, trafficClass: packet.trafficClass, flowLabel: packet.flowLabel}
	delivered := false
	for _, endpoint := range group.ip {
		connection := endpoint.connection
		if !connection.local.IsUnspecified() || connection.protocol != packet.protocol || connection.remote.IsValid() && connection.remote != packet.source || !endpoint.filter.accepts(packet.source) {
			continue
		}
		connection.enqueuePacket(packet, options)
		delivered = true
	}
	return delivered
}

func (s *multicastState) deliverImplicitIP(packet ipPacket, endpoints ipEndpoints) bool {
	state, ok := endpoints.(*ipEndpointState)
	if !ok {
		return false
	}
	var explicit []multicastIPDispatch
	if group := s.loadDispatchGroup(packet.target); group != nil {
		explicit = group.ip
	}
	s.stack.mu.RLock()
	if s.stack.ip != state {
		s.stack.mu.RUnlock()
		return false
	}
	var connectionStorage [ipEndpointInlineFanout]*IPConn
	connections := state.connectionsForLocked(connectionStorage[:0], packet.target, packet.protocol)
	s.stack.mu.RUnlock()
	options := ipPacketOptions{hopLimit: packet.hopLimit, trafficClass: packet.trafficClass, flowLabel: packet.flowLabel}
	delivered := false
	for _, connection := range connections {
		if connection.remote.IsValid() && connection.remote != packet.source {
			continue
		}
		allowed := true
		for _, membership := range explicit {
			if membership.connection == connection {
				allowed = membership.filter.accepts(packet.source)
				break
			}
		}
		if !allowed {
			continue
		}
		delivered = true
		connection.enqueuePacket(packet, options)
	}
	return delivered
}

func (f *multicastFilter) accepts(source netip.Addr) bool {
	_, listed := f.sources[source.Unmap()]
	if f.mode == multicastFilterInclude {
		return listed
	}
	return !listed
}

func nonUnicastOutputPolicy(target netip.Addr, multicastHopLimit byte, multicastLoopback, broadcast bool, options ipPacketOptions) (ipPacketOptions, bool, bool, error) {
	if target.IsMulticast() {
		if !options.hopLimitSet {
			options.hopLimit = multicastHopLimit
			options.hopLimitSet = true
		}
		external := options.hopLimit != 0
		if target.Is6() && target.As16()[1]&0x0f <= 1 {
			external = false
		}
		return options, external, multicastLoopback, nil
	}
	if !broadcast {
		return ipPacketOptions{}, false, false, syscall.EACCES
	}
	return options, true, true, nil
}

func (c *UDPConn) writeNonUnicastDatagram(source, target netip.Addr, sourcePort, targetPort uint16, payload []byte, options ipPacketOptions, pathMTUDiscovery PathMTUDiscovery) error {
	udpSize := udpHeaderSize + len(payload)
	if udpSize > 65535 || target.Is4() && udpSize > 65515 {
		return syscall.EMSGSIZE
	}
	c.mu.Lock()
	options, external, loopback, err := nonUnicastOutputPolicy(target, c.multicastHopLimit, c.multicastLoopback, c.broadcast, options)
	c.mu.Unlock()
	if err != nil {
		return err
	}
	fragmentation := sourceFragmentationForMode(pathMTUDiscovery)
	if !loopback {
		if !external {
			return nil
		}
		return c.writeDatagramForMTU(source, target, sourcePort, targetPort, payload, options, fragmentation, c.stack.network.Load().mtu)
	}
	if source.Is6() && !options.flowLabelSet {
		options.flowLabel = c.stack.automaticTransportFlowLabel(source, target, ProtocolUDP, sourcePort, targetPort)
		options.flowLabelSet = true
	}
	mtu := c.stack.network.Load().mtu
	ipSize := ipHeaderSize(source, target, udpSize)
	if ipSize == 0 {
		return syscall.EMSGSIZE
	}
	if ipSize+udpSize <= mtu {
		identification := uint16(0)
		if source.Is4() && fragmentation.requiresIPv4ID() {
			identification = uint16(c.stack.ipv4ID.Add(1))
		}
		return c.stack.tryWriteNonUnicastPacket(ipSize+udpSize, external, loopback, func(packet []byte) bool {
			if !marshalIPHeader(packet, source, target, ProtocolUDP, identification, fragmentation.dontFragment, options) {
				return false
			}
			marshalUDPDatagram(packet[ipSize:], source, target, sourcePort, targetPort, payload)
			return true
		}, true)
	}
	var layout ipFragmentLayout
	if err := c.stack.ipFragmentLayoutForMTU(source, target, udpSize, fragmentation, options, mtu, &layout); err != nil {
		return err
	}
	datagram := make([]byte, udpSize)
	marshalUDPDatagram(datagram, source, target, sourcePort, targetPort, payload)
	packets := buildIPFragmentPackets(source, target, ProtocolUDP, datagram, layout)
	var flow outputFlowKey
	if external {
		flow = c.stack.outbound.ipFlowKey(source, target, ProtocolUDP, layout.options.flowLabel, datagram)
	}
	return c.stack.tryWriteNonUnicastPackets(packets, external, loopback, flow, true)
}

func (c *IPConn) writeNonUnicastPayload(source, target netip.Addr, payload []byte, options ipPacketOptions, pathMTUDiscovery PathMTUDiscovery) error {
	ipSize := ipHeaderSize(source, target, len(payload))
	if ipSize == 0 {
		return syscall.EMSGSIZE
	}
	c.mu.Lock()
	options, external, loopback, err := nonUnicastOutputPolicy(target, c.multicastHopLimit, c.multicastLoopback, c.broadcast, options)
	c.mu.Unlock()
	if err != nil {
		return err
	}
	fragmentation := sourceFragmentationForMode(pathMTUDiscovery)
	if !loopback {
		if !external {
			return nil
		}
		return c.stack.tryWriteIPSocketPayloadForMTU(source, target, c.protocol, payload, fragmentation, options, c.stack.network.Load().mtu)
	}
	if source.Is6() && !options.flowLabelSet {
		options.flowLabel = c.stack.automaticFlowLabel(source, target, c.protocol, payload)
		options.flowLabelSet = true
	}
	mtu := c.stack.network.Load().mtu
	if ipSize+len(payload) <= mtu {
		identification := uint16(0)
		if source.Is4() && fragmentation.requiresIPv4ID() {
			identification = uint16(c.stack.ipv4ID.Add(1))
		}
		return c.stack.tryWriteNonUnicastPacket(ipSize+len(payload), external, loopback, func(packet []byte) bool {
			if !marshalIPHeader(packet, source, target, c.protocol, identification, fragmentation.dontFragment, options) {
				return false
			}
			copy(packet[ipSize:], payload)
			return true
		}, false)
	}
	var layout ipFragmentLayout
	if err := c.stack.ipFragmentLayoutForMTU(source, target, len(payload), fragmentation, options, mtu, &layout); err != nil {
		return err
	}
	packets := buildIPFragmentPackets(source, target, c.protocol, payload, layout)
	var flow outputFlowKey
	if external {
		flow = c.stack.outbound.ipFlowKey(source, target, c.protocol, layout.options.flowLabel, payload)
	}
	return c.stack.tryWriteNonUnicastPackets(packets, external, loopback, flow, false)
}

func (s *Stack) tryWriteNonUnicastPacket(size int, external, loopback bool, marshal func([]byte) bool, checksumValidated bool) error {
	if !external && !loopback {
		return nil
	}
	var externalSlot uint16
	var externalErr error
	if external {
		externalSlot, externalErr = s.tryReservePacket(&s.outbound)
		if externalErr == ErrResourceLimit {
			externalSlot, externalErr = s.replaceBestEffortPacket(&s.outbound)
		}
		if externalErr == ErrClosed {
			return externalErr
		}
	}
	localSlot, localReserved := uint16(0), false
	if loopback {
		localSlot, localReserved = s.loopback.tryReserve()
		if !localReserved {
			select {
			case <-s.closeCh:
				if external && externalErr == nil {
					s.outbound.releaseReserved(externalSlot)
				}
				return ErrClosed
			default:
			}
		}
	}
	if !external && !localReserved {
		s.stats.loopbackQueueDrops.Add(1)
		return nil
	}
	if externalErr != nil && !localReserved {
		if loopback {
			s.stats.loopbackQueueDrops.Add(1)
		}
		return externalErr
	}
	queue := &s.outbound
	slot := externalSlot
	if externalErr != nil || !external {
		queue = &s.loopback.packetQueue
		slot = localSlot
	}
	var packet []byte
	var reusable bool
	if size <= packetReusableBufferLimit {
		packet, reusable = queue.acquireBuffer(size)
	} else {
		packet, reusable = s.acquireLargeOutputBuffer(size)
	}
	if !marshal(packet) {
		s.releaseOutputBuffer(queue, packet, reusable)
		queue.releaseReserved(slot)
		if localReserved && queue != &s.loopback.packetQueue {
			s.loopback.releaseReserved(localSlot)
		}
		return syscall.EMSGSIZE
	}
	if queue == &s.outbound {
		var localPacket []byte
		var localReusable bool
		if localReserved {
			if size <= packetReusableBufferLimit {
				localPacket, localReusable = s.loopback.acquireBuffer(size)
			} else {
				localPacket, localReusable = s.acquireLargeOutputBuffer(size)
			}
			copy(localPacket, packet)
		}
		if !s.outbound.enqueueReservedPacket(externalSlot, packet, reusable, checksumValidated) {
			if localReserved {
				s.releaseOutputBuffer(&s.loopback.packetQueue, localPacket, localReusable)
				s.loopback.releaseReserved(localSlot)
			}
			return ErrClosed
		}
		s.recordOutput(false)
		if localReserved {
			if !s.loopback.enqueueReservedPacket(localSlot, localPacket, localReusable, checksumValidated) {
				return ErrClosed
			}
			s.recordOutput(true)
		} else if loopback {
			s.stats.loopbackQueueDrops.Add(1)
		}
		return nil
	}
	if !s.loopback.enqueueReservedPacket(localSlot, packet, reusable, checksumValidated) {
		return ErrClosed
	}
	s.recordOutput(true)
	return externalErr
}

func (s *Stack) tryWriteNonUnicastPackets(packets [][]byte, external, loopback bool, flow outputFlowKey, checksumValidated bool) error {
	if len(packets) == 0 || !external && !loopback {
		return nil
	}
	var externalErr error
	if external {
		for _, packet := range packets {
			if externalErr = s.tryWritePacketToFlow(packet, &s.outbound, false, flow, checksumValidated); externalErr != nil {
				break
			}
		}
		if externalErr == ErrClosed {
			return externalErr
		}
	}
	if loopback {
		localErr := s.tryWriteLoopbackPackets(packets, checksumValidated)
		if localErr == ErrClosed {
			return localErr
		}
	}
	return externalErr
}

func isMulticastControlPacket(packet ipPacket) bool {
	if packet.protocol == ProtocolIGMP && packet.source.Is4() {
		return true
	}
	if packet.protocol == ProtocolICMPv6 && len(packet.payload) != 0 {
		switch packet.payload[0] {
		case mldMembershipQuery, mldV1MembershipReport, mldV1ListenerDone, mldV2MembershipReport:
			return true
		}
	}
	return false
}

func (s *Stack) multicastStateForQuery(packet ipPacket, current multicastEndpoints, receivedAt time.Time, skipChecksum bool) multicastEndpoints {
	if current != nil || len(packet.payload) == 0 {
		return current
	}
	var query multicastQuery
	var expected netip.Addr
	var valid bool
	network := s.network.Load()
	switch packet.protocol {
	case ProtocolIGMP:
		if packet.payload[0] != igmpMembershipQuery {
			return nil
		}
		query, expected, valid = parseIGMPQuery(packet, network, skipChecksum)
	case ProtocolICMPv6:
		if packet.payload[0] != mldMembershipQuery {
			return nil
		}
		query, expected, valid = parseMLDQuery(packet, network, skipChecksum)
	default:
		return nil
	}
	if !valid || !s.acceptsMulticastControlDestination(packet.target, expected, nil) {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	if s.multicast != nil {
		return s.multicast
	}
	if s.multicastSeed == nil {
		s.multicastSeed = &multicastQuerierSeed{multicastQuerierState: defaultMulticastQuerierState()}
	}
	s.multicastSeed.noteQuery(query, receivedAt)
	return nil
}

func (s *multicastState) handleControl(packet ipPacket, receivedAt time.Time, skipChecksum bool) {
	if packet.protocol == ProtocolIGMP {
		s.handleIGMP(packet, receivedAt, skipChecksum)
	} else {
		s.handleMLD(packet, receivedAt, skipChecksum)
	}
}

func (s *multicastState) handleIGMP(packet ipPacket, receivedAt time.Time, skipChecksum bool) {
	payload := packet.payload
	if len(payload) != 0 && payload[0] == igmpMembershipQuery {
		query, expected, valid := parseIGMPQuery(packet, s.stack.network.Load(), skipChecksum)
		if valid && s.acceptsControlDestination(packet.target, expected) {
			s.scheduleQuery(query, receivedAt)
		}
		return
	}
	if len(payload) < 8 || packet.hopLimit != 1 || !skipChecksum && checksum(payload) != 0 {
		return
	}
	switch payload[0] {
	case igmpV1MembershipReport, igmpV2MembershipReport:
		if len(payload) < 8 || payload[0] == igmpV2MembershipReport && !packet.hasRouterAlert() {
			return
		}
		group := netip.AddrFrom4([4]byte(payload[4:8]))
		if group.IsMulticast() && s.acceptsControlDestination(packet.target, group) {
			s.heardLegacyReport(group)
		}
	}
}

func (s *multicastState) handleMLD(packet ipPacket, receivedAt time.Time, skipChecksum bool) {
	payload := packet.payload
	if len(payload) != 0 && payload[0] == mldMembershipQuery {
		query, expected, valid := parseMLDQuery(packet, s.stack.network.Load(), skipChecksum)
		if valid && s.acceptsControlDestination(packet.target, expected) {
			s.scheduleQuery(query, receivedAt)
		}
		return
	}
	if len(payload) < 8 || payload[1] != 0 || packet.hopLimit != 1 || !packet.hasRouterAlert() ||
		!packet.source.IsLinkLocalUnicast() ||
		!skipChecksum && transportChecksum(packet.source, packet.target, ProtocolICMPv6, payload) != 0 {
		return
	}
	switch payload[0] {
	case mldV1MembershipReport:
		if len(payload) >= 24 {
			group := netip.AddrFrom16([16]byte(payload[8:24]))
			if group.IsMulticast() && s.acceptsControlDestination(packet.target, group) {
				s.heardLegacyReport(group)
			}
		}
	}
}

func parseIGMPQuery(packet ipPacket, network *networkState, skipChecksum bool) (multicastQuery, netip.Addr, bool) {
	payload := packet.payload
	if len(payload) < 8 || payload[0] != igmpMembershipQuery || packet.hopLimit != 1 || !skipChecksum && checksum(payload) != 0 {
		return multicastQuery{}, netip.Addr{}, false
	}
	query := multicastQuery{version: 3, maximum: decodeIGMPTime(payload[1])}
	if len(payload) == 8 {
		if payload[1] == 0 {
			query.version, query.maximum = 1, multicastDefaultResponseInterval
		} else {
			query.version = 2
			query.maximum = decodeIGMPv2Time(payload[1])
		}
	} else {
		if len(payload) < 12 {
			return multicastQuery{}, netip.Addr{}, false
		}
		query.robustness = payload[8] & 7
		query.queryInterval = decodeIGMPQueryInterval(payload[9])
		count := int(binary.BigEndian.Uint16(payload[10:12]))
		if count > multicastMaximumQuerySources || len(payload)-12 < count*4 {
			return multicastQuery{}, netip.Addr{}, false
		}
		query.sources = make([]netip.Addr, 0, count)
		for offset := 12; len(query.sources) < count; offset += 4 {
			source := netip.AddrFrom4([4]byte(payload[offset : offset+4]))
			if !validMulticastSourceAddress(network, source, false) {
				return multicastQuery{}, netip.Addr{}, false
			}
			query.sources = append(query.sources, source)
		}
	}
	if query.version >= 2 && !packet.hasRouterAlert() {
		return multicastQuery{}, netip.Addr{}, false
	}
	query.group = netip.AddrFrom4([4]byte(payload[4:8]))
	if query.version == 1 && !query.group.IsUnspecified() ||
		!query.group.IsUnspecified() && !validMulticastGroup(query.group) ||
		len(query.sources) != 0 && query.group.IsUnspecified() {
		return multicastQuery{}, netip.Addr{}, false
	}
	query.legacyMaximum = query.maximum
	expected := query.group
	if expected.IsUnspecified() {
		expected = netip.AddrFrom4([4]byte{224, 0, 0, 1})
	}
	return query, expected, true
}

func parseMLDQuery(packet ipPacket, network *networkState, skipChecksum bool) (multicastQuery, netip.Addr, bool) {
	payload := packet.payload
	if len(payload) < 24 || payload[0] != mldMembershipQuery || payload[1] != 0 || packet.hopLimit != 1 ||
		!packet.hasRouterAlert() || !packet.source.IsLinkLocalUnicast() ||
		!skipChecksum && transportChecksum(packet.source, packet.target, ProtocolICMPv6, payload) != 0 {
		return multicastQuery{}, netip.Addr{}, false
	}
	legacyResponse := time.Duration(binary.BigEndian.Uint16(payload[4:6])) * time.Millisecond
	query := multicastQuery{v6: true, version: 1, maximum: legacyResponse, legacyMaximum: legacyResponse}
	if len(payload) != 24 {
		if len(payload) < 28 {
			return multicastQuery{}, netip.Addr{}, false
		}
		query.version = 2
		query.maximum = decodeMLDTime(binary.BigEndian.Uint16(payload[4:6]))
		query.robustness = payload[24] & 7
		query.queryInterval = decodeIGMPQueryInterval(payload[25])
		count := int(binary.BigEndian.Uint16(payload[26:28]))
		if count > multicastMaximumQuerySources || len(payload)-28 < count*16 {
			return multicastQuery{}, netip.Addr{}, false
		}
		query.sources = make([]netip.Addr, 0, count)
		for offset := 28; len(query.sources) < count; offset += 16 {
			source := netip.AddrFrom16([16]byte(payload[offset : offset+16]))
			if !validMulticastSourceAddress(network, source, true) {
				return multicastQuery{}, netip.Addr{}, false
			}
			query.sources = append(query.sources, source)
		}
	}
	query.group = netip.AddrFrom16([16]byte(payload[8:24]))
	if !query.group.IsUnspecified() && !validMulticastGroup(query.group) ||
		len(query.sources) != 0 && query.group.IsUnspecified() {
		return multicastQuery{}, netip.Addr{}, false
	}
	expected := query.group
	if expected.IsUnspecified() {
		expected = netip.AddrFrom16([16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	}
	return query, expected, true
}

func (s *multicastState) acceptsControlDestination(target, expected netip.Addr) bool {
	return s.stack.acceptsMulticastControlDestination(target, expected, s)
}

func (s *Stack) acceptsMulticastControlDestination(target, expected netip.Addr, memberships multicastEndpoints) bool {
	target = target.Unmap()
	network := s.network.Load()
	if target == expected || networkStateHasLocal(network, target) {
		return true
	}
	if isAllHostsGroup(target) && networkStateHasFamily(network, target.Is6()) {
		return true
	}
	return target.IsMulticast() && memberships != nil && memberships.acceptsDestination(target)
}

func decodeIGMPv2Time(code byte) time.Duration {
	return time.Duration(code) * 100 * time.Millisecond
}

func decodeIGMPTime(code byte) time.Duration {
	value := uint32(code)
	if code >= 128 {
		value = uint32(code&0x0f|0x10) << ((code >> 4 & 7) + 3)
	}
	return time.Duration(value) * 100 * time.Millisecond
}

func decodeIGMPQueryInterval(code byte) time.Duration {
	value := uint32(code)
	if code >= 128 {
		value = uint32(code&0x0f|0x10) << ((code >> 4 & 7) + 3)
	}
	return time.Duration(value) * time.Second
}

func decodeMLDTime(code uint16) time.Duration {
	value := uint32(code)
	if code >= 0x8000 {
		value = uint32(code&0x0fff|0x1000) << ((code >> 12 & 7) + 3)
	}
	return time.Duration(value) * time.Millisecond
}

func (s *multicastState) scheduleQuery(query multicastQuery, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	index := 0
	latest := uint8(3)
	if query.v6 {
		index, latest = 1, 2
	}
	s.refreshCompatibilityLocked(now)
	if query.version == latest && s.compatibility[index] < latest {
		query.sources = nil
		if query.v6 {
			query.maximum = query.legacyMaximum
		} else if s.compatibility[index] == 1 {
			query.group = netip.IPv4Unspecified()
			query.maximum = multicastDefaultResponseInterval
		}
	} else {
		s.noteQueryVersionLocked(index, query.version, query.group.IsUnspecified(), query.robustness, query.queryInterval, query.maximum, now)
	}
	if query.maximum <= 0 {
		query.maximum = time.Nanosecond
	}
	legacy := s.compatibility[index] < latest
	if query.group.IsUnspecified() {
		if legacy {
			for address, state := range s.groups {
				if address.Is6() != query.v6 || !multicastGroupNeedsReport(address) {
					continue
				}
				deadline := now.Add(s.randomDelayLocked(query.maximum))
				if state.query.deadline.IsZero() || deadline.Before(state.query.deadline) {
					state.query = multicastPendingQuery{deadline: deadline}
				}
			}
		} else if s.familyGroups[index] != 0 {
			deadline := now.Add(s.randomDelayLocked(query.maximum))
			if s.generalQuery[index].IsZero() || deadline.Before(s.generalQuery[index]) {
				s.generalQuery[index] = deadline
			}
		}
		s.wakeLocked()
		return
	}
	state := s.groups[query.group]
	if state == nil || !multicastGroupNeedsReport(query.group) {
		return
	}
	deadline := now.Add(s.randomDelayLocked(query.maximum))
	if !s.generalQuery[index].IsZero() && !deadline.Before(s.generalQuery[index]) {
		return
	}
	pending := &state.query
	if pending.deadline.IsZero() {
		pending.deadline = deadline
		pending.sourceQuery = len(query.sources) != 0
		if pending.sourceQuery {
			pending.sources = multicastAddressSet(query.sources)
		}
	} else if len(query.sources) == 0 || !pending.sourceQuery {
		pending.sourceQuery, pending.sources = false, nil
		if deadline.Before(pending.deadline) {
			pending.deadline = deadline
		}
	} else {
		if pending.sources == nil {
			pending.sources = make(map[netip.Addr]struct{})
		}
		for _, source := range query.sources {
			if len(pending.sources) >= multicastMaximumQuerySources {
				break
			}
			pending.sources[source] = struct{}{}
		}
		if deadline.Before(pending.deadline) {
			pending.deadline = deadline
		}
	}
	s.wakeLocked()
}

func (s *multicastQuerierSeed) noteQuery(query multicastQuery, now time.Time) {
	s.refresh(now)
	index, latest := 0, uint8(3)
	if query.v6 {
		index, latest = 1, 2
	}
	if query.version == latest && s.compatibility[index] < latest {
		return
	}
	s.noteQueryVersion(index, query.version, query.group.IsUnspecified(), query.robustness, query.queryInterval, query.maximum, now)
	s.refresh(now)
}

func (s *multicastQuerierState) noteQueryVersion(index int, version uint8, general bool, robustness uint8, queryInterval, responseInterval time.Duration, now time.Time) {
	latest := uint8(3)
	if index == 1 {
		latest = 2
	}
	if version == latest {
		if robustness == 0 {
			robustness = multicastDefaultRobustness
		}
		if queryInterval == 0 {
			queryInterval = multicastDefaultQueryInterval
		}
		s.robustness[index] = robustness
		s.queryInterval[index] = queryInterval
		s.responseInterval[index] = responseInterval
	}
	timeout := time.Duration(s.robustness[index])*s.queryInterval[index] + s.responseInterval[index]
	if index == 0 {
		timeout = time.Duration(s.robustness[index])*s.queryInterval[index] + 10*responseInterval
	}
	if index == 0 {
		if version == 1 {
			s.igmpV1Until = now.Add(timeout)
		} else if version == 2 && general {
			s.igmpV2Until = now.Add(timeout)
		}
	} else if version == 1 {
		s.mldV1Until = now.Add(timeout)
	}
}

func (s *multicastState) noteQueryVersionLocked(index int, version uint8, general bool, robustness uint8, queryInterval, responseInterval time.Duration, now time.Time) {
	s.refreshCompatibilityLocked(now)
	s.multicastQuerierState.noteQueryVersion(index, version, general, robustness, queryInterval, responseInterval, now)
	s.refreshCompatibilityLocked(now)
}

func (s *multicastQuerierState) refresh(now time.Time) (changed [2]bool) {
	if !s.igmpV1Until.IsZero() && !now.Before(s.igmpV1Until) {
		s.igmpV1Until = time.Time{}
	}
	if !s.igmpV2Until.IsZero() && !now.Before(s.igmpV2Until) {
		s.igmpV2Until = time.Time{}
	}
	if !s.mldV1Until.IsZero() && !now.Before(s.mldV1Until) {
		s.mldV1Until = time.Time{}
	}
	mode4 := uint8(3)
	if !s.igmpV2Until.IsZero() {
		mode4 = 2
	}
	if !s.igmpV1Until.IsZero() {
		mode4 = 1
	}
	mode6 := uint8(2)
	if !s.mldV1Until.IsZero() {
		mode6 = 1
	}
	for index, mode := range [2]uint8{mode4, mode6} {
		changed[index] = s.compatibility[index] != mode
		s.compatibility[index] = mode
	}
	return changed
}

func (s *multicastState) refreshCompatibilityLocked(now time.Time) {
	if s.closed {
		return
	}
	for index, changed := range s.multicastQuerierState.refresh(now) {
		if !changed {
			continue
		}
		close(s.reportCancel[index])
		s.reportCancel[index] = make(chan struct{})
		s.cancelPendingFamilyLocked(index)
	}
}

func (s *multicastState) cancelPendingFamilyLocked(index int) {
	s.generalQuery[index] = time.Time{}
	v6 := index == 1
	for group, state := range s.groups {
		if group.Is6() == v6 {
			state.query = multicastPendingQuery{}
		}
	}
	for group := range s.retransmissions {
		if group.Is6() == v6 {
			delete(s.retransmissions, group)
		}
	}
}

func (s *multicastState) heardLegacyReport(group netip.Addr) {
	if isSourceSpecificMulticast(group) {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.refreshCompatibilityLocked(time.Now())
	index, latest := multicastFamilyIndex(group), uint8(3)
	if group.Is6() {
		latest = 2
	}
	if s.compatibility[index] == latest {
		s.mu.Unlock()
		return
	}
	if state := s.groups[group]; state != nil {
		state.query = multicastPendingQuery{}
		state.lastReporter = false
		if pending := s.retransmissions[group]; pending != nil && pending.exists {
			delete(s.retransmissions, group)
		}
	}
	s.wakeLocked()
	s.mu.Unlock()
}

func multicastAddressSet(addresses []netip.Addr) map[netip.Addr]struct{} {
	result := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		result[address] = struct{}{}
	}
	return result
}

func (s *multicastState) randomDelayLocked(maximum time.Duration) time.Duration {
	if maximum <= 0 {
		return 0
	}
	s.random += 0x9e3779b97f4a7c15
	value := s.random
	value = (value ^ value>>30) * 0xbf58476d1ce4e5b9
	value = (value ^ value>>27) * 0x94d049bb133111eb
	value ^= value >> 31
	return time.Duration(value%uint64(maximum)) + time.Nanosecond
}

func (s *multicastState) run() {
	timer := newOwnedTimer()
	defer timer.close()
	for {
		now := time.Now()
		batches, next, haveNext := s.collectReports(now)
		for _, batch := range batches {
			s.sendReport(batch)
		}
		timer.stop()
		var timeout <-chan time.Time
		if haveNext {
			delay := time.Until(next)
			if delay < 0 {
				delay = 0
			}
			timeout = timer.reset(delay)
		}
		select {
		case <-timeout:
			timer.consumed()
		case <-s.wake:
		case <-s.done:
			return
		}
	}
}

func (s *multicastState) collectReports(now time.Time) ([]multicastReportBatch, time.Time, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, time.Time{}, false
	}
	s.refreshCompatibilityLocked(now)
	var batches []multicastReportBatch
	for group, pending := range s.retransmissions {
		if pending.due.After(now) {
			continue
		}
		records, remains := s.advanceRetransmissionLocked(pending)
		legacy := s.legacyVersionLocked(group.Is6())
		for index := range records {
			records[index].group = group
		}
		family := multicastFamilyIndex(group)
		batch := multicastReportBatch{v6: group.Is6(), legacy: legacy, group: group, exists: pending.exists, lastReporter: pending.lastReporter, records: records, cancel: s.reportCancel[family]}
		if legacy != 0 && pending.exists {
			if state := s.groups[group]; state != nil {
				state.lastReporter = true
			}
		}
		if legacy != 0 || len(records) != 0 {
			batches = append(batches, batch)
		}
		if legacy != 0 && !pending.exists {
			remains = false
		}
		if remains {
			interval := multicastUnsolicitedReportInterval
			if legacy != 0 {
				interval = 10 * time.Second
			}
			pending.due = now.Add(s.randomDelayLocked(interval))
		} else {
			delete(s.retransmissions, group)
		}
	}
	for index, deadline := range s.generalQuery {
		if deadline.IsZero() || deadline.After(now) {
			continue
		}
		v6 := index == 1
		legacy := s.legacyVersionLocked(v6)
		records := make([]multicastReportRecord, 0, s.familyGroups[index])
		for group, state := range s.groups {
			if group.Is6() != v6 || !multicastGroupNeedsReport(group) {
				continue
			}
			if legacy != 0 {
				state.lastReporter = true
				batches = append(batches, multicastReportBatch{v6: v6, legacy: legacy, group: group, exists: true, cancel: s.reportCancel[index]})
			} else {
				records = append(records, multicastCurrentStateRecord(group, state.aggregate, false, nil))
			}
			if !state.query.deadline.IsZero() {
				state.query.sourceQuery = false
				state.query.sources = nil
			}
		}
		if legacy == 0 && len(records) != 0 {
			batches = append(batches, multicastReportBatch{v6: v6, records: records, cancel: s.reportCancel[index]})
		}
		s.generalQuery[index] = time.Time{}
	}
	for group, state := range s.groups {
		if state.query.deadline.IsZero() || state.query.deadline.After(now) {
			continue
		}
		query := state.query
		state.query = multicastPendingQuery{}
		legacy := s.legacyVersionLocked(group.Is6())
		if legacy != 0 {
			state.lastReporter = true
			batches = append(batches, multicastReportBatch{v6: group.Is6(), legacy: legacy, group: group, exists: true, cancel: s.reportCancel[multicastFamilyIndex(group)]})
			continue
		}
		record := multicastCurrentStateRecord(group, state.aggregate, query.sourceQuery, query.sources)
		if !query.sourceQuery || len(record.sources) != 0 {
			batches = append(batches, multicastReportBatch{v6: group.Is6(), records: []multicastReportRecord{record}, cancel: s.reportCancel[multicastFamilyIndex(group)]})
		}
	}
	var next time.Time
	setNext := func(candidate time.Time) {
		if !candidate.IsZero() && (next.IsZero() || candidate.Before(next)) {
			next = candidate
		}
	}
	for _, pending := range s.retransmissions {
		setNext(pending.due)
	}
	for _, deadline := range s.generalQuery {
		setNext(deadline)
	}
	for _, state := range s.groups {
		setNext(state.query.deadline)
	}
	setNext(s.igmpV1Until)
	setNext(s.igmpV2Until)
	setNext(s.mldV1Until)
	return batches, next, !next.IsZero()
}

func (s *multicastState) sendReport(batch multicastReportBatch) {
	if batch.legacy != 0 {
		if batch.v6 {
			s.sendMLDv1Report(batch.group, batch.exists, batch.lastReporter, batch.cancel)
		} else {
			s.sendIGMPLegacyReport(batch.group, batch.legacy, batch.exists, batch.lastReporter, batch.cancel)
		}
		return
	}
	if batch.v6 {
		s.sendMLDv2Records(batch.records, batch.cancel)
	} else {
		s.sendIGMPv3Records(batch.records, batch.cancel)
	}
}

func (s *multicastState) sendIGMPLegacyReport(group netip.Addr, version uint8, exists, lastReporter bool, cancel <-chan struct{}) {
	if !group.Is4() || !group.IsMulticast() {
		return
	}
	messageType := byte(igmpV1MembershipReport)
	target, routerAlert := group, true
	if version >= 2 {
		messageType = igmpV2MembershipReport
	}
	if !exists {
		if version < 2 || !lastReporter {
			return
		}
		messageType = igmpV2LeaveGroup
		target = netip.AddrFrom4([4]byte{224, 0, 0, 2})
	}
	payload := make([]byte, 8)
	payload[0] = messageType
	groupBytes := group.As4()
	copy(payload[4:8], groupBytes[:])
	binary.BigEndian.PutUint16(payload[2:4], checksum(payload))
	s.sendIGMPPacket(target, payload, routerAlert, cancel)
}

func (s *multicastState) sendMLDv1Report(group netip.Addr, exists, lastReporter bool, cancel <-chan struct{}) {
	if !group.Is6() || !group.IsMulticast() || !exists && !lastReporter {
		return
	}
	messageType := byte(mldV1MembershipReport)
	target := group
	if !exists {
		messageType = mldV1ListenerDone
		target = netip.AddrFrom16([16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
	}
	payload := make([]byte, 24)
	payload[0] = messageType
	groupBytes := group.As16()
	copy(payload[8:24], groupBytes[:])
	s.sendMLDPacket(target, payload, cancel)
}

func (s *multicastState) sendIGMPv3Records(records []multicastReportRecord, cancel <-chan struct{}) {
	maximum := s.stack.network.Load().mtu - 24
	for _, report := range packMulticastRecords(records, maximum, 8, 8, 4) {
		payloadSize := 8
		for _, record := range report {
			payloadSize += 8 + 4*len(record.sources)
		}
		payload := make([]byte, payloadSize)
		payload[0] = igmpV3MembershipReport
		binary.BigEndian.PutUint16(payload[6:8], uint16(len(report)))
		offset := 8
		for _, record := range report {
			payload[offset] = record.recordType
			binary.BigEndian.PutUint16(payload[offset+2:offset+4], uint16(len(record.sources)))
			group := record.group.As4()
			copy(payload[offset+4:offset+8], group[:])
			offset += 8
			for _, source := range record.sources {
				value := source.As4()
				copy(payload[offset:offset+4], value[:])
				offset += 4
			}
		}
		binary.BigEndian.PutUint16(payload[2:4], checksum(payload))
		s.sendIGMPPacket(netip.AddrFrom4([4]byte{224, 0, 0, 22}), payload, true, cancel)
	}
}

func (s *multicastState) sendMLDv2Records(records []multicastReportRecord, cancel <-chan struct{}) {
	maximum := s.stack.network.Load().mtu - 48
	for _, report := range packMulticastRecords(records, maximum, 8, 20, 16) {
		payloadSize := 8
		for _, record := range report {
			payloadSize += 20 + 16*len(record.sources)
		}
		payload := make([]byte, payloadSize)
		payload[0] = mldV2MembershipReport
		binary.BigEndian.PutUint16(payload[6:8], uint16(len(report)))
		offset := 8
		for _, record := range report {
			payload[offset] = record.recordType
			binary.BigEndian.PutUint16(payload[offset+2:offset+4], uint16(len(record.sources)))
			group := record.group.As16()
			copy(payload[offset+4:offset+20], group[:])
			offset += 20
			for _, source := range record.sources {
				value := source.As16()
				copy(payload[offset:offset+16], value[:])
				offset += 16
			}
		}
		s.sendMLDPacket(netip.AddrFrom16([16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x16}), payload, cancel)
	}
}

func packMulticastRecords(records []multicastReportRecord, maximum, reportHeader, recordHeader, addressSize int) [][]multicastReportRecord {
	if maximum < reportHeader+recordHeader {
		return nil
	}
	maximumSources := (maximum - reportHeader - recordHeader) / addressSize
	var reports [][]multicastReportRecord
	var current []multicastReportRecord
	currentSize := reportHeader
	flush := func() {
		if len(current) != 0 {
			reports = append(reports, current)
			current, currentSize = nil, reportHeader
		}
	}
	for _, record := range records {
		if len(record.sources) > maximumSources {
			flush()
			if record.recordType == multicastRecordModeIsExclude || record.recordType == multicastRecordChangeToExcludeMode {
				record.sources = record.sources[:maximumSources]
				reports = append(reports, []multicastReportRecord{record})
				continue
			}
			if maximumSources == 0 {
				continue
			}
			for start := 0; start < len(record.sources); start += maximumSources {
				end := start + maximumSources
				if end > len(record.sources) {
					end = len(record.sources)
				}
				part := record
				part.sources = record.sources[start:end]
				reports = append(reports, []multicastReportRecord{part})
			}
			continue
		}
		size := recordHeader + addressSize*len(record.sources)
		if currentSize+size > maximum {
			flush()
		}
		current = append(current, record)
		currentSize += size
	}
	flush()
	return reports
}

func (s *multicastState) sendIGMPPacket(target netip.Addr, payload []byte, routerAlert bool, cancel <-chan struct{}) {
	select {
	case <-cancel:
		return
	default:
	}
	source, ok := s.reportSource(false)
	if !ok {
		return
	}
	headerSize := 20
	packetValue := IPPacket{
		Source: source, Destination: target, Protocol: ProtocolIGMP,
		HopLimit: 1, TrafficClass: 0xc0, Identification: uint16(s.stack.ipv4ID.Add(1)),
		DontFragment: true, Payload: payload,
	}
	var routerAlertOption [4]byte
	if routerAlert {
		headerSize = 24
		routerAlertOption = [4]byte{IPv4HeaderOptionRouterAlert, 4, 0, 0}
		packetValue.IPv4Options = routerAlertOption[:]
	}
	packet := make([]byte, headerSize+len(payload))
	marshalPublicIPPacket(packet, packetValue, headerSize, true)
	select {
	case <-cancel:
		return
	default:
	}
	_ = s.stack.tryWritePacket(packet, true)
}

func (s *multicastState) sendMLDPacket(target netip.Addr, payload []byte, cancel <-chan struct{}) {
	select {
	case <-cancel:
		return
	default:
	}
	source, ok := s.reportSource(true)
	if !ok || len(payload) < 4 {
		return
	}
	packet := make([]byte, 48+len(payload))
	marshalPublicIPv6BaseHeader(packet, IPPacket{Source: source, Destination: target, HopLimit: 1}, IPv6ExtensionHeaderHopByHop, 8+len(payload))
	copy(packet[40:48], []byte{ProtocolICMPv6, 0, IPv6ExtensionOptionRouterAlert, 2, 0, 0, IPv6ExtensionOptionPadN, 0})
	marshalPublicICMPMessage(packet[48:], ICMPMessage{
		Source: source, Destination: target, Type: payload[0], Code: payload[1], Body: payload[4:],
	})
	select {
	case <-cancel:
		return
	default:
	}
	_ = s.stack.tryWritePacket(packet, true)
}

func (s *multicastState) reportSource(v6 bool) (netip.Addr, bool) {
	network := s.stack.network.Load()
	if !v6 {
		for _, source := range network.sources {
			if source.Is4() && !source.IsLoopback() {
				return source, true
			}
		}
		return netip.Addr{}, false
	}
	for _, source := range network.sources {
		if source.Is6() && source.IsLinkLocalUnicast() {
			return source, true
		}
	}
	if networkStateHasFamily(network, true) {
		return netip.IPv6Unspecified(), true
	}
	return netip.Addr{}, false
}

func (s *multicastState) advanceRetransmissionLocked(pending *multicastRetransmission) ([]multicastReportRecord, bool) {
	if pending.modeRemaining != 0 {
		recordType := byte(multicastRecordChangeToIncludeMode)
		if pending.filter.mode == multicastFilterExclude {
			recordType = multicastRecordChangeToExcludeMode
		}
		pending.modeRemaining--
		record := multicastReportRecord{recordType: recordType, sources: sortedMulticastSources(pending.filter.sources)}
		return []multicastReportRecord{record}, pending.modeRemaining != 0 || len(pending.allow) != 0 || len(pending.block) != 0
	}
	var records []multicastReportRecord
	if len(pending.allow) != 0 {
		records = append(records, multicastReportRecord{recordType: multicastRecordAllowNewSources, sources: advanceMulticastSourceCounters(pending.allow)})
	}
	if len(pending.block) != 0 {
		records = append(records, multicastReportRecord{recordType: multicastRecordBlockOldSources, sources: advanceMulticastSourceCounters(pending.block)})
	}
	return records, len(pending.allow) != 0 || len(pending.block) != 0
}

func advanceMulticastSourceCounters(counters map[netip.Addr]uint8) []netip.Addr {
	result := make([]netip.Addr, 0, len(counters))
	for source, remaining := range counters {
		result = append(result, source)
		if remaining <= 1 {
			delete(counters, source)
		} else {
			counters[source] = remaining - 1
		}
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Compare(result[right]) < 0 })
	return result
}

func multicastCurrentStateRecord(group netip.Addr, filter multicastFilter, sourceQuery bool, queried map[netip.Addr]struct{}) multicastReportRecord {
	recordType := byte(multicastRecordModeIsInclude)
	if !sourceQuery && filter.mode == multicastFilterExclude {
		recordType = multicastRecordModeIsExclude
	}
	var sources []netip.Addr
	if sourceQuery {
		for source := range queried {
			_, listed := filter.sources[source]
			if filter.mode == multicastFilterInclude && listed || filter.mode == multicastFilterExclude && !listed {
				sources = append(sources, source)
			}
		}
		sort.Slice(sources, func(left, right int) bool { return sources[left].Compare(sources[right]) < 0 })
	} else {
		sources = sortedMulticastSources(filter.sources)
	}
	return multicastReportRecord{recordType: recordType, group: group, sources: sources}
}

func sortedMulticastSources(sources map[netip.Addr]struct{}) []netip.Addr {
	result := make([]netip.Addr, 0, len(sources))
	for source := range sources {
		result = append(result, source)
	}
	sort.Slice(result, func(left, right int) bool { return result[left].Compare(result[right]) < 0 })
	return result
}

func (s *multicastState) legacyVersionLocked(v6 bool) uint8 {
	index, latest := 0, uint8(3)
	if v6 {
		index, latest = 1, 2
	}
	if s.compatibility[index] == latest {
		return 0
	}
	return s.compatibility[index]
}

func (s *multicastState) updateConfig(network *networkState) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.removeInvalidSourcesLocked(network)
	now := time.Now()
	for index := range s.generalQuery {
		if s.familyGroups[index] != 0 && networkStateHasFamily(network, index == 1) {
			s.generalQuery[index] = now
		}
	}
	s.wakeLocked()
	s.mu.Unlock()
}

func (s *multicastState) removeInvalidSourcesLocked(network *networkState) {
	indexChanged := false
	for group, groupState := range s.groups {
		old, oldExists := multicastInterfaceFilter(groupState)
		oldLastReporter := groupState.lastReporter
		changed := false
		for endpoint, filter := range groupState.members {
			var updated *multicastFilter
			for source := range filter.sources {
				if validMulticastSourceAddress(network, source, group.Is6()) {
					continue
				}
				if updated == nil {
					copied := cloneMulticastFilter(*filter)
					updated = &copied
				}
				delete(updated.sources, source)
			}
			if updated == nil {
				continue
			}
			changed = true
			if updated.mode == multicastFilterInclude && len(updated.sources) == 0 {
				delete(groupState.members, endpoint)
			} else {
				groupState.members[endpoint] = updated
			}
		}
		if !changed {
			continue
		}
		removed := len(groupState.members) == 0
		if removed {
			s.removeGroupLocked(group)
			indexChanged = true
		} else {
			groupState.aggregate = aggregateMulticastFilter(groupState.members)
		}
		s.interfaceStateChangedLocked(group, old, oldExists, oldLastReporter)
		if !removed {
			s.rebuildGroupDispatchLocked(group)
		}
	}
	if indexChanged {
		s.rebuildDispatchIndexLocked()
	}
}

func (s *multicastState) close() {
	s.closeOnce.Do(func() {
		close(s.done)
		s.mu.Lock()
		s.closed = true
		for index, cancel := range s.reportCancel {
			if cancel != nil {
				close(cancel)
				s.reportCancel[index] = nil
			}
		}
		for _, group := range s.groups {
			group.dispatch.Store(nil)
		}
		s.groups = nil
		s.retransmissions = nil
		s.dispatch.Store(nil)
		s.familyGroups = [2]int{}
		s.generalQuery = [2]time.Time{}
		s.mu.Unlock()
	})
}

func (state *ipEndpointState) contains(connection *IPConn) bool {
	for candidate := range state.bindings[ipKey{address: connection.local, protocol: connection.protocol}] {
		if candidate == connection {
			return true
		}
	}
	return false
}
