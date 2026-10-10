package mipstack

import (
	"crypto/rand"
	"encoding/binary"
	"net/netip"
)

type reuseTCPListenerBinding struct {
	reuseAddress bool
}

type tcpReuseRegistry struct {
	key    [16]byte
	groups map[tcpListenKey][]*TCPListener
}

type udpReuseRegistry struct {
	key    [16]byte
	groups map[udpKey][]*UDPConn
	all    []*UDPConn
}

func (reuseTCPListenerBinding) available(state *tcpPassiveState, address netip.Addr, port uint16, dual bool) bool {
	for key, listener := range state.exclusive {
		if key.port == port && listenAddressesOverlap(key.address, listener.dual, address, dual) {
			return false
		}
	}
	if registry, ok := state.reuse.(*tcpReuseRegistry); ok {
		group := registry.groups[tcpListenKey{address: address, port: port}]
		if len(group) != 0 && group[0].dual != dual {
			return false
		}
	}
	return true
}

func (binding reuseTCPListenerBinding) register(state *tcpPassiveState, listener *TCPListener) error {
	registry, ok := state.reuse.(*tcpReuseRegistry)
	if !ok {
		registry = &tcpReuseRegistry{groups: make(map[tcpListenKey][]*TCPListener)}
		if _, err := rand.Read(registry.key[:]); err != nil {
			return err
		}
		state.reuse = registry
	}
	listener.reuseAddress = binding.reuseAddress
	listener.reusePort = true
	registry.add(listener)
	return nil
}

func (binding reuseTCPListenerBinding) connectionReusable(connection *TCPConn) bool {
	return binding.reuseAddress && connection.reuseAddress || connection.reusePort
}

func (registry *tcpReuseRegistry) empty() bool { return len(registry.groups) == 0 }

func (registry *tcpReuseRegistry) listeners() []*TCPListener {
	var listeners []*TCPListener
	for _, group := range registry.groups {
		listeners = append(listeners, group...)
	}
	return listeners
}

func (registry *tcpReuseRegistry) overlaps(address netip.Addr, port uint16, dual bool) bool {
	for key, group := range registry.groups {
		if key.port == port && len(group) != 0 && listenAddressesOverlap(key.address, group[0].dual, address, dual) {
			return true
		}
	}
	return false
}

func (registry *tcpReuseRegistry) listener(binding, local, remote netip.AddrPort) *TCPListener {
	group := registry.groups[tcpListenKey{address: binding.Addr(), port: binding.Port()}]
	if len(group) == 0 {
		return nil
	}
	return group[reuseFlowIndex(registry.key, local, remote, len(group))]
}

func (registry *tcpReuseRegistry) add(listener *TCPListener) {
	registry.groups[listener.key] = append(registry.groups[listener.key], listener)
}

func (registry *tcpReuseRegistry) remove(listener *TCPListener) bool {
	group := registry.groups[listener.key]
	for index, candidate := range group {
		if candidate != listener {
			continue
		}
		last := len(group) - 1
		group[index] = group[last]
		group[last] = nil
		if last == 0 {
			delete(registry.groups, listener.key)
		} else {
			registry.groups[listener.key] = group[:last]
		}
		return true
	}
	return false
}

type reuseUDPSocketBinding struct {
	reuseAddress bool
}

func (binding reuseUDPSocketBinding) available(stack *Stack, address netip.Addr, port uint16, dual bool) bool {
	return reusableUDPBindingAvailable(stack, address, port, dual, binding.reuseAddress, true)
}

func (binding reuseUDPSocketBinding) register(stack *Stack, connection *UDPConn) error {
	connection.reuseAddress = binding.reuseAddress
	connection.reusePort = true
	return registerReusableUDP(stack, connection)
}

func registerReusableUDP(stack *Stack, connection *UDPConn) error {
	registry, ok := stack.udpReuse.(*udpReuseRegistry)
	if !ok {
		registry = &udpReuseRegistry{groups: make(map[udpKey][]*UDPConn)}
		if _, err := rand.Read(registry.key[:]); err != nil {
			return err
		}
		stack.udpReuse = registry
	}
	registry.add(connection)
	return nil
}

func reusableUDPBindingAvailable(stack *Stack, address netip.Addr, port uint16, dual, reuseAddress, reusePort bool) bool {
	registry, ok := stack.udpReuse.(*udpReuseRegistry)
	if !ok {
		return true
	}
	for _, connection := range registry.all {
		if connection.port != port || !listenAddressesOverlap(connection.local, connection.dual, address, dual) {
			continue
		}
		if connection.local == address && connection.dual != dual {
			return false
		}
		if !(reuseAddress && connection.reuseAddress || reusePort && connection.reusePort) {
			return false
		}
	}
	return true
}

func (registry *udpReuseRegistry) empty() bool { return len(registry.groups) == 0 }

func (registry *udpReuseRegistry) connections() []*UDPConn { return registry.all }

func (registry *udpReuseRegistry) contains(connection *UDPConn) bool {
	key := udpKey{address: connection.local, port: connection.port}
	for _, candidate := range registry.groups[key] {
		if candidate == connection {
			return true
		}
	}
	return false
}

func (registry *udpReuseRegistry) overlaps(address netip.Addr, port uint16, dual bool) bool {
	for key, group := range registry.groups {
		if key.port == port && len(group) != 0 && listenAddressesOverlap(key.address, group[0].dual, address, dual) {
			return true
		}
	}
	return false
}

func (registry *udpReuseRegistry) connection(binding, local, remote netip.AddrPort) *UDPConn {
	group := registry.groups[udpKey{address: binding.Addr(), port: binding.Port()}]
	if len(group) == 0 {
		return nil
	}
	for _, connection := range group {
		if !connection.reusePort {
			return group[len(group)-1]
		}
	}
	return group[reuseFlowIndex(registry.key, local, remote, len(group))]
}

func (registry *udpReuseRegistry) add(connection *UDPConn) {
	key := udpKey{address: connection.local, port: connection.port}
	registry.groups[key] = append(registry.groups[key], connection)
	registry.all = append(registry.all, connection)
}

func (registry *udpReuseRegistry) remove(connection *UDPConn) bool {
	key := udpKey{address: connection.local, port: connection.port}
	group := registry.groups[key]
	for index, candidate := range group {
		if candidate != connection {
			continue
		}
		last := len(group) - 1
		copy(group[index:], group[index+1:])
		group[last] = nil
		if last == 0 {
			delete(registry.groups, key)
		} else {
			registry.groups[key] = group[:last]
		}
		for flatIndex, flatConnection := range registry.all {
			if flatConnection != connection {
				continue
			}
			flatLast := len(registry.all) - 1
			registry.all[flatIndex] = registry.all[flatLast]
			registry.all[flatLast] = nil
			registry.all = registry.all[:flatLast]
			break
		}
		return true
	}
	return false
}

func reuseFlowIndex(key [16]byte, local, remote netip.AddrPort, count int) int {
	var input [38]byte
	encodeReuseAddress(input[0:17], local.Addr())
	encodeReuseAddress(input[17:34], remote.Addr())
	binary.BigEndian.PutUint16(input[34:36], local.Port())
	binary.BigEndian.PutUint16(input[36:38], remote.Port())
	return int(sipHash24(key, input[:]) % uint64(count))
}

func encodeReuseAddress(output []byte, address netip.Addr) {
	if !address.IsValid() {
		return
	}
	if address.Is4() {
		value := address.As4()
		output[0] = 4
		copy(output[1:5], value[:])
		return
	}
	value := address.As16()
	output[0] = 6
	copy(output[1:17], value[:])
}
