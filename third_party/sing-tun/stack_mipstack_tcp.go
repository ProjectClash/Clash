package tun

import (
	mips "github.com/metacubex/mipstack"
	M "github.com/metacubex/sing/common/metadata"
	N "github.com/metacubex/sing/common/network"
)

func (s *Mipstack) forwardTCP(request *mips.TCPForwarderRequest) {
	flow := request.Flow()
	source := M.SocksaddrFromNetIP(flow.Source)
	destination := M.SocksaddrFromNetIP(flow.Destination)
	if _, err := s.handler.PrepareConnection(N.NetworkTCP, source, destination, nil, 0); err != nil {
		_ = request.Reject()
		return
	}
	metadata := M.Metadata{Source: source, Destination: destination}
	if s.forwardTCPDeferred(request, source, destination, metadata) {
		return
	}
	conn, err := request.Accept(s.ctx)
	if err != nil {
		return
	}
	go func() {
		if err := s.handler.NewConnection(s.ctx, conn, metadata); err != nil {
			_ = conn.SetLinger(0)
			_ = conn.Close()
		}
	}()
}

func (s *Mipstack) forwardTCPDeferred(request *mips.TCPForwarderRequest, source, destination M.Socksaddr, metadata M.Metadata) bool {
	deferrer, ok := s.handler.(DeferredHandshakeHandler)
	if !ok || !deferrer.DeferHandshake(N.NetworkTCP, source, destination) {
		return false
	}
	if !s.deferred.enter() {
		return false
	}
	defer s.deferred.leave()
	if !acquireDeferredHandshake() {
		noteDeferredBudgetSpent(s.ctx, s.handler)
		return false
	}
	defer releaseDeferredHandshake()
	conn := newMipsLazyConn(s.ctx, request, s.deferred.done(), destination.TCPAddr(), source.TCPAddr())
	go func() {
		if err := s.handler.NewConnection(s.ctx, conn, metadata); err != nil {
			_ = conn.SetLinger(0)
			_ = conn.Close()
		}
	}()
	conn.waitForVerdict(s.deferred.done())
	return true
}
