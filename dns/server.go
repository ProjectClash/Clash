package dns

import (
	"context"
	"io"
	"net"
	"sync"

	"github.com/ProjectClash/Clash/common/sockopt"
	"github.com/ProjectClash/Clash/component/resolver"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/log"

	D "github.com/miekg/dns"
)

var (
	address string
	server  = &Server{}

	dnsDefaultTTL uint32 = 600
)

type Server struct {
	service resolver.Service

	mu        sync.Mutex
	shutdown  bool
	tcpServer *D.Server
	udpServer *D.Server
	conns []io.Closer
	udpCompanions []*D.Server
}

func (s *Server) register(conn io.Closer, set func()) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.shutdown {
		_ = conn.Close()
		return false
	}
	s.conns = append(s.conns, conn)
	set()
	return true
}

func (s *Server) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.shutdown = true
	for _, started := range append([]*D.Server{s.tcpServer, s.udpServer}, s.udpCompanions...) {
		if started != nil {
			_ = started.Shutdown()
		}
	}
	for _, conn := range s.conns {
		_ = conn.Close()
	}
	s.tcpServer, s.udpServer, s.udpCompanions, s.conns = nil, nil, nil, nil
}

type loopbackPacketCompanions interface {
	LoopbackPacketCompanions(ctx context.Context, network, address string, primary net.PacketConn) ([]net.PacketConn, error)
}

type serverHandler struct {
	*Server
	isUDP bool
}

// ServeDNS implement D.Handler ServeDNS
func (s serverHandler) ServeDNS(w D.ResponseWriter, r *D.Msg) {
	msg, err := s.service.ServeMsg(context.Background(), r)
	if err != nil {
		m := new(D.Msg)
		m.SetRcode(r, D.RcodeServerFailure)
		// does not matter if this write fails
		w.WriteMsg(m)
		return
	}
	if s.isUDP {
		// RFC 6891: fit the reply into the client's advertised buffer size,
		// setting the TC bit if records must be dropped; 512 when no OPT present
		msg.Truncate(resolver.RequestUDPSize(r))
	}
	msg.Compress = true
	w.WriteMsg(msg)
}

func (s *Server) UDPHandler() D.Handler {
	return serverHandler{Server: s, isUDP: true}
}

func (s *Server) TCPHandler() D.Handler {
	return serverHandler{Server: s, isUDP: false}
}

func (s *Server) SetService(service resolver.Service) {
	s.service = service
}

func ReCreateServer(addr string, lc C.InboundListenConfig, service resolver.Service) {
	if addr == address && service != nil {
		server.SetService(service)
		return
	}

	server.close()

	server.service = nil
	address = ""

	if addr == "" || lc == nil || service == nil {
		return
	}

	var err error
	defer func() {
		if err != nil {
			log.Errorln("Start DNS server error: %s", err.Error())
		}
	}()

	_, port, err := net.SplitHostPort(addr)
	if port == "0" || port == "" || err != nil {
		return
	}

	address = addr
	server = &Server{service: service}
	srv := server

	go func() {
		p, err := lc.ListenPacket(context.Background(), "udp", addr)
		if err != nil {
			log.Errorln("Start DNS server(UDP) error: %s", err.Error())
			return
		}

		if err := sockopt.UDPReuseaddr(p); err != nil {
			log.Warnln("Failed to Reuse UDP Address: %s", err)
		}

		log.Infoln("DNS server(UDP) listening at: %s", p.LocalAddr().String())
		if offer, ok := lc.(loopbackPacketCompanions); ok {
			companions, err := offer.LoopbackPacketCompanions(context.Background(), "udp", addr, p)
			if err != nil {
				log.Errorln("DNS server(UDP) loopback companion for %s: %s", addr, err.Error())
			}
			for _, companion := range companions {
				companionServer := &D.Server{Addr: companion.LocalAddr().String(), PacketConn: companion, Handler: srv.UDPHandler()}
				if !srv.register(companion, func() { srv.udpCompanions = append(srv.udpCompanions, companionServer) }) {
					continue
				}
				log.Infoln("DNS server(UDP) also listening at: %s", companion.LocalAddr().String())
				go func() { _ = companionServer.ActivateAndServe() }()
			}
		}
		udpServer := &D.Server{Addr: addr, PacketConn: p, Handler: srv.UDPHandler()}
		if !srv.register(p, func() { srv.udpServer = udpServer }) {
			return
		}
		_ = udpServer.ActivateAndServe()
	}()

	go func() {
		l, err := lc.Listen(context.Background(), "tcp", addr)
		if err != nil {
			log.Errorln("Start DNS server(TCP) error: %s", err.Error())
			return
		}

		log.Infoln("DNS server(TCP) listening at: %s", l.Addr().String())
		tcpServer := &D.Server{Addr: addr, Listener: l, Handler: srv.TCPHandler()}
		if !srv.register(l, func() { srv.tcpServer = tcpServer }) {
			return
		}
		_ = tcpServer.ActivateAndServe()
	}()

}
