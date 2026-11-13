package socks5

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	apicommon "github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/apis/constant"
	"github.com/enfein/mieru/v3/apis/model"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/common"
	"github.com/enfein/mieru/v3/pkg/log"
	"github.com/enfein/mieru/v3/pkg/stderror"
)

const forwardingWriteTimeout = time.Minute

func (s *Server) handleRequest(ctx context.Context, req *model.Request, proxyConn net.Conn) error {
	dst := &req.DstAddr
	if dst.FQDN != "" {
		ips, err := s.config.Resolver.LookupIP(ctx, "ip", dst.FQDN)
		if err != nil || len(ips) == 0 {
			DNSResolveErrors.Add(1)
			if err := model.WriteSocks5Response(proxyConn, constant.Socks5ReplyHostUnreachable, zeroBindAddr()); err != nil {
				return fmt.Errorf("failed to send reply: %w", err)
			}
			if err != nil {
				return fmt.Errorf("failed to resolve destination %q: %w", dst.FQDN, err)
			}
			return fmt.Errorf(stderror.IPAddressNotFound, dst.FQDN)
		}

		dst.IP = common.SelectIPFromList(ips, s.config.DualStackPreference)
		if dst.IP == nil {
			DNSResolveErrors.Add(1)
			if err := model.WriteSocks5Response(proxyConn, constant.Socks5ReplyNetworkUnreachable, zeroBindAddr()); err != nil {
				return fmt.Errorf("failed to send reply: %w", err)
			}
			return fmt.Errorf("resolved domain name %s to IP addresses %v, but no IP address satisfy DNS dual stack preference", dst.FQDN, ips)
		}
		log.Debugf("Resolved domain name %s to IP addresses %v, selected IP address %v", dst.FQDN, ips, dst.IP)
	}

	switch req.Command {
	case constant.Socks5ConnectCmd:
		return s.handleConnect(ctx, req, proxyConn)
	case constant.Socks5BindCmd:
		return s.handleBind(ctx, req, proxyConn)
	case constant.Socks5UDPAssociateCmd:
		return s.handleAssociate(ctx, req, proxyConn)
	default:
		UnsupportedCommandErrors.Add(1)
		if err := model.WriteSocks5Response(proxyConn, constant.Socks5ReplyCommandNotSupported, zeroBindAddr()); err != nil {
			return fmt.Errorf("failed to send reply: %w", err)
		}
		return fmt.Errorf("unsupported command: %v", req.Command)
	}
}

func (s *Server) readRequest(conn io.Reader) (*model.Request, error) {
	if netConn, ok := conn.(net.Conn); ok {
		common.SetReadTimeout(netConn, s.config.HandshakeTimeout)
		defer common.SetReadTimeout(netConn, 0)
	}

	req := &model.Request{}
	if err := req.ReadFromSocks5(conn); err != nil {
		return nil, err
	}
	return req, nil
}

func (s *Server) handleConnect(ctx context.Context, req *model.Request, proxyConn net.Conn) error {
	var d net.Dialer
	target, err := d.DialContext(ctx, "tcp", req.DstAddr.String())
	if err != nil {
		msg := err.Error()
		var replyCode uint8
		if strings.Contains(msg, "refused") {
			replyCode = constant.Socks5ReplyConnectionRefused
			ConnectionRefusedErrors.Add(1)
		} else if strings.Contains(msg, "network is unreachable") {
			replyCode = constant.Socks5ReplyNetworkUnreachable
			NetworkUnreachableErrors.Add(1)
		} else {
			replyCode = constant.Socks5ReplyHostUnreachable
			HostUnreachableErrors.Add(1)
		}
		if err := model.WriteSocks5Response(proxyConn, replyCode, zeroBindAddr()); err != nil {
			return fmt.Errorf("failed to send reply: %w", err)
		}
		return fmt.Errorf("connect to %v failed: %w", req.DstAddr, err)
	}
	defer target.Close()

	local := target.LocalAddr().(*net.TCPAddr)
	bind := model.AddrSpec{IP: local.IP, Port: local.Port}
	if err := model.WriteSocks5Response(proxyConn, constant.Socks5ReplySuccess, bind); err != nil {
		HandshakeErrors.Add(1)
		return fmt.Errorf("failed to send reply: %w", err)
	}

	return common.BidiCopy(proxyConn, target)
}

func (s *Server) handleBind(_ context.Context, _ *model.Request, proxyConn net.Conn) error {
	UnsupportedCommandErrors.Add(1)
	if err := model.WriteSocks5Response(proxyConn, constant.Socks5ReplyCommandNotSupported, zeroBindAddr()); err != nil {
		HandshakeErrors.Add(1)
		return fmt.Errorf("failed to send reply: %w", err)
	}
	return nil
}

func (s *Server) handleAssociate(ctx context.Context, req *model.Request, proxyConn net.Conn) error {
	if s.config.UDPAssociateMode == UDPAssociateModeDatagram {
		return s.handleAssociateDatagram(ctx, req, proxyConn)
	}
	return s.handleAssociatePacketOverStream(ctx, req, proxyConn)
}

func (s *Server) handleAssociatePacketOverStream(_ context.Context, _ *model.Request, proxyConn net.Conn) error {
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		UDPAssociateErrors.Add(1)
		return fmt.Errorf("failed to listen UDP: %w", err)
	}

	udpPort, err := localUDPPort(udpConn)
	if err != nil {
		UDPAssociateErrors.Add(1)
		return err
	}
	bind := model.AddrSpec{IP: net.IP{0, 0, 0, 0}, Port: udpPort}
	if err := model.WriteSocks5Response(proxyConn, constant.Socks5ReplySuccess, bind); err != nil {
		HandshakeErrors.Add(1)
		return fmt.Errorf("failed to send reply: %w", err)
	}

	return RunUDPAssociateLoop(udpConn, apicommon.NewPacketOverStreamTunnel(proxyConn), s.config.Resolver)
}

func (s *Server) handleAssociateDatagram(_ context.Context, _ *model.Request, proxyConn net.Conn) error {
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		UDPAssociateErrors.Add(1)
		return fmt.Errorf("failed to listen UDP: %w", err)
	}

	local, ok := udpConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		udpConn.Close()
		UDPAssociateErrors.Add(1)
		return fmt.Errorf("UDP listener local address has unexpected type %T", udpConn.LocalAddr())
	}
	bind := model.AddrSpec{IP: socks5UDPAssociateBindIP(proxyConn, local), Port: local.Port}
	if err := model.WriteSocks5Response(proxyConn, constant.Socks5ReplySuccess, bind); err != nil {
		udpConn.Close()
		HandshakeErrors.Add(1)
		return fmt.Errorf("failed to send reply: %w", err)
	}

	return runUDPAssociateDatagramLoop(udpConn, proxyConn, s.config.Resolver)
}

func (s *Server) handleForwarding(req *model.Request, proxyConn net.Conn, proxy *appctlpb.EgressProxy) error {
	forwardHost := proxy.GetHost()
	forwardPort := proxy.GetPort()
	egressConn, err := net.Dial("tcp", common.MaybeDecorateIPv6(forwardHost)+":"+strconv.Itoa(int(forwardPort)))
	if err != nil {
		HandshakeErrors.Add(1)
		return fmt.Errorf("dial to egress proxy failed: %w", err)
	}

	auth := proxy.GetSocks5Authentication()
	var credential *Credential
	if auth != nil && auth.GetUser() != "" && auth.GetPassword() != "" {
		credential = &Credential{
			User:     auth.GetUser(),
			Password: auth.GetPassword(),
		}
	}
	common.SetReadTimeout(egressConn, s.config.HandshakeTimeout)
	err = clientNegotiateAuthentication(egressConn, credential)
	common.SetReadTimeout(egressConn, 0)
	if err != nil {
		HandshakeErrors.Add(1)
		egressConn.Close()
		return fmt.Errorf("socks5 authentication with egress proxy failed: %w", err)
	}

	switch req.Command {
	case constant.Socks5ConnectCmd:
		if _, err := egressConn.Write(req.Raw); err != nil {
			HandshakeErrors.Add(1)
			egressConn.Close()
			return fmt.Errorf("failed to write socks5 request to egress proxy: %w", err)
		}
		return common.BidiCopy(proxyConn, common.NewWriteTimeoutConn(egressConn, forwardingWriteTimeout))
	case constant.Socks5UDPAssociateCmd:
		return s.handleForwardingUDP(req, proxyConn, egressConn)
	default:
		return fmt.Errorf("unsupported command: %v", req.Command)
	}
}

func (s *Server) handleForwardingUDP(req *model.Request, proxyConn, egressConn net.Conn) error {
	downstreamReq := &model.Request{
		Command: constant.Socks5UDPAssociateCmd,
		DstAddr: model.AddrSpec{IP: net.IPv4zero, Port: 0},
	}
	if err := downstreamReq.WriteToSocks5(egressConn); err != nil {
		HandshakeErrors.Add(1)
		egressConn.Close()
		return fmt.Errorf("failed to write socks5 request to egress proxy: %w", err)
	}

	resp, err := model.ReadSocks5Response(egressConn)
	if err != nil {
		HandshakeErrors.Add(1)
		egressConn.Close()
		return fmt.Errorf("failed to read socks5 response from egress proxy: %w", err)
	}

	if resp.Reply != constant.Socks5ReplySuccess {
		HandshakeErrors.Add(1)
		egressConn.Close()
		proxyConn.Write(resp.Raw)
		return fmt.Errorf("egress proxy returned error: %d", resp.Reply)
	}

	downstreamUDPAddr, err := socks5UDPAddrFromResponse(egressConn, resp)
	if err != nil {
		HandshakeErrors.Add(1)
		egressConn.Close()
		return err
	}

	udpConn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		UDPAssociateErrors.Add(1)
		egressConn.Close()
		return fmt.Errorf("failed to listen UDP: %w", err)
	}

	udpPort, err := localUDPPort(udpConn)
	if err != nil {
		UDPAssociateErrors.Add(1)
		udpConn.Close()
		egressConn.Close()
		return err
	}
	if err := rewriteSocks5ResponseBindPort(resp, udpPort); err != nil {
		UDPAssociateErrors.Add(1)
		udpConn.Close()
		egressConn.Close()
		return err
	}

	if _, err := proxyConn.Write(resp.Raw); err != nil {
		UDPAssociateErrors.Add(1)
		udpConn.Close()
		egressConn.Close()
		return fmt.Errorf("failed to send socks5 response to client: %w", err)
	}

	clientTunnel := apicommon.NewPacketOverStreamTunnel(proxyConn)
	return RunUDPForwardingLoop(udpConn, clientTunnel, downstreamUDPAddr, egressConn)
}

func (s *Server) proxySocks5AuthReq(userConn, proxyConn net.Conn) error {
	defer common.SetReadTimeout(userConn, 0)
	defer common.SetReadTimeout(proxyConn, 0)
	common.SetReadTimeout(userConn, s.config.HandshakeTimeout)
	version := []byte{0}
	if _, err := io.ReadFull(userConn, version); err != nil {
		return fmt.Errorf("failed to get version byte: %w", err)
	}
	if version[0] != constant.Socks5Version {
		return fmt.Errorf("unsupported SOCKS version: %v", version)
	}
	nMethods := []byte{0}
	if _, err := io.ReadFull(userConn, nMethods); err != nil {
		return fmt.Errorf("failed to get the length of authentication methods: %w", err)
	}
	methods := make([]byte, int(nMethods[0]))
	if _, err := io.ReadFull(userConn, methods); err != nil {
		return fmt.Errorf("failed to get authentication methods: %w", err)
	}
	authReq := []byte{}
	authReq = append(authReq, version...)
	authReq = append(authReq, nMethods...)
	authReq = append(authReq, methods...)
	if _, err := proxyConn.Write(authReq); err != nil {
		return fmt.Errorf("failed to write authentication request to the server: %w", err)
	}

	common.SetReadTimeout(proxyConn, s.config.HandshakeTimeout)
	authResp := make([]byte, 2)
	if _, err := io.ReadFull(proxyConn, authResp); err != nil {
		return fmt.Errorf("failed to read authentication response from the socks5 server: %w", err)
	}
	if _, err := userConn.Write(authResp); err != nil {
		return fmt.Errorf("failed to write authentication response to the socks5 client: %w", err)
	}

	return nil
}

func (s *Server) proxySocks5ConnReq(userConn, proxyConn net.Conn) (*net.UDPConn, []byte, error) {
	defer common.SetReadTimeout(userConn, 0)
	defer common.SetReadTimeout(proxyConn, 0)
	common.SetReadTimeout(userConn, s.config.HandshakeTimeout)

	req, err := model.ReadSocks5Request(userConn)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get socks5 connection request: %w", err)
	}
	cmd := req.Command
	connReq := req.Raw

	if s.config.HandshakeNoWait && cmd == constant.Socks5ConnectCmd {
		var resp bytes.Buffer
		serverBoundAddr := model.NetAddrSpec{}
		if err := serverBoundAddr.From(proxyConn.RemoteAddr()); err != nil {
			return nil, nil, fmt.Errorf("failed to get proxy connection address: %w", err)
		}
		resp.Write([]byte{constant.Socks5Version, constant.Socks5ReplySuccess, 0})
		if err := serverBoundAddr.WriteToSocks5(&resp); err != nil {
			return nil, nil, fmt.Errorf("failed to write proxy connection address: %w", err)
		}

		if _, err := userConn.Write(resp.Bytes()); err != nil {
			return nil, nil, fmt.Errorf("failed to write fake connection response to the socks5 client: %w", err)
		}
		return nil, connReq, nil
	}

	if _, err := proxyConn.Write(connReq); err != nil {
		return nil, nil, fmt.Errorf("failed to write connection request to the server: %w", err)
	}
	log.Debugf("Sent socks5 request %v to server", connReq)

	common.SetReadTimeout(proxyConn, s.config.HandshakeTimeout)
	connResp, err := model.ReadSocks5Response(proxyConn)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read connection response from the server: %w", err)
	}
	log.Debugf("Received socks5 response %v from server", connResp.Raw)

	var udpConn *net.UDPConn
	if cmd == constant.Socks5UDPAssociateCmd {
		udpConn, err = net.ListenUDP("udp4", nil)
		if err != nil {
			return nil, nil, fmt.Errorf("net.ListenUDP() failed: %w", err)
		}
		udpPort, err := localUDPPort(udpConn)
		if err != nil {
			udpConn.Close()
			return nil, nil, err
		}
		if err := rewriteSocks5ResponseBindPort(connResp, udpPort); err != nil {
			udpConn.Close()
			return nil, nil, err
		}
	}

	if _, err := userConn.Write(connResp.Raw); err != nil {
		if udpConn != nil {
			udpConn.Close()
		}
		return nil, nil, fmt.Errorf("failed to write connection response to the socks5 client: %w", err)
	}
	return udpConn, nil, nil
}

func socks5UDPAssociateBindIP(conn net.Conn, udpLocal *net.UDPAddr) net.IP {
	if tcpAddr, ok := conn.LocalAddr().(*net.TCPAddr); ok && tcpAddr.IP != nil && !tcpAddr.IP.IsUnspecified() {
		return tcpAddr.IP
	}
	if udpLocal != nil && udpLocal.IP != nil && !udpLocal.IP.IsUnspecified() {
		return udpLocal.IP
	}
	return net.IPv4(0, 0, 0, 0)
}

func zeroBindAddr() model.AddrSpec {
	return model.AddrSpec{IP: net.IPv4(0, 0, 0, 0)}
}
