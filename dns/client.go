package dns

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ProjectClash/Clash/component/dialer"
	"github.com/ProjectClash/Clash/component/resolver"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/log"

	D "github.com/miekg/dns"
)

type client struct {
	port   string
	host   string
	dialer *dnsDialer
	schema string
}

var _ dnsClient = (*client)(nil)

// Address implements dnsClient
func (c *client) Address() string {
	return fmt.Sprintf("%s://%s", c.schema, net.JoinHostPort(c.host, c.port))
}

func (c *client) ExchangeContext(ctx context.Context, m *D.Msg) (msg *D.Msg, err error) {
	network := "udp"
	if c.schema != "udp" {
		network = "tcp"
	}

	addr := net.JoinHostPort(c.host, c.port)
	conn, err := c.dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	question := newResolverQuestion(addr, network == "udp" && isPhysicalUDP(conn))
	defer func() { question.ended(msg, err) }()

	// miekg/dns ExchangeContext doesn't respond to context cancel.
	// this is a workaround
	type result struct {
		msg *D.Msg
		err error
	}
	ch := make(chan result, 1)
	go func() {
		dClient := &D.Client{
			UDPSize: 4096,
			Timeout: 5 * time.Second,
		}
		dConn := &D.Conn{
			Conn:    conn,
			UDPSize: dClient.UDPSize,
		}

		var msg *D.Msg
		var err error
		if network == "udp" {
			msg, err = exchangeOverUDP(ctx, dConn, m)
			question.answered(msg)
		} else {
			msg, _, err = dClient.ExchangeWithConn(m, dConn)
		}

		// Resolvers MUST resend queries over TCP if they receive a truncated UDP response (with TC=1 set)!
		if msg != nil && msg.Truncated && network == "udp" {
			network = "tcp"
			log.Debugln("[DNS] Truncated reply from %s:%s for %s over UDP, retrying over TCP", c.host, c.port, m.Question[0].String())
			var tcpConn net.Conn
			tcpConn, err = c.dialer.DialContext(ctx, network, addr)
			if err != nil {
				ch <- result{msg, err}
				return
			}
			defer tcpConn.Close()
			dConn.Conn = tcpConn
			msg, _, err = dClient.ExchangeWithConn(m, dConn)
		}

		ch <- result{msg, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case ret := <-ch:
		return ret.msg, ret.err
	}
}

func (c *client) ResetConnection() {}

type resolverQuestion struct {
	endpoint string
	report   bool
	started  time.Time
	done     atomic.Bool
}

var errAnswerSaysNothing = errors.New("answered, but not by a resolver that speaks for the bearer")

var errCallerGaveUp = errors.New("the caller's deadline ended the question before the resolver was given a second chance")

func newResolverQuestion(endpoint string, report bool) *resolverQuestion {
	q := &resolverQuestion{endpoint: endpoint, report: report, started: time.Now()}
	if report {
		dialer.ObserveResolverQuestion(endpoint, dialer.PhysicalDialStarted, nil)
	}
	return q
}

func (q *resolverQuestion) answered(reply *D.Msg) {
	if reply == nil || !q.report || !q.done.CompareAndSwap(false, true) {
		return
	}
	if speaksForTheBearer(q.endpoint, reply) {
		dialer.ObserveResolverQuestion(q.endpoint, dialer.PhysicalDialSucceeded, nil)
		return
	}
	dialer.ObserveResolverQuestion(q.endpoint, dialer.PhysicalDialFailed, errAnswerSaysNothing)
}

func (q *resolverQuestion) ended(reply *D.Msg, err error) {
	if reply != nil {
		q.answered(reply)
		return
	}
	if !q.report || !q.done.CompareAndSwap(false, true) {
		return
	}
	if err == nil {
		err = errAnswerSaysNothing
	}
	if time.Since(q.started) < udpQuestionResendAt[0] {
		var netErr net.Error
		if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
			err = errCallerGaveUp
		}
	}
	dialer.ObserveResolverQuestion(q.endpoint, dialer.PhysicalDialFailed, err)
}

func speaksForTheBearer(endpoint string, reply *D.Msg) bool {
	if reply.Rcode != D.RcodeSuccess && reply.Rcode != D.RcodeNameError {
		return false
	}
	addrPort, err := netip.ParseAddrPort(endpoint)
	if err != nil {
		return false
	}
	return resolverBeyondThisLink(addrPort.Addr().Unmap())
}

var resolverBeyondThisLink = func(addr netip.Addr) bool {
	return !addr.IsPrivate() && !addr.IsLinkLocalUnicast() && !addr.IsLoopback()
}

func isPhysicalUDP(conn net.Conn) bool {
	_, ok := conn.(*net.UDPConn)
	return ok
}

var udpQuestionResendAt = []time.Duration{time.Second, 3 * time.Second}

const udpQuestionDeadline = 5 * time.Second

func exchangeOverUDP(ctx context.Context, conn *D.Conn, m *D.Msg) (*D.Msg, error) {
	started := time.Now()
	deadline := started.Add(udpQuestionDeadline)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	if err := conn.WriteMsg(m); err != nil {
		return nil, err
	}
	resent := 0
	for {
		next := deadline
		if resent < len(udpQuestionResendAt) {
			if at := started.Add(udpQuestionResendAt[resent]); at.Before(deadline) {
				next = at
			}
		}
		_ = conn.SetReadDeadline(next)
		reply, err := conn.ReadMsg()
		if err == nil {
			if reply.Id != m.Id {
				continue
			}
			return reply, nil
		}
		var netErr net.Error
		if !(errors.As(err, &netErr) && netErr.Timeout()) || !next.Before(deadline) {
			return nil, err
		}
		resent++
		_ = conn.WriteMsg(m)
	}
}

func newClient(addr string, resolver resolver.Resolver, netType string, params map[string]string, proxyAdapter C.ProxyAdapter, proxyName string) *client {
	host, port, _ := net.SplitHostPort(addr)
	c := &client{
		port:   port,
		host:   host,
		dialer: newDNSDialer(resolver, proxyAdapter, proxyName),
		schema: "udp",
	}
	if strings.HasPrefix(netType, "tcp") {
		c.schema = "tcp"
	}
	return c
}
