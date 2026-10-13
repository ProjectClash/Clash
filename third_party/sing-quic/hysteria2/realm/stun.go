package realm

import (
	"context"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/metacubex/sing-quic/hysteria2/internal/stun"
	"github.com/metacubex/sing/common/batch"
	E "github.com/metacubex/sing/common/exceptions"
)

func ResolveSTUNServers(ctx context.Context, servers []string, resolver Resolver, ipv4, ipv6 bool) ([]netip.AddrPort, error) {
	if resolver == nil {
		return nil, E.New("realm: resolver is required")
	}
	group, ctx := batch.New[[]netip.AddrPort](ctx)
	for i, server := range servers {
		i, server := i, server
		group.Go(strconv.Itoa(i), func() ([]netip.AddrPort, error) {
			host, port, err := net.SplitHostPort(server)
			if err != nil {
				host = server
				port = "3478"
			}
			portNumber, err := strconv.ParseUint(port, 10, 16)
			if err != nil {
				return nil, E.Cause(err, "resolve STUN port: ", port)
			}
			addr, parseErr := netip.ParseAddr(host)
			if parseErr == nil {
				addr = addr.Unmap()
				if addr.Is4() && !ipv4 {
					return nil, nil
				}
				if !addr.Is4() && !ipv6 {
					return nil, nil
				}
				return []netip.AddrPort{netip.AddrPortFrom(addr, uint16(portNumber))}, nil
			}
			addresses, err := resolver(ctx, host, ipv4, ipv6)
			if err != nil {
				return nil, E.Cause(err, "resolve STUN server: ", server)
			}
			entries := make([]netip.AddrPort, 0, len(addresses))
			for _, address := range addresses {
				entries = append(entries, netip.AddrPortFrom(address, uint16(portNumber)))
			}
			return entries, nil
		})
	}
	results, groupErr := group.WaitAndGetResult()
	if groupErr != nil {
		return nil, groupErr.Err
	}
	var resolved []netip.AddrPort
	for i := range servers {
		resolved = append(resolved, results[strconv.Itoa(i)].Value...)
	}
	if len(resolved) == 0 {
		return nil, E.New("no STUN servers resolved")
	}
	return resolved, nil
}

type stunRequest struct {
	server        netip.AddrPort
	rawMessage    []byte
	transactionID stun.TransactionID
}

func Discover(ctx context.Context, conn net.PacketConn, servers []netip.AddrPort) ([]netip.AddrPort, error) {
	if len(servers) == 0 {
		return nil, E.New("no STUN servers")
	}
	requests, err := buildSTUNRequests(servers)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = conn.SetReadDeadline(time.Time{})
	}()
	buffer := make([]byte, 1500)
	runAttempt := func(deadline time.Time, pending map[stun.TransactionID]struct{}) ([]netip.AddrPort, error) {
		err := conn.SetReadDeadline(deadline)
		if err != nil {
			return nil, E.Cause(err, "set read deadline")
		}
		var addresses []netip.AddrPort
		for time.Now().Before(deadline) && len(pending) > 0 {
			n, _, readErr := conn.ReadFrom(buffer)
			if readErr != nil {
				if E.IsTimeout(readErr) {
					return addresses, nil
				}
				return nil, E.Cause(readErr, "read STUN response")
			}
			message, parseErr := stun.Decode(buffer[:n])
			if parseErr != nil {
				continue
			}
			_, isPending := pending[message.TransactionID]
			if !isPending {
				continue
			}
			delete(pending, message.TransactionID)
			address, parseErr := message.XORMappedAddress()
			if parseErr != nil {
				continue
			}
			addresses = append(addresses, address)
		}
		return addresses, nil
	}
	return runDiscoveryAttempts(ctx, conn, requests, runAttempt)
}

func DiscoverDemuxed(ctx context.Context, conn *PunchPacketConn, servers []netip.AddrPort) ([]netip.AddrPort, error) {
	if len(servers) == 0 {
		return nil, E.New("no STUN servers")
	}
	requests, err := buildSTUNRequests(servers)
	if err != nil {
		return nil, err
	}
	stunEvents := conn.STUNEvents()
	runAttempt := func(deadline time.Time, pending map[stun.TransactionID]struct{}) ([]netip.AddrPort, error) {
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		var addresses []netip.AddrPort
		for len(pending) > 0 {
			select {
			case <-ctx.Done():
				return addresses, ctx.Err()
			case <-timer.C:
				return addresses, nil
			case event := <-stunEvents:
				_, isPending := pending[event.Message.TransactionID]
				if !isPending {
					continue
				}
				delete(pending, event.Message.TransactionID)
				address, parseErr := event.Message.XORMappedAddress()
				if parseErr != nil {
					continue
				}
				addresses = append(addresses, address)
			}
		}
		return addresses, nil
	}
	return runDiscoveryAttempts(ctx, conn, requests, runAttempt)
}

func buildSTUNRequests(servers []netip.AddrPort) ([]stunRequest, error) {
	requests := make([]stunRequest, 0, len(servers))
	for _, server := range servers {
		message, err := stun.NewBindingRequest()
		if err != nil {
			return nil, E.Cause(err, "build STUN request")
		}
		requests = append(requests, stunRequest{
			server:        server,
			rawMessage:    message.Raw,
			transactionID: message.TransactionID,
		})
	}
	return requests, nil
}

func transmitSTUNRequests(conn net.PacketConn, requests []stunRequest, pending map[stun.TransactionID]struct{}) error {
	var sendErr error
	sent := 0
	for _, request := range requests {
		_, isPending := pending[request.transactionID]
		if !isPending {
			continue
		}
		_, err := conn.WriteTo(request.rawMessage, net.UDPAddrFromAddrPort(request.server))
		if err != nil {
			sendErr = E.Errors(sendErr, E.Cause(err, "send STUN request to ", request.server))
			continue
		}
		sent++
	}
	if sent == 0 {
		if sendErr != nil {
			return sendErr
		}
		return E.New("no STUN requests sent")
	}
	return sendErr
}

func runDiscoveryAttempts(
	ctx context.Context,
	conn net.PacketConn,
	requests []stunRequest,
	runAttempt func(deadline time.Time, pending map[stun.TransactionID]struct{}) ([]netip.AddrPort, error),
) ([]netip.AddrPort, error) {
	attemptTimeouts := []time.Duration{
		500 * time.Millisecond,
		2 * time.Second,
		4 * time.Second,
	}
	pending := make(map[stun.TransactionID]struct{}, len(requests))
	for _, request := range requests {
		pending[request.transactionID] = struct{}{}
	}
	seen := make(map[netip.AddrPort]bool)
	var result []netip.AddrPort
	var lastErr error
	for _, attemptTimeout := range attemptTimeouts {
		err := ctx.Err()
		if err != nil {
			lastErr = err
			break
		}
		if len(pending) == 0 {
			break
		}
		err = transmitSTUNRequests(conn, requests, pending)
		if err != nil {
			lastErr = err
		}
		deadline := time.Now().Add(attemptTimeout)
		addresses, attemptErr := runAttempt(deadline, pending)
		for _, address := range addresses {
			if !seen[address] {
				seen[address] = true
				result = append(result, address)
			}
		}
		if attemptErr != nil {
			if E.IsCanceled(attemptErr) {
				lastErr = attemptErr
				break
			}
			return nil, attemptErr
		}
	}
	if len(result) > 0 {
		return result, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, E.New("no STUN responses received")
}
