//go:build darwin

package clash

import (
	"context"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ProjectClash/Clash/component/keepalive"
	"github.com/ProjectClash/Clash/log"

	"golang.org/x/sys/unix"
)

var lanCompanionsEnabled = runtime.GOOS == "ios"

type lanFace struct {
	name  string
	index int
	addr  netip.Addr
}

type interfaceWithAddrs struct {
	name  string
	index int
	flags net.Flags
	addrs []string
}

func lanInterfaceName(name string) bool {
	return strings.HasPrefix(name, "en") || strings.HasPrefix(name, "bridge")
}

func lanFacesOf(interfaces []interfaceWithAddrs, defaultIndex int) []lanFace {
	if defaultIndex <= 0 {
		return nil
	}
	var faces []lanFace
	for _, candidate := range interfaces {
		if candidate.flags&net.FlagUp == 0 || candidate.flags&(net.FlagLoopback|net.FlagPointToPoint) != 0 {
			continue
		}
		if !lanInterfaceName(candidate.name) || candidate.index == defaultIndex {
			continue
		}
		for _, text := range candidate.addrs {
			prefix, err := netip.ParsePrefix(text)
			if err != nil {
				continue
			}
			addr := prefix.Addr().Unmap()
			if addr.IsLinkLocalUnicast() || addr.IsLoopback() || addr.IsUnspecified() {
				continue
			}
			faces = append(faces, lanFace{name: candidate.name, index: candidate.index, addr: addr})
		}
	}
	return faces
}

func systemInterfaces() []interfaceWithAddrs {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	result := make([]interfaceWithAddrs, 0, len(interfaces))
	for _, candidate := range interfaces {
		entry := interfaceWithAddrs{name: candidate.Name, index: candidate.Index, flags: candidate.Flags}
		if addrs, err := candidate.Addrs(); err == nil {
			for _, a := range addrs {
				entry.addrs = append(entry.addrs, a.String())
			}
		}
		result = append(result, entry)
	}
	return result
}

var currentLANFaces = func() []lanFace {
	return lanFacesOf(systemInterfaces(), int(publishedInterfaceIndex.Load()))
}

var listenLANCompanion = func(network, address string) (net.Listener, error) {
	index, err := loopbackInterfaceIndex()
	if err != nil {
		return nil, err
	}
	config := net.ListenConfig{Control: func(network, address string, conn syscall.RawConn) error {
		var opErr error
		if err := conn.Control(func(fd uintptr) {
			if network == "tcp6" {
				opErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF, index)
			} else {
				opErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, index)
			}
		}); err != nil {
			return err
		}
		return opErr
	}}
	keepalive.SetNetListenConfig(&config)
	return config.Listen(context.Background(), network, address)
}

type lanCompanions struct {
	port           string
	wantV4, wantV6 bool
	mu             sync.Mutex
	byFace         map[lanFace]net.Listener
}

func (l *companionListener) lanCompanionsOn(face lanFace) []net.Listener {
	if l.lan == nil {
		return nil
	}
	l.lan.mu.Lock()
	defer l.lan.mu.Unlock()
	if companion, ok := l.lan.byFace[face]; ok {
		return []net.Listener{companion}
	}
	return nil
}

func closeLANCompanionsLocked(lan *lanCompanions, face lanFace) {
	if companion, ok := lan.byFace[face]; ok {
		_ = companion.Close()
	}
	delete(lan.byFace, face)
}

func (l *companionListener) reconcile(faces []lanFace) (failed bool) {
	lan := l.lan
	if lan == nil {
		return false
	}
	lan.mu.Lock()
	defer lan.mu.Unlock()
	select {
	case <-l.closed:
		return false
	default:
	}
	wanted := map[lanFace]bool{}
	for _, face := range faces {
		if (face.addr.Is4() && !lan.wantV4) || (face.addr.Is6() && !lan.wantV6) {
			continue
		}
		wanted[face] = true
		if _, ok := lan.byFace[face]; ok {
			continue
		}
		network := "tcp4"
		if face.addr.Is6() {
			network = "tcp6"
		}
		address := net.JoinHostPort(face.addr.String(), lan.port)
		companion, err := listenLANCompanion(network, address)
		if err != nil {
			log.Warnln("[Apple] LAN companion listener on %s (address of %s) failed: %v", address, face.name, err)
			failed = true
			continue
		}
		lan.byFace[face] = companion
		go l.pump(companion)
		log.Infoln("[Apple] LAN companion listener on %s (address of %s), bound to lo0", address, face.name)
	}
	defaultIndex := currentDefaultIndex()
	for face := range lan.byFace {
		if wanted[face] {
			continue
		}
		closeLANCompanionsLocked(lan, face)
		log.Infoln("[Apple] LAN companion listener on %s (address of %s) closed: %s", net.JoinHostPort(face.addr.String(), lan.port), face.name, lanCompanionCloseReason(face, defaultIndex))
	}
	return failed
}

var currentDefaultIndex = func() int { return int(publishedInterfaceIndex.Load()) }

func lanCompanionCloseReason(face lanFace, defaultIndex int) string {
	switch {
	case defaultIndex <= 0:
		return "the default interface is not known (the path is not published), so no LAN face is told from it"
	case face.index == defaultIndex:
		return "its interface is now the default, which the wildcard already hears"
	default:
		return "the interface or its address is gone"
	}
}

var lanCompanionRegistry = struct {
	mu        sync.Mutex
	listeners map[*companionListener]struct{}
	watcher   *os.File
	timer     *time.Timer
	retry     *time.Timer
	retries   int
}{listeners: map[*companionListener]struct{}{}}

var lanReconcileMu sync.Mutex

const lanRetryAttempts = 4

var lanRetryDelay = defaultLANRetryDelay

func defaultLANRetryDelay(attempt int) time.Duration {
	if attempt < 0 || attempt >= lanRetryAttempts {
		return 0
	}
	return (2 * time.Second) << attempt
}

var startLANWatcher = startRouteSocketWatcher

func registerLANCompanions(l *companionListener) {
	lanReconcileMu.Lock()
	failed := l.reconcile(currentLANFaces())
	lanReconcileMu.Unlock()
	lanCompanionRegistry.mu.Lock()
	lanCompanionRegistry.listeners[l] = struct{}{}
	if lanCompanionRegistry.watcher == nil {
		lanCompanionRegistry.watcher = startLANWatcher()
	}
	lanCompanionRegistry.mu.Unlock()
	if failed {
		scheduleLANRetry()
	}
}

func unregisterLANCompanions(l *companionListener) {
	lanCompanionRegistry.mu.Lock()
	defer lanCompanionRegistry.mu.Unlock()
	delete(lanCompanionRegistry.listeners, l)
	if len(lanCompanionRegistry.listeners) == 0 {
		if lanCompanionRegistry.watcher != nil {
			_ = lanCompanionRegistry.watcher.Close()
			lanCompanionRegistry.watcher = nil
		}
		stopLANTimersLocked()
	}
}

func stopLANTimersLocked() {
	if lanCompanionRegistry.timer != nil {
		lanCompanionRegistry.timer.Stop()
		lanCompanionRegistry.timer = nil
	}
	if lanCompanionRegistry.retry != nil {
		lanCompanionRegistry.retry.Stop()
		lanCompanionRegistry.retry = nil
	}
	lanCompanionRegistry.retries = 0
}

func scheduleLANRetry() {
	lanCompanionRegistry.mu.Lock()
	defer lanCompanionRegistry.mu.Unlock()
	if len(lanCompanionRegistry.listeners) == 0 || lanCompanionRegistry.retry != nil {
		return
	}
	delay := lanRetryDelay(lanCompanionRegistry.retries)
	if delay <= 0 {
		log.Warnln("[Apple] LAN companion listeners: a face still fails to bind after %d retries; the next interface change tries again", lanCompanionRegistry.retries)
		return
	}
	lanCompanionRegistry.retries++
	lanCompanionRegistry.retry = time.AfterFunc(delay, func() {
		lanCompanionRegistry.mu.Lock()
		lanCompanionRegistry.retry = nil
		lanCompanionRegistry.mu.Unlock()
		reconcileLANCompanions()
	})
}

func reconcileLANCompanions() {
	lanReconcileMu.Lock()
	lanCompanionRegistry.mu.Lock()
	listeners := make([]*companionListener, 0, len(lanCompanionRegistry.listeners))
	for l := range lanCompanionRegistry.listeners {
		listeners = append(listeners, l)
	}
	lanCompanionRegistry.mu.Unlock()
	if len(listeners) == 0 {
		lanReconcileMu.Unlock()
		return
	}
	faces := currentLANFaces()
	failed := false
	for _, l := range listeners {
		if l.reconcile(faces) {
			failed = true
		}
	}
	lanReconcileMu.Unlock()
	if failed {
		scheduleLANRetry()
		return
	}
	lanCompanionRegistry.mu.Lock()
	lanCompanionRegistry.retries = 0
	lanCompanionRegistry.mu.Unlock()
}

const lanReconcileDelay = 300 * time.Millisecond

func scheduleLANReconcile() {
	lanCompanionRegistry.mu.Lock()
	defer lanCompanionRegistry.mu.Unlock()
	if len(lanCompanionRegistry.listeners) == 0 {
		return
	}
	if lanCompanionRegistry.timer != nil {
		lanCompanionRegistry.timer.Stop()
	}
	lanCompanionRegistry.timer = time.AfterFunc(lanReconcileDelay, reconcileLANCompanions)
}

func startRouteSocketWatcher() *os.File {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		log.Warnln("[Apple] LAN companion listeners will not follow interface changes: routing socket: %v", err)
		return nil
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		log.Warnln("[Apple] LAN companion listeners will not follow interface changes: routing socket: %v", err)
		return nil
	}
	file := os.NewFile(uintptr(fd), "route")
	go pumpRouteMessages(file, scheduleLANReconcile, time.Sleep)
	return file
}

const (
	routeReadBackoffMin = 100 * time.Millisecond
	routeReadBackoffMax = 5 * time.Second
)

func pumpRouteMessages(socket io.Reader, schedule func(), sleep func(time.Duration)) {
	buffer := make([]byte, 2048)
	backoff := routeReadBackoffMin
	for {
		n, err := socket.Read(buffer)
		if err != nil {
			if errors.Is(err, os.ErrClosed) || errors.Is(err, io.EOF) {
				return
			}
			log.Warnln("[Apple] LAN companion routing socket read: %v; reading on in %s", err, backoff)
			schedule()
			sleep(backoff)
			if backoff *= 2; backoff > routeReadBackoffMax {
				backoff = routeReadBackoffMax
			}
			continue
		}
		backoff = routeReadBackoffMin
		if n >= 4 {
			switch buffer[3] {
			case unix.RTM_IFINFO, unix.RTM_NEWADDR, unix.RTM_DELADDR:
				schedule()
			}
		}
	}
}
