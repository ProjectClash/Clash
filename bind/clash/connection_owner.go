package clash

import (
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ProjectClash/Clash/component/process"
)

type ConnectionOwner struct {
	UserId      int32
	UserName    string
	ProcessPath string
}

type ConnectionOwnerResolver interface {
	FindConnectionOwner(ipProtocol int32, sourceAddress string, sourcePort int32, destinationAddress string, destinationPort int32) (*ConnectionOwner, error)
}

type ownerResolverBox struct {
	resolver   ConnectionOwnerResolver
	generation int
}

var platformOwnerResolver atomic.Pointer[ownerResolverBox]

var errNoOwner = errors.New("the platform found no owner")

func SetConnectionOwnerResolver(resolver ConnectionOwnerResolver) {
	if resolver != nil {
		if _, ok := resolver.(bridgeSafeOwnerResolverDecorator); !ok {
			resolver = bridgeSafeOwnerResolverDecorator{resolver}
		}
	}
	platformOwnerBound.forget(func(generation int) {
		if resolver == nil {
			platformOwnerResolver.Store(nil)
			return
		}
		platformOwnerResolver.Store(&ownerResolverBox{resolver: resolver, generation: generation})
	})
}

type bridgeSafeOwnerResolverDecorator struct{ ConnectionOwnerResolver }

func (d bridgeSafeOwnerResolverDecorator) FindConnectionOwner(ipProtocol int32, sourceAddress string, sourcePort int32, destinationAddress string, destinationPort int32) (*ConnectionOwner, error) {
	return d.ConnectionOwnerResolver.FindConnectionOwner(ipProtocol, bridgeSafeString(sourceAddress), sourcePort, bridgeSafeString(destinationAddress), destinationPort)
}

func init() {
	process.SetConnectionOwnerResolver(askPlatformForConnectionOwner)
}

func askPlatformForConnectionOwner(network string, srcIP netip.Addr, srcPort int, dstIP netip.Addr, dstPort int) (uint32, string, error) {
	box := platformOwnerResolver.Load()
	if box == nil || currentRuntimeProfile() != runtimeProfileMacOSPacketTunnel {
		return 0, "", errNoOwner
	}
	return platformOwnerBound.findAs(box.resolver, box.generation, network, srcIP, srcPort, dstIP, dstPort)
}

type ownerBound struct {
	atOnce        int
	waiting       int
	deadline      time.Duration
	leastExchange time.Duration
	remembered    time.Duration

	mu        sync.Mutex
	places    chan struct{}
	queued    int
	asking    map[ownerKey]*ownerAsking
	known     map[ownerKey]ownerKnown
	resolvers int
	swept     time.Time
	sweeps    int
}

type ownerKey struct {
	protocol int32
	source   netip.AddrPort
}

type ownerAsking struct {
	done    chan struct{}
	uid     uint32
	path    string
	err     error
	placing bool
	waitFor time.Time
}

type ownerKnown struct {
	uid  uint32
	path string
	at   time.Time
}

var platformOwnerBound = ownerBound{atOnce: 4, waiting: 1024, deadline: 150 * time.Millisecond, leastExchange: 15 * time.Millisecond, remembered: 2 * time.Second}

func (b *ownerBound) find(resolver ConnectionOwnerResolver, network string, srcIP netip.Addr, srcPort int, dstIP netip.Addr, dstPort int) (uint32, string, error) {
	return b.findAs(resolver, -1, network, srcIP, srcPort, dstIP, dstPort)
}

func (b *ownerBound) findAs(resolver ConnectionOwnerResolver, generation int, network string, srcIP netip.Addr, srcPort int, dstIP netip.Addr, dstPort int) (uint32, string, error) {
	until := time.Now().Add(b.deadline)
	key := ownerKey{protocol: 6, source: netip.AddrPortFrom(srcIP, uint16(srcPort))}
	if network == process.UDP {
		key.protocol = 17
	}
	b.mu.Lock()
	if generation >= 0 && generation != b.resolvers {
		b.mu.Unlock()
		return 0, "", errNoOwner
	}
	if known, ok := b.known[key]; ok && time.Since(known.at) < b.remembered {
		b.mu.Unlock()
		return known.uid, known.path, nil
	}
	asking := b.asking[key]
	if asking != nil && asking.placing {
		if waitFor := until.Add(-b.leastExchange); waitFor.After(asking.waitFor) {
			asking.waitFor = waitFor
		}
	}
	if asking == nil {
		if b.places == nil {
			b.places = make(chan struct{}, b.atOnce)
			b.asking = make(map[ownerKey]*ownerAsking)
			b.known = make(map[ownerKey]ownerKnown)
		}
		placed := false
		select {
		case b.places <- struct{}{}:
			placed = true
		default:
			if b.queued >= b.waiting {
				b.mu.Unlock()
				return 0, "", errNoOwner
			}
			b.queued++
		}
		asking = &ownerAsking{done: make(chan struct{}), err: errNoOwner, placing: !placed, waitFor: until.Add(-b.leastExchange)}
		b.asking[key] = asking
		go b.ask(asking, key, b.resolvers, resolver, srcIP, srcPort, dstIP, dstPort)
	}
	b.mu.Unlock()
	return asking.await(until)
}

func (b *ownerBound) ask(asking *ownerAsking, key ownerKey, resolvers int, resolver ConnectionOwnerResolver, srcIP netip.Addr, srcPort int, dstIP netip.Addr, dstPort int) {
	placed := true
	if asking.placing {
		placed = b.takePlace(asking)
	}
	if placed {
		owner, err := resolver.FindConnectionOwner(key.protocol, srcIP.String(), int32(srcPort), dstIP.String(), int32(dstPort))
		if err == nil && owner != nil && owner.ProcessPath != "" {
			asking.uid, asking.path, asking.err = uint32(owner.UserId), owner.ProcessPath, nil
		}
		<-b.places
	}
	b.mu.Lock()
	if b.asking[key] == asking {
		delete(b.asking, key)
	}
	if asking.err == nil && key.protocol == 17 && resolvers == b.resolvers {
		now := time.Now()
		if now.Sub(b.swept) >= b.remembered {
			b.swept = now
			b.sweeps++
			for other, known := range b.known {
				if now.Sub(known.at) >= b.remembered {
					delete(b.known, other)
				}
			}
		}
		b.known[key] = ownerKnown{uid: asking.uid, path: asking.path, at: now}
	}
	b.mu.Unlock()
	close(asking.done)
}

func (a *ownerAsking) await(until time.Time) (uint32, string, error) {
	select {
	case <-a.done:
		return a.uid, a.path, a.err
	default:
	}
	timer := time.NewTimer(time.Until(until))
	defer timer.Stop()
	select {
	case <-a.done:
		return a.uid, a.path, a.err
	case <-timer.C:
		return 0, "", errNoOwner
	}
}

func (b *ownerBound) forget(then func(generation int)) {
	b.mu.Lock()
	clear(b.known)
	clear(b.asking)
	b.resolvers++
	if then != nil {
		then(b.resolvers)
	}
	b.mu.Unlock()
}

func (b *ownerBound) takePlace(asking *ownerAsking) bool {
	for {
		b.mu.Lock()
		wait := time.Until(asking.waitFor)
		if wait <= 0 {
			asking.placing = false
			b.queued--
			b.mu.Unlock()
			return false
		}
		b.mu.Unlock()
		timer := time.NewTimer(wait)
		select {
		case b.places <- struct{}{}:
			timer.Stop()
			b.mu.Lock()
			asking.placing = false
			b.queued--
			b.mu.Unlock()
			return true
		case <-timer.C:
		}
	}
}
