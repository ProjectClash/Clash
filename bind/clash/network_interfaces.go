package clash

import (
	"net"
	"sync"
	"time"

	"github.com/ProjectClash/Clash/component/dialer"
	"github.com/ProjectClash/Clash/log"
)

const (
	interfaceFlagAvailable = 1 << 8
	interfaceFlagDefault   = 1 << 9
	interfaceFlagOwnTunnel = 1 << 10
)

const networkInterfaceCacheTTL = 5 * time.Second

type networkInterfaceCache struct {
	mu         sync.Mutex
	platform   PlatformInterface
	values     []dialer.NetworkInterface
	readAt     time.Time
	lastError  string
	refreshing bool
}

var platformInterfaces networkInterfaceCache

func installNetworkInterfaceProvider(platform PlatformInterface) {
	platformInterfaces.mu.Lock()
	platformInterfaces.platform = platform
	platformInterfaces.values = nil
	platformInterfaces.readAt = time.Time{}
	platformInterfaces.lastError = ""
	platformInterfaces.refreshing = false
	platformInterfaces.mu.Unlock()
	if platform == nil {
		dialer.NetworkInterfaceProvider.Store(nil)
		return
	}
	dialer.NetworkInterfaceProvider.Store(platformInterfaces.load)
}

func invalidateNetworkInterfaces() {
	platformInterfaces.mu.Lock()
	platformInterfaces.readAt = time.Time{}
	platformInterfaces.mu.Unlock()
}

func (c *networkInterfaceCache) load() []dialer.NetworkInterface {
	c.mu.Lock()
	if c.platform == nil {
		c.mu.Unlock()
		return nil
	}
	if !c.readAt.IsZero() {
		values := c.values
		if time.Since(c.readAt) < networkInterfaceCacheTTL {
			c.mu.Unlock()
			return values
		}
		if !c.refreshing {
			c.refreshing = true
			go c.refresh()
		}
		c.mu.Unlock()
		return values
	}
	defer c.mu.Unlock()
	return c.readLocked()
}

func (c *networkInterfaceCache) refresh() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.refreshing = false
	if c.platform == nil {
		return
	}
	c.readLocked()
}

func (c *networkInterfaceCache) readLocked() []dialer.NetworkInterface {
	iterator, err := c.platform.GetInterfaces()
	if err != nil {
		if message := err.Error(); message != c.lastError {
			c.lastError = message
			log.Warnln("[Apple] cannot read the network interface list, so a network strategy has nothing to choose between: %s", message)
		}
		c.readAt = time.Now()
		c.values = nil
		return nil
	}
	c.lastError = ""
	c.values = decodeNetworkInterfaces(iterator)
	c.readAt = time.Now()
	return c.values
}

func decodeNetworkInterfaces(iterator NetworkInterfaceIterator) []dialer.NetworkInterface {
	if iterator == nil {
		return nil
	}
	var out []dialer.NetworkInterface
	for iterator.HasNext() {
		entry := iterator.Next()
		if entry == nil {
			continue
		}
		flags := net.Flags(uint32(entry.Flags) & 0xff)
		out = append(out, dialer.NetworkInterface{
			Index:     int(entry.Index),
			Name:      entry.Name,
			Type:      dialer.InterfaceType(entry.Type),
			Available: entry.Flags&interfaceFlagAvailable != 0 && flags&net.FlagUp != 0 && flags&net.FlagRunning != 0,
			Default:   entry.Flags&interfaceFlagDefault != 0,
			OwnTunnel: entry.Flags&interfaceFlagOwnTunnel != 0,
			Metered:   entry.Metered,
		})
	}
	return out
}
