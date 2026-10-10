package clash

import (
	"errors"
	"net"
	"net/netip"
	"strconv"

	"github.com/ProjectClash/Clash/log"
)

var (
	errNoRoute                = errors.New("no route")
	errRouteLookupUnsupported = errors.New("route lookup unsupported here")
)

var (
	resolverRouteInterface = routeInterfaceIndex
	primaryRouteInterface  = defaultRouteInterfaceIndex
)

func reachableFromThePhysicalPath(servers []string) []string {
	if len(servers) == 0 {
		return servers
	}
	primary, primaryErr := primaryRouteInterface()
	kept := make([]string, 0, len(servers))
	for _, server := range servers {
		addr, err := netip.ParseAddr(server)
		if err != nil {
			if endpoint, endpointErr := netip.ParseAddrPort(server); endpointErr == nil {
				addr, err = endpoint.Addr(), nil
			}
		}
		if err != nil || addr.IsLoopback() {
			kept = append(kept, server)
			continue
		}
		index, err := resolverRouteInterface(addr)
		switch {
		case errors.Is(err, errNoRoute):
			log.Warnln("[Apple] system resolver %s has no route at all; dropped", server)
			continue
		case err != nil, primaryErr != nil:
			kept = append(kept, server)
			continue
		case index != primary:
			log.Warnln("[Apple] system resolver %s is routed through %s, not the primary interface %s a packet tunnel binds to; dropped", server, interfaceNameByIndex(index), interfaceNameByIndex(primary))
			continue
		}
		kept = append(kept, server)
	}
	return kept
}

func interfaceNameByIndex(index int) string {
	if iface, err := net.InterfaceByIndex(index); err == nil {
		return iface.Name
	}
	return "interface#" + strconv.Itoa(index)
}
