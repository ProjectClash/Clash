package clash

import (
	"bufio"
	"io"
	"net/netip"
	"os"
	"strings"
)

var resolvConfPath = "/etc/resolv.conf"

var tunnelOwnedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("fdfe:dcba:9876::/48"),
}

func SystemResolverLines() string {
	return bridgeSafeString(recoverAppCallValue("SystemResolverLines", func() string { return systemResolverLinesUnguarded() }))
}

func systemResolverLinesUnguarded() string {
	return bridgeSafeString(strings.Join(reachableFromThePhysicalPath(systemResolverAddresses()), "\n"))
}

var platformResolvers = libresolvResolvers

func systemResolverAddresses() []string {
	if fromLibrary, err := platformResolvers(); err == nil && len(fromLibrary) != 0 {
		servers := make([]string, 0, len(fromLibrary))
		for _, line := range fromLibrary {
			if addr := substituteAddr(line); addr.IsValid() && usableSystemResolver(addr) {
				servers = append(servers, line)
			}
		}
		if len(servers) != 0 {
			return servers
		}
	}
	file, err := os.Open(resolvConfPath)
	if err != nil {
		return nil
	}
	defer func() { _ = file.Close() }()
	return readResolvConf(file)
}

func readResolvConf(r io.Reader) []string {
	var servers []string
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) > 0 && (line[0] == ';' || line[0] == '#') {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "nameserver" {
			continue
		}
		addr, err := netip.ParseAddr(f[1])
		if err != nil || !usableSystemResolver(addr) {
			continue
		}
		servers = append(servers, addr.String())
	}
	return servers
}

func usableSystemResolver(addr netip.Addr) bool {
	addr = addr.Unmap()
	if addr.Zone() != "" || addr.IsLinkLocalUnicast() || addr.IsUnspecified() || addr.IsMulticast() {
		return false
	}
	return !insideAnyPrefix(addr, tunnelOwnedPrefixes)
}

func insideAnyPrefix(addr netip.Addr, prefixes []netip.Prefix) bool {
	addr = addr.Unmap()
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}
