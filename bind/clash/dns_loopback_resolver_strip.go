package clash

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/ProjectClash/Clash/config"
)

type loopbackResolverEndpoint struct {
	host  string
	port  int
	plain bool
}

func parseLoopbackResolverEndpoint(entry string) (loopbackResolverEndpoint, bool) {
	s := strings.TrimSpace(entry)
	if i := strings.Index(s, "#"); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return loopbackResolverEndpoint{}, false
	}
	if !strings.Contains(s, "://") {
		host, port := splitResolverHostPort(s, 53)
		return loopbackResolverEndpoint{host: host, port: port, plain: true}, host != ""
	}
	u, err := url.Parse(s)
	if err != nil {
		return loopbackResolverEndpoint{}, false
	}
	var defPort int
	plain := false
	switch strings.ToLower(u.Scheme) {
	case "udp", "tcp":
		defPort, plain = 53, true
	case "tls", "quic":
		defPort = 853
	case "https":
		defPort = 443
	case "http":
		defPort = 80
	default:
		return loopbackResolverEndpoint{}, false
	}
	host, port := splitResolverHostPort(u.Host, defPort)
	return loopbackResolverEndpoint{host: host, port: port, plain: plain}, host != ""
}

func splitResolverHostPort(s string, defPort int) (string, int) {
	if h, p, err := net.SplitHostPort(s); err == nil {
		if port, err := strconv.Atoi(p); err == nil {
			return h, port
		}
		return h, defPort
	}
	return strings.TrimSuffix(strings.TrimPrefix(s, "["), "]"), defPort
}

func isThisDeviceHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	if i := strings.Index(host, "%"); i >= 0 {
		host = host[:i]
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsUnspecified())
}

func dnsListenAnswersOn(listen string, port int) bool {
	s := strings.TrimSpace(listen)
	if s == "" {
		return false
	}
	host, p, err := net.SplitHostPort(s)
	if err != nil {
		return false
	}
	listenPort, err := strconv.Atoi(p)
	if err != nil || listenPort != port {
		return false
	}
	return host == "" || isThisDeviceHost(host)
}

func isDeadLoopbackResolver(entry, listen string) (int, bool) {
	ep, ok := parseLoopbackResolverEndpoint(entry)
	if !ok || !isThisDeviceHost(ep.host) {
		return 0, false
	}
	if ep.plain && dnsListenAnswersOn(listen, ep.port) {
		return ep.port, false
	}
	return ep.port, true
}

func loopbackStripReason(port int) string {
	return fmt.Sprintf(" (loopback, no dns.listen on port %d)", port)
}

func stripLoopbackResolvers(raw *config.RawConfig) []string {
	stripped := []string{}
	listen := raw.DNS.Listen
	dead := func(entry string) bool {
		_, dead := isDeadLoopbackResolver(entry, listen)
		return dead
	}
	filter := func(field string, list []string) []string {
		kept := make([]string, 0, len(list))
		for _, ns := range list {
			if port, dead := isDeadLoopbackResolver(ns, listen); dead {
				stripped = append(stripped, field+" "+ns+loopbackStripReason(port))
				continue
			}
			kept = append(kept, ns)
		}
		return kept
	}
	raw.DNS.NameServer = filter("nameserver", raw.DNS.NameServer)
	raw.DNS.Fallback = filter("fallback", raw.DNS.Fallback)
	raw.DNS.ProxyServerNameserver = filter("proxy-server-nameserver", raw.DNS.ProxyServerNameserver)
	raw.DNS.DirectNameServer = filter("direct-nameserver", raw.DNS.DirectNameServer)
	raw.DNS.DefaultNameserver = filter("default-nameserver", raw.DNS.DefaultNameserver)
	for _, line := range filterPolicyNameserversWhere("nameserver-policy", raw.DNS.NameServerPolicy, dead) {
		stripped = append(stripped, line+loopbackStripReason(portOfPolicyLine(line, listen)))
	}
	for _, line := range filterPolicyNameserversWhere("proxy-server-nameserver-policy", raw.DNS.ProxyServerNameserverPolicy, dead) {
		stripped = append(stripped, line+loopbackStripReason(portOfPolicyLine(line, listen)))
	}
	return stripped
}

func portOfPolicyLine(line, listen string) int {
	entry := line[strings.LastIndex(line, " ")+1:]
	port, _ := isDeadLoopbackResolver(entry, listen)
	return port
}

func strippedDNSLoopbackNotices(root map[string]any, policy appleRuntimePolicy) []planNotice {
	if !policy.networkExtension || !policy.stripLoopbackResolvers {
		return nil
	}
	dns, ok := root["dns"].(map[string]any)
	if !ok {
		return nil
	}
	listen, _ := dns["listen"].(string)
	notices := []planNotice{}
	for _, field := range []string{
		"nameserver", "fallback", "proxy-server-nameserver", "direct-nameserver", "default-nameserver",
		"nameserver-policy", "proxy-server-nameserver-policy",
	} {
		walkStrings(dns[field], func(v string) {
			port, dead := isDeadLoopbackResolver(v, listen)
			if !dead {
				return
			}
			notices = append(notices, planNotice{Kind: planNoticeDNSLoopbackResolverStripped, Field: "dns." + field, Value: v,
				Text: fmt.Sprintf("dns.%s '%s' points at this device and no dns.listen in this configuration answers on port %d; "+
					"nothing else on this platform can, so the entry is stripped. To use it, add dns.listen on port %d to the same configuration.",
					field, v, port, port)})
		})
	}
	return notices
}
