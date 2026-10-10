package dns

// export functions from tunnel module

import "github.com/ProjectClash/Clash/tunnel"

const RespectRules = tunnel.DnsRespectRules

type dnsDialer = tunnel.DNSDialer

var newDNSDialer = tunnel.NewDNSDialer
