package clash

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"

	"github.com/ProjectClash/Clash/component/process"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/hub/route"
	LC "github.com/ProjectClash/Clash/listener/config"
	"github.com/ProjectClash/Clash/tunnel"
	"github.com/metacubex/chi"
	"github.com/metacubex/http"
)

func init() {
	route.Register(func(router chi.Router) {
		for _, prefix := range privateRoutePrefixes {
			router.Get(prefix+"/rules/match", serveRuleMatch)
		}
	})
}

type ruleMatchReply struct {
	Mode        string             `json:"mode"`
	Host        string             `json:"host,omitempty"`
	FakeIP      bool               `json:"fakeIP,omitempty"`
	ResolvedIP  string             `json:"resolvedIP,omitempty"`
	HostsIP     string             `json:"hostsIP,omitempty"`
	Assumed     []string           `json:"assumed"`
	Decided     bool               `json:"decided"`
	Missing     []string           `json:"missing"`
	Rule        *ruleMatchRuleJSON `json:"rule"`
	Proxy       string             `json:"proxy"`
	Chain       []string           `json:"chain"`
	Conditional bool               `json:"conditional"`
	Dropped     bool               `json:"dropped,omitempty"`
	Notes       []string           `json:"notes"`
	Error       string             `json:"error,omitempty"`
}

type ruleMatchRuleJSON struct {
	Index    int                `json:"index"`
	Type     string             `json:"type"`
	Payload  string             `json:"payload"`
	SubRules string             `json:"subRules,omitempty"`
	Through  *ruleMatchRuleJSON `json:"through,omitempty"`
}

func ruleMatchRuleFor(rule *tunnel.ExplainedRule) *ruleMatchRuleJSON {
	if rule == nil {
		return nil
	}
	return &ruleMatchRuleJSON{Index: rule.Index, Type: rule.Type, Payload: rule.Payload, SubRules: rule.SubRules,
		Through: ruleMatchRuleFor(rule.Through)}
}

const ruleMatchDefaultPort = 443

func parseRuleMatchQuery(request *http.Request) (tunnel.RuleExplainInput, string) {
	query := request.URL.Query()
	input := tunnel.RuleExplainInput{Host: strings.TrimSpace(query.Get("host")), Network: C.TCP}
	if text := strings.TrimSpace(query.Get("ip")); text != "" {
		ip, err := netip.ParseAddr(strings.Trim(text, "[]"))
		if err != nil {
			return input, "ip is not an address"
		}
		input.DstIP = ip.Unmap()
	}
	if input.Host != "" {
		if ip, err := netip.ParseAddr(strings.Trim(input.Host, "[]")); err == nil {
			if input.DstIP.IsValid() && input.DstIP != ip.Unmap() {
				return input, "host and ip name two different addresses"
			}
			input.Host, input.DstIP = "", ip.Unmap()
		}
	}
	if input.Host == "" && !input.DstIP.IsValid() {
		return input, "host or ip is required"
	}
	if text := strings.TrimSpace(query.Get("port")); text != "" {
		port, err := strconv.ParseUint(text, 10, 16)
		if err != nil || port == 0 {
			return input, "port is not 1-65535"
		}
		input.DstPort = uint16(port)
	}
	switch strings.ToLower(strings.TrimSpace(query.Get("network"))) {
	case "", "tcp":
	case "udp":
		input.Network = C.UDP
	default:
		return input, "network is tcp or udp"
	}
	if text := strings.TrimSpace(query.Get("src")); text != "" {
		host, portText, err := net.SplitHostPort(text)
		if err != nil {
			host, portText = text, ""
		}
		ip, err := netip.ParseAddr(strings.Trim(host, "[]"))
		if err != nil {
			return input, "src is not an address"
		}
		input.SrcIP = ip.Unmap()
		if portText != "" {
			port, err := strconv.ParseUint(portText, 10, 16)
			if err != nil {
				return input, "src port is not 0-65535"
			}
			input.SrcPort = uint16(port)
		}
	}
	input.Process = strings.TrimSpace(query.Get("process"))
	input.Resolve = query.Get("resolve") == "1" || strings.EqualFold(query.Get("resolve"), "true")
	input.ProcessAvailable = currentRuntimePolicy(true).processMetadata().processPath &&
		tunnel.FindProcessMode() != process.FindProcessOff
	return input, ""
}

func serveRuleMatch(writer http.ResponseWriter, request *http.Request) {
	input, problem := parseRuleMatchQuery(request)
	if problem != "" {
		http.Error(writer, problem, http.StatusBadRequest)
		return
	}
	assumed := assumeRuleMatchDefaults(&input, currentTunSourceAddress())
	reply := ruleMatchReplyFor(tunnel.ExplainRule(input))
	reply.Assumed = assumed
	writeControllerJSON(writer, reply)
}

func assumeRuleMatchDefaults(input *tunnel.RuleExplainInput, tunSource netip.Addr) []string {
	assumed := []string{}
	if input.DstPort == 0 {
		input.DstPort = ruleMatchDefaultPort
		assumed = append(assumed, "port="+strconv.Itoa(ruleMatchDefaultPort))
	}
	if !input.SrcIP.IsValid() && tunSource.IsValid() {
		input.SrcIP = tunSource
		assumed = append(assumed, "src="+input.SrcIP.String())
	}
	if input.SrcPort == 0 {
		assumed = append(assumed, "src-port=0")
	}
	assumed = append(assumed, "inbound=tun")
	if input.ProcessAvailable {
		if input.Process != "" && !strings.Contains(input.Process, "/") {
			assumed = append(assumed, "process-path=unknown")
		}
		assumed = append(assumed, "uid=unknown")
	}
	return assumed
}

var tunSourceAddress atomic.Pointer[netip.Addr]

func publishTunSourceAddress(tun LC.Tun) {
	if tun.Enable {
		for _, prefix := range tun.Inet4Address {
			if address := prefix.Addr(); address.IsValid() {
				tunSourceAddress.Store(&address)
				return
			}
		}
	}
	tunSourceAddress.Store(nil)
}

func currentTunSourceAddress() netip.Addr {
	if address := tunSourceAddress.Load(); address != nil {
		return *address
	}
	return netip.Addr{}
}

func ruleMatchReplyFor(explanation tunnel.RuleExplanation) ruleMatchReply {
	reply := ruleMatchReply{
		Mode: explanation.Mode, Host: explanation.Host, FakeIP: explanation.FakeIP, ResolvedIP: explanation.ResolvedIP,
		HostsIP: explanation.HostsIP, Assumed: []string{}, Dropped: explanation.Dropped,
		Decided: explanation.Decided, Missing: explanation.Missing, Proxy: explanation.Proxy,
		Chain: explanation.Chain, Conditional: explanation.Conditional, Error: explanation.Error,
		Notes: []string{},
	}
	if reply.Missing == nil {
		reply.Missing = []string{}
	}
	if explanation.Dropped {
		reply.Notes = append(reply.Notes, "the tunnel refuses this flow before any rule (the IP version policy)")
		return reply
	}
	if explanation.Rule != nil {
		reply.Rule = ruleMatchRuleFor(explanation.Rule)
	} else if explanation.Mode == "rule" && explanation.Error == "" {
		reply.Notes = append(reply.Notes, "no rule matched; the flow goes DIRECT")
	}
	for _, missing := range explanation.Missing {
		switch missing {
		case "ip":
			reply.Notes = append(reply.Notes, "IP rules were skipped: the host was not resolved (resolve=1 resolves it)")
		case "process":
			reply.Notes = append(reply.Notes, "PROCESS rules were skipped: no process was given")
		}
	}
	if explanation.ProcessUnavailable {
		reply.Notes = append(reply.Notes, "this device does not name the process behind a flow, so PROCESS rules never match here")
	}
	if explanation.Conditional {
		reply.Notes = append(reply.Notes, "the chain is the groups' current choice, which can change")
	}
	return reply
}
