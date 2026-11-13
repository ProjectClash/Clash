package clash

import (
	"fmt"
	"strconv"

	"github.com/ProjectClash/Clash/adapter/outbound"
)

func quicTunnelReceiveWindowProfile(policy appleRuntimePolicy) bool {
	return policy.profile.inheritsIOSPacketTunnelBehavior()
}

func applyQUICTunnelReceiveWindows(profile runtimeProfile) {
	if profile.inheritsIOSPacketTunnelBehavior() {
		outbound.SetQUICDefaultReceiveWindows(outbound.QUICTunnelReceiveWindows())
		return
	}
	outbound.SetQUICDefaultReceiveWindows(nil)
}

type quicWindowPair struct {
	nodeType        string
	keys            []string
	field           string
	upstreamDefault string
	effective       string
	alternative     string
	value           string
}

const (
	quicFixedWindowAlternative = "write recv-window on the node: the connection's window is then that size from the first byte, " +
		"not growing -- written at upstream's 67108864 it can hold 64 MiB at once, more than the tunnel has"
	quicHysteria2Alternative       = "write the window on the node -- initial and max -- and both run as written; any window other than 0 is kept"
	quicHysteria2OwnConnection     = 20 << 20
	quicConnectionCeilingEffective = "16777216 (16 MiB): the connection's window grows from 6.4 MiB to 16 MiB at most, " +
		"and the node holds no more than that its apps have not read"
	quicGrowingConnectionDefault = "67108864 (grows from 6.4 MiB to 64 MiB)"
)

var (
	quicHysteria2StreamKeys     = []string{"initial-stream-receive-window", "max-stream-receive-window"}
	quicHysteria2ConnectionKeys = []string{"initial-connection-receive-window", "max-connection-receive-window"}
)

var quicHysteria2WindowPairs = []quicWindowPair{
	{"hysteria2", quicHysteria2StreamKeys, "proxies[hysteria2].initial-stream-receive-window", "8388608 (8 MiB, from the first byte)",
		"1048576 (1 MiB): a stream's window starts at 1 MiB and grows to 8 MiB while its app reads; one the app stopped reading stays where it was",
		quicHysteria2Alternative, "1048576"},
	{"hysteria2", quicHysteria2ConnectionKeys, "proxies[hysteria2].initial-connection-receive-window", "20971520 (20 MiB, from the first byte)",
		"12582912 (12 MiB): the connection's window starts at 12 MiB and grows while its apps read, up to its max window",
		quicHysteria2Alternative, "12582912"},
}

var quicHysteria2CeilingPairs = []quicWindowPair{
	{"hysteria2", quicHysteria2ConnectionKeys, "proxies[hysteria2].max-connection-receive-window", "20971520 (20 MiB)",
		"16777216 (16 MiB): the connection's window grows to 16 MiB at most, and the node holds no more than that its apps have not read",
		quicHysteria2Alternative, "16777216"},
}

var quicGrowingWindowPairs = []quicWindowPair{
	{"hysteria", []string{"recv-window"}, "proxies[hysteria].recv-window", quicGrowingConnectionDefault, quicConnectionCeilingEffective, quicFixedWindowAlternative, ""},
	{"shadowquic", []string{"recv-window"}, "proxies[shadowquic].recv-window", quicGrowingConnectionDefault, quicConnectionCeilingEffective, quicFixedWindowAlternative, ""},
	{"tuic", []string{"recv-window"}, "proxies[tuic].recv-window", quicGrowingConnectionDefault, quicConnectionCeilingEffective, quicFixedWindowAlternative, ""},
}

var quicWindowPairs = func() []quicWindowPair {
	pairs := quicHysteria2WindowPairs[:len(quicHysteria2WindowPairs):len(quicHysteria2WindowPairs)]
	if quicTunnelHasACeiling(outbound.QUICTunnelMaxConnection, 0) {
		pairs = append(pairs, quicHysteria2CeilingPairs...)
	}
	if outbound.QUICTunnelGrowingMaxConnection != 0 {
		pairs = append(pairs, quicGrowingWindowPairs...)
	}
	return pairs
}()

func init() {
	for index := len(quicHysteria2WindowPairs); index < len(quicWindowPairs); index++ {
		deviationRules = append(deviationRules, quicWindowRule(index))
	}
}

func quicTunnelHasACeiling(maxConnection, growingMaxConnection uint64) bool {
	return maxConnection < quicHysteria2OwnConnection || growingMaxConnection != 0
}

const (
	quicWindowReasonHeld = "this device holds in memory what a QUIC node received and its apps have not read yet, " +
		"up to the node's receive windows; with the protocol's default, videos an app paused filled them " +
		"and the tunnel came within 2 MiB of the memory it is killed at. The windows here start small and grow " +
		"while they are read, "
	quicWindowReasonOwnSize = quicWindowReasonHeld + "to the size the protocol's own have: the same speed wherever it was measured. " +
		"A window you write on the node is used instead"
	quicWindowReasonCeiling = quicWindowReasonHeld + "to a connection window of 16 MiB at most: the same speed, except four downloads " +
		"at once on a node 100 ms or more away, which are 4 to 5 % slower. " +
		"A window you write on the node is used instead"
)

func quicWindowReason() string {
	if quicTunnelHasACeiling(outbound.QUICTunnelMaxConnection, outbound.QUICTunnelGrowingMaxConnection) {
		return quicWindowReasonCeiling
	}
	return quicWindowReasonOwnSize
}

func quicWindowRule(index int) deviationRule {
	pair := quicWindowPairs[index]
	return deviationRule{
		field:       pair.field,
		ruleScan:    true,
		nodeKey:     true,
		forcedValue: pair.value,
		category:    deviationForced,
		defaultOnly: true,
		recoverable: true,
		effective:   pair.effective,
		reason:      quicWindowReason(),
		source: "adapter/outbound/clash_quic_receive_window.go QUICTunnelReceiveWindows; " +
			"quic-go's receive window auto-tuning (flow_controller_base.go maybeAdjustWindowSize); " +
			"Hysteria's performance guide (v2.hysteria.network/docs/advanced/Performance: lower the windows " +
			"to save memory); sing-quic hysteria2/protocol.go DefaultStreamReceiveWindow and " +
			"DefaultConnReceiveWindow; mihomo adapter/outbound tuic.go and hysteria.go defaults",
		alternative:     pair.alternative,
		upstreamDefault: pair.upstreamDefault,
		applies:         quicTunnelReceiveWindowProfile,
		mechanism: "bind/clash Setup sets outbound.SetQUICDefaultReceiveWindows from the runtime profile; " +
			"a Hysteria2 outbound fills the pair of windows the node leaves at 0 (fillQUICDefaultReceiveWindows), " +
			"and a TUIC, Hysteria or ShadowQUIC outbound stops its connection window at the ceiling " +
			"(applyQUICDefaultReceiveWindows)",
	}
}

func isQUICWindowField(field string) bool {
	for _, pair := range quicWindowPairs {
		if pair.field == field {
			return true
		}
	}
	return false
}

func quicWindowNode(proxy map[string]any) (string, bool) {
	kind, _ := proxy["type"].(string)
	for _, pair := range quicWindowPairs {
		if pair.nodeType == kind {
			return kind, true
		}
	}
	return kind, false
}

func quicWindowDefaulted(proxy map[string]any) []string {
	kind, ok := quicWindowNode(proxy)
	if !ok {
		return nil
	}
	var fields []string
	for _, pair := range quicWindowPairs {
		if pair.nodeType != kind {
			continue
		}
		written := false
		for _, key := range pair.keys {
			if value := proxyOption(proxy, key); value != nil && !quicWindowReadsZero(value) {
				written = true
			}
		}
		if !written {
			fields = append(fields, pair.field)
		}
	}
	return fields
}

func quicWindowReadsZero(value any) bool {
	switch v := value.(type) {
	case string:
		n, err := strconv.ParseInt(v, 0, 64)
		return err == nil && n == 0
	case bool:
		return !v
	}
	n, whole := yamlWhole(value)
	return whole && n == 0
}

func quicWindowKept(proxy map[string]any) map[string]any {
	kept := map[string]any{"type": proxy["type"], "name": proxy["name"]}
	kind, _ := quicWindowNode(proxy)
	for _, pair := range quicWindowPairs {
		if pair.nodeType != kind {
			continue
		}
		for _, key := range pair.keys {
			if value := proxyOption(proxy, key); value != nil {
				kept[key] = value
			}
		}
	}
	return kept
}

func tallyQUICWindows(tallies map[string]*ipStackTally, proxy map[string]any, at int) {
	fields := quicWindowDefaulted(proxy)
	if len(fields) == 0 {
		return
	}
	node := fmt.Sprintf("proxies[%d]", at)
	if name, _ := proxy["name"].(string); name != "" {
		node = fmt.Sprintf("%s (proxies[%d])", name, at)
	}
	for _, field := range fields {
		if tallies[field] == nil {
			tallies[field] = &ipStackTally{}
		}
		tallies[field].add(1, node, at)
	}
}

func quicWindowDefaultedIn(list []any, held []int) map[string]any {
	return nodeTallyRecordIn(list, held, tallyQUICWindows)
}

func quicWindowDeviations(root map[string]any, policy appleRuntimePolicy) []configDeviation {
	if !quicTunnelReceiveWindowProfile(policy) {
		return nil
	}
	tallies := nodeTalliesOf(root, "quic-window-defaulted", tallyQUICWindows, isQUICWindowField)
	var reported []configDeviation
	for i := range deviationRules {
		rule := &deviationRules[i]
		tally := tallies[rule.field]
		if tally == nil || !isQUICWindowField(rule.field) || !rule.active(policy) {
			continue
		}
		given := tally.first
		if tally.count > 1 {
			given = fmt.Sprintf("%d nodes, the first %s", tally.count, tally.first)
		}
		reported = append(reported, configDeviation{
			Field:           rule.field,
			Given:           given + ": not set (core default: " + rule.upstreamDefault + ")",
			Effective:       rule.effective,
			Category:        rule.category,
			Reason:          rule.reason,
			Source:          rule.source,
			Recoverable:     rule.recoverable,
			Alternative:     rule.alternative,
			Mechanism:       rule.mechanism,
			Written:         false,
			UpstreamDefault: rule.upstreamDefault,
		})
	}
	return reported
}
