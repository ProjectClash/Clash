package clash

import (
	"fmt"

	"github.com/ProjectClash/Clash/adapter/outbound"
)

const mieruMultiplexingField = "proxies[mieru].multiplexing"

const (
	mieruMultiplexingRecord     = "mieru-multiplexing-replaced"
	mieruMultiplexingWrittenKey = mieruMultiplexingField + " (written)"
)

func mieruTunnelBoundsProfile(policy appleRuntimePolicy) bool {
	return policy.profile.inheritsIOSPacketTunnelBehavior()
}

var mieruMultiplexingRule = deviationRule{
	field:       mieruMultiplexingField,
	ruleScan:    true,
	nodeKey:     true,
	onlyWhere:   []deviationOnlyWhere{{key: "transport", values: []string{outbound.MieruTunnelMultiplexingTransport}}},
	forcedValue: outbound.MieruTunnelMultiplexing,
	category:    deviationForced,
	recoverable: false,
	effective: outbound.MieruTunnelMultiplexing + " on a node of the TCP transport, whatever level it writes: every flow opens its own " +
		"connection to the node, one more TCP handshake each. A node of the UDP transport runs the level it writes",
	reason: "this device holds in memory what a mieru node received and its apps have not read yet; with the module's own " +
		"queue a video an app paused took the tunnel past the memory it is killed at within seconds. The tunnel stops a flow's " +
		"queue at 256 KiB, which it can only do for a flow that has its connection to itself: a flow stopped there would hold " +
		"back every flow sharing its connection. So every flow of a node on the TCP transport gets a connection of its own",
	source: "third_party/mieru pkg/protocol clash_tunnel_bounds.go (the byte limit, for a session alone on its underlay); " +
		"mieru pkg/appctl/appctlcommon/client.go (no level is MULTIPLEXING_LOW, a multiplex factor of 1) and " +
		"pkg/protocol/mux.go (a new session reuses an underlay with k in k+1 odds); mieru docs/client-install.md " +
		"(multiplexing levels)",
	upstreamDefault: "MULTIPLEXING_LOW (flows share a connection)",
	applies:         mieruTunnelBoundsProfile,
	mechanism: "bind/clash Setup sets outbound.SetMieruTunnelMultiplexingOff from the runtime profile; " +
		"a mieru outbound on the TCP transport gives its client MULTIPLEXING_OFF in place of the level it wrote (mieruMultiplexing)",
}

func mieruMultiplexingReplaced(proxy map[string]any) (replaced bool, written string) {
	if kind, _ := proxy["type"].(string); kind != "mieru" {
		return false, ""
	}
	if proxyOption(proxy, "transport") != outbound.MieruTunnelMultiplexingTransport {
		return false, ""
	}
	switch value := proxyOption(proxy, "multiplexing").(type) {
	case nil:
		return true, ""
	case string:
		return value != outbound.MieruTunnelMultiplexing, value
	default:
		return true, fmt.Sprint(value)
	}
}

func tallyMieruMultiplexing(tallies map[string]*ipStackTally, proxy map[string]any, at int) {
	replaced, written := mieruMultiplexingReplaced(proxy)
	if !replaced {
		return
	}
	node := fmt.Sprintf("proxies[%d]", at)
	if name, _ := proxy["name"].(string); name != "" {
		node = fmt.Sprintf("%s (proxies[%d])", name, at)
	}
	key := mieruMultiplexingField
	if written != "" {
		key, node = mieruMultiplexingWrittenKey, node+": "+written
	}
	if tallies[key] == nil {
		tallies[key] = &ipStackTally{}
	}
	tallies[key].add(1, node, at)
}

func mieruMultiplexingDeviations(root map[string]any, policy appleRuntimePolicy) []configDeviation {
	rule := &mieruMultiplexingRule
	if !rule.active(policy) {
		return nil
	}
	tallies := nodeTalliesOf(root, mieruMultiplexingRecord, tallyMieruMultiplexing,
		func(key string) bool { return key == mieruMultiplexingField || key == mieruMultiplexingWrittenKey })
	var reported []configDeviation
	for _, key := range []string{mieruMultiplexingField, mieruMultiplexingWrittenKey} {
		tally := tallies[key]
		if tally == nil {
			continue
		}
		given := tally.first
		if tally.count > 1 {
			given = fmt.Sprintf("%d nodes, the first %s", tally.count, tally.first)
		}
		written := key == mieruMultiplexingWrittenKey
		if !written {
			given += ": not set (core default: " + rule.upstreamDefault + ")"
		}
		reported = append(reported, configDeviation{
			Field:           rule.field,
			Given:           given,
			Effective:       rule.effective,
			Category:        rule.category,
			Reason:          rule.reason,
			Source:          rule.source,
			Recoverable:     rule.recoverable,
			Mechanism:       rule.mechanism,
			Written:         written,
			UpstreamDefault: rule.upstreamDefault,
		})
	}
	return reported
}

func mieruMultiplexingReplacedIn(list []any, held []int) map[string]any {
	return nodeTallyRecordIn(list, held, tallyMieruMultiplexing)
}

func mieruMultiplexingKept(proxy map[string]any) map[string]any {
	kept := map[string]any{"type": proxy["type"], "name": proxy["name"], "transport": proxyOption(proxy, "transport")}
	if level := proxyOption(proxy, "multiplexing"); level != nil {
		kept["multiplexing"] = level
	}
	return kept
}
