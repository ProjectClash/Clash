package clash

import (
	"github.com/ProjectClash/Clash/adapter/outboundgroup"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/tunnel"
	"github.com/ProjectClash/Clash/tunnel/statistic"
)

func WidgetStatsJSON(group string) string {
	return bridgeSafeString(recoverAppCallValue("WidgetStatsJSON", func() string { return widgetStatsJSONUnguarded(group) }))
}

func widgetStatsJSONUnguarded(group string) string {
	manager := statistic.DefaultManager
	totals := manager.OutboundTotals()
	upTotal, downTotal := manager.Total()
	stats := map[string]any{
		"mode":      tunnel.Mode().String(),
		"upTotal":   upTotal,
		"downTotal": downTotal,
		"byOutbound": map[string]any{
			"proxy":  map[string]int64{"up": totals.Proxy.Up, "down": totals.Proxy.Down},
			"direct": map[string]int64{"up": totals.Direct.Up, "down": totals.Direct.Down},
			"reject": map[string]int64{"up": totals.Reject.Up, "down": totals.Reject.Down, "count": totals.Rejected},
		},
		"connections": map[string]int64{
			"opened":   totals.Opened,
			"active":   totals.Active,
			"rejected": totals.Rejected,
		},
	}
	if egress := widgetEgress(group); egress != "" {
		stats["egress"] = egress
	}
	return bridgeSafeString(mustJSON(stats))
}

func WidgetGroupJSON(group string, limit int) string {
	return bridgeSafeString(recoverAppCallValue("WidgetGroupJSON", func() string { return widgetGroupJSONUnguarded(group, limit) }))
}

func widgetGroupJSONUnguarded(group string, limit int) string {
	proxy, ok := tunnel.Proxies()[group]
	if !ok {
		return bridgeSafeString("{}")
	}
	members, ok := proxy.Adapter().(outboundgroup.ProxyGroup)
	if !ok {
		return bridgeSafeString("{}")
	}
	all := members.Proxies()
	names := make([]string, 0, len(all))
	for _, member := range all {
		if limit > 0 && len(names) == limit {
			break
		}
		names = append(names, member.Name())
	}
	return bridgeSafeString(mustJSON(map[string]any{
		"name": proxy.Name(),
		"type": proxy.Type().String(),
		"now":  members.Now(),
		"all":  names,
	}))
}

func widgetEgress(group string) string {
	if tunnel.Mode() == tunnel.Global {
		group = "GLOBAL"
	}
	if group == "" {
		return ""
	}
	proxies := tunnel.Proxies()
	name := group
	for depth := 0; depth < 32; depth++ {
		proxy, ok := proxies[name]
		if !ok {
			if depth == 0 {
				return ""
			}
			return name
		}
		members, isGroup := proxy.Adapter().(outboundgroup.ProxyGroup)
		if !isGroup {
			return proxy.Name()
		}
		now := members.Now()
		if now == "" || now == name {
			return proxy.Name()
		}
		name = now
	}
	return name
}

var _ = C.Selector
