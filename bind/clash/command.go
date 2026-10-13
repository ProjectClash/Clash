package clash

import (
	"bytes"
	"encoding/json"
	"sync"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	P "github.com/ProjectClash/Clash/constant/provider"
	"github.com/ProjectClash/Clash/tunnel"
	"github.com/ProjectClash/Clash/tunnel/statistic"
)

func StatusJSON() string {
	return bridgeSafeString(mustJSON(map[string]string{
		"status": tunnel.Status().String(),
		"mode":   tunnel.Mode().String(),
	}))
}

type trafficRateSource interface {
	LastRate() (up, down int64, sampledAt time.Time, fresh bool)
	Now() (up, down int64)
	Total() (up, down int64)
}

var trafficRates trafficRateSource = statistic.DefaultManager

func TrafficJSON() string {
	source := trafficRates
	up, down, sampledAt, current := source.LastRate()
	source.Now()
	fresh, sampledAtMs := int64(0), int64(0)
	if current {
		fresh = 1
	}
	if !sampledAt.IsZero() {
		sampledAtMs = sampledAt.UnixMilli()
	}
	upTotal, downTotal := source.Total()
	return bridgeSafeString(mustJSON(map[string]int64{
		"up":                  up,
		"down":                down,
		"upTotal":             upTotal,
		"downTotal":           downTotal,
		"rateFresh":           fresh,
		"rateSampledAtUnixMs": sampledAtMs,
		"memory":              MemoryFootprint(),
	}))
}

func ConnectionsJSON() string {
	return bridgeSafeString(mustJSON(statistic.DefaultManager.Snapshot()))
}

func ProxiesJSON() string {
	if library := tunnel.ProxyLibrary(); library != nil {
		var b bytes.Buffer
		b.WriteString(`{"proxies":`)
		if err := adapter.WriteProxiesJSON(&b, tunnel.Proxies(), library); err == nil {
			b.WriteByte('}')
			return bridgeSafeString(b.String())
		}
	}
	return bridgeSafeString(proxiesJSON(tunnel.Proxies()))
}

func RuleProvidersJSON() string {
	return bridgeSafeString(mustJSON(ruleProvidersCatalog(tunnel.SnapshotRuleProviders())))
}

func ruleProvidersCatalog(providers map[string]P.RuleProvider) map[string]any {
	rows := make(map[string]any, len(providers))
	for name, provider := range providers {
		if provider == nil {
			continue
		}
		var data []byte
		var err error
		if cached, ok := provider.(interface{ LoadedMetadataJSON() ([]byte, error) }); ok {
			data, err = cached.LoadedMetadataJSON()
		} else {
			data, err = json.Marshal(provider)
		}
		if err != nil {
			continue
		}
		var row map[string]any
		if json.Unmarshal(data, &row) != nil || row == nil {
			continue
		}
		if provider.VehicleType() == P.Inline {
			row["loaded"] = true
			delete(row, "payload")
		}
		rows[name] = row
	}
	return map[string]any{"providers": rows}
}

type ringBuffer struct {
	mu    sync.Mutex
	lines []string
	max   int
}

const defaultLogMaxLines = 400

func (r *ringBuffer) add(line string) {
	r.mu.Lock()
	r.lines = append(r.lines, line)
	if len(r.lines) > r.max {
		r.lines = r.lines[len(r.lines)-r.max:]
	}
	r.mu.Unlock()
}

func (r *ringBuffer) snapshot() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.lines))
	copy(out, r.lines)
	return out
}

func (r *ringBuffer) setMax(max int) {
	if max <= 0 {
		max = defaultLogMaxLines
	}
	r.mu.Lock()
	r.max = max
	if len(r.lines) > max {
		r.lines = append([]string(nil), r.lines[len(r.lines)-max:]...)
	}
	r.mu.Unlock()
}

var recentLogs = &ringBuffer{max: defaultLogMaxLines}

func RecentLogsJSON() string {
	return bridgeSafeString(mustJSON(recentLogs.snapshot()))
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		eb, _ := json.Marshal(map[string]string{"error": err.Error()})
		return string(eb)
	}
	return string(b)
}
