package clash

import (
	"encoding/json"
	"runtime/debug"
	"strconv"
	"sync"
)

type ProxyPayload struct {
	mu         sync.Mutex
	summary    string
	nodes      []byte
	ends       []int
	identities []string
	closed     bool
}

func OpenProxyPayloadForIOS(payload []byte, context string) (*ProxyPayload, error) {
	view, err := recoverAppCall("OpenProxyPayloadForIOS", func() (*ProxyPayload, error) {
		report, err := proxyImportReportOf(payload, context, false)
		if err != nil {
			return nil, err
		}
		summary, err := encodeProxyImportSummary(report)
		if err != nil {
			return nil, err
		}
		view := &ProxyPayload{summary: summary, ends: make([]int, 0, len(report.Proxies)), identities: report.Identities}
		for i, proxy := range report.Proxies {
			encoded, err := json.Marshal(proxy)
			if err != nil {
				return nil, err
			}
			view.nodes = append(view.nodes, encoded...)
			view.ends = append(view.ends, len(view.nodes))
			report.Proxies[i] = nil
		}
		report = proxyImportReport{}
		debug.FreeOSMemory()
		view.nodes = append(make([]byte, 0, len(view.nodes)), view.nodes...)
		debug.FreeOSMemory()
		return view, nil
	})
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return view, nil
}

func (p *ProxyPayload) SummaryJSON() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return bridgeSafeString(`{"error":"the payload is closed"}`)
	}
	return bridgeSafeString(p.summary)
}

func (p *ProxyPayload) PageJSON(offset, limit int32) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return bridgeSafeString(`{"error":"the payload is closed"}`)
	}
	from, to := pageBounds(len(p.ends), int(offset), int(limit))
	b := make([]byte, 0, 64)
	b = append(b, `{"total":`...)
	b = strconv.AppendInt(b, int64(len(p.ends)), 10)
	b = append(b, `,"proxies":[`...)
	for i := from; i < to; i++ {
		if i > from {
			b = append(b, ',')
		}
		start := 0
		if i > 0 {
			start = p.ends[i-1]
		}
		b = append(b, p.nodes[start:p.ends[i]]...)
	}
	b = append(b, `],"identities":[`...)
	for i := from; i < to && i < len(p.identities); i++ {
		if i > from {
			b = append(b, ',')
		}
		b = appendJSONString(b, p.identities[i])
	}
	b = append(b, "]}"...)
	return bridgeSafeString(string(b))
}

func (p *ProxyPayload) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed, p.nodes, p.ends, p.identities = true, nil, nil, nil
}
