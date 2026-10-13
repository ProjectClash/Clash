package provider

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/ProjectClash/Clash/adapter"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
)


func clashProviderHead(provider P.ProxyProvider) (providerForApi, C.ProxyList, bool) {
	switch p := provider.(type) {
	case *ProxySetProvider:
		return providerForApi{Name: p.Name(), Type: p.Type().String(), VehicleType: p.VehicleType().String(),
			TestUrl: p.healthCheck.url, ExpectedStatus: p.healthCheck.expectedStatus.String(),
			UpdatedAt: p.UpdatedAt(), SubscriptionInfo: p.subscriptionInfo}, p.ProxyList(), true
	case *InlineProvider:
		return providerForApi{Name: p.Name(), Type: p.Type().String(), VehicleType: p.VehicleType().String(),
			TestUrl: p.healthCheck.url, ExpectedStatus: p.healthCheck.expectedStatus.String(),
			UpdatedAt: p.updateAt}, p.ProxyList(), true
	case *CompatibleProvider:
		return providerForApi{Name: p.Name(), Type: p.Type().String(), VehicleType: p.VehicleType().String(),
			TestUrl: p.healthCheck.url, ExpectedStatus: p.healthCheck.expectedStatus.String()}, p.ProxyList(), true
	}
	return providerForApi{}, nil, false
}

func ClashProviderWritable(provider P.ProxyProvider) bool {
	_, _, ok := clashProviderHead(provider)
	return ok
}

func ClashWriteProviderJSON(w io.Writer, provider P.ProxyProvider) (ok bool, err error) {
	head, list, ok := clashProviderHead(provider)
	if !ok {
		return false, nil
	}
	nodes := []C.Proxy{}
	if list == nil {
		nodes = nil
	}
	head.Proxies = nodes
	encoded, err := json.Marshal(head)
	if err != nil {
		return true, err
	}
	at := bytes.Index(encoded, []byte(`"proxies":`))
	if at < 0 {
		return true, errors.New("provider JSON without proxies")
	}
	at += len(`"proxies":`)
	if _, err := w.Write(encoded[:at]); err != nil {
		return true, err
	}
	if list == nil {
		_, err = w.Write(encoded[at:])
		return true, err
	}
	const piece = 64 << 10
	b := make([]byte, 0, piece+4096)
	b = append(b, '[')
	for i := 0; i < list.Len(); i++ {
		if i > 0 {
			b = append(b, ',')
		}
		if b, err = adapter.AppendProxyJSON(b, list.At(i)); err != nil {
			return true, err
		}
		if len(b) >= piece {
			if _, err := w.Write(b); err != nil {
				return true, err
			}
			b = b[:0]
		}
	}
	b = append(b, ']')
	b = append(b, encoded[at+len("[]"):]...)
	_, err = w.Write(b)
	return true, err
}

func ClashProviderSummary(provider P.ProxyProvider) map[string]any {
	head, list, ok := clashProviderHead(provider)
	if !ok {
		return nil
	}
	encoded, err := json.Marshal(head)
	if err != nil {
		return nil
	}
	var summary map[string]any
	if json.Unmarshal(encoded, &summary) != nil {
		return nil
	}
	delete(summary, "proxies")
	total := 0
	if list != nil {
		total = list.Len()
	}
	summary["total"] = total
	summary["alive"], summary["dead"] = adapter.ClashHealthCounts(list)
	return summary
}
