package tunnel

import (
	"errors"
	"strings"

	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/log"
	RC "github.com/ProjectClash/Clash/rules/common"
)


var errQUICBlocked = errors.New("QUIC is blocked by x-clash-block-quic")

func quicBlocked(firstProtocol string, proxy C.Proxy, metadata *C.Metadata, mode string) bool {
	if mode == "" || firstProtocol != RC.ProtocolQUIC || proxy == nil {
		return false
	}
	switch terminalAdapterType(proxy, metadata) {
	case C.Reject, C.RejectDrop:
		return false
	case C.Direct:
		return mode == C.BlockQUICAll
	}
	return true
}

func logQUICBlocked(metadata *C.Metadata, rule C.Rule, proxy C.Proxy) {
	matched := "no rule"
	if rule != nil {
		matched = rule.RuleType().String()
		if payload := rule.Payload(); payload != "" {
			matched += "(" + payload + ")"
		}
	}
	log.Infoln("[UDP] %s --> %s match %s using %s: QUIC blocked (x-clash-block-quic), the client falls back to TCP",
		metadata.SourceDetail(), metadata.RemoteAddress(), matched, strings.Join(chainOf(proxy, metadata), "/"))
}

func chainOf(proxy C.Proxy, metadata *C.Metadata) []string {
	var chain []string
	for adapter := proxy; adapter != nil; adapter = adapter.Unwrap(metadata, false) {
		chain = append(chain, adapter.Name())
	}
	return chain
}
