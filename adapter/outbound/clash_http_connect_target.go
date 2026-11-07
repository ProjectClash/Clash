package outbound

import (
	"strconv"

	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/log"
)

const clashConnectSniffedHostField = "x-clash-connect-sniffed-host"

func ClashConnectsSniffedHost(mapping map[string]any) bool {
	switch v := mapping[clashConnectSniffedHostField].(type) {
	case bool:
		return v
	case string:
		marked, err := strconv.ParseBool(v)
		return err == nil && marked
	}
	return false
}

func (h *Http) connectTarget(metadata *C.Metadata) string {
	if h.option.ClashConnectSniffedHost && metadata.SniffHost != "" && metadata.Host != "" {
		sniffed := *metadata
		sniffed.Host = metadata.SniffHost
		log.Debugln("[HTTP] %s --> %s asks %s for %s, the name its sniffer read", metadata.SourceDetail(), metadata.RemoteAddress(), h.Name(), sniffed.RemoteAddress())
		return sniffed.RemoteAddress()
	}
	return metadata.RemoteAddress()
}
