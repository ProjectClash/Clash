package clash

import (
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/dns"
	coreListener "github.com/ProjectClash/Clash/listener"
	LC "github.com/ProjectClash/Clash/listener/config"
	"github.com/ProjectClash/Clash/tunnel"
)

func closeConfiguredInbounds() {
	var t C.Tunnel = tunnel.Tunnel
	coreListener.ReCreateHTTP(0, t)
	coreListener.ReCreateSocks(0, t)
	coreListener.ReCreateRedir(0, t)
	coreListener.ReCreateTProxy(0, t)
	coreListener.ReCreateMixed(0, t)
	coreListener.ReCreateShadowSocks("", t)
	coreListener.ReCreateVmess("", t)
	coreListener.ReCreateTuic(LC.TuicServer{}, t)
	coreListener.PatchInboundListeners(map[string]C.InboundListener{}, t, true)
	coreListener.PatchTunnel(nil, t)
	dns.ReCreateServer("", nil, nil)
}
