package clash

import "testing"

const dnsListenDocument = `
dns:
  enable: true
  listen: 0.0.0.0:1053
  listen-routing-mark: 666
  nameserver:
    - 223.5.5.5
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`

func TestDNSListenSurvivesBothNormalizationLayers(t *testing.T) {
	mihomo, ours := parseBoth(t, dnsListenDocument)

	if mihomo.DNS.Listen != "0.0.0.0:1053" {
		t.Fatalf("fixture is wrong, not the code: mihomo parsed dns.listen as %q", mihomo.DNS.Listen)
	}

	if ours.DNS.Listen != mihomo.DNS.Listen {
		t.Fatalf("dns.listen after the raw layer: mihomo %q, ours %q", mihomo.DNS.Listen, ours.DNS.Listen)
	}
	finalizeConfigForIOS(ours, true)
	if ours.DNS.Listen != mihomo.DNS.Listen {
		t.Errorf("dns.listen after finalize: mihomo %q, ours %q -- updateDNS reads this field, "+
			"so clearing it here means the configured server never starts", mihomo.DNS.Listen, ours.DNS.Listen)
	}
}

func TestDNSListenRoutingMarkStaysStrippedBecauseDarwinHasNoSOMARK(t *testing.T) {
	_, ours := parseBoth(t, dnsListenDocument)

	if ours.DNS.ListenRoutingMark != 0 {
		t.Errorf("dns.listen-routing-mark = %d survived the raw layer", ours.DNS.ListenRoutingMark)
	}
	finalizeConfigForIOS(ours, true)
	if ours.DNS.ListenRoutingMark != 0 {
		t.Errorf("dns.listen-routing-mark = %d survived; Darwin has no SO_MARK, so carrying it "+
			"would promise a routing decision nothing can execute", ours.DNS.ListenRoutingMark)
	}
}

func TestTheOverrideLayerClearsTheMarkOnItsOwn(t *testing.T) {
	const noMark = `
dns:
  enable: true
  listen: 0.0.0.0:1053
  nameserver:
    - 223.5.5.5
proxies: []
proxy-groups: []
rules:
  - MATCH,DIRECT
`
	_, ours := parseBoth(t, noMark)
	ours.DNS.ListenRoutingMark = 666

	finalizeConfigForIOS(ours, true)

	if ours.DNS.ListenRoutingMark != 0 {
		t.Error("overrideForNetworkExtension stopped clearing dns.listen-routing-mark; the raw " +
			"layer covers the configured path, but this is the defence that survives a raw-layer edit")
	}
}
