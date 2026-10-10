package clash

import (
	"regexp"
	"testing"
)

var developerRegister = regexp.MustCompile(
	`\.(go|swift)\b` +
		`|\b(?:NE|CF|NS)[A-Z][A-Za-z0-9]+\b|\b(?:TunOptions|FinalizeForIOS|StoreFakeIPSet|DefaultRawConfig)\b` +
		`|\b(?:SOCK_DGRAM|IP_BOUND_IF|SO_MARK|IP_TRANSPARENT|DIOCNATLOOK)\b` +
		`|\b(?:nftables|iptables|iproute2|netfilter|sing-tun|gVisor|bbolt)\b` +
		`|\b(?:bind|listener|hub|component|config|adapter)/[a-z_/]+\.go\b` +
		`|\b(?:ioctl|sysctl|settimeofday|readv|writev|recvmsg|sendmsg)\b` +
		`|\b(?:utun|fd|pcblist)\b` +
		`|/dev/` +
		`|\bD-\d{3}\b|\bT-[A-Z0-9-]+\b` +
		`|\b(?:mihomo|sing-box|Meta|darwin)\b`,
)

func TestUserFacingSentencesCarryNoMechanism(t *testing.T) {
	check := func(where, sentence string) {
		if m := developerRegister.FindAllString(sentence, -1); len(m) > 0 {
			t.Errorf("%s carries developer-register material %v; move it to mechanism/source:\n  %q", where, m, sentence)
		}
	}
	for _, rule := range deviationRules {
		check(rule.field+".effective", rule.effective)
		check(rule.field+".reason", rule.reason)
		check(rule.field+".alternative", rule.alternative)
	}
	for name, text := range map[string]string{
		"tunPacketTunnelShape": tunPacketTunnelShape,
		"tunRoutingIsApples":   tunRoutingIsApples,
		"tunOffloadBridge":     tunOffloadBridge,
		"tunBatchIOBridge":     tunBatchIOBridge,
		"tunAutoRouteFilter":   tunAutoRouteFilter,
	} {
		check("family "+name, text)
	}
	box, err := ConfigDeviationsJSON("rules:\n  - PROCESS-NAME,curl,DIRECT\n  - PROCESS-NAME-REGEX,.*,DIRECT\n  - MATCH,DIRECT\nproxies: []\n", RuntimeProfileIOSPacketTunnel)
	if err != nil {
		t.Fatal(err)
	}
	check("synthetic rows (whole report)", stripDeveloperOnlyFields(box.Value))
}

func stripDeveloperOnlyFields(report string) string {
	for _, key := range []string{`"source":"`, `"mechanism":"`} {
		for {
			i := indexOf(report, key)
			if i < 0 {
				break
			}
			j := i + len(key)
			for j < len(report) && !(report[j] == '"' && report[j-1] != '\\') {
				j++
			}
			report = report[:i] + `"x":"` + report[j:]
		}
	}
	return report
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
