package clash

import (
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	C "github.com/ProjectClash/Clash/constant"
	LC "github.com/ProjectClash/Clash/listener/config"
	R "github.com/ProjectClash/Clash/rules"
	"github.com/ProjectClash/Clash/tunnel"
	mhttp "github.com/metacubex/http"
	"github.com/metacubex/http/httptest"
)

func TestRuleMatchQueriesAreValidated(t *testing.T) {
	for query, wantBad := range map[string]bool{
		"":                               true,
		"?host=example.com":              false,
		"?ip=93.184.216.34":              false,
		"?host=1.2.3.4":                  false,
		"?host=1.2.3.4&ip=5.6.7.8":       true,
		"?ip=nope":                       true,
		"?host=a.b&port=70000":           true,
		"?host=a.b&port=0":               true,
		"?host=a.b&network=icmp":         true,
		"?host=a.b&network=udp&port=53":  false,
		"?host=a.b&src=192.168.1.2:5000": false,
		"?host=a.b&src=nope":             true,
	} {
		request, _ := mhttp.NewRequest(http.MethodGet, "http://x/clash/v1/rules/match"+query, nil)
		_, problem := parseRuleMatchQuery(request)
		if (problem != "") != wantBad {
			t.Errorf("%q: problem %q, want bad=%v", query, problem, wantBad)
		}
	}
}

func TestRuleMatchAnswersFromTheRunningRules(t *testing.T) {
	previousMode := tunnel.Mode()
	previousRules := tunnel.Rules()
	previousProxies := tunnel.Proxies()
	t.Cleanup(func() {
		tunnel.SetMode(previousMode)
		tunnel.UpdateRules(previousRules, nil, nil)
		tunnel.UpdateProxies(previousProxies, nil)
	})
	direct, err := R.ParseRule("MATCH", "", "DIRECT", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	cidr, err := R.ParseRule("IP-CIDR", "93.184.0.0/16", "DIRECT", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	tunnel.UpdateProxies(map[string]C.Proxy{"DIRECT": adapter.NewProxy(outbound.NewDirect())}, nil)
	tunnel.UpdateRules([]C.Rule{cidr, direct}, nil, nil)
	tunnel.SetMode(tunnel.Rule)

	recorder := httptest.NewRecorder()
	request, _ := mhttp.NewRequest(http.MethodGet, "http://x/clash/v1/rules/match?host=example.com&port=443", nil)
	serveRuleMatch(recorder, request)
	var reply ruleMatchReply
	if recorder.Code != http.StatusOK || json.Unmarshal(recorder.Body.Bytes(), &reply) != nil {
		t.Fatalf("%d %s", recorder.Code, recorder.Body)
	}
	if reply.Decided || len(reply.Missing) != 1 || reply.Missing[0] != "ip" || reply.Rule == nil || reply.Rule.Index != 1 || len(reply.Notes) == 0 {
		t.Fatalf("%+v", reply)
	}
}

func TestRuleMatchAssumesWhatAFlowFromThisDeviceCarries(t *testing.T) {
	input := tunnel.RuleExplainInput{Host: "example.com"}
	publishTunSourceAddress(LC.Tun{Enable: true, Inet4Address: []netip.Prefix{netip.MustParsePrefix("198.18.0.1/30")}})
	t.Cleanup(func() { publishTunSourceAddress(LC.Tun{}) })
	tun := currentTunSourceAddress()
	assumed := assumeRuleMatchDefaults(&input, tun)
	if input.DstPort != 443 || input.SrcIP != netip.MustParseAddr("198.18.0.1") ||
		strings.Join(assumed, " ") != "port=443 src=198.18.0.1 src-port=0 inbound=tun" {
		t.Fatalf("%+v %v", input, assumed)
	}
	given := tunnel.RuleExplainInput{Host: "example.com", DstPort: 80, SrcIP: netip.MustParseAddr("192.168.1.9"), SrcPort: 5000}
	if assumed := assumeRuleMatchDefaults(&given, tun); strings.Join(assumed, " ") != "inbound=tun" || given.DstPort != 80 {
		t.Fatalf("a given value was replaced: %+v %v", given, assumed)
	}
	mac := tunnel.RuleExplainInput{Host: "example.com", DstPort: 80, SrcPort: 1, ProcessAvailable: true, Process: "curl"}
	if assumed := assumeRuleMatchDefaults(&mac, netip.Addr{}); strings.Join(assumed, " ") != "inbound=tun process-path=unknown uid=unknown" {
		t.Fatalf("%v", assumed)
	}
	noTun := tunnel.RuleExplainInput{Host: "example.com"}
	if assumeRuleMatchDefaults(&noTun, netip.Addr{}); noTun.SrcIP.IsValid() {
		t.Fatal("without a tunnel there is no address every flow comes from")
	}
}
