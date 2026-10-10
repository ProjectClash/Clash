package clash

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"sort"
	"testing"
)

func TestAJSONBodyKeyNobodyMapsIsNamedUnderTheNodeAndTheNodeArrives(t *testing.T) {
	tests := []struct {
		name    string
		payload string
		node    string
		notices []string
	}{
		{
			name: "sing-box outbound, three levels deep",
			payload: `{"outbounds":[{"type":"vless","tag":"Sing","server":"sing.example.invalid","server_port":443,` +
				`"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811","domain_resolver":"local",` +
				`"tls":{"enabled":true,"server_name":"sni.example.invalid","utls":{"enabled":true,"fingerprint":"chrome","clash-no-such-key":1}},` +
				`"transport":{"type":"ws","path":"/ray","clash-no-such-key":"x"}}]}`,
			node: "Sing",
			notices: []string{
				"clash: proxy field sing-box.outbound.domain_resolver: not mapped by this importer build",
				"clash: proxy field sing-box.outbound.tls.utls.clash-no-such-key: not mapped by this importer build",
				"clash: proxy field sing-box.outbound.transport.ws.clash-no-such-key: not mapped by this importer build",
			},
		},
		{
			name: "v2ray outbound, the keys every v2ray file carries",
			payload: `{"outbounds":[{"tag":"V2Ray","protocol":"vmess","sendThrough":"0.0.0.0","mux":{"enabled":true},` +
				`"settings":{"vnext":[{"address":"v2ray.example.invalid","port":443,` +
				`"users":[{"id":"b831381d-6324-4d53-ad4f-8cda48b30811","alterId":0,"security":"auto","level":0}]}]},` +
				`"streamSettings":{"network":"ws","security":"tls","tlsSettings":{"serverName":"sni.example.invalid"},` +
				`"wsSettings":{"path":"/ray","headers":{"Host":"cdn.example.invalid"},"clash-no-such-key":true}}}]}`,
			node: "V2Ray",
			notices: []string{
				"clash: proxy field v2ray.outbound.mux: not mapped by this importer build",
				"clash: proxy field v2ray.outbound.sendThrough: not mapped by this importer build",
				"clash: proxy field v2ray.outbound.settings.vnext[0].users[0].level: not mapped by this importer build",
				"clash: proxy field v2ray.outbound.streamSettings.wsSettings.clash-no-such-key: not mapped by this importer build",
			},
		},
		{
			name:    "Shadowrocket server object, the two keys the subscription carried",
			payload: `{"servers":[{"type":"trojan","remarks":"Rocket","server":"rocket.example.invalid","port":443,"password":"secret","class":0,"verify_cert":true}]}`,
			node:    "Rocket",
			notices: []string{
				"clash: proxy field json.server.class: not mapped by this importer build",
				"clash: proxy field json.server.verify_cert: not mapped by this importer build",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			box, err := InspectProxyPayloadForIOS([]byte(test.payload), "subscriptionBody")
			if err != nil {
				t.Fatalf("inspect: %v", err)
			}
			report := decodeProxyImportReport(t, box)
			if len(report.Proxies) != 1 || len(report.Skipped) != 0 {
				t.Fatalf("the node must arrive and nothing must be skipped: %#v", report)
			}
			if got := report.Proxies[0]["name"]; got != test.node {
				t.Fatalf("node name = %#v, want %q", got, test.node)
			}
			got := make([]string, 0, len(report.NotHonoured))
			for _, issue := range report.NotHonoured {
				if issue.Code != "fieldNotHonoured" || issue.Proxy != test.node {
					t.Errorf("notice must carry the code and the node's name: %#v", issue)
				}
				got = append(got, issue.Message)
			}
			sort.Strings(got)
			if !reflect.DeepEqual(got, test.notices) {
				t.Fatalf("notices = %#v\nwant      %#v", got, test.notices)
			}
		})
	}
}

func TestAContainerNoticeWaitsForTheNameTheNodeEndsUpWith(t *testing.T) {
	payload := `{"outbounds":[` +
		`{"type":"trojan","tag":"HK","server":"one.example.invalid","server_port":443,"password":"a","clash-first":1},` +
		`{"type":"trojan","tag":"HK","server":"two.example.invalid","server_port":443,"password":"b","clash-second":1}]}`
	box, err := InspectProxyPayloadForIOS([]byte(payload), "subscriptionBody")
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	report := decodeProxyImportReport(t, box)
	if len(report.Proxies) != 2 || len(report.Skipped) != 0 || len(report.NotHonoured) != 2 {
		t.Fatalf("report = %#v", report)
	}
	byNode := map[string]string{}
	for _, issue := range report.NotHonoured {
		byNode[issue.Proxy] = issue.Message
	}
	want := map[string]string{
		"HK":    "clash: proxy field sing-box.outbound.clash-first: not mapped by this importer build",
		"HK-01": "clash: proxy field sing-box.outbound.clash-second: not mapped by this importer build",
	}
	if !reflect.DeepEqual(byNode, want) {
		t.Fatalf("notices by node = %#v, want %#v", byNode, want)
	}
}

func TestAContainerNoticeRidesWithTheSkipWhenTheRecordProducesNoNode(t *testing.T) {
	payload := `{"outbounds":[{"type":"vless","tag":"NoUUID","server":"sing.example.invalid","server_port":443,"domain_resolver":"local"}]}`
	box, err := InspectProxyPayloadForIOS([]byte(payload), "subscriptionBody")
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	report := decodeProxyImportReport(t, box)
	if len(report.Proxies) != 0 || len(report.Skipped) != 1 || len(report.NotHonoured) != 0 {
		t.Fatalf("report = %#v", report)
	}
	skip := report.Skipped[0]
	if skip.Code != "malformedRecord" {
		t.Fatalf("the record must be skipped for its own reason, not the key: %#v", skip)
	}
	want := []string{"clash: proxy field sing-box.outbound.domain_resolver: not mapped by this importer build"}
	if !reflect.DeepEqual(skip.AlsoNotHonoured, want) {
		t.Fatalf("alsoNotHonoured = %#v, want %#v", skip.AlsoNotHonoured, want)
	}
}

func TestAFalseInABodyIsAValueAndIsNamed(t *testing.T) {
	payload := `{"servers":[{"type":"trojan","server":"e.example","port":443,"password":"pw",` +
		`"remarks":"Rocket","verify_cert":false,"blank":"","nothing":[],"empty":{}}]}`
	box, err := InspectProxyPayloadForIOS([]byte(payload), "subscriptionBody")
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	report := decodeProxyImportReport(t, box)
	if len(report.Proxies) != 1 || len(report.Skipped) != 0 {
		t.Fatalf("the node did not arrive: proxies=%#v skipped=%#v", report.Proxies, report.Skipped)
	}
	got := make([]string, 0, len(report.NotHonoured))
	for _, notice := range report.NotHonoured {
		got = append(got, notice.Message)
	}
	want := []string{"clash: proxy field json.server.verify_cert: not mapped by this importer build"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("notices = %#v, want %#v", got, want)
	}
}

func TestAVMessBodyNoticeRidesWithTheSkipWhenUpstreamYieldsNoNode(t *testing.T) {
	body, err := json.Marshal(map[string]any{
		"v": "2", "add": "e.example", "port": "443",
		"id": "11111111-1111-1111-1111-111111111111", "class": json.Number("0"),
	})
	if err != nil {
		t.Fatal(err)
	}
	link := "vmess://" + base64.StdEncoding.EncodeToString(body)
	box, err := InspectProxyPayloadForIOS([]byte(link), "singleNode")
	if err != nil {
		t.Fatalf("inspect: %v", err)
	}
	report := decodeProxyImportReport(t, box)
	if len(report.Proxies) != 0 || len(report.Skipped) != 1 || len(report.NotHonoured) != 0 {
		t.Fatalf("expected one skip and nothing else: proxies=%#v skipped=%#v notHonoured=%#v",
			report.Proxies, report.Skipped, report.NotHonoured)
	}
	want := []string{"clash: proxy field vmess.base64-json.class: not mapped by this importer build"}
	if !reflect.DeepEqual(report.Skipped[0].AlsoNotHonoured, want) {
		t.Fatalf("skip = %#v, want alsoNotHonoured %#v", report.Skipped[0], want)
	}
}

func TestOneUnreadableServerRecordDoesNotCostTheRestOfTheArray(t *testing.T) {
	ssd := `{"airport":"Example","port":8388,"encryption":"aes-128-gcm","password":"secret","servers":[` +
		`{"server":"a.example","remarks":"A"},` +
		`{"remarks":"B","class":0},` +
		`{"server":"c.example","remarks":"C"}]}`
	for _, test := range []struct {
		name            string
		payload         string
		names           []string
		skipMessage     string
		alsoNotHonoured []string
	}{
		{
			name: "sip008 servers, the middle one with no port",
			payload: `{"servers":[` +
				`{"server":"a.example","server_port":8388,"method":"aes-128-gcm","password":"pw","remarks":"A"},` +
				`{"server":"b.example","method":"aes-128-gcm","password":"pw","remarks":"B","class":0},` +
				`{"server":"c.example","server_port":8388,"method":"aes-128-gcm","password":"pw","remarks":"C"}]}`,
			names:           []string{"A", "C"},
			skipMessage:     "server 1: missing server or port",
			alsoNotHonoured: []string{"clash: proxy field json.server.class: not mapped by this importer build"},
		},
		{
			name:            "ssd servers, the middle one with no server",
			payload:         "ssd://" + base64.RawURLEncoding.EncodeToString([]byte(ssd)),
			names:           []string{"A", "C"},
			skipMessage:     "server 1: missing server or port",
			alsoNotHonoured: []string{"clash: proxy field json.server.class: not mapped by this importer build"},
		},
		{
			name: "canonical proxies, the middle one not an object",
			payload: `{"proxies":[` +
				`{"name":"A","type":"ss","server":"a.example","port":8388,"cipher":"aes-128-gcm","password":"pw"},` +
				`"not a proxy",` +
				`{"name":"C","type":"ss","server":"c.example","port":8388,"cipher":"aes-128-gcm","password":"pw"}]}`,
			names:       []string{"A", "C"},
			skipMessage: "proxy 1 must be an object",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			box, err := InspectProxyPayloadForIOS([]byte(test.payload), "subscriptionBody")
			if err != nil {
				t.Fatalf("one unreadable record cost the whole document: %v", err)
			}
			report := decodeProxyImportReport(t, box)
			names := make([]string, 0, len(report.Proxies))
			for _, proxy := range report.Proxies {
				name, _ := proxy["name"].(string)
				names = append(names, name)
			}
			if !reflect.DeepEqual(names, test.names) {
				t.Fatalf("the readable records did not survive: %v, want %v", names, test.names)
			}
			if len(report.Skipped) != 1 || report.Skipped[0].Code != "malformedRecord" ||
				report.Skipped[0].Index != 1 || report.Skipped[0].Message != test.skipMessage {
				t.Fatalf("expected one malformedRecord skip at index 1 saying %q, got %#v", test.skipMessage, report.Skipped)
			}
			if !reflect.DeepEqual(report.Skipped[0].AlsoNotHonoured, test.alsoNotHonoured) {
				t.Fatalf("skip alsoNotHonoured = %#v, want %#v", report.Skipped[0].AlsoNotHonoured, test.alsoNotHonoured)
			}
			if len(report.NotHonoured) != 0 {
				t.Fatalf("the surviving nodes named nothing, got %#v", report.NotHonoured)
			}
		})
	}
}
