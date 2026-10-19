package clash

import (
	"encoding/json"
	"testing"
)

func TestTheOfflineMatchReadsTheInboundAndTheProtocolWhenTheQueryGivesThem(t *testing.T) {
	setupForMatch(t)
	document := "proxies:\n  - {name: P, type: direct}\nrules:\n" +
		"  - IN-PORT,6152,P\n" +
		"  - IN-NAME,mixed-in,P\n" +
		"  - IN-TYPE,HTTP,P\n" +
		"  - PROTOCOL,HTTPS,P\n" +
		"  - SUBNET,TYPE:WIFI,P\n" +
		"  - MATCH,DIRECT\n"
	for name, tc := range map[string]struct {
		query  string
		result matchRuleResult
		index  int
	}{
		"no inbound":       {`{"host":"a.example","port":443}`, matchRuleResult{Undecided: true, Rule: "IN-PORT,6152,P", Reason: "needsInbound"}, 0},
		"its port":         {`{"host":"a.example","port":443,"inPort":6152,"inName":"x"}`, matchRuleResult{Matched: true, Rule: "IN-PORT,6152,P", Policy: "P"}, 0},
		"its name":         {`{"host":"a.example","port":443,"inPort":7890,"inName":"mixed-in"}`, matchRuleResult{Matched: true, Rule: "IN-NAME,mixed-in,P", Policy: "P"}, 1},
		"its type":         {`{"host":"a.example","port":443,"inPort":7890,"inName":"x","inType":"http"}`, matchRuleResult{Matched: true, Rule: "IN-TYPE,HTTP,P", Policy: "P"}, 2},
		"no protocol":      {`{"host":"a.example","port":443,"inPort":7890,"inName":"x"}`, matchRuleResult{Undecided: true, Rule: "PROTOCOL,HTTPS,P", Reason: "needsProtocol"}, 3},
		"TLS":              {`{"host":"a.example","port":443,"inPort":7890,"inName":"x","protocol":"tls"}`, matchRuleResult{Matched: true, Rule: "PROTOCOL,HTTPS,P", Policy: "P"}, 3},
		"another protocol": {`{"host":"a.example","port":443,"inPort":7890,"inName":"x","protocol":"other"}`, matchRuleResult{Undecided: true, Rule: "SUBNET,TYPE:WIFI,P", Reason: "needsNetwork"}, 4},
	} {
		box, err := MatchRuleForIOS(document, "", tc.query)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var got matchRuleResult
		if err := json.Unmarshal([]byte(box.Value), &got); err != nil {
			t.Fatal(err)
		}
		index := got.Index
		got.Index = nil
		if got != tc.result || index == nil || *index != tc.index {
			t.Errorf("%s: %+v at %v, want %+v at %d", name, got, index, tc.result, tc.index)
		}
	}
	if _, err := MatchRuleForIOS(document, "", `{"host":"a.example","protocol":"gopher"}`); err == nil {
		t.Error("a protocol PROTOCOL does not know was accepted")
	}
	if _, err := MatchRuleForIOS(document, "", `{"host":"a.example","inType":"nowhere"}`); err == nil {
		t.Error("an inbound type the core does not know was accepted")
	}
}
