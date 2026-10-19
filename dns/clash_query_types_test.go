package dns

import (
	"context"
	"testing"

	"github.com/ProjectClash/Clash/component/fakeip"
	icontext "github.com/ProjectClash/Clash/context"

	D "github.com/miekg/dns"
)

func boolPointer(b bool) *bool { return &b }

func TestQueryTypesAnswerEmptyWhatTheyRefuse(t *testing.T) {
	types := []uint16{D.TypeA, D.TypeAAAA, D.TypeHTTPS, D.TypeSVCB, D.TypeTXT, D.TypeMX}
	for name, tc := range map[string]struct {
		q       QueryTypes
		reached []bool
	}{
		"left out":                {QueryTypes{}, []bool{true, true, true, true, true, true}},
		"svcb false":              {QueryTypes{SVCB: boolPointer(false)}, []bool{true, true, false, false, true, true}},
		"svcb true":               {QueryTypes{SVCB: boolPointer(true)}, []bool{true, true, true, true, true, true}},
		"others false":            {QueryTypes{Others: boolPointer(false)}, []bool{true, true, false, false, false, false}},
		"others false, svcb true": {QueryTypes{Others: boolPointer(false), SVCB: boolPointer(true)}, []bool{true, true, true, true, false, false}},
		"others true, svcb false": {QueryTypes{Others: boolPointer(true), SVCB: boolPointer(false)}, []bool{true, true, false, false, true, true}},
	} {
		for i, qtype := range types {
			reached := false
			h := withQueryTypes(tc.q, func(_ *icontext.DNSContext, r *D.Msg) (*D.Msg, error) { reached = true; return r, nil })
			m := new(D.Msg)
			m.SetQuestion("example.com.", qtype)
			reply, err := h(icontext.NewDNSContext(context.Background()), m)
			if err != nil || reached != tc.reached[i] {
				t.Errorf("%s, %s: reached %v (%v), want %v", name, D.TypeToString[qtype], reached, err, tc.reached[i])
			}
			if !reached && (reply == nil || len(reply.Answer) != 0 || reply.Rcode != D.RcodeSuccess) {
				t.Errorf("%s, %s: refused with %v, want an empty success", name, D.TypeToString[qtype], reply)
			}
		}
	}
}

func TestFakeIPLetsSVCBThroughWhenAsked(t *testing.T) {
	for answer, want := range map[bool]bool{false: false, true: true} {
		reached := false
		h := withFakeIP(&fakeip.Skipper{}, nil, nil, 60, answer)(func(_ *icontext.DNSContext, r *D.Msg) (*D.Msg, error) { reached = true; return r, nil })
		m := new(D.Msg)
		m.SetQuestion("example.com.", D.TypeHTTPS)
		if _, err := h(icontext.NewDNSContext(context.Background()), m); err != nil || reached != want {
			t.Errorf("answer-svcb %v: the resolver was reached %v (%v), want %v", answer, reached, err, want)
		}
	}
}
