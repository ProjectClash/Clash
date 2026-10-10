package dns

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/component/resolver"
	D "github.com/miekg/dns"
)

type refusingClient struct{}

func (refusingClient) ExchangeContext(context.Context, *D.Msg) (*D.Msg, error) {
	return nil, errors.New("read udp 127.0.0.1:61234->127.0.0.1:7874: read: connection refused")
}
func (refusingClient) Address() string  { return "udp://127.0.0.1:7874" }
func (refusingClient) ResetConnection() {}

func TestLookupIPKeepsTheUpstreamFailureBehindErrIPNotFound(t *testing.T) {
	r := &Resolver{main: []dnsClient{refusingClient{}}, cache: Config{}.newCache()}
	_, err := r.LookupIP(context.Background(), "relay.example")
	if err == nil {
		t.Fatal("a refused upstream must fail the lookup")
	}
	if !errors.Is(err, resolver.ErrIPNotFound) {
		t.Fatalf("callers match on ErrIPNotFound; got %v", err)
	}
	if !strings.Contains(err.Error(), "connection refused") || !strings.Contains(err.Error(), "127.0.0.1:7874") {
		t.Fatalf("the failure that produced it must be in the sentence: %v", err)
	}
}
