package clash

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/component/resolver"
	"github.com/ProjectClash/Clash/hub/executor"
	D "github.com/miekg/dns"
)

func TestClientDNSConfigDecidesWhoResolves(t *testing.T) {
	general, generalAddress, generalQueries := startControlledDNSServer(t, "udp")
	defer func() { _ = general.Shutdown() }()
	policy, policyAddress, policyQueries := startControlledDNSServer(t, "udp")
	defer func() { _ = policy.Shutdown() }()

	configYAML := fmt.Sprintf(`
mode: rule
dns:
  enable: true
  listen: ""
  enhanced-mode: redir-host
  default-nameserver:
    - %s
  nameserver:
    - %s
  nameserver-policy:
    "policy.controlled.test": %s
proxies:
  - {name: a, type: socks5, server: 127.0.0.1, port: 1080}
proxy-groups:
  - {name: pick, type: select, proxies: [a]}
rules:
  - MATCH,pick
`, generalAddress, generalAddress, policyAddress)

	configuration, err := executor.ParseWithBytes([]byte(configYAML))
	if err != nil {
		t.Fatalf("ParseWithBytes() error = %v\n%s", err, configYAML)
	}
	executor.ApplyConfig(configuration, true)
	if resolver.DefaultResolver == nil {
		t.Fatal("applying a dns block must install a resolver")
	}

	drain(generalQueries)
	drain(policyQueries)

	answer := exchange(t, "a.controlled.test.")
	if len(answer.Answer) != 1 {
		t.Fatalf("answer count = %d, want 1", len(answer.Answer))
	}
	if got := answer.Answer[0].(*D.A).A.String(); got != "192.0.2.10" {
		t.Fatalf("resolved %s, want the controlled server's 192.0.2.10", got)
	}
	if !observedWithin(generalQueries, 2*time.Second) {
		t.Fatal("the query never reached the configured nameserver")
	}

	if _, err := resolver.DefaultResolver.ExchangeContext(
		contextWithTimeout(t), question("policy.controlled.test."),
	); err != nil {
		t.Fatalf("policy query error = %v", err)
	}
	if !observedWithin(policyQueries, 2*time.Second) {
		t.Fatal("a policied name did not reach its policy resolver")
	}
	if observedWithin(generalQueries, 300*time.Millisecond) {
		t.Fatal("a policied name must not fall through to the general nameserver")
	}
}

func exchange(t *testing.T, name string) *D.Msg {
	t.Helper()
	response, err := resolver.DefaultResolver.ExchangeContext(
		contextWithTimeout(t), question(name),
	)
	if err != nil {
		t.Fatalf("ExchangeContext(%s) error = %v", name, err)
	}
	return response
}

func question(name string) *D.Msg {
	msg := new(D.Msg)
	msg.SetQuestion(name, D.TypeA)
	return msg
}

func contextWithTimeout(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func observedWithin(queries <-chan string, wait time.Duration) bool {
	select {
	case <-queries:
		return true
	case <-time.After(wait):
		return false
	}
}

func drain(queries <-chan string) {
	for {
		select {
		case <-queries:
		default:
			return
		}
	}
}
