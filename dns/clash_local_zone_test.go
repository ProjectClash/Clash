package dns

import (
	"context"
	"errors"
	"testing"

	D "github.com/miekg/dns"
)

func TestIsLocalZone(t *testing.T) {
	for _, name := range []string{
		"local.", "nas.local.", "nas.local", "NAS.LOCAL",
		"printer._ipp._tcp.local.",
		"1.254.169.in-addr.arpa.",
		"254.169.in-addr.arpa.",
		"1.0.0.0.8.e.f.ip6.arpa.",
		"9.e.f.ip6.arpa.", "a.e.f.ip6.arpa.", "b.e.f.ip6.arpa.",
	} {
		if !IsLocalZone(name) {
			t.Fatalf("%q is a multicast-DNS name", name)
		}
	}
	for _, name := range []string{
		"example.com.", "local.example.com.", "notlocal.",
		"mylocal.", "1.168.192.in-addr.arpa.", "c.e.f.ip6.arpa.",
		"",
	} {
		if IsLocalZone(name) {
			t.Fatalf("%q is not a multicast-DNS name", name)
		}
	}
}

func restoreLocalZoneExchanger(t *testing.T) {
	t.Helper()
	previous := localZoneExchanger.Load()
	t.Cleanup(func() { localZoneExchanger.Store(previous) })
}

func TestLocalZoneIsInertWithoutAnExchanger(t *testing.T) {
	restoreLocalZoneExchanger(t)
	SetLocalZoneExchanger(nil)
	m := new(D.Msg)
	m.SetQuestion("nas.local.", D.TypeA)
	msg, ok, err := exchangeLocalZone(context.Background(), m)
	if ok || err != nil || msg != nil {
		t.Fatalf("expected the local-zone path to decline, got ok=%v err=%v", ok, err)
	}
}

func TestLocalZoneOnlyClaimsMulticastNames(t *testing.T) {
	restoreLocalZoneExchanger(t)
	var asked []string
	SetLocalZoneExchanger(func(_ context.Context, m *D.Msg) (*D.Msg, error) {
		asked = append(asked, m.Question[0].Name)
		reply := new(D.Msg)
		reply.SetReply(m)
		return reply, nil
	})

	local := new(D.Msg)
	local.SetQuestion("nas.local.", D.TypeA)
	if _, ok, err := exchangeLocalZone(context.Background(), local); !ok || err != nil {
		t.Fatalf("a .local name must be claimed, got ok=%v err=%v", ok, err)
	}

	ordinary := new(D.Msg)
	ordinary.SetQuestion("example.com.", D.TypeA)
	if _, ok, _ := exchangeLocalZone(context.Background(), ordinary); ok {
		t.Fatal("an ordinary name must not be claimed")
	}

	if len(asked) != 1 || asked[0] != "nas.local." {
		t.Fatalf("the exchanger saw %v", asked)
	}
}

func TestLocalZoneReportsThePlatformsFailure(t *testing.T) {
	restoreLocalZoneExchanger(t)
	sentinel := errors.New("daemon is not listening")
	SetLocalZoneExchanger(func(context.Context, *D.Msg) (*D.Msg, error) { return nil, sentinel })
	m := new(D.Msg)
	m.SetQuestion("nas.local.", D.TypeA)
	_, ok, err := exchangeLocalZone(context.Background(), m)
	if !ok || !errors.Is(err, sentinel) {
		t.Fatalf("expected the platform's error, got ok=%v err=%v", ok, err)
	}
}

func TestLocalZoneIgnoresAQuestionlessMessage(t *testing.T) {
	restoreLocalZoneExchanger(t)
	SetLocalZoneExchanger(func(context.Context, *D.Msg) (*D.Msg, error) {
		t.Fatal("a message with no question must never reach the exchanger")
		return nil, nil
	})
	if _, ok, _ := exchangeLocalZone(context.Background(), new(D.Msg)); ok {
		t.Fatal("a message with no question must not be claimed")
	}
}
