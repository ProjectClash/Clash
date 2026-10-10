package dns

import (
	"testing"
	"time"

	D "github.com/miekg/dns"
)


func negativeReply(t *testing.T, rcode int, soaHeaderTTL, soaMinimum uint32) *D.Msg {
	t.Helper()
	question := new(D.Msg)
	question.SetQuestion("absent.example.com.", D.TypeA)
	reply := new(D.Msg)
	reply.SetReply(question)
	reply.Rcode = rcode
	reply.Ns = []D.RR{&D.SOA{
		Hdr: D.RR_Header{
			Name: "example.com.", Rrtype: D.TypeSOA, Class: D.ClassINET, Ttl: soaHeaderTTL,
		},
		Ns: "ns.example.com.", Mbox: "root.example.com.", Minttl: soaMinimum,
	}}
	return reply
}

func cachedLifetime(t *testing.T, reply *D.Msg) (time.Duration, bool) {
	t.Helper()
	cache := Config{}.newCache()
	question := reply.Question[0]
	before := time.Now()
	putMsgToCache(cache, question, reply)
	_, expireAt, hit := getMsgFromCache(cache, question)
	if !hit {
		return 0, false
	}
	return expireAt.Sub(before).Truncate(time.Second) + time.Second, true
}

func TestNXDomainTakesTheSOAHeaderTTLLikeMihomo(t *testing.T) {
	lifetime, hit := cachedLifetime(t, negativeReply(t, D.RcodeNameError, 7200, 60))
	if !hit {
		t.Fatal("an NXDOMAIN carrying an SOA was not cached at all")
	}
	if lifetime != 7200*time.Second {
		t.Fatalf("cached for %v, want 7200s. mihomo's putMsgToCache takes minimalTTL over "+
			"Answer+Ns+Extra, which for a negative answer is the SOA's header TTL; bounding "+
			"it by SOA MINIMUM is RFC 2308 and is not what upstream does", lifetime)
	}
}

func TestNoDataTakesTheSameUnbranchedPath(t *testing.T) {
	lifetime, hit := cachedLifetime(t, negativeReply(t, D.RcodeSuccess, 1800, 30))
	if !hit {
		t.Fatal("a NODATA answer was not cached")
	}
	if lifetime != 1800*time.Second {
		t.Fatalf("cached for %v, want 1800s", lifetime)
	}
}

func TestNegativeAnswerWithoutSOAIsStillCached(t *testing.T) {
	question := new(D.Msg)
	question.SetQuestion("absent.example.com.", D.TypeA)
	reply := new(D.Msg)
	reply.SetReply(question)
	reply.Rcode = D.RcodeNameError
	reply.Ns = []D.RR{&D.NSEC{
		Hdr: D.RR_Header{
			Name: "absent.example.com.", Rrtype: D.TypeNSEC, Class: D.ClassINET, Ttl: 300,
		},
		NextDomain: "next.example.com.",
	}}

	lifetime, hit := cachedLifetime(t, reply)
	if !hit {
		t.Fatal("mihomo caches this on the NSEC's TTL; refusing to cache it is the RFC's rule, not upstream's")
	}
	if lifetime != 300*time.Second {
		t.Fatalf("cached for %v, want 300s (the NSEC's own TTL)", lifetime)
	}
}

func TestCNAMEOnlyAnswerIsCachedOnTheCNAMETTL(t *testing.T) {
	question := new(D.Msg)
	question.SetQuestion("alias.example.com.", D.TypeA)
	reply := new(D.Msg)
	reply.SetReply(question)
	reply.Answer = []D.RR{&D.CNAME{
		Hdr: D.RR_Header{
			Name: "alias.example.com.", Rrtype: D.TypeCNAME, Class: D.ClassINET, Ttl: 3600,
		},
		Target: "target.example.com.",
	}}
	reply.Ns = []D.RR{&D.SOA{
		Hdr: D.RR_Header{
			Name: "example.com.", Rrtype: D.TypeSOA, Class: D.ClassINET, Ttl: 3600,
		},
		Ns: "ns.example.com.", Mbox: "root.example.com.", Minttl: 60,
	}}

	lifetime, hit := cachedLifetime(t, reply)
	if !hit {
		t.Fatal("a CNAME-only answer was not cached")
	}
	if lifetime != 3600*time.Second {
		t.Fatalf("cached for %v, want 3600s: mihomo sees records with a 3600 TTL and caches "+
			"for that; the SOA MINIMUM of 60 is the RFC's bound, not upstream's", lifetime)
	}
}

func TestZeroTTLIsStillNotCached(t *testing.T) {
	if _, hit := cachedLifetime(t, negativeReply(t, D.RcodeNameError, 0, 0)); hit {
		t.Fatal("an answer whose minimal TTL is zero was cached")
	}
}

func TestServerFailureKeepsUpstreamsOwnBound(t *testing.T) {
	lifetime, hit := cachedLifetime(t, negativeReply(t, D.RcodeServerFailure, 7200, 60))
	if !hit {
		t.Fatal("a SERVFAIL was not cached")
	}
	want := time.Duration(serverFailureCacheTTL) * time.Second
	if lifetime != want {
		t.Fatalf("cached for %v, want %v (upstream's serverFailureCacheTTL)", lifetime, want)
	}
}
