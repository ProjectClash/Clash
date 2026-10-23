package outboundgroup

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/adapter/provider"
	"github.com/ProjectClash/Clash/common/utils"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
)

func groupOfDirect(t *testing.T) *GroupBase {
	t.Helper()
	direct := []C.Proxy{adapter.NewProxy(outbound.NewDirect())}
	compatible, err := provider.NewCompatibleProvider("members", direct, provider.NewHealthCheck(direct, "", 0, 0, true, nil))
	if err != nil {
		t.Fatal(err)
	}
	return NewGroupBase(GroupBaseOption{Name: "g", Type: C.URLTest, Providers: []P.ProxyProvider{compatible}})
}

func TestAGroupDelayTreatsAnUnexpectedStatusAsAFailureWhenExpectedIsGiven(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	expected, err := utils.NewUnsignedRanges[uint16]("200-299")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	delays, err := groupOfDirect(t).URLTest(ctx, server.URL, expected)
	if err == nil || len(delays) != 0 {
		t.Fatalf("with expected=200-299 a 503 member is a failure, got %v, %v", delays, err)
	}
	delays, err = groupOfDirect(t).URLTest(ctx, server.URL, nil)
	if err != nil || delays["DIRECT"] == 0 {
		t.Fatalf("without expected any answer counts, got %v, %v", delays, err)
	}
}

func TestAGroupsTestKeepsWhyEachMemberFailed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	refusing, err := adapter.ParseProxy(map[string]any{"name": "refusing", "type": "http", "server": "127.0.0.1", "port": closed})
	if err != nil {
		t.Fatal(err)
	}
	answering := adapter.NewProxy(outbound.NewDirect())
	members := []C.Proxy{refusing, answering}
	compatible, err := provider.NewCompatibleProvider("members", members, provider.NewHealthCheck(members, "", 0, 0, true, nil))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = compatible.Close() })
	group := NewGroupBase(GroupBaseOption{Name: "g", Type: C.URLTest, Providers: []P.ProxyProvider{compatible}})
	expected, err := utils.NewUnsignedRanges[uint16]("200-299")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = group.URLTest(ctx, server.URL, expected)

	failureUnder := func(proxy C.Proxy) *adapter.URLTestFailure {
		for _, d := range proxy.(adapter.DelayRecords).AppendURLDelays(nil) {
			if d.URL == server.URL {
				return d.Failure
			}
		}
		return nil
	}
	if failure := failureUnder(refusing); failure == nil || failure.Kind != "dial" || failure.Message == "" {
		t.Fatalf("the refusing member's failure: %+v", failure)
	}
	if failure := failureUnder(answering); failure == nil || failure.Kind != adapter.URLTestFailureStatus || failure.HTTPStatus != http.StatusServiceUnavailable {
		t.Fatalf("the answering member's failure: %+v", failure)
	}
	if _, failure, _ := refusing.(adapter.DelayRecords).LastRecord(); failure == nil {
		t.Fatal("the refusing member's newest record has no failure")
	}
}
