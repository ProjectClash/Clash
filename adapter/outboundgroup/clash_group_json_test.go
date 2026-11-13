package outboundgroup

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/adapter/provider"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
)

func TestGroupsWriteTheirMarshalJSON(t *testing.T) {
	var members []C.Proxy
	for i := 0; i < 5; i++ {
		members = append(members, adapter.NewProxy(outbound.NewDirectWithOption(outbound.DirectOption{Name: fmt.Sprintf("HK <%d> & \"co\" 🇭🇰", i)})))
	}
	empty := adapter.NewProxy(outbound.NewCompatible())
	for _, filter := range []string{"", "matches nothing"} {
		compatible, err := provider.NewCompatibleProvider("members", members, provider.NewHealthCheck(members, "", 0, 0, true, nil))
		if err != nil {
			t.Fatal(err)
		}
		providers := []P.ProxyProvider{compatible}
		common := GroupCommonOption{Name: "g <&>", URL: "https://example.net/<&>", Icon: "i<&>", Hidden: true, ExpectedStatus: "204", Filter: filter}
		selector, err := NewSelector(common, SelectorOption{}, empty, providers)
		if err != nil {
			t.Fatal(err)
		}
		defaultURL := common
		defaultURL.URL = C.DefaultTestURL
		selectorDefault, err := NewSelector(defaultURL, SelectorOption{}, empty, providers)
		if err != nil {
			t.Fatal(err)
		}
		urlTest, err := NewURLTest(common, URLTestOption{}, empty, providers)
		if err != nil {
			t.Fatal(err)
		}
		fallback, err := NewFallback(common, FallbackOption{}, empty, providers)
		if err != nil {
			t.Fatal(err)
		}
		loadBalance, err := NewLoadBalance(common, LoadBalanceOption{Strategy: "round-robin"}, empty, providers)
		if err != nil {
			t.Fatal(err)
		}
		for _, group := range []interface {
			MarshalJSON() ([]byte, error)
			ClashAppendJSON([]byte) []byte
		}{selector, selectorDefault, urlTest, fallback, loadBalance} {
			want, err := group.MarshalJSON()
			if err != nil {
				t.Fatal(err)
			}
			if got := group.ClashAppendJSON(nil); string(got) != string(want) {
				t.Errorf("%T, filter %q:\n got  %s\n want %s", group, filter, got, want)
			}
		}
	}
}

func TestAGroupWithADeadFixedMemberWritesItsMarshalJSON(t *testing.T) {
	const testURL = "http://127.0.0.1:1/"
	var members []C.Proxy
	for i := 0; i < 3; i++ {
		members = append(members, adapter.NewProxy(outbound.NewDirectWithOption(outbound.DirectOption{Name: fmt.Sprintf("member %d", i)})))
	}
	dead := members[1]
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := dead.URLTest(ctx, testURL, nil); err == nil {
		t.Fatal("the test of a URL nothing answers succeeded")
	}
	if dead.AliveForTestUrl(testURL) {
		t.Fatal("the member is alive after its test failed")
	}
	compatible, err := provider.NewCompatibleProvider("members", members, provider.NewHealthCheck(members, "", 0, 0, true, nil))
	if err != nil {
		t.Fatal(err)
	}
	providers := []P.ProxyProvider{compatible}
	empty := adapter.NewProxy(outbound.NewCompatible())
	common := GroupCommonOption{Name: "g", URL: testURL}
	fallback, err := NewFallback(common, FallbackOption{}, empty, providers)
	if err != nil {
		t.Fatal(err)
	}
	urlTest, err := NewURLTest(common, URLTestOption{}, empty, providers)
	if err != nil {
		t.Fatal(err)
	}
	for _, group := range []interface {
		ForceSet(string)
		MarshalJSON() ([]byte, error)
		ClashAppendJSON([]byte) []byte
		ClashAppendSummaryJSON([]byte) []byte
	}{fallback, urlTest} {
		group.ForceSet(dead.Name())
		want, err := group.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		group.ForceSet(dead.Name())
		if got := group.ClashAppendJSON(nil); string(got) != string(want) {
			t.Errorf("%T:\n got  %s\n want %s", group, got, want)
		}
		fixed := `"fixed":"` + dead.Name() + `"`
		if group == any(fallback) {
			fixed = `"fixed":""`
		}
		if !strings.Contains(string(want), fixed) {
			t.Fatalf("%T: upstream's bytes do not have %s: %s", group, fixed, want)
		}
		group.ForceSet(dead.Name())
		if got := group.ClashAppendSummaryJSON(nil); !strings.Contains(string(got), fixed) {
			t.Errorf("%T: the summary does not have %s: %s", group, fixed, got)
		}
	}
}
