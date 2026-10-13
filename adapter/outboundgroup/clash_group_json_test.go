package outboundgroup

import (
	"fmt"
	"testing"

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
		compatible, err := provider.NewCompatibleProvider("members", members, nil)
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
