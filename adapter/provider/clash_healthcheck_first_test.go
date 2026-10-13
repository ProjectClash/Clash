package provider

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outbound"
	C "github.com/ProjectClash/Clash/constant"
)

type holdingNode struct {
	*outbound.Direct
	dialed  chan<- string
	release <-chan struct{}
}

func (h holdingNode) DialContext(ctx context.Context, metadata *C.Metadata) (C.Conn, error) {
	h.dialed <- h.Name()
	<-h.release
	return nil, errors.New("released")
}

func withHealthCheckFirst(t *testing.T, names ...string) {
	t.Helper()
	SetHealthCheckFirst(func() map[string]struct{} {
		first := map[string]struct{}{}
		for _, name := range names {
			first[name] = struct{}{}
		}
		return first
	})
	t.Cleanup(func() { SetHealthCheckFirst(nil) })
}

func TestARoundMeasuresTheChosenNodesFirst(t *testing.T) {
	const nodes = 12
	dialed := make(chan string, nodes)
	release := make(chan struct{})
	proxies := make([]C.Proxy, 0, nodes)
	for i := 0; i < nodes; i++ {
		direct := outbound.NewDirectWithOption(outbound.DirectOption{Name: fmt.Sprintf("n%02d", i)})
		proxies = append(proxies, adapter.NewProxy(holdingNode{Direct: direct, dialed: dialed, release: release}))
	}
	chosen := proxies[nodes-1].Name()
	withHealthCheckFirst(t, chosen)

	hc := NewHealthCheck(proxies, "http://127.0.0.1:1/generate_204", 2000, 0, false, nil)
	var round sync.WaitGroup
	round.Add(1)
	go func() {
		defer round.Done()
		hc.check()
	}()
	first := map[string]bool{}
	for len(first) < 10 {
		select {
		case name := <-dialed:
			first[name] = true
		case <-time.After(3 * time.Second):
			t.Fatalf("only %d probes started", len(first))
		}
	}
	close(release)
	round.Wait()
	if !first[chosen] {
		t.Fatalf("the chosen node %s was not among the first ten measured", chosen)
	}
}

func TestTheChosenFirstOrderLeavesTheProvidersListAlone(t *testing.T) {
	var proxies []C.Proxy
	for _, name := range []string{"a", "b", "c", "d"} {
		proxies = append(proxies, adapter.NewProxy(outbound.NewDirectWithOption(outbound.DirectOption{Name: name})))
	}
	withHealthCheckFirst(t, "c", "a")
	ordered := C.ProxiesOf(chosenFirst(C.ProxySlice(proxies)))
	var got, kept []string
	for _, proxy := range ordered {
		got = append(got, proxy.Name())
	}
	for _, proxy := range proxies {
		kept = append(kept, proxy.Name())
	}
	if fmt.Sprint(got) != "[a c b d]" || fmt.Sprint(kept) != "[a b c d]" {
		t.Fatalf("ordered %v, provider %v", got, kept)
	}
	SetHealthCheckFirst(nil)
	if ordered := C.ProxiesOf(chosenFirst(C.ProxySlice(proxies))); &ordered[0] != &proxies[0] {
		t.Fatal("with no hook the provider's list is not used as is")
	}
}
