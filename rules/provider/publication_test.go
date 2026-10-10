package provider

import (
	"encoding/json"
	"path/filepath"
	"sync"
	"testing"

	"github.com/ProjectClash/Clash/common/utils"
	"github.com/ProjectClash/Clash/component/resource"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
)

type publicationTunnel struct {
	callback *utils.Callback[P.RuleProvider]
}

func (p publicationTunnel) Providers() map[string]P.ProxyProvider               { return nil }
func (p publicationTunnel) RuleProviders() map[string]P.RuleProvider            { return nil }
func (p publicationTunnel) RuleUpdateCallback() *utils.Callback[P.RuleProvider] { return p.callback }

func TestRuleStrategyConcurrentPublication(t *testing.T) {
	old := tunnel
	SetTunnel(publicationTunnel{utils.NewCallback[P.RuleProvider]()})
	defer SetTunnel(old)
	p := NewRuleSetProvider("publication", P.Domain, P.TextRule, 0,
		resource.NewFileVehicle(filepath.Join(t.TempDir(), "rules.txt")), []string{"shared.example"}, nil, nil).(*RuleSetProvider)
	defer p.Close()
	var wg sync.WaitGroup
	start := make(chan struct{})
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			metadata := &C.Metadata{Host: "shared.example"}
			for iteration := 0; iteration < 1000; iteration++ {
				if !p.Match(metadata, C.RuleMatchHelper{}) {
					t.Error("published strategy lost shared rule")
					return
				}
				if n := p.Count(); n < 1 || n > 2 {
					t.Errorf("invalid published count %d", n)
					return
				}
				s := p.Strategy().(ruleStrategy)
				if !s.Match(metadata, C.RuleMatchHelper{}) {
					t.Error("incomplete strategy snapshot")
					return
				}
				if _, err := json.Marshal(p); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	close(start)
	for i := 0; i < 100; i++ {
		data := []byte("shared.example\n")
		if i%2 == 0 {
			data = []byte("shared.example\nsecond.example\n")
		}
		if err := p.SideUpdate(data); err != nil {
			t.Error(err)
			break
		}
	}
	wg.Wait()
}
