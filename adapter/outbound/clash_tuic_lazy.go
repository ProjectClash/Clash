package outbound

import (
	"sync"
	"sync/atomic"

	"github.com/metacubex/quic-go"
	"github.com/metacubex/tls"
)

type clashTuicConfigs struct {
	mu     sync.Mutex
	built  atomic.Pointer[clashTuicBuilt]
	kept   bool
	builds int
}

type clashTuicBuilt struct {
	tls  *tls.Config
	quic *quic.Config
}

func (t *Tuic) clashKeepParsedConfigs(parsed *tls.Config) {
	if t.option.Certificate == "" && t.option.PrivateKey == "" {
		return
	}
	t.clashConfigs.kept = true
	t.clashConfigs.built.Store(&clashTuicBuilt{tls: parsed, quic: newTuicQUICConfig(t.option)})
}

func (t *Tuic) clashDialConfigs() (*tls.Config, *quic.Config, error) {
	c := &t.clashConfigs
	if built := c.built.Load(); built != nil {
		return built.tls, built.quic, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if built := c.built.Load(); built != nil {
		return built.tls, built.quic, nil
	}
	tlsConfig, err := newTuicTLSConfig(t.option)
	if err != nil {
		return nil, nil, err
	}
	built := &clashTuicBuilt{tls: tlsConfig, quic: newTuicQUICConfig(t.option)}
	c.built.Store(built)
	c.builds++
	return built.tls, built.quic, nil
}

func (t *Tuic) clashReleaseConfigs() {
	c := &t.clashConfigs
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.kept {
		c.built.Store(nil)
	}
}

func (t *Tuic) clashConfigBuilds() int {
	t.clashConfigs.mu.Lock()
	defer t.clashConfigs.mu.Unlock()
	return t.clashConfigs.builds
}
