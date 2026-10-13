package adapter

import (
	"sync"
	"sync/atomic"

	"github.com/ProjectClash/Clash/adapter/outbound"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/log"
)


var clashNodeCatalogOff atomic.Bool

func SetNodeCatalog(on bool) (previous bool) {
	return !clashNodeCatalogOff.Swap(!on)
}

var catalogBuildOverride outbound.NodeBuilder

func catalogKeepsBuilt(proxyType string) bool {
	switch proxyType {
	case "tailscale", "zerotier", "easytier":
		return true
	}
	return false
}

func clashCatalogConfig(mapping map[string]any, proxyType string, opt proxyOption) (config string, ok bool) {
	if opt.clashBuilt != nil || clashNodeCatalogOff.Load() || catalogKeepsBuilt(proxyType) {
		return "", false
	}
	return encodeNodeConfig(mapping)
}

func clashCatalogNode(built outbound.ProxyAdapter, config string, ok bool, opt proxyOption) outbound.ProxyAdapter {
	if !ok {
		return built
	}
	build := outbound.NodeBuilder(buildCatalogNode)
	if catalogBuildOverride != nil {
		build = catalogBuildOverride
	}
	if store := opt.clashSession.storeFor(opt, build); store != nil {
		node, _ := outbound.NewCatalogNode(built, config, store)
		return node
	}
	node, _ := outbound.NewSingleCatalogNode(built, config, opt.ProviderName, opt.DialerForAPI, opt.TunnelForAPI, build)
	return node
}

type NodeCatalogSession struct {
	mu    sync.Mutex
	store *outbound.NodeStore
}

func NewNodeCatalogSession() *NodeCatalogSession { return &NodeCatalogSession{} }

func WithNodeCatalogSession(session *NodeCatalogSession) ProxyOption {
	return func(opt *proxyOption) { opt.clashSession = session }
}

func (s *NodeCatalogSession) storeFor(opt proxyOption, build outbound.NodeBuilder) *outbound.NodeStore {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.store == nil {
		s.store = outbound.NewNodeStore(opt.ProviderName, opt.DialerForAPI, opt.TunnelForAPI, build)
	}
	if !s.store.Holds(opt.ProviderName, opt.DialerForAPI, opt.TunnelForAPI) {
		return nil
	}
	return s.store
}

func (s *NodeCatalogSession) Seal() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	store := s.store
	s.mu.Unlock()
	if store == nil {
		return nil
	}
	dir, _ := nodeCatalogDirectory.Load().(string)
	err := store.Seal(dir)
	if err != nil {
		log.Warnln("[Proxy] node records stay on the heap: %v", err)
	}
	return err
}

func (s *NodeCatalogSession) Stored() (bytes int, mapped bool) {
	if s == nil {
		return 0, false
	}
	s.mu.Lock()
	store := s.store
	s.mu.Unlock()
	if store == nil {
		return 0, false
	}
	return store.Bytes()
}

var nodeCatalogDirectory atomic.Value

func SetNodeCatalogDirectory(dir string) {
	nodeCatalogDirectory.Store(dir)
}

func buildCatalogNode(config string, dialerForAPI C.Dialer, tunnelForAPI C.Tunnel, providerName string) (outbound.ProxyAdapter, error) {
	mapping, err := decodeNodeConfig(config)
	if err != nil {
		return nil, err
	}
	var built outbound.ProxyAdapter
	if _, err := ParseProxy(mapping, func(opt *proxyOption) {
		opt.DialerForAPI, opt.TunnelForAPI, opt.ProviderName = dialerForAPI, tunnelForAPI, providerName
		opt.clashBuilt = &built
	}); err != nil {
		return nil, err
	}
	return built, nil
}
