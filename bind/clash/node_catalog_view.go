package clash

import (
	"bytes"
	"sync"

	"github.com/ProjectClash/Clash/config"
)

type NodeCatalog struct {
	mu             sync.Mutex
	cfg            *config.Config
	view           nodeView
	providerErrors map[string]string
	configs        nodeConfigSources
}

func OpenNodeCatalogForIOS(configContent, resourceMapJSON, selectionsJSON string) (*NodeCatalog, error) {
	catalog, err := recoverAppCall("OpenNodeCatalogForIOS", func() (*NodeCatalog, error) {
		cfg, providerErrors, document, err := openProxyCatalogDocument(configContent, resourceMapJSON, selectionsJSON)
		if err != nil {
			return nil, err
		}
		return &NodeCatalog{cfg: cfg, providerErrors: providerErrors,
			view:    nodeView{proxies: cfg.Proxies, library: cfg.ProxyLibrary, providers: cfg.Providers},
			configs: readNodeConfigSources(configContent, document, cfg.Proxies)}, nil
	})
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return catalog, nil
}

func (c *NodeCatalog) read(answer func(v nodeView) string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cfg == nil {
		return `{"error":"the catalog is closed"}`
	}
	return answer(c.view)
}

func (c *NodeCatalog) SummaryJSON() string {
	return bridgeSafeString(c.read(func(v nodeView) string {
		summary := v.summaryJSON()
		errors := mustJSON(c.providerErrors)
		return summary[:len(summary)-1] + `,"providerErrors":` + errors + "}"
	}))
}

func (c *NodeCatalog) ProxiesPageJSON(after string, limit int32) string {
	return bridgeSafeString(c.read(func(v nodeView) string {
		var b bytes.Buffer
		if err := v.writeProxiesPage(&b, after, int(limit)); err != nil {
			return mustJSON(map[string]any{"error": err.Error()})
		}
		return b.String()
	}))
}

func (c *NodeCatalog) GroupMembersJSON(group string, offset, limit int32) string {
	return bridgeSafeString(c.read(func(v nodeView) string {
		answer, _ := v.membersAnswer(group, int(offset), int(limit))
		return answer
	}))
}

func (c *NodeCatalog) SearchGroupMembersJSON(group, query string, offset, limit int32) string {
	return bridgeSafeString(c.read(func(v nodeView) string {
		answer, _ := v.memberSearchAnswer(group, query, int(offset), int(limit))
		return answer
	}))
}

func (c *NodeCatalog) LookupJSON(name string) string {
	return bridgeSafeString(c.read(func(v nodeView) string {
		answer, _ := v.lookupAnswer(name)
		return answer
	}))
}

func (c *NodeCatalog) SearchJSON(query string, offset, limit int32) string {
	return bridgeSafeString(c.read(func(v nodeView) string {
		answer, _ := v.searchAnswer(query, int(offset), int(limit))
		return answer
	}))
}

func (c *NodeCatalog) ProviderNodesJSON(provider string, offset, limit int32) string {
	return bridgeSafeString(c.read(func(v nodeView) string {
		answer, _ := v.providerNodesAnswer(provider, int(offset), int(limit))
		return answer
	}))
}

func (c *NodeCatalog) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cfg == nil {
		return
	}
	closeCatalogObjects(c.cfg.Proxies, c.cfg.Providers)
	c.cfg, c.view = nil, nodeView{}
}
