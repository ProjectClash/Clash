package clash

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/adapter/outboundgroup"
	"github.com/ProjectClash/Clash/component/geodata"
	"github.com/ProjectClash/Clash/config"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	"go.yaml.in/yaml/v3"
)

type detachedLoader interface {
	LoadDetached(buf []byte, updatedAt time.Time) error
}

var catalogIgnoredSections = []string{
	"rules", "sub-rules", "rule-providers", "dns", "hosts", "sniffer",
	"tun", "listeners", "tunnels", "ntp", "experimental",
	"x-clash-rule-index",
}

func ProxyCatalogForIOS(configContent, resourceMapJSON, selectionsJSON string) (*StringBox, error) {
	catalog, err := recoverAppCall("ProxyCatalogForIOS", func() (*StringBox, error) {
		return proxyCatalog(configContent, resourceMapJSON, selectionsJSON)
	})
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return catalog, nil
}

func proxyCatalog(configContent, resourceMapJSON, selectionsJSON string) (*StringBox, error) {
	cfg, providerErrors, err := openProxyCatalog(configContent, resourceMapJSON, selectionsJSON)
	if err != nil {
		return nil, err
	}
	defer closeCatalogObjects(cfg.Proxies, cfg.Providers)
	var b bytes.Buffer
	b.WriteString(`{"proxies":`)
	if err := adapter.WriteProxiesJSON(&b, cfg.Proxies, cfg.ProxyLibrary); err != nil {
		return nil, bridgeSafeError(fmt.Errorf("clash: encode proxy catalog: %w", err))
	}
	rest, err := json.Marshal(map[string]any{"providers": cfg.Providers, "providerErrors": providerErrors})
	if err != nil {
		return nil, bridgeSafeError(fmt.Errorf("clash: encode proxy catalog: %w", err))
	}
	b.WriteByte(',')
	b.Write(rest[1:])
	return WrapString(bridgeSafeString(b.String())), nil
}

func openProxyCatalog(configContent, resourceMapJSON, selectionsJSON string) (*config.Config, map[string]string, error) {
	cfg, providerErrors, _, err := openProxyCatalogDocument(configContent, resourceMapJSON, selectionsJSON)
	return cfg, providerErrors, err
}

func openProxyCatalogDocument(configContent, resourceMapJSON, selectionsJSON string) (*config.Config, map[string]string, string, error) {
	setupMu.Lock()
	ready := setupDone
	setupMu.Unlock()
	if !ready {
		return nil, nil, "", bridgeSafeError(fmt.Errorf("clash: call Setup before ProxyCatalogForIOS"))
	}
	var resources resourceMap
	if resourceMapJSON != "" {
		if err := json.Unmarshal([]byte(resourceMapJSON), &resources); err != nil {
			return nil, nil, "", bridgeSafeError(fmt.Errorf("clash: resource map: %w", err))
		}
	}
	selections := map[string]string{}
	if selectionsJSON != "" {
		if err := json.Unmarshal([]byte(selectionsJSON), &selections); err != nil {
			return nil, nil, "", bridgeSafeError(fmt.Errorf("clash: selections: %w", err))
		}
	}
	document, staged, err := catalogDocument(configContent, resources)
	if err != nil {
		return nil, nil, "", bridgeSafeError(err)
	}

	appParseMu.Lock()
	defer appParseMu.Unlock()
	previousGeoSiteOnly, previousGeoIPOnly := geodata.CompiledGeoSiteOnly(), geodata.CompiledGeoIPOnly()
	defer func() {
		geodata.SetCompiledGeoSiteOnly(previousGeoSiteOnly)
		geodata.SetCompiledGeoIPOnly(previousGeoIPOnly)
	}()

	cfg, err := parseConfigForIOS(document, true)
	if err != nil {
		return nil, nil, "", bridgeSafeError(err)
	}

	providerErrors := map[string]string{}
	for name, provider := range cfg.Providers {
		loader, ok := provider.(detachedLoader)
		if !ok {
			continue
		}
		vehicle, ok := provider.(interface{ Vehicle() P.Vehicle })
		if !ok {
			continue
		}
		path := vehicle.Vehicle().Path()
		info, err := os.Stat(path)
		if err != nil {
			if !os.IsNotExist(err) {
				providerErrors[name] = err.Error()
			}
			continue
		}
		payload, err := os.ReadFile(path)
		if err != nil {
			providerErrors[name] = err.Error()
			continue
		}
		content := payload
		if format, ok := staged[name]; ok && !strings.HasSuffix(path, providerRuntimeIndexStubSuffix) {
			content = proxyProviderRuntimeContent(format, payload)
		}
		if err := loader.LoadDetached(content, info.ModTime()); err != nil {
			providerErrors[name] = err.Error()
		}
	}

	restoreCatalogSelections(cfg, selections)
	return cfg, providerErrors, document, nil
}

func catalogDocument(content string, resources resourceMap) (string, map[string]string, error) {
	var root map[string]any
	if resources.NodeLibraryDirectory != "" {
		document, err := decodeMihomoDocument([]byte(content))
		if err != nil {
			return "", nil, fmt.Errorf("clash: parse config: %w", err)
		}
		root = document
	} else if err := yaml.Unmarshal([]byte(content), &root); err != nil {
		return "", nil, fmt.Errorf("clash: parse config: %w", err)
	}
	if root == nil {
		root = map[string]any{}
	}
	canonicalizeProviderDefinitionKeysInDocument(root)
	collisions := providerNamespaceCollisions(root)
	remote := remoteProviderDefinitions(root, "proxy-providers")
	resources.ProviderFetchedAt = publishedRefreshDefinitions(root, "proxy-providers", "proxy", remote, resources.ProviderFetchedAt)
	if err := rewriteProviders(root, "proxy-providers", "proxy", resources.ProviderPaths, collisions); err != nil {
		return "", nil, err
	}
	rewriteRefreshedForCatalog(root, "proxy-providers", "proxy", remote, resources.ProviderFetchedAt)
	staged := map[string]string{}
	if providers, ok := root["proxy-providers"].(map[string]any); ok {
		for name, raw := range providers {
			definition, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if kind, _ := definition["type"].(string); strings.EqualFold(kind, "file") {
				staged[name], _ = definition["format"].(string)
			}
		}
	}
	reference, published := root["x-clash-node-library"]
	if published && publishedNodeLibraryHere(reference) != nil && !nodesOnlyInLibrary(root, reference) {
		published = false
	}
	if published {
		if directory := resources.NodeLibraryDirectory; directory != "" {
			catalogProviderLibraries(root, directory, staged)
		}
	} else if directory := resources.NodeLibraryDirectory; directory != "" {
		dropWrittenNodeFields(root)
		if err := writeNodeLibrary(root, directory); err != nil {
			return "", nil, err
		}
		catalogProviderLibraries(root, directory, staged)
	}
	for _, key := range catalogIgnoredSections {
		delete(root, key)
	}
	out, err := yaml.Marshal(root)
	if err != nil {
		return "", nil, fmt.Errorf("clash: encode catalog document: %w", err)
	}
	return string(out), staged, nil
}

func proxyProviderRuntimeContent(format string, payload []byte) []byte {
	prepared, stripped, err := sanitizeProxyProviderPayloadForIOS(format, payload, false)
	if err == nil && len(stripped) > 0 {
		return prepared
	}
	return payload
}

func restoreCatalogSelections(cfg *config.Config, selections map[string]string) {
	for group, member := range selections {
		proxy, ok := cfg.Proxies[group]
		if !ok {
			continue
		}
		selectable, ok := proxy.Adapter().(outboundgroup.SelectAble)
		if !ok {
			continue
		}
		if cfg.Profile.StoreSelected || groupHasMember(proxy, member) {
			selectable.ForceSet(member)
		}
	}
}

func groupHasMember(group C.Proxy, member string) bool {
	holder, ok := group.Adapter().(interface{ Members(bool) C.ProxyList })
	if !ok {
		return false
	}
	members := holder.Members(false)
	for i := 0; i < members.Len(); i++ {
		if members.At(i).Name() == member {
			return true
		}
	}
	return false
}

func closeCatalogObjects(proxies map[string]C.Proxy, providers map[string]P.ProxyProvider) {
	closed := map[C.ProxyAdapter]bool{}
	closeAdapter := func(proxy C.Proxy) {
		adapter := proxy.Adapter()
		if adapter == nil {
			return
		}
		if reflect.TypeOf(adapter).Comparable() {
			if closed[adapter] {
				return
			}
			closed[adapter] = true
		}
		if closer, ok := adapter.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
	}
	for _, proxy := range proxies {
		closeAdapter(proxy)
	}
	for _, provider := range providers {
		rangeHeldMembers(provider.ProxyList(), func(proxy C.Proxy) bool { closeAdapter(proxy); return true })
		if closer, ok := provider.(interface{ Close() error }); ok {
			_ = closer.Close()
		}
	}
}
