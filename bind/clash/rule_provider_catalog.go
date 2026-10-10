package clash

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ProjectClash/Clash/component/geodata"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	"go.yaml.in/yaml/v3"
)

type detachedRuleLoader interface {
	LoadDetached(buf []byte, updatedAt time.Time) error
}

var ruleCatalogDroppedSections = []string{
	"rules", "sub-rules", "dns", "hosts", "sniffer", "tun", "listeners", "tunnels", "ntp", "experimental",
}

func RuleProviderCatalogForIOS(configContent, resourceMapJSON string, compileRuleSets bool) (*StringBox, error) {
	out, err := recoverAppCall("RuleProviderCatalogForIOS", func() (*StringBox, error) {
		return ruleProviderCatalogForIOSUnguarded(configContent, resourceMapJSON, compileRuleSets)
	})
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

func ruleProviderCatalogForIOSUnguarded(configContent, resourceMapJSON string, compileRuleSets bool) (*StringBox, error) {
	catalog, err := ruleProviderCatalog(configContent, resourceMapJSON, compileRuleSets)
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return catalog, nil
}

func ruleProviderCatalog(configContent, resourceMapJSON string, compileRuleSets bool) (*StringBox, error) {
	setupMu.Lock()
	ready := setupDone
	setupMu.Unlock()
	if !ready {
		return nil, fmt.Errorf("clash: call Setup before RuleProviderCatalogForIOS")
	}
	var resources resourceMap
	if resourceMapJSON != "" {
		if err := json.Unmarshal([]byte(resourceMapJSON), &resources); err != nil {
			return nil, fmt.Errorf("clash: resource map: %w", err)
		}
	}
	appParseMu.Lock()
	defer appParseMu.Unlock()
	policy := currentRuntimePolicy(true)
	document, loads, err := ruleCatalogDocument(configContent, resources, policy, compileRuleSets)
	if err != nil {
		return nil, err
	}
	previousGeoSiteOnly, previousGeoIPOnly := geodata.CompiledGeoSiteOnly(), geodata.CompiledGeoIPOnly()
	defer func() {
		geodata.SetCompiledGeoSiteOnly(previousGeoSiteOnly)
		geodata.SetCompiledGeoIPOnly(previousGeoIPOnly)
	}()

	cfg, err := parseConfigForIOS(document, true)
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, provider := range cfg.RuleProviders {
			if closer, ok := provider.(interface{ Close() error }); ok {
				_ = closer.Close()
			}
		}
		closeCatalogObjects(cfg.Proxies, cfg.Providers)
		geodata.ClearGeoSiteCache()
		geodata.ClearGeoIPCache()
	}()

	providerErrors := map[string]string{}
	for name, provider := range cfg.RuleProviders {
		loader, ok := provider.(detachedRuleLoader)
		if !ok {
			continue
		}
		if load, ok := loads[name]; ok {
			if err := loader.LoadDetached(load.content, load.updatedAt); err != nil {
				providerErrors[name] = err.Error()
			}
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
		if err := loader.LoadDetached(payload, info.ModTime()); err != nil {
			providerErrors[name] = err.Error()
		}
	}

	data, err := json.Marshal(map[string]any{
		"providers":      cfg.RuleProviders,
		"providerErrors": providerErrors,
	})
	if err != nil {
		return nil, fmt.Errorf("clash: encode rule provider catalog: %w", err)
	}
	return WrapString(bridgeSafeString(string(data))), nil
}

type ruleLoad struct {
	content   []byte
	updatedAt time.Time
}

func ruleCatalogDocument(content string, resources resourceMap, policy appleRuntimePolicy, compileRuleSets bool) (string, map[string]ruleLoad, error) {
	var root map[string]any
	if err := yaml.Unmarshal([]byte(content), &root); err != nil {
		return "", nil, fmt.Errorf("clash: parse config: %w", err)
	}
	if root == nil {
		root = map[string]any{}
	}
	canonicalizeProviderDefinitionKeysInDocument(root)
	collisions := providerNamespaceCollisions(root)
	remote := remoteProviderDefinitions(root, "rule-providers")
	if err := rewriteProviders(root, "rule-providers", "rule", resources.ProviderPaths, collisions); err != nil {
		return "", nil, err
	}
	rewriteRefreshedForCatalog(root, "rule-providers", "rule", remote, resources.ProviderFetchedAt)
	loads := map[string]ruleLoad{}
	if providers, ok := root["rule-providers"].(map[string]any); ok {
		for name, raw := range providers {
			definition, ok := raw.(map[string]any)
			if !ok {
				continue
			}
			if kind, _ := definition["type"].(string); !strings.EqualFold(kind, "file") {
				continue
			}
			native, _ := definition[providerCatalogNativeField].(bool)
			delete(definition, providerCatalogNativeField)
			sourceValue, _ := definition["path"].(string)
			if strings.TrimSpace(sourceValue) == "" {
				continue
			}
			sourcePath := C.Path.Resolve(sourceValue)
			info, err := os.Stat(sourcePath)
			if err != nil {
				if native {
					definition["format"] = "mrs"
					behavior, _ := definition["behavior"].(string)
					definition["behavior"] = strings.ToLower(strings.TrimSpace(behavior))
				}
				continue
			}
			payload, err := os.ReadFile(sourcePath)
			if err != nil {
				continue
			}
			if _, identityErr := stagedSourceIdentity(sourcePath); identityErr != nil {
				loads[name] = ruleLoad{content: payload, updatedAt: info.ModTime()}
				continue
			}
			behavior, _ := definition["behavior"].(string)
			format, _ := definition["format"].(string)
			served := payload
			if !strings.EqualFold(strings.TrimSpace(format), "mrs") {
				prepared, stripped, prepareErr := prepareRuleProviderRuntimePayload(behavior, format, payload, policy)
				if prepareErr == nil {
					if len(stripped) > 0 {
						served = prepared
					}
					if (compileRuleSets || native) && len(payload) > 0 {
						if compilation := compileRuleProviderPayload(served, behavior, format); compilation.Reason == "" {
							definition["format"] = "mrs"
							definition["behavior"] = compilation.Behavior
							served = compilation.artifact
						}
					}
				}
			}
			loads[name] = ruleLoad{content: served, updatedAt: info.ModTime()}
		}
	}
	for _, key := range ruleCatalogDroppedSections {
		delete(root, key)
	}
	out, err := yaml.Marshal(root)
	if err != nil {
		return "", nil, fmt.Errorf("clash: encode rule catalog document: %w", err)
	}
	return string(out), loads, nil
}
