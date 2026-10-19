package clash

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ProjectClash/Clash/common/structure"
)

const (
	projectionPackageCatalog   = "catalog"
	projectionPackageResources = "resources"
	projectionPackageRuleFacts = "ruleFacts"
	projectionPackageScalars   = "scalars"
)

const projectionSchemaVersion = 1

const (
	projectionKindSource = "source"
	projectionKindMerged = "merged"
)

type projectionNode struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type projectionGroup struct {
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	Proxies    []string `json:"proxies"`
	Use        []string `json:"use"`
	IncludeAll bool     `json:"includeAll"`
	Filter     string   `json:"filter"`
}

type projectionCatalog struct {
	Proxies []projectionNode  `json:"proxies"`
	Groups  []projectionGroup `json:"groups"`
}

type projectionProvider struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Behavior string `json:"behavior"`
	Path     string `json:"path"`
}

type projectionResources struct {
	ProxyProviders []projectionProvider `json:"proxyProviders"`
	RuleProviders  []projectionProvider `json:"ruleProviders"`
}

type projectionRuleFacts struct {
	RuleCount       int      `json:"ruleCount"`
	LastMatchTarget string   `json:"lastMatchTarget"`
	SubRuleNames    []string `json:"subRuleNames"`
}

type projectionScalars struct {
	Mode      *string `json:"mode"`
	GlobalUA  *string `json:"globalUA"`
	DNSEnable *bool   `json:"dnsEnable"`
}

type configProjection struct {
	SchemaVersion int                  `json:"schemaVersion"`
	DocumentKind  string               `json:"documentKind"`
	Catalog       *projectionCatalog   `json:"catalog,omitempty"`
	Resources     *projectionResources `json:"resources,omitempty"`
	RuleFacts     *projectionRuleFacts `json:"ruleFacts,omitempty"`
	Scalars       *projectionScalars   `json:"scalars,omitempty"`
}

type projectionProxyDecl struct {
	Name string `proxy:"name,omitempty"`
	Type string `proxy:"type,omitempty"`
}

type projectionGroupDecl struct {
	Name       string   `group:"name,omitempty"`
	Type       string   `group:"type,omitempty"`
	Proxies    []string `group:"proxies,omitempty"`
	Use        []string `group:"use,omitempty"`
	IncludeAll bool     `group:"include-all,omitempty"`
	Filter     string   `group:"filter,omitempty"`
}

type projectionProviderDecl struct {
	Type     string `provider:"type,omitempty"`
	Behavior string `provider:"behavior,omitempty"`
	Path     string `provider:"path,omitempty"`
}

func buildConfigProjection(doc *ConfigDocument, kind string, packages []string) (configProjection, error) {
	views, err := doc.snapshot()
	if err != nil {
		return configProjection{}, err
	}
	if kind != projectionKindSource && kind != projectionKindMerged {
		return configProjection{}, fmt.Errorf("clash: unknown projection document kind %q", kind)
	}
	out := configProjection{SchemaVersion: projectionSchemaVersion, DocumentKind: kind}
	wanted := make(map[string]bool, len(packages))
	for _, name := range packages {
		wanted[name] = true
	}
	proxyDecoder := structure.NewDecoder(structure.Option{TagName: "proxy", WeaklyTypedInput: true})
	groupDecoder := structure.NewDecoder(structure.Option{TagName: "group", WeaklyTypedInput: true})
	providerDecoder := structure.NewDecoder(structure.Option{TagName: "provider", WeaklyTypedInput: true})
	if wanted[projectionPackageCatalog] {
		catalog := &projectionCatalog{
			Proxies: make([]projectionNode, 0, len(views.raw.Proxy)),
			Groups:  make([]projectionGroup, 0, len(views.raw.ProxyGroup)),
		}
		for _, proxy := range views.raw.Proxy {
			var decl projectionProxyDecl
			_ = proxyDecoder.Decode(proxy, &decl)
			catalog.Proxies = append(catalog.Proxies, projectionNode{
				Name: decl.Name, Type: decl.Type,
			})
		}
		for _, group := range views.raw.ProxyGroup {
			var decl projectionGroupDecl
			_ = groupDecoder.Decode(group, &decl)
			catalog.Groups = append(catalog.Groups, projectionGroup{
				Name:       decl.Name,
				Type:       decl.Type,
				Proxies:    decl.Proxies,
				Use:        decl.Use,
				IncludeAll: decl.IncludeAll,
				Filter:     decl.Filter,
			})
		}
		out.Catalog = catalog
	}
	if wanted[projectionPackageResources] {
		resources := &projectionResources{
			ProxyProviders: make([]projectionProvider, 0, len(views.raw.ProxyProvider)),
			RuleProviders:  make([]projectionProvider, 0, len(views.raw.RuleProvider)),
		}
		for name, definition := range views.raw.ProxyProvider {
			var decl projectionProviderDecl
			_ = providerDecoder.Decode(definition, &decl)
			resources.ProxyProviders = append(resources.ProxyProviders, projectionProvider{
				Name: name, Type: decl.Type, Path: decl.Path,
			})
		}
		for name, definition := range views.raw.RuleProvider {
			var decl projectionProviderDecl
			_ = providerDecoder.Decode(definition, &decl)
			resources.RuleProviders = append(resources.RuleProviders, projectionProvider{
				Name: name, Type: decl.Type, Behavior: decl.Behavior, Path: decl.Path,
			})
		}
		sort.Slice(resources.ProxyProviders, func(i, j int) bool {
			return resources.ProxyProviders[i].Name < resources.ProxyProviders[j].Name
		})
		sort.Slice(resources.RuleProviders, func(i, j int) bool {
			return resources.RuleProviders[i].Name < resources.RuleProviders[j].Name
		})
		out.Resources = resources
	}
	if wanted[projectionPackageRuleFacts] {
		index, err := rawRuleIndexChecked(views.raw)
		if err != nil {
			return configProjection{}, err
		}
		facts := &projectionRuleFacts{
			RuleCount:    ruleCountOfIndex(views.raw, index),
			SubRuleNames: make([]string, 0, len(views.raw.SubRules)),
		}
		eachRuleLineOf(views.raw, index, func(_ int, rule string) {
			parts := strings.Split(rule, ",")
			if len(parts) >= 2 && strings.EqualFold(strings.TrimSpace(parts[0]), "MATCH") {
				facts.LastMatchTarget = strings.TrimSpace(parts[1])
			}
		})
		for name := range views.raw.SubRules {
			facts.SubRuleNames = append(facts.SubRuleNames, name)
		}
		sort.Strings(facts.SubRuleNames)
		out.RuleFacts = facts
	}
	if wanted[projectionPackageScalars] {
		scalars := &projectionScalars{}
		if _, present := views.root["mode"]; present {
			mode := views.raw.Mode.String()
			scalars.Mode = &mode
		}
		if _, present := views.root["global-ua"]; present {
			globalUA := views.raw.GlobalUA
			scalars.GlobalUA = &globalUA
		}
		if dns, ok := views.root["dns"].(map[string]any); ok {
			if _, present := dns["enable"]; present {
				enable := views.raw.DNS.Enable
				scalars.DNSEnable = &enable
			}
		}
		out.Scalars = scalars
	}
	return out, nil
}
