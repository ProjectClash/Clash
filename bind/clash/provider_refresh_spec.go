package clash

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ProjectClash/Clash/common/structure"
	C "github.com/ProjectClash/Clash/constant"

	http "github.com/metacubex/http"
)

const providerRefreshField = "x-clash-refresh"

var providerRefreshCarriedFields = []string{"url", "interval", "header", "size-limit", "proxy", "age-secret-key"}

const (
	providerRefreshFetchedAtField        = "fetched-at"
	providerRefreshETagField             = "etag"
	providerRefreshSubscriptionInfoField = "subscription-userinfo"
)

const providerRefreshUnseededDirectory = "provider-refresh/unseeded"

type providerRefreshMarker struct {
	URL              string              `provider:"url"`
	Interval         int                 `provider:"interval,omitempty"`
	SizeLimit        int64               `provider:"size-limit,omitempty"`
	Header           map[string][]string `provider:"header,omitempty"`
	Proxy            string              `provider:"proxy,omitempty"`
	AgeKey           string              `provider:"age-secret-key,omitempty"`
	FetchedAt        int64               `provider:"fetched-at,omitempty"`
	ETag             string              `provider:"etag,omitempty"`
	SubscriptionInfo string              `provider:"subscription-userinfo,omitempty"`
	LegacyPath       string              `provider:"legacy-path,omitempty"`
}

var providerRefreshDecoder = &lazyValue[*structure.Decoder]{build: func() *structure.Decoder {
	return structure.NewDecoder(structure.Option{TagName: "provider", WeaklyTypedInput: true})
}}

type providerRefreshSpec struct {
	URL              string
	Interval         time.Duration
	SizeLimit        int64
	Header           http.Header
	Proxy            string
	AgeKey           string
	FetchedAt        time.Time
	ETag             string
	SubscriptionInfo string
	LegacyPath       string
}

func decodeProviderRefreshMarker(raw any) (*providerRefreshSpec, bool) {
	mapping, ok := raw.(map[string]any)
	if !ok {
		return nil, false
	}
	var marker providerRefreshMarker
	if err := providerRefreshDecoder.get().Decode(mapping, &marker); err != nil {
		return nil, false
	}
	if strings.TrimSpace(marker.URL) == "" {
		return nil, false
	}
	spec := &providerRefreshSpec{
		URL:              marker.URL,
		SizeLimit:        marker.SizeLimit,
		Proxy:            marker.Proxy,
		AgeKey:           marker.AgeKey,
		ETag:             marker.ETag,
		SubscriptionInfo: marker.SubscriptionInfo,
		LegacyPath:       marker.LegacyPath,
	}
	if marker.Interval > 0 {
		spec.Interval = time.Duration(uint(marker.Interval)) * time.Second
	}
	if len(marker.Header) > 0 {
		spec.Header = http.Header(marker.Header)
	}
	if marker.FetchedAt > 0 {
		spec.FetchedAt = time.Unix(marker.FetchedAt, 0)
	}
	return spec, true
}

func (spec *providerRefreshSpec) requestKey(kind string) string {
	digest := sha256.New()
	write := func(parts ...string) {
		for _, part := range parts {
			digest.Write([]byte(part))
			digest.Write([]byte{0})
		}
	}
	write("kind", kind, "url", spec.URL, "proxy", spec.Proxy, "size-limit", fmt.Sprint(spec.SizeLimit), "age", spec.AgeKey)
	names := make([]string, 0, len(spec.Header))
	for name := range spec.Header {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		write("header", name)
		write(spec.Header[name]...)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func remoteProviderDefinitions(root map[string]any, key string) map[string]map[string]any {
	providers, _ := root[key].(map[string]any)
	result := map[string]map[string]any{}
	for name, raw := range providers {
		definition, _ := raw.(map[string]any)
		if typeName, _ := definition["type"].(string); !strings.EqualFold(typeName, "http") {
			continue
		}
		if rawURL, _ := definition["url"].(string); true {
			if _, err := normalizeResourceURL(rawURL, "provider"); err != nil {
				continue
			}
		}
		carried := map[string]any{}
		for _, field := range providerRefreshCarriedFields {
			if value, ok := definition[field]; ok {
				carried[field] = value
			}
		}
		if path, _ := definition["path"].(string); strings.TrimSpace(path) != "" {
			carried["legacy-path"] = path
		}
		result[name] = carried
	}
	return result
}

func unseededProviderPath(kind, name string) string {
	digest := sha256.Sum256([]byte(kind + "\x00" + name))
	return filepath.ToSlash(filepath.Join(providerRefreshUnseededDirectory, kind+"-"+hex.EncodeToString(digest[:8])))
}

func annotateProviderRefresh(root map[string]any, key, kind string, remote map[string]map[string]any, rm resourceMap) {
	providers, _ := root[key].(map[string]any)
	for name, raw := range providers {
		definition, _ := raw.(map[string]any)
		if definition == nil {
			continue
		}
		delete(definition, providerRefreshField)
		carried, wasRemote := remote[name]
		if !wasRemote {
			continue
		}
		marker := map[string]any{}
		for field, value := range carried {
			marker[field] = value
		}
		seeded := false
		if typeName, _ := definition["type"].(string); typeName == "file" {
			seeded = true
		}
		resourceKey := providerResourceKey(kind, name)
		if seeded {
			if at, ok := rm.ProviderFetchedAt[resourceKey]; ok && at > 0 {
				marker[providerRefreshFetchedAtField] = at
			}
			if etag := rm.ProviderETags[resourceKey]; etag != "" {
				marker[providerRefreshETagField] = etag
			}
		}
		if info := rm.ProviderSubscriptionInfo[resourceKey]; info != "" {
			marker[providerRefreshSubscriptionInfoField] = info
		}
		if _, ok := decodeProviderRefreshMarker(marker); !ok {
			continue
		}
		if !seeded {
			if legacy, _ := definition["path"].(string); legacy != "" {
				marker["legacy-path"] = legacy
			}
			definition["type"] = "file"
			definition["path"] = unseededProviderPath(kind, name)
			for _, field := range providerRefreshCarriedFields {
				delete(definition, field)
			}
		}
		definition[providerRefreshField] = marker
	}
}

func rewriteRefreshedForCatalog(root map[string]any, key, kind string, remote map[string]map[string]any, fetchedAt map[string]int64) {
	providers, _ := root[key].(map[string]any)
	if len(providers) == 0 {
		return
	}
	home := C.Path.HomeDir()
	entries := readProviderCacheEntries(home)
	type catalogName struct {
		name       string
		definition map[string]any
		spec       *providerRefreshSpec
		requestKey string
		form       string
		seedPath   string
		seedAt     int64
		unseeded   bool
		legacyPath string
	}
	byRequest := map[string][]*catalogName{}
	var order []string
	names := make([]string, 0, len(providers))
	for name := range providers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		definition, _ := providers[name].(map[string]any)
		carried, wasRemote := remote[name]
		if definition == nil || !wasRemote {
			continue
		}
		spec, ok := decodeProviderRefreshMarker(carried)
		if !ok {
			continue
		}
		behavior, _ := definition["behavior"].(string)
		format, _ := definition["format"].(string)
		entry := &catalogName{name: name, definition: definition, spec: spec, requestKey: spec.requestKey(kind),
			form: catalogForm(behavior, format)}
		pathValue, _ := definition["path"].(string)
		if typeName, _ := definition["type"].(string); strings.EqualFold(typeName, "http") {
			entry.unseeded, entry.legacyPath = true, pathValue
		} else if pathValue != "" && regularFileExists(C.Path.Resolve(pathValue)) {
			entry.seedPath, entry.seedAt = pathValue, fetchedAt[providerResourceKey(kind, name)]
		}
		if byRequest[entry.requestKey] == nil {
			order = append(order, entry.requestKey)
		}
		byRequest[entry.requestKey] = append(byRequest[entry.requestKey], entry)
	}
	for _, requestKey := range order {
		group := byRequest[requestKey]
		var best *catalogName
		for _, member := range group {
			if member.seedPath != "" && (best == nil || member.seedAt > best.seedAt) {
				best = member
			}
		}
		state := entries[requestKey]
		cacheHasContent := state != nil && state.SourceSHA256 != ""
		seedNewer := false
		if best != nil {
			bestPath := C.Path.Resolve(best.seedPath)
			switch {
			case !knowsRunningContent(state):
				seedNewer = true
			case state.PendingSHA256 != "" && seedIsPayload(bestPath, state.PendingSHA256):
				seedNewer = true
			case state.SeedCheckedAt > 0 && state.SeedCheckedAt >= state.LastCheckedAt && sameSeedIdentity(bestPath, state.SeedIdentity):
				seedNewer = true
			default:
				seedNewer = best.seedAt > 0 && best.seedAt > runningConfirmation(state)
			}
		}
		owners := map[string]string{}
		if seedNewer {
			for _, member := range group {
				if member.seedPath == best.seedPath {
					owners[member.form] = best.seedPath
				}
			}
		}
		for _, member := range group {
			definition := member.definition
			path, behavior, format, serverBytes := "", "", "", false
			switch {
			case seedNewer && owners[member.form] != "":
				path = owners[member.form]
			case !seedNewer && cacheHasContent:
				if product, productPath := cachedProviderProduct(home, requestKey, state, member.form); product != nil {
					path, behavior, format = productPath, product.Behavior, product.Format
				} else if member.seedPath == "" {
					if source := cachedProviderSource(kind, member.spec); source != "" {
						path, serverBytes = source, true
					}
				}
			}
			if path == "" && member.seedPath != "" {
				path = member.seedPath
			}
			legacy := ""
			if path == "" && member.unseeded {
				member.spec.LegacyPath = member.legacyPath
				if legacy = legacyProviderDownload(kind, member.spec); legacy != "" {
					path, serverBytes = legacy, true
				}
			}
			if path == "" {
				path = unseededProviderPath(kind, member.name)
			}
			if path == member.seedPath && !member.unseeded {
				continue
			}
			if serverBytes && kind == "proxy" && member.spec.AgeKey != "" {
				definition["age-secret-key"] = member.spec.AgeKey
			}
			definition["type"] = "file"
			definition["path"] = path
			for _, field := range providerRefreshCarriedFields {
				if field == "age-secret-key" && serverBytes {
					continue
				}
				delete(definition, field)
			}
			if behavior != "" {
				definition["behavior"], definition["format"] = behavior, format
				continue
			}
			sourceBehavior, _ := definition["behavior"].(string)
			sourceFormat, _ := definition["format"].(string)
			if kind == "rule" && member.seedPath == "" && legacy == "" && compilesNatively(sourceBehavior, sourceFormat) {
				definition[providerCatalogNativeField] = true
			}
		}
	}
}

func catalogForm(behavior, format string) string {
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		format = "yaml"
	}
	return strings.ToLower(strings.TrimSpace(behavior)) + "\x00" + format
}

func readProviderCacheEntries(home string) map[string]*providerCacheEntry {
	payload, err := readBoundedRegularFile(filepath.Join(home, ProviderRefreshDirectoryName, ProviderRefreshStateFileName), providerRefreshStateMaximumBytes, "provider refresh state")
	if err != nil {
		return nil
	}
	var state providerCacheStateFile
	if json.Unmarshal(payload, &state) != nil || state.Version != providerRefreshStateVersion {
		return nil
	}
	return state.Entries
}

func cachedProviderProduct(home, requestKey string, entry *providerCacheEntry, form string) (*providerCacheProduct, string) {
	keys := make([]string, 0, len(entry.Products))
	for productKey := range entry.Products {
		keys = append(keys, productKey)
	}
	sort.Strings(keys)
	for _, productKey := range keys {
		product := entry.Products[productKey]
		if product == nil || product.SourceSHA256 != entry.SourceSHA256 {
			continue
		}
		madeFor := product.SourceForm
		if madeFor == "" {
			madeFor = catalogForm(product.Behavior, product.Format)
		}
		if madeFor != form {
			continue
		}
		directory := filepath.Join(home, ProviderRefreshDirectoryName, providerRefreshCacheDirectory, requestKey, "products", productKey, product.Generation)
		if productFilesExist(directory, product) {
			return product, filepath.Join(directory, product.Entry)
		}
	}
	return nil, ""
}

const providerCatalogNativeField = "x-clash-catalog-native"

func cachedProviderSource(kind string, spec *providerRefreshSpec) string {
	home := C.Path.HomeDir()
	path := filepath.Join(home, ProviderRefreshDirectoryName, providerRefreshCacheDirectory, spec.requestKey(kind), "source")
	if !regularFileExists(path) || !providerSourceContained(path, home) {
		return ""
	}
	return path
}

func sameSeedIdentity(path, identity string) bool {
	if identity == "" {
		return false
	}
	current, ok := providerSeedIdentity(path)
	return ok && current == identity
}
