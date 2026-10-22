package clash

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ProjectClash/Clash/adapter/provider"
	"github.com/ProjectClash/Clash/component/age"
	"github.com/ProjectClash/Clash/config"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	rules "github.com/ProjectClash/Clash/rules"
	ruleprovider "github.com/ProjectClash/Clash/rules/provider"
)

const maximumPendingCompileBytes = 256 << 20

type pendingCompileResult struct {
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	Result     string `json:"result"`
	Error      string `json:"error,omitempty"`
	CountAfter int    `json:"countAfter,omitempty"`
}

func (c *APIClient) CompilePendingProviders(configContent, targetProfile string) (string, error) {
	out, err := recoverAppCall("CompilePendingProviders", func() (string, error) { return c.compilePendingProviders(configContent, targetProfile) })
	return bridgeSafeString(out), bridgeSafeError(err)
}

func (c *APIClient) compilePendingProviders(configContent, targetProfile string) (string, error) {
	results := []pendingCompileResult{}
	err := eachPendingCompile(configContent, targetProfile, func(kind, name, seedJSON string, set []byte, configSHA256 string, err error) {
		result := pendingCompileResult{Kind: kind, Name: name}
		if err == nil {
			var answer string
			if answer, err = c.SeedProvider(kind, name, set, seedJSON, configSHA256); err == nil {
				var reply providerRefreshResult
				if json.Unmarshal([]byte(answer), &reply) == nil {
					result.Result, result.Error, result.CountAfter = reply.Result, reply.Error, reply.CountAfter
				}
			}
		}
		if err != nil {
			result.Result, result.Error = providerRefreshFailed, err.Error()
		}
		results = append(results, result)
	})
	if err != nil {
		return "", err
	}
	return mustJSON(results), nil
}

const pendingSeedDirectoryName = "app-seeds"

const pendingSeedLifetime = 10 * time.Minute

type pendingSeedFile struct {
	Kind                 string `json:"kind"`
	Name                 string `json:"name"`
	PayloadPath          string `json:"payloadPath,omitempty"`
	Seed                 string `json:"seed,omitempty"`
	ExpectedConfigSHA256 string `json:"expectedConfigSHA256,omitempty"`
	Result               string `json:"result,omitempty"`
	Error                string `json:"error,omitempty"`
}

func PreparePendingProviderSeeds(configContent, targetProfile string) (string, error) {
	out, err := recoverAppCall("PreparePendingProviderSeeds", func() (string, error) { return preparePendingProviderSeeds(configContent, targetProfile) })
	return bridgeSafeString(out), bridgeSafeError(err)
}

func preparePendingProviderSeeds(configContent, targetProfile string) (string, error) {
	parent := filepath.Join(C.Path.HomeDir(), ProviderRefreshDirectoryName, pendingSeedDirectoryName)
	if names, err := os.ReadDir(parent); err == nil {
		for _, name := range names {
			if info, err := name.Info(); err == nil && time.Since(info.ModTime()) > pendingSeedLifetime {
				_ = os.RemoveAll(filepath.Join(parent, name.Name()))
			}
		}
	}
	directory := filepath.Join(parent, newProductGeneration())
	entries := []pendingSeedFile{}
	err := eachPendingCompile(configContent, targetProfile, func(kind, name, seedJSON string, set []byte, configSHA256 string, err error) {
		entry := pendingSeedFile{Kind: kind, Name: name}
		if err == nil {
			path := filepath.Join(directory, fmt.Sprintf("%s-%d.seed", kind, len(entries)))
			if err = os.MkdirAll(directory, 0o700); err == nil {
				err = os.WriteFile(path, set, 0o600)
			}
			entry.PayloadPath, entry.Seed, entry.ExpectedConfigSHA256 = path, seedJSON, configSHA256
		}
		if err != nil {
			entry = pendingSeedFile{Kind: kind, Name: name, Result: providerRefreshFailed, Error: err.Error()}
		}
		entries = append(entries, entry)
	})
	if err != nil {
		return "", err
	}
	return mustJSON(entries), nil
}

func eachPendingCompile(configContent, targetProfile string, visit func(kind, name, seedJSON string, set []byte, configSHA256 string, err error)) error {
	profile, err := normalizeRuntimeProfile(targetProfile)
	if err != nil {
		return err
	}
	definitions, ruleDefinitions := map[string]map[string]any{}, map[string]map[string]any{}
	if strings.TrimSpace(configContent) == "" {
		return errors.New("clash: compile the waiting providers with the configuration the tunnel runs")
	}
	{
		raw, err := config.UnmarshalRawConfig([]byte(configContent))
		if err != nil {
			return fmt.Errorf("clash: parse config: %w", err)
		}
		canonicalizeProviderDefinitionKeys(raw)
		definitions, ruleDefinitions = raw.ProxyProvider, raw.RuleProvider
	}
	policy := runtimePolicyFor(profile, true)
	home := C.Path.HomeDir()
	state := readProviderCacheState(home)
	if state == nil {
		return nil
	}
	if configurationSHA256(configContent) != state.Running.ConfigSHA256 {
		return errors.New(SideUpdateStalePrefix + "the tunnel runs another configuration than the one given; compile with the configuration it runs")
	}
	keys := make([]string, 0, len(state.Running.Providers))
	for key := range state.Running.Providers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		requestKey := state.Running.Providers[key]
		kind, name, ok := strings.Cut(key, ":")
		variant := state.Running.Variants[key]
		if !ok || !((kind == "rule" && (variant == "mapped" || variant == "indexed")) || (kind == "proxy" && variant == "library")) {
			continue
		}
		entry := state.Entries[requestKey]
		if entry == nil || entry.PendingSHA256 == "" {
			continue
		}
		var definition map[string]any
		if kind == "proxy" {
			definition = definitions[name]
		} else {
			definition = ruleDefinitions[name]
		}
		if runsWaitingContent(home, requestKey, entry, kind, name, definition) {
			continue
		}
		var seedJSON string
		var set []byte
		if kind == "proxy" {
			seedJSON, set, err = compilePendingSubscription(home, requestKey, name, entry, definitions[name])
			if errors.Is(err, provider.ErrProviderNotLibrary) && !holdsVariant(entry, compileVerdictLibrary) {
				seedJSON, set, err = pendingContentAsSource(home, requestKey, entry)
			}
		} else {
			seedJSON, set, err = compilePendingRuleSet(home, requestKey, entry, variant, policy, ruleDefinitions[name])
		}
		visit(kind, name, seedJSON, set, state.Running.ConfigSHA256, err)
	}
	return nil
}

func compilePendingRuleSet(home, requestKey string, entry *providerCacheEntry, variant string, policy appleRuntimePolicy, definition map[string]any) (string, []byte, error) {
	form := ""
	if definition != nil {
		behavior, _ := definition["behavior"].(string)
		format, _ := definition["format"].(string)
		form = catalogForm(behavior, format)
	}
	var product *providerCacheProduct
	for _, candidate := range entry.Products {
		if candidate != nil && candidate.Variant == variant && (form == "" || candidate.SourceForm == form) {
			product = candidate
		}
	}
	if product == nil && definition != nil {
		behavior, _ := definition["behavior"].(string)
		format, _ := definition["format"].(string)
		product = &providerCacheProduct{Variant: variant, Behavior: strings.ToLower(strings.TrimSpace(behavior)), SourceForm: catalogForm(behavior, format)}
	}
	if product == nil {
		return "", nil, fmt.Errorf("the set does not run %s", variant)
	}
	sourceBehavior, sourceFormat, _ := strings.Cut(product.SourceForm, "\x00")
	pending := filepath.Join(home, ProviderRefreshDirectoryName, providerRefreshCacheDirectory, requestKey, "pending")
	payload, err := readBoundedRegularFile(pending, maximumPendingCompileBytes, "waiting provider content")
	if err != nil {
		return "", nil, err
	}
	if sum := sha256.Sum256(payload); hex.EncodeToString(sum[:]) != entry.PendingSHA256 {
		return "", nil, fmt.Errorf("the waiting content changed while it was read")
	}
	content := payload
	prepared, stripped, prepareErr := prepareRuleProviderRuntimePayload(sourceBehavior, sourceFormat, payload, policy)
	if prepareErr != nil {
		return "", nil, prepareErr
	}
	if len(stripped) > 0 {
		content = prepared
	}
	if variant == "indexed" {
		parsed, err := P.ParseRuleFormat(strings.TrimSpace(sourceFormat))
		if err != nil {
			return "", nil, err
		}
		lines, err := ruleprovider.ClashClassicalLines(content, parsed)
		if err != nil {
			return "", nil, err
		}
		index, err := ruleprovider.ClashCompileClassicalIndex(lines, rules.ParseRule)
		if err != nil {
			return "", nil, err
		}
		seed, _ := json.Marshal(providerSeed{Payload: "indexed", SourceSHA256: entry.PendingSHA256, FetchedAt: entry.PendingCheckedAt, Count: index.Rules})
		return string(seed), index.Bytes, nil
	}
	artifact := content
	if strings.EqualFold(strings.TrimSpace(sourceFormat), "mrs") {
		if got := strings.ToLower(strings.TrimSpace(sourceBehavior)); got != product.Behavior {
			return "", nil, fmt.Errorf("the set runs %s and the content is %s; publish the configuration", product.Behavior, got)
		}
	} else {
		compilation := compileRuleProviderPayload(content, sourceBehavior, sourceFormat)
		if compilation.Reason != "" || compilation.Behavior != product.Behavior {
			return "", nil, fmt.Errorf("the content does not compile into the set the tunnel runs; publish the configuration")
		}
		artifact = compilation.artifact
	}
	behavior, err := ruleBehavior(product.Behavior)
	if err != nil {
		return "", nil, err
	}
	set, err := ruleprovider.ClashMappedFromMrs(artifact, behavior)
	if err != nil {
		return "", nil, err
	}
	seed, _ := json.Marshal(providerSeed{Payload: "mapped", SourceSHA256: entry.PendingSHA256, FetchedAt: entry.PendingCheckedAt, Count: set.Count})
	return string(seed), set.Bytes, nil
}

func holdsVariant(entry *providerCacheEntry, variant string) bool {
	for _, product := range entry.Products {
		if product != nil && product.Variant == variant {
			return true
		}
	}
	return false
}

func runsWaitingContent(home, requestKey string, entry *providerCacheEntry, kind, name string, definition map[string]any) bool {
	if definition == nil {
		return false
	}
	selection := providerProductSelection(kind, name, definition)
	behavior, _ := definition["behavior"].(string)
	format, _ := definition["format"].(string)
	form := catalogForm(behavior, format)
	for productKey, product := range entry.Products {
		if product == nil || product.SourceSHA256 != entry.PendingSHA256 {
			continue
		}
		if kind == "proxy" && product.Selection == selection || kind != "proxy" && product.SourceForm == form {
			return productFilesExist(providerProductDirectory(home, requestKey, productKey, product.Generation), product)
		}
	}
	return false
}

func readProviderCacheState(home string) *providerCacheStateFile {
	payload, err := readBoundedRegularFile(filepath.Join(home, ProviderRefreshDirectoryName, ProviderRefreshStateFileName), providerRefreshStateMaximumBytes, "provider refresh state")
	if err != nil {
		return nil
	}
	var state providerCacheStateFile
	if json.Unmarshal(payload, &state) != nil || state.Version != providerRefreshStateVersion {
		return nil
	}
	return &state
}

func pendingContentAsSource(home, requestKey string, entry *providerCacheEntry) (string, []byte, error) {
	pending := filepath.Join(home, ProviderRefreshDirectoryName, providerRefreshCacheDirectory, requestKey, "pending")
	payload, err := readBoundedRegularFile(pending, int64(maximumProviderResourceBytes), "waiting provider content")
	if err != nil {
		return "", nil, err
	}
	if sum := sha256.Sum256(payload); hex.EncodeToString(sum[:]) != entry.PendingSHA256 {
		return "", nil, fmt.Errorf("the waiting content changed while it was read")
	}
	seed, _ := json.Marshal(providerSeed{Payload: "source", SourceSHA256: entry.PendingSHA256, FetchedAt: entry.PendingCheckedAt, BuildHere: true})
	return string(seed), payload, nil
}

func withoutAgeKey(definition map[string]any) map[string]any {
	if _, ok := definition["age-secret-key"]; !ok {
		return definition
	}
	copied := make(map[string]any, len(definition))
	for key, value := range definition {
		if key != "age-secret-key" {
			copied[key] = value
		}
	}
	return copied
}

func compilePendingSubscription(home, requestKey, name string, entry *providerCacheEntry, definition map[string]any) (string, []byte, error) {
	if definition == nil {
		return "", nil, fmt.Errorf("the configuration has no proxy provider %q", name)
	}
	pending := filepath.Join(home, ProviderRefreshDirectoryName, providerRefreshCacheDirectory, requestKey, "pending")
	payload, err := readBoundedRegularFile(pending, maximumPendingCompileBytes, "waiting provider content")
	if err != nil {
		return "", nil, err
	}
	if sum := sha256.Sum256(payload); hex.EncodeToString(sum[:]) != entry.PendingSHA256 {
		return "", nil, fmt.Errorf("the waiting content changed while it was read")
	}
	if spec, ok := decodeProviderRefreshMarker(definition[providerRefreshField]); ok && spec.AgeKey != "" {
		decrypted, err := age.DecryptBytes(payload, spec.AgeKey)
		if err != nil {
			return "", nil, fmt.Errorf("decrypt config error: %w", err)
		}
		payload = decrypted
	} else if key, _ := definition["age-secret-key"].(string); key != "" {
		decrypted, err := age.DecryptBytes(payload, key)
		if err != nil {
			return "", nil, fmt.Errorf("decrypt config error: %w", err)
		}
		payload = decrypted
	}
	format, _ := definition["format"].(string)
	content, _, err := sanitizeProxyProviderPayloadForIOS(format, payload, false)
	if err != nil {
		return "", nil, err
	}
	library, count, err := provider.ClashCompileProviderLibrary(name, withoutAgeKey(definition), content)
	if err != nil {
		return "", nil, err
	}
	seed, _ := json.Marshal(providerSeed{Payload: "library", SourceSHA256: entry.PendingSHA256, FetchedAt: entry.PendingCheckedAt, Count: count})
	return string(seed), library, nil
}
