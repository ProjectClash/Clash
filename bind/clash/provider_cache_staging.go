package clash

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/ProjectClash/Clash/config"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/log"
)

const providerCacheServedField = "x-clash-cache-served"

const providerCacheNativeEntry = "payload"

type providerRefreshTarget struct {
	kind, name                   string
	requestKey, productKey       string
	spec                         *providerRefreshSpec
	sourceBehavior, sourceFormat string
	sideUpdateSafe               bool
	definition                   map[string]any
	productDirectory             string
	product                      *providerCacheProduct
	checkSoon                    bool
	serverFirst                  bool
	awaits                       string
	selection                    string
	builtHere                    bool
	pending                      *providerCacheImport
}

type providerCacheImport struct {
	product                     *providerCacheProduct
	fromSeed                    bool
	seedPath, seedIdentity, sha string
	sourceBytes                 int64
	fetchedAt                   time.Time
	etag, subscriptionInfo      string
	older                       bool
	serverFirst                 bool
	groupMember                 bool
	waitsForApp                 bool
}

type providerSeedCandidate struct {
	path, identity         string
	fetchedAt              time.Time
	etag, subscriptionInfo string
	legacy                 bool
}

func providerCacheKnowsContent(entry *providerCacheEntry) bool {
	return entry != nil && (entry.SourceSHA256 != "" || entry.PendingSHA256 != "")
}

func seedIsPayload(path, sha string) bool {
	digest, _, err := hashFile(path)
	return err == nil && digest == sha
}

type providerRefreshPlan struct {
	targets []*providerRefreshTarget
}

func providerProductKey(kind, behavior, format, selection string, policy appleRuntimePolicy) string {
	format = strings.ToLower(strings.TrimSpace(format))
	if format == "" {
		format = "yaml"
	}
	parts := []string{kind, strings.ToLower(strings.TrimSpace(behavior)), format, stagedPolicyFingerprint(policy)}
	if selection != "" {
		parts = append(parts, selection)
	}
	digest := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(digest[:16])
}

func providerProductSelection(kind, name string, definition map[string]any) string {
	if kind != "proxy" {
		return ""
	}
	return name + "\x00" + providerProductSelectionKey(definition)
}

func newProductGeneration() string {
	var random [6]byte
	_, _ = rand.Read(random[:])
	return fmt.Sprintf("%x-%x", time.Now().UnixNano(), random)
}

func providerSeedIdentity(path string) (string, bool) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return "", false
	}
	identity, err := stagedSourceIdentity(path)
	if err != nil {
		return "", false
	}
	return fmt.Sprintf("%d:%d:%d", identity.size, identity.mtimeNS, identity.inode), true
}

func unseededPath(path string) bool {
	relative, err := filepath.Rel(filepath.Join(C.Path.HomeDir(), providerRefreshUnseededDirectory), path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func productFilesExist(directory string, product *providerCacheProduct) bool {
	if product == nil || product.Entry == "" || product.Generation == "" {
		return false
	}
	for _, name := range append([]string{product.Entry}, product.Files...) {
		if info, err := os.Lstat(filepath.Join(directory, name)); err != nil || !info.Mode().IsRegular() {
			return false
		}
	}
	return true
}

func prepareProviderRefreshForTunnel(raw *config.RawConfig, policy appleRuntimePolicy) *providerRefreshPlan {
	plan := &providerRefreshPlan{}
	seeds := map[*providerRefreshTarget]*providerSeedCandidate{}
	for _, namespace := range []struct {
		kind      string
		providers map[string]map[string]any
	}{{"proxy", raw.ProxyProvider}, {"rule", raw.RuleProvider}} {
		names := make([]string, 0, len(namespace.providers))
		for name := range namespace.providers {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			definition := namespace.providers[name]
			if typeName, _ := definition["type"].(string); typeName != "file" {
				continue
			}
			spec, ok := decodeProviderRefreshMarker(definition[providerRefreshField])
			delete(definition, providerRefreshField)
			if !ok {
				continue
			}
			behavior, _ := definition["behavior"].(string)
			format, _ := definition["format"].(string)
			target := &providerRefreshTarget{
				kind: namespace.kind, name: name, spec: spec, definition: definition,
				requestKey:     spec.requestKey(namespace.kind),
				productKey:     providerProductKey(namespace.kind, behavior, format, providerProductSelection(namespace.kind, name, definition), policy),
				selection:      providerProductSelection(namespace.kind, name, definition),
				sourceBehavior: behavior, sourceFormat: format,
				sideUpdateSafe: namespace.kind == "proxy" || providerSideUpdateSafe(definition),
			}
			plan.targets = append(plan.targets, target)
			pathValue, _ := definition["path"].(string)
			seedPath := C.Path.Resolve(pathValue)
			if !unseededPath(seedPath) {
				if identity, ok := providerSeedIdentity(seedPath); ok {
					seeds[target] = &providerSeedCandidate{path: seedPath, identity: identity,
						fetchedAt: spec.FetchedAt, etag: spec.ETag, subscriptionInfo: spec.SubscriptionInfo}
				}
			} else if legacy := legacyProviderDownload(namespace.kind, spec); legacy != "" && !providerCacheKnowsContent(providerCache.get(spec.requestKey(namespace.kind))) {
				if identity, ok := providerSeedIdentity(legacy); ok {
					seeds[target] = &providerSeedCandidate{path: legacy, identity: identity, legacy: true}
				}
			}
		}
	}
	byRequest := map[string][]*providerRefreshTarget{}
	var order []string
	for _, target := range plan.targets {
		if byRequest[target.requestKey] == nil {
			order = append(order, target.requestKey)
		}
		byRequest[target.requestKey] = append(byRequest[target.requestKey], target)
	}
	unloaded := map[string]string{}
	for _, requestKey := range order {
		targets := byRequest[requestKey]
		var best *providerSeedCandidate
		for _, target := range targets {
			candidate := seeds[target]
			if candidate == nil {
				continue
			}
			if best == nil || candidate.fetchedAt.After(best.fetchedAt) ||
				(candidate.fetchedAt.Equal(best.fetchedAt) && best.legacy && !candidate.legacy) {
				best = candidate
			}
		}
		entry := providerCache.get(requestKey)
		cacheHasContent := entry != nil && entry.SourceSHA256 != ""
		seedNewer, checkSoon := false, false
		if best != nil {
			switch {
			case !knowsRunningContent(entry):
				seedNewer = true
			case !best.legacy && entry.PendingSHA256 != "" && seedIsPayload(best.path, entry.PendingSHA256):
				seedNewer = true
			case !best.legacy && entry.RoutesAwaitSHA256 != "" && entry.RoutesAwaitSHA256 == entry.SourceSHA256 && seedIsPayload(best.path, entry.RoutesAwaitSHA256):
				seedNewer = true
			case entry.SeedCheckedAt > 0 && entry.SeedCheckedAt >= entry.LastCheckedAt && best.identity == entry.SeedIdentity:
				seedNewer = true
			case !best.fetchedAt.IsZero():
				seedNewer = best.fetchedAt.Unix() > runningConfirmation(entry)
			default:
				checkSoon = true
			}
		}
		owned := map[string]bool{}
		if seedNewer {
			for _, target := range targets {
				if candidate := seeds[target]; candidate != nil && candidate.path == best.path {
					owned[target.productKey] = true
				}
			}
		}
		for _, target := range targets {
			target.checkSoon = checkSoon
			definition := target.definition
			var product *providerCacheProduct
			if cacheHasContent {
				if candidate := entry.Products[target.productKey]; productRuns(entry, candidate) {
					if candidate.BuiltHere {
						target.builtHere = true
					}
					directory := providerCache.productDirectory(target.requestKey, target.productKey, candidate.Generation)
					if productFilesExist(directory, candidate) && !productParsedTooLarge(target, candidate, directory) {
						product = candidate
					}
				}
			}
			own := seeds[target]
			switch {
			case seedNewer && own != nil && own.path == best.path:
				target.pending = &providerCacheImport{fromSeed: true, seedPath: best.path, seedIdentity: best.identity,
					fetchedAt: best.fetchedAt, etag: best.etag, subscriptionInfo: best.subscriptionInfo}
				definition["path"] = best.path
			case seedNewer && owned[target.productKey]:
				target.pending = &providerCacheImport{groupMember: true}
				definition[providerCacheServedField] = true
			case !seedNewer && product != nil:
				serveCachedProduct(target, product)
			case own != nil:
				target.pending = &providerCacheImport{fromSeed: true, older: true, seedPath: own.path, seedIdentity: own.identity,
					fetchedAt: own.fetchedAt}
				definition["path"] = own.path
			default:
				groupKey := target.requestKey + "\x00" + target.productKey
				if unloaded[groupKey] == "" {
					unloaded[groupKey] = providerCache.productDirectory(target.requestKey, target.productKey, newProductGeneration())
				}
				startUnloaded(target, unloaded[groupKey])
				definition[providerCacheServedField] = true
			}
		}
	}
	return plan
}

func startUnloaded(target *providerRefreshTarget, directory string) {
	target.productDirectory = directory
	target.definition["path"] = filepath.Join(directory, providerCacheNativeEntry)
	if target.awaits = formTheAppCompiles(target); target.awaits != "" {
		target.definition["path"] = filepath.Join(directory, awaitedEntry)
		if target.awaits == "mapped" {
			target.definition["format"] = "text"
			target.definition["behavior"] = strings.ToLower(strings.TrimSpace(target.sourceBehavior))
		}
		return
	}
	if target.kind == "rule" && compilesNatively(target.sourceBehavior, target.sourceFormat) {
		target.definition["format"] = "mrs"
		target.definition["behavior"] = strings.ToLower(strings.TrimSpace(target.sourceBehavior))
	}
}

func formTheAppCompiles(target *providerRefreshTarget) string {
	if !stagingMapsRuleSets || !target.sideUpdateSafe {
		return ""
	}
	switch {
	case target.kind == "proxy":
		return "library"
	case target.kind != "rule":
		return ""
	case mappable(target.sourceBehavior):
		return "mapped"
	case strings.EqualFold(strings.TrimSpace(target.sourceBehavior), "classical") && !strings.EqualFold(strings.TrimSpace(target.sourceFormat), "mrs"):
		return "indexed"
	}
	return ""
}

const unloadedTextName = "source"

const awaitedEntry = providerCacheNativeEntry + providerRuntimeIndexStubSuffix

func awaitedProduct(target *providerRefreshTarget) *providerCacheProduct {
	return awaitedProductIn(target, target.awaits)
}

func awaitedProductIn(target *providerRefreshTarget, form string) *providerCacheProduct {
	product := &providerCacheProduct{
		Variant: form, Entry: awaitedEntry, Generation: filepath.Base(target.productDirectory),
		Behavior: target.sourceBehavior, Format: target.sourceFormat,
		SourceForm: catalogForm(target.sourceBehavior, target.sourceFormat), Selection: target.selection,
	}
	switch form {
	case "mapped":
		product.Behavior, product.Format = strings.ToLower(strings.TrimSpace(target.sourceBehavior)), "text"
		product.Files = []string{awaitedEntry, providerCacheNativeEntry + mappedSuffix(target.sourceBehavior)}
	case "indexed":
		product.Files = []string{awaitedEntry, unloadedTextName, unloadedTextName + providerRuntimeIndexSuffix}
	case "library":
		product.Files = []string{awaitedEntry, providerCacheNativeEntry + providerRuntimeLibrarySuffix}
	}
	return product
}

func formOf(target *providerRefreshTarget) string {
	if target.product != nil {
		if target.product.Stopgap && !target.builtHere {
			if form := formTheAppCompiles(target); form != "" {
				return form
			}
		}
		return target.product.Variant
	}
	if target.builtHere {
		return ""
	}
	return target.awaits
}

func compilesNatively(behavior, format string) bool {
	switch strings.ToLower(strings.TrimSpace(behavior)) {
	case "domain", "ipcidr":
	default:
		return false
	}
	return !strings.EqualFold(strings.TrimSpace(format), "mrs")
}

func serveCachedProduct(target *providerRefreshTarget, product *providerCacheProduct) {
	target.product = product
	if product.BuiltHere {
		target.builtHere = true
	}
	target.productDirectory = providerCache.productDirectory(target.requestKey, target.productKey, product.Generation)
	target.definition["path"] = filepath.Join(target.productDirectory, product.Entry)
	if target.kind == "rule" {
		target.definition["behavior"] = product.Behavior
		target.definition["format"] = product.Format
	}
	target.definition[providerCacheServedField] = true
}

func regularFileExists(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode().IsRegular()
}

func completeProviderRefreshAfterStaging(plan *providerRefreshPlan, runtime *providerRuntime, policy appleRuntimePolicy) {
	type productGroup struct {
		directory string
		imported  *providerCacheImport
	}
	groups := map[string]*productGroup{}
	deferred := map[string]*providerCacheImport{}
	groupOf := func(target *providerRefreshTarget) *productGroup {
		key := target.requestKey + "\x00" + target.productKey
		if groups[key] == nil {
			groups[key] = &productGroup{}
		}
		return groups[key]
	}
	for _, target := range plan.targets {
		if target.pending == nil {
			continue
		}
		group := groupOf(target)
		if group.imported != nil {
			continue
		}
		if runtime != nil && runtime.deferred[providerRuntimeKey(target.kind, target.name)] != "" && target.pending.fromSeed {
			seed := *target.pending
			deferred[target.requestKey+"\x00"+target.productKey] = &seed
			continue
		}
		var entry providerRuntimeEntry
		ok := false
		if runtime != nil {
			entry, ok = runtime.entries[providerRuntimeKey(target.kind, target.name)]
		}
		if !ok || entry.runtimePath == "" {
			continue
		}
		generation := newProductGeneration()
		target.productDirectory = providerCache.productDirectory(target.requestKey, target.productKey, generation)
		product, err := linkStagedProduct(target, entry, generation)
		if err != nil {
			log.Warnln("[Provider] %s: its product could not be kept in the tunnel's cache: %v", target.name, err)
			target.productDirectory = ""
			continue
		}
		imported := *target.pending
		if imported.fromSeed {
			sha, size, err := hashFile(imported.seedPath)
			if err != nil {
				imported.older = true
			} else {
				imported.sha, imported.sourceBytes = sha, size
			}
		}
		if target.spec.AgeKey != "" && !imported.older {
			imported.older, imported.serverFirst = true, true
		}
		product.SourceSHA256 = imported.sha
		imported.product = product
		group.directory, group.imported = target.productDirectory, &imported
	}
	for _, target := range plan.targets {
		if target.pending == nil {
			continue
		}
		group := groupOf(target)
		if seed := deferred[target.requestKey+"\x00"+target.productKey]; group.imported == nil && seed != nil {
			target.pending = nil
			if !seed.older {
				target.pending = &providerCacheImport{waitsForApp: true, seedPath: seed.seedPath, seedIdentity: seed.seedIdentity, fetchedAt: seed.fetchedAt, etag: seed.etag}
			}
			if product := runnableCachedProduct(target); product != nil {
				serveCachedProduct(target, product)
				continue
			}
			if group.directory == "" {
				group.directory = providerCache.productDirectory(target.requestKey, target.productKey, newProductGeneration())
			}
			startUnloaded(target, group.directory)
			continue
		}
		if group.imported == nil {
			if group.directory == "" {
				group.directory = providerCache.productDirectory(target.requestKey, target.productKey, newProductGeneration())
			}
			target.pending = nil
			startUnloaded(target, group.directory)
			continue
		}
		copied := *group.imported
		target.pending = &copied
		target.serverFirst = copied.serverFirst
		target.product = group.imported.product
		target.productDirectory = group.directory
		pointAtProduct(target, group.imported.product)
	}
}

const startTextSeedLimit = 1 << 20

const builtHereStartLimit = 2 << 20

func productParsedTooLarge(target *providerRefreshTarget, product *providerCacheProduct, directory string) bool {
	if product.BuiltHere {
		return sourceLargerThan(filepath.Join(directory, product.Entry), builtHereStartLimit)
	}
	form := formTheAppCompiles(target)
	return form != "" && product.Variant != form && sourceLargerThan(filepath.Join(directory, product.Entry), startTextSeedLimit)
}

func runnableCachedProduct(target *providerRefreshTarget) *providerCacheProduct {
	entry := providerCache.get(target.requestKey)
	if entry == nil || entry.SourceSHA256 == "" {
		return nil
	}
	product := entry.Products[target.productKey]
	if product == nil {
		return nil
	}
	directory := providerCache.productDirectory(target.requestKey, target.productKey, product.Generation)
	stopgap := product.Stopgap && !sourceLargerThan(filepath.Join(directory, product.Entry), startTextSeedLimit)
	builtHere := product.BuiltHere && !sourceLargerThan(filepath.Join(directory, product.Entry), builtHereStartLimit)
	if !productRuns(entry, product) || product.Variant != formTheAppCompiles(target) && !stopgap && !builtHere ||
		!productFilesExist(directory, product) {
		return nil
	}
	return product
}

func pointAtProduct(target *providerRefreshTarget, product *providerCacheProduct) {
	target.definition["path"] = filepath.Join(target.productDirectory, product.Entry)
	if target.kind == "rule" {
		target.definition["behavior"] = product.Behavior
		target.definition["format"] = product.Format
	}
}

func commitProviderRefreshPlan(plan *providerRefreshPlan) map[string]int {
	seeded := map[string]int{}
	if plan == nil {
		return seeded
	}
	now := time.Now().Unix()
	for _, target := range plan.targets {
		imported := target.pending
		target.pending = nil
		if imported != nil && imported.waitsForApp {
			commitSeedForTheApp(target, imported, now)
			continue
		}
		if imported == nil || imported.product == nil {
			continue
		}
		if imported.older {
			providerCache.update(target.requestKey, func(cached *providerCacheEntry) {
				cached.Kind, cached.URL = target.kind, target.spec.URL
				cached.LastReferencedAt = now
				if at := unixOrZero(imported.fetchedAt); imported.serverFirst && at >= cached.SeedCheckedAt {
					cached.SeedCheckedAt, cached.SeedIdentity = at, imported.seedIdentity
				}
			})
			continue
		}
		if imported.fromSeed && imported.sha != "" {
			if err := linkOrCopyFile(imported.seedPath, providerCache.sourcePath(target.requestKey)); err != nil {
				log.Warnln("[Provider] %s: the seed could not be kept in the tunnel's cache: %v", target.name, err)
			}
		}
		dropPendingFile := false
		providerCache.update(target.requestKey, func(cached *providerCacheEntry) {
			cached.Kind, cached.URL = target.kind, target.spec.URL
			cached.LastReferencedAt = now
			product := imported.product
			if imported.fromSeed && imported.sha != "" {
				if _, recorded := seeded[target.requestKey]; !recorded {
					seeded[target.requestKey] = cached.CountAfter
				}
				changed := cached.SourceSHA256 != imported.sha
				fetchedAt := unixOrZero(imported.fetchedAt)
				if changed {
					cached.Products = map[string]*providerCacheProduct{}
					cached.ETag, cached.ETagSHA256 = "", ""
					cached.LastChangedAt = fetchedAt
					if fetchedAt == 0 {
						cached.LastChangedAt = now
					}
					cached.RebuildFailedSHA256 = ""
				}
				cached.SourceSHA256, cached.SourceBytes = imported.sha, imported.sourceBytes
				switch {
				case fetchedAt > cached.LastCheckedAt:
					cached.LastCheckedAt = fetchedAt
				case fetchedAt == 0 && changed:
					cached.LastCheckedAt = 0
				}
				if cached.PendingSHA256 == imported.sha && cached.PendingCheckedAt > cached.LastCheckedAt {
					cached.LastCheckedAt = cached.PendingCheckedAt
				}
				cached.RoutesAwaitSHA256 = ""
				if imported.etag != "" {
					cached.ETag, cached.ETagSHA256 = imported.etag, imported.sha
				}
				if imported.subscriptionInfo != "" {
					cached.SubscriptionInfo = imported.subscriptionInfo
				}
				cached.SeedIdentity = imported.seedIdentity
				if settlesWaitLocked(cached, imported.sha, fetchedAt) {
					clearPendingLocked(cached)
					dropPendingFile = true
					if cached.Result == providerRefreshPendingApp || cached.Result == providerRefreshScheduled {
						cached.Result = providerRefreshUpdated
					}
					cached.PendingReason, cached.Error = "", ""
				}
				reflectWaitLocked(cached)
			}
			product.SourceSHA256 = cached.SourceSHA256
			if cached.Products == nil {
				cached.Products = map[string]*providerCacheProduct{}
			}
			cached.Products[target.productKey] = product
		})
		if dropPendingFile {
			_ = os.Remove(providerCache.pendingPath(target.requestKey))
		}
	}
	return seeded
}

func linkStagedProduct(target *providerRefreshTarget, entry providerRuntimeEntry, generation string) (*providerCacheProduct, error) {
	directory := filepath.Dir(entry.runtimePath)
	entryName := filepath.Base(entry.runtimePath)
	files := []string{entryName}
	variant := "text"
	switch {
	case target.kind == "proxy" && entry.compileVerdict == compileVerdictLibrary:
		variant = "library"
		files = append(files, entry.textFileName+providerRuntimeLibrarySuffix)
	case target.kind == "proxy":
		variant = "proxy"
	case entry.compileVerdict == compileVerdictIndexed:
		variant = "indexed"
		files = append(files, entry.textFileName, entry.textFileName+providerRuntimeIndexSuffix)
	case entry.compileVerdict == compileVerdictMapped:
		variant = "mapped"
		files = append(files, entry.textFileName+mappedSuffix(entry.behavior))
	case entry.compileVerdict == compileVerdictCompiled && !strings.EqualFold(strings.TrimSpace(entry.sourceFormat), "mrs"):
		variant = "compiled"
	case strings.EqualFold(strings.TrimSpace(entry.sourceFormat), "mrs"):
		variant = "mrs"
	}
	if err := os.MkdirAll(target.productDirectory, 0o700); err != nil {
		return nil, err
	}
	for _, name := range files {
		if err := linkOrCopyFile(filepath.Join(directory, name), filepath.Join(target.productDirectory, name)); err != nil {
			return nil, err
		}
	}
	return &providerCacheProduct{
		Variant: variant, Entry: entryName, Files: files, Generation: generation,
		Behavior: entry.behavior, Format: entry.format,
		SourceForm: catalogForm(target.sourceBehavior, target.sourceFormat), Selection: target.selection,
	}, nil
}

func commitSeedForTheApp(target *providerRefreshTarget, imported *providerCacheImport, now int64) {
	sha, _, err := hashFile(imported.seedPath)
	if err != nil {
		log.Warnln("[Provider] %s: its content could not be left for Clash to compile: %v", target.name, err)
		return
	}
	confirmed := unixOrZero(imported.fetchedAt)
	if confirmed == 0 {
		confirmed = now
	}
	pendingPath := providerCache.pendingPath(target.requestKey)
	if entry := providerCache.get(target.requestKey); entry != nil &&
		(entry.SourceSHA256 == sha ||
			knowsRunningContent(entry) && confirmed <= runningConfirmation(entry) ||
			entry.PendingSHA256 == sha && regularFileExists(pendingPath) ||
			entry.PendingSHA256 != "" && entry.PendingCheckedAt > confirmed && regularFileExists(pendingPath)) {
		providerCache.update(target.requestKey, func(cached *providerCacheEntry) {
			cached.LastReferencedAt = now
			reflectWaitLocked(cached)
		})
		return
	}
	if err := linkOrCopyFile(imported.seedPath, pendingPath); err != nil {
		log.Warnln("[Provider] %s: its content could not be left for Clash to compile: %v", target.name, err)
		return
	}
	providerCache.update(target.requestKey, func(cached *providerCacheEntry) {
		cached.Kind, cached.URL = target.kind, target.spec.URL
		cached.LastReferencedAt = now
		cached.PendingSHA256, cached.PendingETag, cached.PendingWait = sha, imported.etag, providerRefreshPendingRecompile
		cached.PendingCheckedAt = confirmed
		cached.Result, cached.Error, cached.PendingReason = providerRefreshPendingApp, "", providerRefreshPendingRecompile
	})
}

func linkOrCopyFile(source, destination string) error {
	if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
		return err
	}
	temporary := fmt.Sprintf("%s.link-%d-%d", destination, os.Getpid(), time.Now().UnixNano())
	if err := os.Link(source, temporary); err != nil {
		payload, readErr := readBoundedRegularFile(source, int64(providerContentBytes()), "provider product")
		if readErr != nil {
			return err
		}
		return writeRuntimeProviderFile(destination, payload)
	}
	if err := os.Rename(temporary, destination); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func hashFile(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	digest := sha256.New()
	size, err := io.Copy(digest, io.LimitReader(file, maximumPendingCompileBytes+1))
	if err != nil {
		return "", 0, err
	}
	if size > maximumPendingCompileBytes {
		return "", 0, fmt.Errorf("%s is larger than %d bytes", filepath.Base(path), maximumPendingCompileBytes)
	}
	return hex.EncodeToString(digest.Sum(nil)), size, nil
}

func legacyProviderDownload(kind string, spec *providerRefreshSpec) string {
	path := spec.LegacyPath
	if path != "" {
		path = C.Path.Resolve(path)
	} else {
		directory := "rules"
		if kind == "proxy" {
			directory = "proxies"
		}
		path = C.Path.GetPathByHash(directory, spec.URL)
	}
	if !providerSourceContained(path, C.Path.HomeDir()) || !regularFileExists(path) {
		return ""
	}
	return path
}
