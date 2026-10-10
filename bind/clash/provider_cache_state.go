package clash

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ProjectClash/Clash/log"
)

const (
	ProviderRefreshDirectoryName = "provider-refresh"
	ProviderRefreshStateFileName = "state.json"
)

const (
	providerRefreshScheduled  = "scheduled"
	providerRefreshUpdated    = "updated"
	providerRefreshUnchanged  = "unchanged"
	providerRefreshFailed     = "failed"
	providerRefreshPendingApp = "pendingApp"
)

const (
	providerRefreshPendingMemory    = "memory"
	providerRefreshPendingRecompile = "recompile"
	providerRefreshPendingRoutes    = "routes"
	providerRefreshPendingKilled    = "killed"
)

const (
	providerRefreshStateVersion      = 2
	providerRefreshCacheDirectory    = "cache"
	providerRefreshInflightFileName  = "inflight.json"
	providerRefreshStateMaximumBytes = 8 << 20
	providerRefreshInflightMaximum   = 64 << 10
	providerCacheUnreferencedAge     = 30 * 24 * time.Hour
	providerCacheMaximumBytes        = 128 << 20
)

type providerCacheProduct struct {
	Variant       string   `json:"variant"`
	Entry         string   `json:"entry"`
	Files         []string `json:"files"`
	Behavior      string   `json:"behavior"`
	Format        string   `json:"format"`
	SourceSHA256  string   `json:"sourceSHA256"`
	Count         int      `json:"count,omitempty"`
	IndexChecksum uint32   `json:"indexChecksum,omitempty"`
	Generation    string   `json:"generation"`
	SourceForm    string   `json:"sourceForm,omitempty"`
}

type providerCacheEntry struct {
	Kind             string `json:"kind"`
	URL              string `json:"url"`
	Interval         int64  `json:"interval,omitempty"`
	LastCheckedAt    int64  `json:"lastCheckedAt,omitempty"`
	LastChangedAt    int64  `json:"lastChangedAt,omitempty"`
	NextDueAt        int64  `json:"nextDueAt,omitempty"`
	Result           string `json:"result"`
	Error            string `json:"error,omitempty"`
	PendingReason    string `json:"pendingReason,omitempty"`
	CountBefore      int    `json:"countBefore"`
	CountAfter       int    `json:"countAfter"`
	SubscriptionInfo string `json:"subscriptionInfo,omitempty"`
	SourceSHA256     string `json:"sourceSHA256,omitempty"`
	SourceBytes      int64  `json:"sourceBytes,omitempty"`

	LastReferencedAt    int64                            `json:"lastReferencedAt,omitempty"`
	ETag                string                           `json:"etag,omitempty"`
	ETagSHA256          string                           `json:"etagSHA256,omitempty"`
	KilledSHA256        string                           `json:"killedSHA256,omitempty"`
	PendingSHA256       string                           `json:"pendingSHA256,omitempty"`
	PendingETag         string                           `json:"pendingETag,omitempty"`
	PendingWait         string                           `json:"pendingWait,omitempty"`
	PendingCheckedAt    int64                            `json:"pendingCheckedAt,omitempty"`
	RebuildFailedSHA256 string                           `json:"rebuildFailedSHA256,omitempty"`
	SeedCheckedAt       int64                            `json:"seedCheckedAt,omitempty"`
	RoutesAwaitSHA256   string                           `json:"routesAwaitSHA256,omitempty"`
	SeedIdentity        string                           `json:"seedIdentity,omitempty"`
	Products            map[string]*providerCacheProduct `json:"products,omitempty"`
}

type providerCacheRunning struct {
	ConfigSHA256 string            `json:"configSHA256"`
	Providers    map[string]string `json:"providers"`
	Variants     map[string]string `json:"variants,omitempty"`
}

type providerCacheStateFile struct {
	Version   int                            `json:"version"`
	WrittenAt int64                          `json:"writtenAt"`
	Running   providerCacheRunning           `json:"running"`
	Entries   map[string]*providerCacheEntry `json:"entries"`
}

type providerBuildInflight struct {
	RequestKey    string `json:"requestKey"`
	PayloadSHA256 string `json:"payloadSHA256"`
	At            int64  `json:"at"`
	PID           int    `json:"pid"`
	Committing    bool   `json:"committing,omitempty"`
	Abandoned     bool   `json:"abandoned,omitempty"`
}

type providerCacheStore struct {
	mu        sync.Mutex
	home      string
	homePath  atomic.Value
	directory string
	state     providerCacheStateFile
}

var providerCache = &providerCacheStore{}

func (st *providerCacheStore) useHome(home string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.home = home
	st.homePath.Store(home)
}

func (st *providerCacheStore) homeDirectory() string {
	home, _ := st.homePath.Load().(string)
	return home
}

func (st *providerCacheStore) rootDirectory() string {
	return filepath.Join(st.homeDirectory(), ProviderRefreshDirectoryName)
}

func (st *providerCacheStore) requestDirectory(requestKey string) string {
	return filepath.Join(st.rootDirectory(), providerRefreshCacheDirectory, requestKey)
}

func (st *providerCacheStore) sourcePath(requestKey string) string {
	return filepath.Join(st.requestDirectory(requestKey), "source")
}

func (st *providerCacheStore) productDirectory(requestKey, productKey, generation string) string {
	return filepath.Join(st.requestDirectory(requestKey), "products", productKey, generation)
}

func (st *providerCacheStore) pendingPath(requestKey string) string {
	return filepath.Join(st.requestDirectory(requestKey), "pending")
}

func (st *providerCacheStore) loadLocked() {
	directory := filepath.Join(st.home, ProviderRefreshDirectoryName)
	if st.directory == directory && st.state.Entries != nil {
		return
	}
	st.directory = directory
	st.state = providerCacheStateFile{Version: providerRefreshStateVersion, Entries: map[string]*providerCacheEntry{}}
	payload, err := readBoundedRegularFile(filepath.Join(directory, ProviderRefreshStateFileName), providerRefreshStateMaximumBytes, "provider refresh state")
	if err != nil {
		return
	}
	var state providerCacheStateFile
	if json.Unmarshal(payload, &state) != nil || state.Version != providerRefreshStateVersion || state.Entries == nil {
		return
	}
	for key, entry := range state.Entries {
		if entry == nil {
			delete(state.Entries, key)
		}
	}
	st.state = state
}

func (st *providerCacheStore) saveLocked() {
	st.state.Version = providerRefreshStateVersion
	st.state.WrittenAt = time.Now().Unix()
	payload, err := json.Marshal(st.state)
	if err != nil {
		return
	}
	if err := os.MkdirAll(st.directory, 0o700); err != nil {
		log.Warnln("[Provider] refresh state could not be written: %v", err)
		return
	}
	if err := writeRuntimeProviderFile(filepath.Join(st.directory, ProviderRefreshStateFileName), payload); err != nil {
		log.Warnln("[Provider] refresh state could not be written: %v", err)
	}
}

func (st *providerCacheStore) update(requestKey string, mutate func(*providerCacheEntry)) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.loadLocked()
	entry := st.state.Entries[requestKey]
	if entry == nil {
		entry = &providerCacheEntry{Result: providerRefreshScheduled}
		st.state.Entries[requestKey] = entry
	}
	mutate(entry)
	st.saveLocked()
}

func (st *providerCacheStore) updateEach(requestKeys []string, mutate func(string, *providerCacheEntry)) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.loadLocked()
	for _, requestKey := range requestKeys {
		entry := st.state.Entries[requestKey]
		if entry == nil {
			entry = &providerCacheEntry{Result: providerRefreshScheduled}
			st.state.Entries[requestKey] = entry
		}
		mutate(requestKey, entry)
	}
	st.saveLocked()
}

func (st *providerCacheStore) get(requestKey string) *providerCacheEntry {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.loadLocked()
	entry := st.state.Entries[requestKey]
	if entry == nil {
		return nil
	}
	copied := *entry
	copied.Products = map[string]*providerCacheProduct{}
	for key, product := range entry.Products {
		value := *product
		value.Files = append([]string(nil), product.Files...)
		copied.Products[key] = &value
	}
	return &copied
}

func (st *providerCacheStore) setRunning(configSHA256 string, providers, variants map[string]string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.loadLocked()
	st.state.Running = providerCacheRunning{ConfigSHA256: configSHA256, Providers: providers, Variants: variants}
	now := time.Now().Unix()
	for _, requestKey := range providers {
		entry := st.state.Entries[requestKey]
		if entry == nil {
			entry = &providerCacheEntry{Result: providerRefreshScheduled}
			st.state.Entries[requestKey] = entry
		}
		entry.LastReferencedAt = now
	}
	st.saveLocked()
}

func (st *providerCacheStore) prune(running map[string]bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.loadLocked()
	cacheDirectory := filepath.Join(st.directory, providerRefreshCacheDirectory)
	cutoff := time.Now().Add(-providerCacheUnreferencedAge).Unix()
	changed := false
	for requestKey, entry := range st.state.Entries {
		if running[requestKey] || entry.LastReferencedAt >= cutoff {
			continue
		}
		delete(st.state.Entries, requestKey)
		_ = os.RemoveAll(filepath.Join(cacheDirectory, requestKey))
		changed = true
	}
	if names, err := os.ReadDir(cacheDirectory); err == nil {
		for _, name := range names {
			if _, known := st.state.Entries[name.Name()]; !known && !running[name.Name()] {
				_ = os.RemoveAll(filepath.Join(cacheDirectory, name.Name()))
			}
		}
	}
	type sized struct {
		key        string
		bytes      int64
		referenced int64
	}
	var all []sized
	var total int64
	for requestKey, entry := range st.state.Entries {
		bytes := directoryBytes(filepath.Join(cacheDirectory, requestKey))
		total += bytes
		all = append(all, sized{requestKey, bytes, entry.LastReferencedAt})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].referenced < all[j].referenced })
	for _, candidate := range all {
		if total <= providerCacheMaximumBytes {
			break
		}
		if running[candidate.key] {
			continue
		}
		delete(st.state.Entries, candidate.key)
		_ = os.RemoveAll(filepath.Join(cacheDirectory, candidate.key))
		total -= candidate.bytes
		changed = true
	}
	if changed {
		st.saveLocked()
	}
}

func directoryBytes(directory string) int64 {
	var total int64
	_ = filepath.WalkDir(directory, func(_ string, entry os.DirEntry, err error) error {
		if err == nil && entry.Type().IsRegular() {
			if info, infoErr := entry.Info(); infoErr == nil {
				total += info.Size()
			}
		}
		return nil
	})
	return total
}

func (st *providerCacheStore) writeInflight(requestKey, sha string) {
	st.writeInflightMarker(providerBuildInflight{RequestKey: requestKey, PayloadSHA256: sha, PID: os.Getpid()})
}

func (st *providerCacheStore) writeInflightCommitting(requestKey, sha string) {
	st.writeInflightMarker(providerBuildInflight{RequestKey: requestKey, PayloadSHA256: sha, PID: os.Getpid(), Committing: true})
}

func (st *providerCacheStore) writeInflightFor(pid int, requestKey, sha string) {
	st.writeInflightMarker(providerBuildInflight{RequestKey: requestKey, PayloadSHA256: sha, PID: pid})
}

func (st *providerCacheStore) writeInflightMarker(marker providerBuildInflight) {
	directory := st.rootDirectory()
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return
	}
	marker.At = time.Now().Unix()
	payload, err := json.Marshal(marker)
	if err != nil {
		return
	}
	_ = writeRuntimeProviderFile(filepath.Join(directory, providerRefreshInflightFileName), payload)
}

func (st *providerCacheStore) abandonInflight() {
	path := filepath.Join(st.rootDirectory(), providerRefreshInflightFileName)
	payload, err := readBoundedRegularFile(path, providerRefreshInflightMaximum, "provider build marker")
	if err != nil {
		return
	}
	var marker providerBuildInflight
	if json.Unmarshal(payload, &marker) != nil || marker.PID != os.Getpid() || marker.Committing {
		return
	}
	marker.Abandoned = true
	st.writeInflightMarker(marker)
}

func (st *providerCacheStore) clearInflight() {
	_ = os.Remove(filepath.Join(st.rootDirectory(), providerRefreshInflightFileName))
}

func (st *providerCacheStore) consumeInflight() {
	path := filepath.Join(st.rootDirectory(), providerRefreshInflightFileName)
	payload, err := readBoundedRegularFile(path, providerRefreshInflightMaximum, "provider build marker")
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			_ = os.Remove(path)
		}
		return
	}
	var marker providerBuildInflight
	if json.Unmarshal(payload, &marker) == nil && marker.PID == os.Getpid() {
		return
	}
	_ = os.Remove(path)
	if marker.RequestKey == "" || marker.PayloadSHA256 == "" || marker.Abandoned {
		return
	}
	log.Warnln("[Provider] the tunnel stopped while it built a payload (%s); that payload waits for the App", marker.PayloadSHA256)
	st.update(marker.RequestKey, func(entry *providerCacheEntry) {
		if marker.Committing {
			entry.Products = nil
		}
		entry.KilledSHA256 = marker.PayloadSHA256
		entry.LastReferencedAt = time.Now().Unix()
		entry.Result = providerRefreshPendingApp
		entry.PendingReason = providerRefreshPendingKilled
		entry.Error = ""
	})
}

func (st *providerCacheStore) relativeToHome(path string) string {
	relative, err := filepath.Rel(st.homeDirectory(), path)
	if err != nil || relative == "." || strings.HasPrefix(relative, "..") || filepath.IsAbs(relative) {
		return ""
	}
	return filepath.ToSlash(relative)
}

func (st *providerCacheStore) setRunningVariant(name, variant string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.loadLocked()
	if st.state.Running.Variants == nil {
		st.state.Running.Variants = map[string]string{}
	}
	if st.state.Running.Variants[name] == variant {
		return
	}
	st.state.Running.Variants[name] = variant
	st.saveLocked()
}

func (st *providerCacheStore) pruneProducts(live map[string]bool) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.loadLocked()
	cacheDirectory := filepath.Join(st.directory, providerRefreshCacheDirectory)
	for requestKey, entry := range st.state.Entries {
		productsDirectory := filepath.Join(cacheDirectory, requestKey, "products")
		keys, err := os.ReadDir(productsDirectory)
		if err != nil {
			continue
		}
		for _, key := range keys {
			generations, err := os.ReadDir(filepath.Join(productsDirectory, key.Name()))
			if err != nil {
				continue
			}
			for _, generation := range generations {
				path := filepath.Join(productsDirectory, key.Name(), generation.Name())
				if live[path] {
					continue
				}
				if product := entry.Products[key.Name()]; product != nil && product.Generation == generation.Name() {
					continue
				}
				_ = os.RemoveAll(path)
			}
		}
	}
}
