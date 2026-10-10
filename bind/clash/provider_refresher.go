package clash

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/ProjectClash/Clash/component/age"
	mihomoHttp "github.com/ProjectClash/Clash/component/http"
	"github.com/ProjectClash/Clash/component/resource"
	P "github.com/ProjectClash/Clash/constant/provider"
	"github.com/ProjectClash/Clash/log"
	"github.com/ProjectClash/Clash/tunnel"

	http "github.com/metacubex/http"
)

var providerRefreshSettleDelay = 30 * time.Second

var providerRefreshMinimumBackoff = 10 * time.Second

var (
	providerRefreshFirstLoadMinimum = 10 * time.Second
	providerRefreshFirstLoadMaximum = 10 * time.Minute
)

var providerRefreshPoll = 30 * time.Second

const ProviderUpdateUnavailablePrefix = "clash: provider update unavailable: "

type providerRefreshTask struct {
	requestKey, kind string
	spec             *providerRefreshSpec
	interval         time.Duration
	targets          []*providerRefreshTarget
	due              time.Time
	failures         int
	routes           bool
}

func (task *providerRefreshTask) loaded() bool {
	for _, target := range task.targets {
		if target.product == nil {
			return false
		}
	}
	return true
}

func (task *providerRefreshTask) current(entry *providerCacheEntry) bool {
	if entry == nil || entry.SourceSHA256 == "" {
		return task.loaded()
	}
	for _, target := range task.targets {
		if target.product == nil || target.product.SourceSHA256 != entry.SourceSHA256 {
			return false
		}
	}
	return true
}

type providerSourceOrigin int

const (
	originFresh providerSourceOrigin = iota
	originSeed
	originPending
	originCache
)

type providerSourceFile struct {
	path, sha string
	size      int64
	origin    providerSourceOrigin
}

func (source providerSourceFile) discard() {
	if source.origin == originFresh || source.origin == originSeed {
		_ = os.Remove(source.path)
	}
}

type providerSeed struct {
	FetchedAt        int64  `json:"fetchedAt"`
	SourceSHA256     string `json:"sourceSHA256"`
	ETag             string `json:"etag"`
	SubscriptionInfo string `json:"subscriptionInfo"`
	Payload          string `json:"payload"`
	path             string
	bytes            int64
}

type providerRefreshRequest struct {
	kind, name string
	seed       *providerSeed
	reply      chan providerRefreshResult
}

type providerRefreshResult struct {
	Result        string `json:"result"`
	CountBefore   int    `json:"countBefore"`
	CountAfter    int    `json:"countAfter"`
	Error         string `json:"error,omitempty"`
	PendingReason string `json:"pendingReason,omitempty"`
	CheckedAt     int64  `json:"checkedAt,omitempty"`
	stale         bool
}

type providerRefresher struct {
	done                                                             chan struct{}
	service                                                          *BoxService
	generation                                                       uint64
	runtime                                                          *providerRuntime
	ctx                                                              context.Context
	tasks                                                            []*providerRefreshTask
	byName                                                           map[string]*providerRefreshTask
	requests                                                         chan providerRefreshRequest
	configSHA256                                                     string
	home                                                             string
	settle, minimumBackoff, firstLoadMinimum, firstLoadMaximum, poll time.Duration
}

func (s *BoxService) startProviderRefreshLocked() {
	s.stopProviderRefreshLocked()
	var plan *providerRefreshPlan
	if s.providerRuntime != nil {
		plan = s.providerRuntime.refresh
	}
	seeded := commitProviderRefreshPlan(plan)
	ctx, cancel := context.WithCancel(context.Background())
	refresher := &providerRefresher{
		done:    make(chan struct{}),
		service: s, generation: s.refreshGeneration, runtime: s.providerRuntime, ctx: ctx,
		byName: map[string]*providerRefreshTask{}, requests: make(chan providerRefreshRequest),
		configSHA256: s.runningConfigSHA256, home: providerCache.homeDirectory(),
		settle: providerRefreshSettleDelay, minimumBackoff: providerRefreshMinimumBackoff,
		firstLoadMinimum: providerRefreshFirstLoadMinimum, firstLoadMaximum: providerRefreshFirstLoadMaximum,
		poll: providerRefreshPoll,
	}
	byRequest := map[string]*providerRefreshTask{}
	if plan != nil {
		for _, target := range plan.targets {
			task := byRequest[target.requestKey]
			if task == nil {
				task = &providerRefreshTask{requestKey: target.requestKey, kind: target.kind, spec: target.spec}
				byRequest[target.requestKey] = task
				refresher.tasks = append(refresher.tasks, task)
			}
			task.targets = append(task.targets, target)
			task.routes = task.routes || !target.sideUpdateSafe
			if interval := target.spec.Interval; interval > 0 && (task.interval == 0 || interval < task.interval) {
				task.interval = interval
			}
			refresher.byName[providerResourceKey(target.kind, target.name)] = task
		}
	}
	sort.Slice(refresher.tasks, func(i, j int) bool { return refresher.tasks[i].requestKey < refresher.tasks[j].requestKey })
	refresher.publishRunning(seeded)
	s.refreshCancel = cancel
	s.refresher = refresher
	go refresher.run()
}

func (r *providerRefresher) publishRunning(seeded map[string]int) {
	running, variants := map[string]string{}, map[string]string{}
	referenced, liveDirectories := map[string]bool{}, map[string]bool{}
	for name, task := range r.byName {
		running[name] = task.requestKey
		referenced[task.requestKey] = true
	}
	for _, task := range r.tasks {
		for _, target := range task.targets {
			if target.productDirectory != "" {
				liveDirectories[target.productDirectory] = true
			}
			if target.product != nil {
				variants[providerResourceKey(target.kind, target.name)] = target.product.Variant
			}
		}
	}
	providerCache.setRunning(r.configSHA256, running, variants)
	{
		keys := make([]string, 0, len(r.tasks))
		byKey := map[string]*providerRefreshTask{}
		for _, task := range r.tasks {
			keys = append(keys, task.requestKey)
			byKey[task.requestKey] = task
		}
		providerCache.updateEach(keys, func(requestKey string, cached *providerCacheEntry) {
			task := byKey[requestKey]
			cached.Kind, cached.URL = task.kind, task.spec.URL
			cached.Interval = int64(task.interval / time.Second)
			if cached.Result == "" {
				cached.Result = providerRefreshScheduled
			}
		})
	}
	if len(seeded) > 0 {
		keys := make([]string, 0, len(seeded))
		counts := map[string]int{}
		for _, task := range r.tasks {
			if _, ok := seeded[task.requestKey]; !ok {
				continue
			}
			entry := providerCache.get(task.requestKey)
			count := 0
			for _, target := range task.targets {
				if target.product == nil || entry == nil || target.product.SourceSHA256 != entry.SourceSHA256 {
					continue
				}
				if live, ok := liveFileProvider(target.kind, target.name); ok {
					count = live.Count()
					break
				}
			}
			keys = append(keys, task.requestKey)
			counts[task.requestKey] = count
		}
		providerCache.updateEach(keys, func(requestKey string, cached *providerCacheEntry) {
			cached.CountBefore, cached.CountAfter = seeded[requestKey], counts[requestKey]
		})
	}
	providerCache.prune(referenced)
	providerCache.pruneProducts(liveDirectories)
	removeStaleRefreshFiles()
	for _, task := range r.tasks {
		entry := providerCache.get(task.requestKey)
		if entry == nil {
			continue
		}
		for _, target := range task.targets {
			if target.product == nil {
				continue
			}
			if live, ok := liveFileProvider(target.kind, target.name); ok && entry.LastCheckedAt > 0 {
				live.SetUpdatedAt(time.Unix(entry.LastCheckedAt, 0))
			}
			if target.kind == "proxy" && entry.SubscriptionInfo != "" {
				if live, ok := tunnel.Providers()[target.name]; ok {
					if recorder, ok := live.(interface{ ClashSetSubscriptionInfo(string) }); ok {
						recorder.ClashSetSubscriptionInfo(entry.SubscriptionInfo)
					}
				}
			}
		}
	}
}

func (s *BoxService) stopProviderRefreshLocked() <-chan struct{} {
	s.refreshGeneration++
	if s.refreshCancel != nil {
		s.refreshCancel()
		s.refreshCancel = nil
	}
	var done <-chan struct{}
	if s.refresher != nil {
		done = s.refresher.done
	}
	s.refresher = nil
	return done
}

func awaitProviderRefreshExit(done <-chan struct{}) {
	if done == nil {
		return
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		providerCache.abandonInflight()
	}
}

func (r *providerRefresher) judgeAndReserve(needed int64) (fits bool, available int64, current bool) {
	current = r.locked(func() {
		fits, available = judgeProviderBuild(needed)
		if fits {
			providerBuildReserved.Add(needed)
		}
	})
	return fits && current, available, current
}

func (r *providerRefresher) mirrorToLegacy(task *providerRefreshTask, path string) {
	legacy := task.spec.LegacyPath
	if legacy == "" || r.home == "" || !regularFileExists(path) {
		return
	}
	if !filepath.IsAbs(legacy) {
		legacy = filepath.Join(r.home, legacy)
	}
	home := resolvedThroughExisting(filepath.Clean(r.home))
	legacy = filepath.Join(resolvedThroughExisting(filepath.Dir(filepath.Clean(legacy))), filepath.Base(legacy))
	relative, err := filepath.Rel(home, legacy)
	if err != nil || !filepath.IsLocal(relative) || relative == "." {
		return
	}
	switch strings.SplitN(filepath.ToSlash(relative), "/", 2)[0] {
	case ProviderRefreshDirectoryName, providerRuntimeDirectoryName, providerRuntimePrivateDirectoryName, internalDiagnosticsDirectoryName:
		return
	}
	if err := os.MkdirAll(filepath.Dir(legacy), 0o700); err != nil || !providerSourceContained(legacy, home) {
		return
	}
	if info, err := os.Lstat(legacy); err == nil {
		if info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return
		}
		if current, err := os.Stat(path); err == nil && os.SameFile(info, current) {
			return
		}
	}
	if err := linkOrCopyFile(path, legacy); err != nil {
		log.Warnln("[Provider] %s: the download could not be kept at %s: %v", task.targets[0].name, legacy, err)
	}
}

func (r *providerRefresher) mirrorAtStart() {
	for _, task := range r.tasks {
		if task.spec.LegacyPath == "" {
			continue
		}
		entry := providerCache.get(task.requestKey)
		if entry == nil {
			continue
		}
		source := ""
		if pending := providerCache.pendingPath(task.requestKey); entry.PendingSHA256 != "" && regularFileExists(pending) {
			source = pending
		} else if current := providerCache.sourcePath(task.requestKey); entry.SourceSHA256 != "" && regularFileExists(current) {
			source = current
		}
		if source != "" {
			r.mirrorToLegacy(task, source)
		}
	}
}

const internalDiagnosticsDirectoryName = "internal-diagnostics"

func resolvedThroughExisting(path string) string {
	rest := ""
	for current := path; ; current = filepath.Dir(current) {
		if resolved, err := filepath.EvalSymlinks(current); err == nil {
			if rest == "" {
				return resolved
			}
			return filepath.Join(resolved, rest)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return path
		}
		if rest == "" {
			rest = filepath.Base(current)
		} else {
			rest = filepath.Join(filepath.Base(current), rest)
		}
	}
}

func readFileHead(path string, size int) []byte {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()
	head := make([]byte, size)
	n, _ := io.ReadFull(file, head)
	return head[:n]
}

func (r *providerRefresher) locked(write func()) bool {
	s := r.service
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.refreshGeneration != r.generation || !s.running || r.ctx.Err() != nil {
		return false
	}
	write()
	return true
}

func (r *providerRefresher) run() {
	defer close(r.done)
	defer func() {
		if recovered := recover(); recovered != nil {
			log.Errorln("[Provider] the tunnel's provider refresh stopped: %v", recovered)
		}
	}()
	r.locked(r.mirrorAtStart)
	now := time.Now()
	for _, task := range r.tasks {
		r.schedule(task, now)
	}
	r.locked(func() {
		keys := make([]string, 0, len(r.tasks))
		byKey := map[string]*providerRefreshTask{}
		for _, task := range r.tasks {
			keys = append(keys, task.requestKey)
			byKey[task.requestKey] = task
		}
		providerCache.updateEach(keys, func(requestKey string, cached *providerCacheEntry) {
			task := byKey[requestKey]
			cached.Kind, cached.URL = task.kind, task.spec.URL
			cached.Interval = int64(task.interval / time.Second)
			if cached.Result == "" {
				cached.Result = providerRefreshScheduled
			}
			cached.NextDueAt = 0
			if !task.due.IsZero() {
				cached.NextDueAt = task.due.Unix()
			}
		})
	})
	for {
		next := r.nextDue()
		wait := r.poll
		if next != nil {
			if until := time.Until(next.due); until < wait {
				wait = until
			}
		}
		if wait < 0 {
			wait = 0
		}
		timer := time.NewTimer(wait)
		select {
		case <-r.ctx.Done():
			timer.Stop()
			return
		case request := <-r.requests:
			timer.Stop()
			request.reply <- r.guarded(r.byName[providerResourceKey(request.kind, request.name)], func() providerRefreshResult { return r.handle(request) })
			if request.seed != nil && request.seed.path != "" {
				_ = os.Remove(request.seed.path)
			}
			continue
		case <-timer.C:
		}
		if next := r.nextDue(); next != nil && !time.Now().Before(next.due) {
			r.guarded(next, func() providerRefreshResult { return r.refresh(next) })
		}
	}
}

func (r *providerRefresher) guarded(task *providerRefreshTask, round func() providerRefreshResult) (result providerRefreshResult) {
	defer func() {
		recovered := recover()
		if recovered == nil {
			return
		}
		log.Errorln("[Provider] the tunnel's provider refresh failed: %v", recovered)
		err := fmt.Errorf("clash: provider refresh panicked: %v", recovered)
		if task == nil {
			result = providerRefreshResult{Result: providerRefreshFailed, Error: err.Error()}
			return
		}
		result = r.fail(task, time.Now(), err)
	}()
	return round()
}

func (r *providerRefresher) nextDue() *providerRefreshTask {
	var next *providerRefreshTask
	for _, task := range r.tasks {
		if task.due.IsZero() {
			continue
		}
		if next == nil || task.due.Before(next.due) {
			next = task
		}
	}
	return next
}

func (r *providerRefresher) schedule(task *providerRefreshTask, now time.Time) {
	entry := providerCache.get(task.requestKey)
	soon := now.Add(r.settle)
	checkSoon, serverFirst := false, false
	for _, target := range task.targets {
		checkSoon = checkSoon || target.checkSoon
		serverFirst = serverFirst || target.serverFirst
	}
	switch {
	case !task.loaded():
		task.due = now
	case serverFirst:
		task.due = soon
	case !task.current(entry):
		task.due = now
	case task.interval <= 0:
		task.due = time.Time{}
	case entry == nil || entry.LastCheckedAt == 0 || checkSoon:
		task.due = soon
	default:
		task.due = time.Unix(runningConfirmation(entry), 0).Add(task.interval)
		if entry.NextDueAt > 0 && time.Unix(entry.NextDueAt, 0).Before(task.due) {
			task.due = time.Unix(entry.NextDueAt, 0)
		}
		if task.due.Before(soon) {
			task.due = soon
		}
	}
}

func (r *providerRefresher) handle(request providerRefreshRequest) providerRefreshResult {
	task := r.byName[providerResourceKey(request.kind, request.name)]
	if task == nil {
		if request.seed != nil && request.seed.path != "" {
			_ = os.Remove(request.seed.path)
		}
		return providerRefreshResult{Result: providerRefreshFailed, Error: ProviderUpdateUnavailablePrefix + "the running configuration has no such provider for the tunnel to refresh"}
	}
	if request.seed != nil {
		return r.applySeed(task, request.seed)
	}
	return r.refresh(task)
}

func (r *providerRefresher) backoff(task *providerRefreshTask) time.Duration {
	if !task.loaded() {
		wait := r.firstLoadMinimum
		for i := 1; i < task.failures && wait < r.firstLoadMaximum; i++ {
			wait *= 2
		}
		if wait > r.firstLoadMaximum {
			wait = r.firstLoadMaximum
		}
		return wait
	}
	if task.interval <= 0 {
		return 0
	}
	minimum := r.minimumBackoff
	if task.interval < minimum {
		minimum = task.interval
	}
	wait := minimum
	for i := 0; i < task.failures && wait < task.interval; i++ {
		wait *= 2
	}
	if wait > task.interval {
		wait = task.interval
	}
	return wait
}

func (r *providerRefresher) reschedule(task *providerRefreshTask, ended time.Time, failed bool) {
	switch {
	case failed:
		if wait := r.backoff(task); wait > 0 {
			task.due = ended.Add(wait)
		} else {
			task.due = time.Time{}
		}
	case task.interval > 0:
		task.due = ended.Add(task.interval)
	default:
		task.due = time.Time{}
	}
}

func (r *providerRefresher) record(task *providerRefreshTask, mutate func(*providerCacheEntry)) bool {
	return r.locked(func() { r.recordLocked(task, mutate) })
}

func (r *providerRefresher) recordLocked(task *providerRefreshTask, mutate func(*providerCacheEntry)) {
	providerCache.update(task.requestKey, func(cached *providerCacheEntry) {
		cached.Kind, cached.URL = task.kind, task.spec.URL
		cached.Interval = int64(task.interval / time.Second)
		mutate(cached)
		cached.NextDueAt = 0
		if !task.due.IsZero() {
			cached.NextDueAt = task.due.Unix()
		}
	})
}

type providerDownload struct {
	notModified      bool
	path             string
	sha256           string
	bytes            int64
	etag             string
	subscriptionInfo string
}

func (r *providerRefresher) download(task *providerRefreshTask, entry *providerCacheEntry) (providerDownload, error) {
	ctx, cancel := context.WithTimeout(r.ctx, resource.DefaultHttpTimeout)
	defer cancel()
	header := http.Header{}
	for name, values := range task.spec.Header {
		header[name] = append([]string(nil), values...)
	}
	etag := ""
	switch {
	case entry == nil:
	case entry.PendingSHA256 != "" && entry.PendingETag != "" && regularFileExists(providerCache.pendingPath(task.requestKey)):
		etag = entry.PendingETag
	case task.current(entry) && entry.ETag != "" && entry.ETagSHA256 != "" && entry.ETagSHA256 == entry.SourceSHA256:
		etag = entry.ETag
	}
	if etag != "" {
		header.Set("If-None-Match", etag)
	}
	response, err := mihomoHttp.HttpRequest(ctx, task.spec.URL, http.MethodGet, header, nil, mihomoHttp.WithSpecialProxy(task.spec.Proxy))
	if err != nil {
		return providerDownload{}, err
	}
	defer response.Body.Close()
	result := providerDownload{subscriptionInfo: response.Header.Get("subscription-userinfo")}
	if response.StatusCode < 200 || response.StatusCode > 299 {
		if etag != "" && response.StatusCode == http.StatusNotModified {
			result.notModified = true
			result.etag = etag
			return result, nil
		}
		return result, errors.New(response.Status)
	}
	limit, defaulted := task.spec.SizeLimit, false
	if limit <= 0 {
		limit, defaulted = resource.DefaultRemoteSizeLimit, true
	}
	reader := io.Reader(response.Body)
	if limit > 0 {
		readLimit := limit
		if defaulted {
			readLimit++
		}
		reader = io.LimitReader(reader, readLimit)
	}
	path, sha, written, err := streamToCacheFile(task.requestKey, ".download-", reader)
	if err != nil {
		return result, err
	}
	if defaulted && limit > 0 && written > limit {
		_ = os.Remove(path)
		return result, fmt.Errorf("response is larger than the %d-byte limit this build applies to a provider with no size-limit; set size-limit to accept it, or trim the source", limit)
	}
	result.path, result.sha256, result.bytes = path, sha, written
	result.etag = response.Header.Get("ETag")
	return result, nil
}

func streamToCacheFile(requestKey, prefix string, body io.Reader) (string, string, int64, error) {
	directory := providerCache.requestDirectory(requestKey)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", "", 0, err
	}
	file, err := os.CreateTemp(directory, prefix)
	if err != nil {
		return "", "", 0, err
	}
	digest := sha256.New()
	written, err := io.Copy(io.MultiWriter(file, digest), body)
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(file.Name())
		return "", "", 0, err
	}
	return file.Name(), hex.EncodeToString(digest.Sum(nil)), written, nil
}

func (r *providerRefresher) refresh(task *providerRefreshTask) providerRefreshResult {
	started := time.Now()
	entry := providerCache.get(task.requestKey)
	serverFirst := false
	for _, target := range task.targets {
		serverFirst = serverFirst || target.serverFirst
	}
	if entry != nil && entry.SourceSHA256 != "" && !task.current(entry) && entry.PendingSHA256 == "" &&
		entry.RebuildFailedSHA256 != entry.SourceSHA256 && !serverFirst {
		sourcePath := providerCache.sourcePath(task.requestKey)
		if sha, size, err := hashFile(sourcePath); err == nil && sha == entry.SourceSHA256 {
			var confirmed time.Time
			if entry.LastCheckedAt > 0 {
				confirmed = time.Unix(entry.LastCheckedAt, 0)
			}
			etag := ""
			if entry.ETagSHA256 == sha {
				etag = entry.ETag
			}
			return r.applySource(task, entry, providerSourceFile{sourcePath, sha, size, originCache}, confirmed, etag)
		}
	}
	downloaded, err := r.download(task, entry)
	if r.ctx.Err() != nil {
		if downloaded.path != "" {
			_ = os.Remove(downloaded.path)
		}
		return providerRefreshResult{stale: true}
	}
	r.noteSubscriptionInfo(task, downloaded.subscriptionInfo)
	if err != nil {
		return r.fail(task, started, err)
	}
	pendingHeld := entry != nil && entry.PendingSHA256 != "" && regularFileExists(providerCache.pendingPath(task.requestKey))
	switch {
	case downloaded.notModified && pendingHeld && downloaded.etag == entry.PendingETag,
		!downloaded.notModified && pendingHeld && downloaded.sha256 == entry.PendingSHA256:
		if downloaded.path != "" {
			_ = os.Remove(downloaded.path)
		}
		wait := entry.PendingWait
		if wait == "" {
			wait = entry.PendingReason
		}
		if wait != providerRefreshPendingMemory {
			return r.stillPending(task, started, wait)
		}
		pendingPath := providerCache.pendingPath(task.requestKey)
		return r.applySource(task, entry, providerSourceFile{pendingPath, entry.PendingSHA256, fileSize(pendingPath), originPending}, started, entry.PendingETag)
	case downloaded.notModified,
		task.current(entry) && entry != nil && downloaded.sha256 == entry.SourceSHA256:
		if downloaded.path != "" {
			_ = os.Remove(downloaded.path)
		}
		return r.unchanged(task, started, downloaded.etag)
	}
	return r.applySource(task, entry, providerSourceFile{downloaded.path, downloaded.sha256, downloaded.bytes, originFresh}, started, downloaded.etag)
}

func unixOrZero(at time.Time) int64 {
	if at.IsZero() {
		return 0
	}
	return at.Unix()
}

func clearPendingLocked(cached *providerCacheEntry) {
	cached.PendingSHA256, cached.PendingETag, cached.PendingWait, cached.PendingCheckedAt = "", "", "", 0
}

func runningConfirmation(entry *providerCacheEntry) int64 {
	if entry == nil {
		return 0
	}
	if entry.SeedCheckedAt > entry.LastCheckedAt {
		return entry.SeedCheckedAt
	}
	return entry.LastCheckedAt
}

func knowsRunningContent(entry *providerCacheEntry) bool {
	return entry != nil && (entry.SourceSHA256 != "" || entry.SeedCheckedAt > 0)
}

func settlesWaitLocked(cached *providerCacheEntry, sha string, confirmedAt int64) bool {
	return cached.PendingSHA256 == "" || cached.PendingSHA256 == sha || confirmedAt >= cached.PendingCheckedAt
}

func reflectWaitLocked(cached *providerCacheEntry) {
	if cached.Result == providerRefreshFailed {
		return
	}
	switch {
	case cached.PendingSHA256 != "" && cached.PendingWait != "":
		cached.Result, cached.PendingReason = providerRefreshPendingApp, cached.PendingWait
	case cached.RoutesAwaitSHA256 != "" && cached.RoutesAwaitSHA256 == cached.SourceSHA256:
		cached.Result, cached.PendingReason = providerRefreshPendingApp, providerRefreshPendingRoutes
	}
}

func fileSize(path string) int64 {
	info, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return info.Size()
}

func (r *providerRefresher) noteSubscriptionInfo(task *providerRefreshTask, info string) {
	if info == "" || task.kind != "proxy" {
		return
	}
	r.locked(func() {
		for _, target := range task.targets {
			if live, ok := tunnel.Providers()[target.name]; ok {
				if recorder, ok := live.(interface{ ClashSetSubscriptionInfo(string) }); ok {
					recorder.ClashSetSubscriptionInfo(info)
				}
			}
		}
		r.recordLocked(task, func(cached *providerCacheEntry) { cached.SubscriptionInfo = info })
	})
}

func (r *providerRefresher) liveCount(task *providerRefreshTask) int {
	for _, target := range task.targets {
		if live, ok := liveFileProvider(target.kind, target.name); ok {
			return live.Count()
		}
	}
	return 0
}

func (r *providerRefresher) unchanged(task *providerRefreshTask, started time.Time, etag string) providerRefreshResult {
	task.failures = 0
	r.reschedule(task, time.Now(), false)
	count := r.liveCount(task)
	withdrawn := false
	if !r.locked(func() {
		for _, target := range task.targets {
			if live, ok := liveFileProvider(target.kind, target.name); ok {
				live.SetUpdatedAt(started)
			}
		}
		r.recordLocked(task, func(cached *providerCacheEntry) {
			cached.LastCheckedAt = started.Unix()
			if etag != "" && cached.SourceSHA256 != "" {
				cached.ETag, cached.ETagSHA256 = etag, cached.SourceSHA256
			}
			if settlesWaitLocked(cached, cached.SourceSHA256, started.Unix()) {
				if cached.PendingSHA256 != "" {
					withdrawn = true
				}
				clearPendingLocked(cached)
				_ = os.Remove(providerCache.pendingPath(task.requestKey))
			}
			cached.Result, cached.Error, cached.PendingReason = providerRefreshUnchanged, "", ""
			reflectWaitLocked(cached)
			cached.CountBefore, cached.CountAfter = count, count
		})
		if withdrawn {
			r.mirrorToLegacy(task, providerCache.sourcePath(task.requestKey))
		}
	}) {
		return providerRefreshResult{stale: true}
	}
	log.Debugln("[Provider] %s is unchanged", task.targets[0].name)
	return providerRefreshResult{Result: providerRefreshUnchanged, CountBefore: count, CountAfter: count, CheckedAt: started.Unix()}
}

func (r *providerRefresher) fail(task *providerRefreshTask, started time.Time, err error) providerRefreshResult {
	return r.failed(task, started, err, false, "")
}

func (r *providerRefresher) failBuild(task *providerRefreshTask, started time.Time, err error, source providerSourceFile) providerRefreshResult {
	switch source.origin {
	case originCache:
		return r.failed(task, started, err, false, source.sha)
	case originSeed:
		return r.failed(task, started, err, false, "")
	}
	return r.failed(task, started, err, true, "")
}

func (r *providerRefresher) failed(task *providerRefreshTask, started time.Time, err error, dropPending bool, rebuildFailed string) providerRefreshResult {
	task.failures++
	r.reschedule(task, time.Now(), true)
	count := r.liveCount(task)
	withdrawn := false
	if !r.record(task, func(cached *providerCacheEntry) {
		cached.Result, cached.Error, cached.PendingReason = providerRefreshFailed, err.Error(), ""
		cached.CountBefore, cached.CountAfter = count, count
		if dropPending {
			if cached.PendingSHA256 != "" {
				withdrawn = true
			}
			clearPendingLocked(cached)
			_ = os.Remove(providerCache.pendingPath(task.requestKey))
		}
		if rebuildFailed != "" {
			cached.RebuildFailedSHA256 = rebuildFailed
		}
		if !dropPending && cached.PendingSHA256 != "" && cached.PendingWait != "" {
			cached.Result, cached.PendingReason = providerRefreshPendingApp, cached.PendingWait
		}
	}) {
		return providerRefreshResult{stale: true}
	}
	if withdrawn {
		r.locked(func() { r.mirrorToLegacy(task, providerCache.sourcePath(task.requestKey)) })
	}
	log.Warnln("[Provider] %s refresh failed: %v", task.targets[0].name, err)
	return providerRefreshResult{Result: providerRefreshFailed, Error: err.Error(), CountBefore: count, CountAfter: count, CheckedAt: unixOrZero(started)}
}

func (r *providerRefresher) pending(task *providerRefreshTask, started time.Time, reason string, source providerSourceFile, etag string) providerRefreshResult {
	task.failures = 0
	r.reschedule(task, time.Now(), false)
	count := r.liveCount(task)
	sha := source.sha
	if !r.locked(func() {
		if waiting := providerCache.get(task.requestKey); waiting != nil && waiting.PendingSHA256 != "" && waiting.PendingSHA256 != sha &&
			waiting.PendingCheckedAt > unixOrZero(started) {
			source.discard()
			r.recordLocked(task, func(cached *providerCacheEntry) {
				cached.Result, cached.Error, cached.PendingReason = providerRefreshPendingApp, "", reason
				cached.CountBefore, cached.CountAfter = count, count
				reflectWaitLocked(cached)
			})
			return
		}
		pendingPath := providerCache.pendingPath(task.requestKey)
		_ = os.MkdirAll(filepath.Dir(pendingPath), 0o700)
		var err error
		switch source.origin {
		case originFresh, originSeed:
			err = os.Rename(source.path, pendingPath)
			if err == nil && source.origin == originFresh {
				r.mirrorToLegacy(task, pendingPath)
			}
		case originCache:
			_ = os.Remove(pendingPath)
			err = os.Link(source.path, pendingPath)
		}
		if err != nil {
			source.discard()
			etag, sha = "", ""
		}
		r.recordLocked(task, func(cached *providerCacheEntry) {
			cached.Result, cached.Error, cached.PendingReason = providerRefreshPendingApp, "", reason
			confirmed := unixOrZero(started)
			if cached.PendingSHA256 == sha && cached.PendingCheckedAt > confirmed {
				confirmed = cached.PendingCheckedAt
			}
			cached.PendingSHA256, cached.PendingETag, cached.PendingWait = sha, etag, reason
			cached.PendingCheckedAt = confirmed
			if sha == "" {
				clearPendingLocked(cached)
			}
			cached.CountBefore, cached.CountAfter = count, count
		})
	}) {
		source.discard()
		return providerRefreshResult{stale: true}
	}
	log.Warnln("[Provider] %s: a new payload waits for the App (%s); the running content stays", task.targets[0].name, reason)
	return providerRefreshResult{Result: providerRefreshPendingApp, PendingReason: reason, CountBefore: count, CountAfter: count, CheckedAt: unixOrZero(started)}
}

func (r *providerRefresher) stillPending(task *providerRefreshTask, started time.Time, reason string) providerRefreshResult {
	task.failures = 0
	r.reschedule(task, time.Now(), false)
	count := r.liveCount(task)
	if !r.record(task, func(cached *providerCacheEntry) {
		cached.Result, cached.Error, cached.PendingReason = providerRefreshPendingApp, "", reason
		cached.PendingCheckedAt = unixOrZero(started)
	}) {
		return providerRefreshResult{stale: true}
	}
	return providerRefreshResult{Result: providerRefreshPendingApp, PendingReason: reason, CountBefore: count, CountAfter: count, CheckedAt: started.Unix()}
}

type providerProductBuild struct {
	targets   []*providerRefreshTarget
	directory string
	product   *providerCacheProduct
	writes    []refreshWrite
}

type refreshWrite struct {
	name    string
	payload []byte
}

func (r *providerRefresher) applySource(task *providerRefreshTask, entry *providerCacheEntry, source providerSourceFile, checkedAt time.Time, etag string) providerRefreshResult {
	sourcePath, sha, size := source.path, source.sha, source.size
	discard := source.discard
	if entry != nil && entry.KilledSHA256 == sha {
		return r.pending(task, checkedAt, providerRefreshPendingKilled, source, etag)
	}
	routesWait := task.routes
	if task.routes && task.loaded() {
		return r.pending(task, checkedAt, providerRefreshPendingRoutes, source, etag)
	}
	groups := r.groups(task)
	var needed int64
	for _, group := range groups {
		estimate := estimateProviderBuildBytes(task.kind, group.product.Variant, group.targets[0].sourceBehavior, int(size), nil)
		if estimate > needed {
			needed = estimate
		}
	}
	needed += int64(len(task.targets)-1) * size

	providerBuildGate.Lock()
	defer providerBuildGate.Unlock()
	if r.ctx.Err() != nil {
		discard()
		return providerRefreshResult{stale: true}
	}
	fits, available, current := r.judgeAndReserve(needed)
	if !current {
		discard()
		return providerRefreshResult{stale: true}
	}
	if !fits {
		log.Warnln("[Provider] %s: building the new payload needs about %d MiB and %d MiB are free", task.targets[0].name, needed>>20, available>>20)
		return r.pending(task, checkedAt, providerRefreshPendingMemory, source, etag)
	}
	defer providerBuildReserved.Add(-needed)
	providerCache.writeInflight(task.requestKey, sha)
	defer providerCache.clearInflight()
	defer runtime.GC()

	var payload []byte
	if size > 0 {
		read, err := readBoundedRegularFile(sourcePath, int64(maximumProviderResourceBytes)+1, "downloaded provider")
		if err != nil {
			discard()
			return r.failBuild(task, checkedAt, err, source)
		}
		payload = read
	}
	for _, group := range groups {
		pendingReason, err := r.buildProduct(task, group, payload, sha)
		if pendingReason != "" {
			payload = nil
			return r.pending(task, checkedAt, pendingReason, source, etag)
		}
		if err != nil {
			discard()
			return r.failBuild(task, checkedAt, err, source)
		}
	}
	payload = nil
	countBefore := r.liveCount(task)
	var countAfter int
	var commitErr error
	dropPendingFile := false
	committed := r.locked(func() {
		providerCache.writeInflightCommitting(task.requestKey, sha)
		countAfter, commitErr = commitProducts(groups)
		if commitErr != nil {
			return
		}
		if source.origin != originCache {
			if err := os.Rename(sourcePath, providerCache.sourcePath(task.requestKey)); err != nil {
				discard()
			} else if source.origin == originFresh {
				r.mirrorToLegacy(task, providerCache.sourcePath(task.requestKey))
			}
		}
		for _, group := range groups {
			for _, target := range group.targets {
				target.product = group.product
				target.productDirectory = group.directory
				target.serverFirst = false
				if live, ok := liveFileProvider(target.kind, target.name); ok && !checkedAt.IsZero() {
					live.SetUpdatedAt(checkedAt)
				}
				providerCache.setRunningVariant(providerResourceKey(target.kind, target.name), group.product.Variant)
			}
		}
		task.failures = 0
		r.reschedule(task, time.Now(), false)
		switch {
		case task.interval <= 0:
		case checkedAt.IsZero():
			task.due = time.Now().Add(r.settle)
		case source.origin == originCache:
			if due := checkedAt.Add(task.interval); due.Before(task.due) {
				task.due = due
			}
			if soon := time.Now().Add(r.settle); task.due.Before(soon) {
				task.due = soon
			}
		}
		r.recordLocked(task, func(cached *providerCacheEntry) {
			changed := cached.SourceSHA256 != sha
			cached.SourceSHA256, cached.SourceBytes = sha, size
			if !checkedAt.IsZero() {
				cached.LastCheckedAt = checkedAt.Unix()
			} else if changed {
				cached.LastCheckedAt = 0
			}
			if cached.PendingSHA256 == sha && cached.PendingCheckedAt > cached.LastCheckedAt {
				cached.LastCheckedAt = cached.PendingCheckedAt
			}
			if changed || cached.LastChangedAt == 0 {
				cached.LastChangedAt = time.Now().Unix()
				if !checkedAt.IsZero() {
					cached.LastChangedAt = checkedAt.Unix()
				}
			}
			cached.ETag, cached.ETagSHA256 = "", ""
			if etag != "" {
				cached.ETag, cached.ETagSHA256 = etag, sha
			}
			cached.Products = map[string]*providerCacheProduct{}
			for _, group := range groups {
				cached.Products[group.targets[0].productKey] = group.product
			}
			cached.Result, cached.Error, cached.PendingReason = providerRefreshUpdated, "", ""
			cached.RoutesAwaitSHA256 = ""
			if routesWait {
				cached.RoutesAwaitSHA256 = sha
			}
			cached.RebuildFailedSHA256 = ""
			cached.CountBefore, cached.CountAfter = countBefore, countAfter
			if source.origin == originCache {
				reflectWaitLocked(cached)
				return
			}
			if source.origin == originPending || settlesWaitLocked(cached, sha, unixOrZero(checkedAt)) {
				clearPendingLocked(cached)
				dropPendingFile = true
			}
			reflectWaitLocked(cached)
			cached.KilledSHA256 = ""
		})
		if dropPendingFile {
			_ = os.Remove(providerCache.pendingPath(task.requestKey))
		}
		providerCache.clearInflight()
	})
	if !committed {
		discard()
		return providerRefreshResult{stale: true}
	}
	if commitErr != nil {
		discard()
		return r.failBuild(task, checkedAt, commitErr, source)
	}
	log.Infoln("[Provider] %s refreshed in the tunnel: %d entries", task.targets[0].name, countAfter)
	return providerRefreshResult{Result: providerRefreshUpdated, CountBefore: countBefore, CountAfter: countAfter, CheckedAt: checkedAt.Unix()}
}

func (r *providerRefresher) groups(task *providerRefreshTask) []*providerProductBuild {
	byKey := map[string]*providerProductBuild{}
	var order []*providerProductBuild
	for _, target := range task.targets {
		key := target.productKey + "\x00" + target.productDirectory
		group := byKey[key]
		if group == nil {
			group = &providerProductBuild{directory: target.productDirectory, product: r.productFor(target)}
			byKey[key] = group
			order = append(order, group)
		}
		group.targets = append(group.targets, target)
	}
	return order
}

func (r *providerRefresher) productFor(target *providerRefreshTarget) *providerCacheProduct {
	if target.product != nil {
		copied := *target.product
		copied.Files = append([]string(nil), target.product.Files...)
		copied.SourceForm = catalogForm(target.sourceBehavior, target.sourceFormat)
		return &copied
	}
	variant, behavior, format := "text", target.sourceBehavior, target.sourceFormat
	switch {
	case target.kind == "proxy":
		variant = "proxy"
	case compilesNatively(target.sourceBehavior, target.sourceFormat):
		variant, behavior, format = "compiled", strings.ToLower(strings.TrimSpace(target.sourceBehavior)), "mrs"
	case strings.EqualFold(strings.TrimSpace(target.sourceFormat), "mrs"):
		variant = "mrs"
	}
	return &providerCacheProduct{
		Variant: variant, Entry: providerCacheNativeEntry, Files: []string{providerCacheNativeEntry},
		Behavior: behavior, Format: format, Generation: filepath.Base(target.productDirectory),
		SourceForm: catalogForm(target.sourceBehavior, target.sourceFormat),
	}
}

func textHoldsNoRules(format string, payload []byte) bool {
	if !strings.EqualFold(strings.TrimSpace(format), "text") {
		return false
	}
	scanner := bufio.NewScanner(bytes.NewReader(payload))
	scanner.Buffer(make([]byte, 64<<10), int(maximumProviderResourceBytes))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		return false
	}
	return true
}

func (r *providerRefresher) buildProduct(task *providerRefreshTask, group *providerProductBuild, payload []byte, sha string) (string, error) {
	target := group.targets[0]
	product := group.product
	product.SourceSHA256 = sha
	if task.kind == "proxy" {
		content := payload
		if task.spec.AgeKey != "" {
			decrypted, err := age.DecryptBytes(payload, task.spec.AgeKey)
			if err != nil {
				return "", fmt.Errorf("decrypt config error: %w", err)
			}
			content = decrypted
		}
		prepared, _, err := sanitizeProxyProviderPayloadForIOS(target.sourceFormat, content, false)
		if err != nil {
			return "", err
		}
		group.writes = []refreshWrite{{product.Entry, prepared}}
		return "", nil
	}
	content := payload
	if !textHoldsNoRules(target.sourceFormat, payload) {
		prepared, stripped, err := prepareRuleProviderRuntimePayload(target.sourceBehavior, target.sourceFormat, payload, r.runtime.policy)
		if err != nil {
			return "", err
		}
		if len(stripped) > 0 {
			content = prepared
		}
	}
	switch product.Variant {
	case "compiled":
		compilation := compileRuleProviderPayload(content, target.sourceBehavior, target.sourceFormat)
		if compilation.Reason != "" || compilation.Behavior != product.Behavior {
			return providerRefreshPendingRecompile, nil
		}
		group.writes = []refreshWrite{{product.Entry, compilation.artifact}}
		product.Count = compilation.Rules
	case "indexed":
		if len(product.Files) < 2 {
			return providerRefreshPendingRecompile, nil
		}
		textName := product.Files[1]
		var collected []refreshWrite
		stub, index, err := stageClassicalIndex(content, target.sourceFormat, group.directory, textName, func(path string, bytes []byte) error {
			collected = append(collected, refreshWrite{filepath.Base(path), bytes})
			return nil
		})
		if err != nil {
			return "", err
		}
		switch {
		case stub == product.Entry:
			group.writes = append([]refreshWrite{{textName, content}}, collected...)
			product.IndexChecksum = index.Checksum
			product.Count = index.Rules
		case stub == "":
			group.writes = []refreshWrite{{textName, content}, {product.Entry, content}}
			product.IndexChecksum = 0
		default:
			return providerRefreshPendingRecompile, nil
		}
	default:
		group.writes = []refreshWrite{{product.Entry, content}}
	}
	return "", nil
}

func commitProducts(builds []*providerProductBuild) (count int, err error) {
	type rollback struct {
		path, saved string
		existed     bool
	}
	var rollbacks []rollback
	restore := func() {
		for i := len(rollbacks) - 1; i >= 0; i-- {
			if rollbacks[i].existed {
				_ = os.Rename(rollbacks[i].saved, rollbacks[i].path)
			} else {
				_ = os.Remove(rollbacks[i].path)
			}
		}
	}
	for _, build := range builds {
		if err := os.MkdirAll(build.directory, 0o700); err != nil {
			restore()
			return 0, err
		}
		for _, write := range build.writes {
			path := filepath.Join(build.directory, write.name)
			saved := path + ".rollback"
			_ = os.Remove(saved)
			existed := true
			if err := os.Link(path, saved); err != nil {
				if !errors.Is(err, os.ErrNotExist) {
					restore()
					return 0, err
				}
				existed = false
			}
			rollbacks = append(rollbacks, rollback{path, saved, existed})
			if err := writeRuntimeProviderFile(path, write.payload); err != nil {
				restore()
				return 0, err
			}
		}
	}
	for _, build := range builds {
		for _, target := range build.targets {
			live, ok := liveFileProvider(target.kind, target.name)
			if !ok {
				continue
			}
			if err := live.Update(); err != nil {
				restore()
				for _, other := range builds {
					for _, again := range other.targets {
						if provider, ok := liveFileProvider(again.kind, again.name); ok {
							_ = provider.Update()
						}
					}
				}
				return 0, err
			}
			if build == builds[0] && target == build.targets[0] {
				count = live.Count()
			}
		}
	}
	for _, saved := range rollbacks {
		if saved.existed {
			_ = os.Remove(saved.saved)
		}
	}
	return count, nil
}

func (r *providerRefresher) applySeed(task *providerRefreshTask, seed *providerSeed) providerRefreshResult {
	entry := providerCache.get(task.requestKey)
	var fetchedAt time.Time
	if seed.FetchedAt > 0 {
		fetchedAt = time.Unix(seed.FetchedAt, 0)
	}
	discard := func() { _ = os.Remove(seed.path) }
	if task.routes {
		discard()
		count := r.liveCount(task)
		return providerRefreshResult{Result: providerRefreshPendingApp, PendingReason: providerRefreshPendingRoutes, CountBefore: count, CountAfter: count,
			Error: "this set feeds the tunnel's routes; publish the configuration"}
	}
	sourceSHA := seed.SourceSHA256
	if seed.Payload == "source" || seed.Payload == "" {
		if sha, _, err := hashFile(seed.path); err == nil {
			sourceSHA = sha
		}
	}
	awaited := entry != nil && sourceSHA != "" && sourceSHA == entry.PendingSHA256
	if knowsRunningContent(entry) && !awaited && (seed.FetchedAt <= 0 || seed.FetchedAt <= runningConfirmation(entry)) {
		discard()
		count := r.liveCount(task)
		checked := runningConfirmation(entry)
		return providerRefreshResult{Result: providerRefreshUnchanged, CountBefore: count, CountAfter: count,
			Error: "the seed is older than the tunnel's copy", CheckedAt: checked}
	}
	r.noteSubscriptionInfo(task, seed.SubscriptionInfo)
	switch seed.Payload {
	case "source", "":
		sha, _, err := hashFile(seed.path)
		if err != nil {
			discard()
			return r.fail(task, fetchedAt, err)
		}
		if seed.SourceSHA256 != "" && seed.SourceSHA256 != sha {
			discard()
			return r.fail(task, fetchedAt, errors.New("the seed's bytes are not the content its sourceSHA256 names"))
		}
		if entry != nil && entry.SourceSHA256 == sha && task.current(entry) {
			discard()
			return r.unchanged(task, fetchedAt, seed.ETag)
		}
		return r.applySource(task, entry, providerSourceFile{seed.path, sha, seed.bytes, originSeed}, fetchedAt, seed.ETag)
	case "mrs":
		defer discard()
		return r.applyCompiledSeed(task, seed, fetchedAt)
	default:
		discard()
		return r.fail(task, fetchedAt, fmt.Errorf("unknown seed payload %q", seed.Payload))
	}
}

func (r *providerRefresher) applyCompiledSeed(task *providerRefreshTask, seed *providerSeed, fetchedAt time.Time) providerRefreshResult {
	target := task.targets[0]
	for _, other := range task.targets {
		if other.productKey != target.productKey {
			return r.fail(task, fetchedAt, errors.New("this set is read in more than one form; send its source"))
		}
	}
	if target.product == nil || target.product.Variant != "compiled" || seed.SourceSHA256 == "" {
		return r.fail(task, fetchedAt, errors.New("this set does not run compiled; send its source"))
	}
	group := r.groups(task)[0]
	providerBuildGate.Lock()
	defer providerBuildGate.Unlock()
	needed := mrsReadFloor(readFileHead(seed.path, 64)) + int64(float64(seed.bytes)*providerBuildMRSFactor)*int64(len(task.targets))
	fits, _, current := r.judgeAndReserve(needed)
	if !current {
		return providerRefreshResult{stale: true}
	}
	if !fits {
		return providerRefreshResult{Result: providerRefreshPendingApp, PendingReason: providerRefreshPendingMemory, CountBefore: r.liveCount(task), CountAfter: r.liveCount(task),
			Error: "the tunnel has no headroom to read this set now; publish the configuration"}
	}
	defer providerBuildReserved.Add(-needed)
	artifact, err := readBoundedRegularFile(seed.path, int64(maximumProviderResourceBytes), "seeded product")
	if err != nil {
		return r.fail(task, fetchedAt, err)
	}
	providerCache.writeInflight(task.requestKey, seed.SourceSHA256)
	defer providerCache.clearInflight()
	defer runtime.GC()
	count, err := ProviderEntryCountForIOS("rule", group.product.Behavior, "mrs", artifact)
	if err != nil {
		return r.fail(task, fetchedAt, fmt.Errorf("the seed is not an MRS of this set's behavior: %w", err))
	}
	group.product.Count = count
	group.product.SourceSHA256 = seed.SourceSHA256
	group.writes = []refreshWrite{{group.product.Entry, artifact}}
	artifact = nil
	countBefore := r.liveCount(task)
	var countAfter int
	var commitErr error
	committed := r.locked(func() {
		providerCache.writeInflightCommitting(task.requestKey, seed.SourceSHA256)
		countAfter, commitErr = commitProducts([]*providerProductBuild{group})
		if commitErr != nil {
			return
		}
		_ = os.Remove(providerCache.sourcePath(task.requestKey))
		for _, target := range task.targets {
			target.product = group.product
			if live, ok := liveFileProvider(target.kind, target.name); ok && !fetchedAt.IsZero() {
				live.SetUpdatedAt(fetchedAt)
			}
		}
		task.failures = 0
		r.reschedule(task, time.Now(), false)
		r.recordLocked(task, func(cached *providerCacheEntry) {
			cached.SourceSHA256, cached.SourceBytes = seed.SourceSHA256, 0
			cached.LastCheckedAt, cached.LastChangedAt = unixOrZero(fetchedAt), time.Now().Unix()
			if cached.PendingSHA256 == seed.SourceSHA256 && cached.PendingCheckedAt > cached.LastCheckedAt {
				cached.LastCheckedAt = cached.PendingCheckedAt
			}
			if !fetchedAt.IsZero() {
				cached.LastChangedAt = fetchedAt.Unix()
			}
			cached.RebuildFailedSHA256 = ""
			cached.ETag, cached.ETagSHA256 = "", ""
			if seed.ETag != "" {
				cached.ETag, cached.ETagSHA256 = seed.ETag, seed.SourceSHA256
			}
			cached.Products = map[string]*providerCacheProduct{target.productKey: group.product}
			cached.Result, cached.Error, cached.PendingReason = providerRefreshUpdated, "", ""
			if settlesWaitLocked(cached, seed.SourceSHA256, unixOrZero(fetchedAt)) {
				clearPendingLocked(cached)
				_ = os.Remove(providerCache.pendingPath(task.requestKey))
			}
			reflectWaitLocked(cached)
			cached.CountBefore, cached.CountAfter = countBefore, countAfter
			if cached.KilledSHA256 == seed.SourceSHA256 || settlesWaitLocked(cached, seed.SourceSHA256, unixOrZero(fetchedAt)) {
				cached.KilledSHA256 = ""
			}
		})
		providerCache.clearInflight()
	})
	if !committed {
		return providerRefreshResult{stale: true}
	}
	if commitErr != nil {
		return r.fail(task, fetchedAt, commitErr)
	}
	return providerRefreshResult{Result: providerRefreshUpdated, CountBefore: countBefore, CountAfter: countAfter, CheckedAt: unixOrZero(fetchedAt)}
}

type liveProvider interface {
	Update() error
	VehicleType() P.VehicleType
	Count() int
	SetUpdatedAt(time.Time)
}

func liveFileProvider(kind, name string) (liveProvider, bool) {
	var candidate any
	switch kind {
	case "rule":
		if provider, ok := tunnel.RuleProviders()[name]; ok {
			candidate = provider
		}
	case "proxy":
		if provider, ok := tunnel.Providers()[name]; ok {
			candidate = provider
		}
	}
	live, ok := candidate.(liveProvider)
	if !ok || live.VehicleType() != P.File {
		return nil, false
	}
	return live, true
}

func payloadSHA256(payload []byte) string {
	digest := sha256.Sum256(payload)
	return hex.EncodeToString(digest[:])
}
