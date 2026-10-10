package clash

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ProjectClash/Clash/component/geodata"
	"github.com/ProjectClash/Clash/component/geodata/compiled"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/log"
	"go.yaml.in/yaml/v3"
)

func GeoSiteCategoriesIn(content string) []string {
	return geoSiteCategoriesInDocument(content, nil)
}

func isGeoSiteCategoryByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= '0' && b <= '9':
		return true
	case b == '-', b == '_', b == '.', b == '@', b == '!':
		return true
	}
	return false
}

func geoSiteCategoryName(name string) (string, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return "", false
	}
	for i := 0; i < len(name); i++ {
		if !isGeoSiteCategoryByte(name[i]) {
			return "", false
		}
	}
	return name, true
}

func geoSiteCategoriesInDocument(content string, document *yaml.Node) []string {
	lowered := strings.ToLower(content)

	isCategoryByte := isGeoSiteCategoryByte
	atBoundary := func(index int) bool {
		return index == 0 || !isCategoryByte(lowered[index-1])
	}

	seen := make(map[string]struct{})
	var found []string
	collect := func(name string) {
		name, ok := geoSiteCategoryName(name)
		if !ok {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		found = append(found, name)
	}

	endsSegment := func(b byte) bool {
		switch b {
		case '\n', '\r', '"', '\'', ':', ']', '#', '(', ')':
			return true
		}
		return false
	}
	isSpace := func(b byte) bool { return b == ' ' || b == '\t' }
	const word = "geosite"
	for offset := 0; ; {
		index := strings.Index(lowered[offset:], word)
		if index < 0 {
			break
		}
		index += offset
		offset = index + len(word)
		if !atBoundary(index) {
			continue
		}
		next := offset
		for next < len(lowered) && isSpace(lowered[next]) {
			next++
		}
		var start int
		var wantEveryPiece bool
		switch {
		case next < len(lowered) && lowered[next] == ',':
			start, wantEveryPiece = next+1, false
		case next == offset && next < len(lowered) && lowered[next] == ':':
			start, wantEveryPiece = next+1, true
		default:
			continue
		}
		end := start
		for end < len(lowered) && !endsSegment(lowered[end]) {
			end++
		}
		if end < len(lowered) && lowered[end] == ':' && strings.HasPrefix(lowered[end+1:], "//") {
			offset = end
			continue
		}
		pieces := strings.Split(lowered[start:end], ",")
		if !wantEveryPiece && len(pieces) > 1 {
			pieces = pieces[:1]
		}
		for _, piece := range pieces {
			collect(piece)
		}
		offset = end
	}
	collectFallbackFilterGeoSiteFrom(content, document, collect)
	return found
}

func collectFallbackFilterGeoSite(content string, collect func(string)) {
	var document struct {
		DNS struct {
			FallbackFilter struct {
				GeoSite []string `yaml:"geosite"`
			} `yaml:"fallback-filter"`
		} `yaml:"dns"`
	}
	if yaml.Unmarshal([]byte(content), &document) != nil {
		return
	}
	for _, category := range document.DNS.FallbackFilter.GeoSite {
		collect(category)
	}
}

func collectFallbackFilterGeoSiteFrom(content string, document *yaml.Node, collect func(string)) {
	if document == nil || len(document.Content) == 0 {
		collectFallbackFilterGeoSite(content, collect)
		return
	}
	var read struct {
		DNS struct {
			FallbackFilter struct {
				GeoSite []string `yaml:"geosite"`
			} `yaml:"fallback-filter"`
		} `yaml:"dns"`
	}
	if document.Decode(&read) != nil {
		collectFallbackFilterGeoSite(content, collect)
		return
	}
	for _, category := range read.DNS.FallbackFilter.GeoSite {
		collect(category)
	}
}

func PrepareGeoSiteCache(content string) (string, error) {
	out, err := recoverAppCall("PrepareGeoSiteCache", func() (string, error) { return prepareGeoSiteCacheUnguarded(content) })
	if err != nil {
		return "", bridgeSafeError(err)
	}
	return bridgeSafeString(out), nil
}

func prepareGeoSiteCacheUnguarded(content string) (string, error) {
	appParseMu.Lock()
	defer appParseMu.Unlock()
	return prepareGeoSiteCacheFor(GeoSiteCategoriesIn(content))
}

func PrepareGeoSiteCacheForCategories(categoriesJSON string) (string, error) {
	out, err := recoverAppCall("PrepareGeoSiteCacheForCategories", func() (string, error) {
		var listed []string
		if err := json.Unmarshal([]byte(categoriesJSON), &listed); err != nil {
			return "", fmt.Errorf("clash: geosite categories: %w", err)
		}
		categories := make([]string, 0, len(listed))
		seen := make(map[string]struct{}, len(listed))
		for _, name := range listed {
			name, ok := geoSiteCategoryName(name)
			if !ok {
				continue
			}
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			categories = append(categories, name)
		}
		appParseMu.Lock()
		defer appParseMu.Unlock()
		return prepareGeoSiteCacheFor(categories)
	})
	if err != nil {
		return "", bridgeSafeError(err)
	}
	return bridgeSafeString(out), nil
}

func prepareGeoSiteCacheFor(categories []string) (string, error) {
	if len(categories) == 0 {
		return "geosite: no categories named", nil
	}
	previous := geodata.CompiledGeoSiteOnly()
	geodata.SetCompiledGeoSiteOnly(false)
	defer geodata.SetCompiledGeoSiteOnly(previous)

	sourceModified := time.Time{}
	if info, err := os.Stat(C.Path.GeoSite()); err == nil {
		sourceModified = info.ModTime()
	}
	source := compiledSourceIdentity(C.Path.GeoSite())

	prepared, reused := 0, 0
	var failures []string
	for _, category := range categories {
		key, keyErr := geodata.CompiledGeoSiteKey(category)
		if keyErr != nil {
			key = category
		}
		if path, err := compiled.Path(geodata.CompiledGeoSiteDir(), key); err == nil {
			if info, err := os.Stat(path); err == nil && compiledFromSource(path, source) && info.ModTime().After(sourceModified) {
				if count, err := compiled.EntryCount(
					geodata.CompiledGeoSiteDir(), key,
				); err == nil && count > 0 {
					reused++
					continue
				}
			}
		}
		if err := geodata.CompileGeoSite(category); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %s", category, err))
			if path, err := compiled.Path(geodata.CompiledGeoSiteDir(), key); err == nil && !compiledFromSource(path, source) {
				retireCompiledArtifact(path)
			}
			continue
		}
		if path, err := compiled.Path(geodata.CompiledGeoSiteDir(), key); err == nil {
			stampCompiledSource(path, source)
		}
		prepared++
	}
	summary := fmt.Sprintf("geosite: %d compiled, %d current, %d failed of %d named, dir=%s",
		prepared, reused, len(categories)-prepared-reused, len(categories),
		geodata.CompiledGeoSiteDir())
	if len(failures) > 0 {
		summary += " | " + strings.Join(failures, "; ")
		log.Warnln("[Apple] geosite: %d of %d named categories will match nothing (compile failed): %s",
			len(failures), len(categories), strings.Join(failures, "; "))
	}
	log.Infoln("[Apple] %s", summary)
	geodata.ClearGeoSiteCache()
	return bridgeSafeString(summary), nil
}

func GeoSiteCategoryLines(content string) string {
	return bridgeSafeString(recoverAppCallValue("GeoSiteCategoryLines", func() string { return geoSiteCategoryLinesUnguarded(content) }))
}

func geoSiteCategoryLinesUnguarded(content string) string {
	return bridgeSafeString(strings.Join(GeoSiteCategoriesIn(content), "\n"))
}

var geoCountMemo = struct {
	sync.Mutex
	sources map[string]string
	counts  map[string]map[string]int
}{sources: map[string]string{}, counts: map[string]map[string]int{}}

func resetGeoCountMemo() {
	geoCountMemo.Lock()
	defer geoCountMemo.Unlock()
	geoCountMemo.sources = map[string]string{}
	geoCountMemo.counts = map[string]map[string]int{}
}

func geodataCount(kind string, sourcePath func() string, key string, count func(string) (int, error)) int {
	appParseMu.Lock()
	defer appParseMu.Unlock()

	path := sourcePath()
	identity := compiledSourceIdentity(path)
	if identity == "" {
		return -1
	}
	source := path + "|" + identity
	geoCountMemo.Lock()
	if geoCountMemo.sources[kind] != source {
		geoCountMemo.sources[kind], geoCountMemo.counts[kind] = source, map[string]int{}
	}
	remembered, known := geoCountMemo.counts[kind][key]
	geoCountMemo.Unlock()
	if known {
		return remembered
	}
	answer := -1
	if n, err := count(key); err == nil {
		answer = n
	}
	geoCountMemo.Lock()
	if geoCountMemo.sources[kind] == source {
		geoCountMemo.counts[kind][key] = answer
	}
	geoCountMemo.Unlock()
	return answer
}

func GeoSiteDomainCount(category string) int {
	return recoverAppCallValueOr("GeoSiteDomainCount", -1, func() int { return geoSiteDomainCountUnguarded(category) })
}

func geoSiteDomainCountUnguarded(category string) int {
	category = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(category)), "!")
	if category == "" {
		return -1
	}
	return geodataCount("geosite", C.Path.GeoSite, category, geodata.CountGeoSite)
}

func GeoIPDatEntryCount(code string) int {
	return recoverAppCallValueOr("GeoIPDatEntryCount", -1, func() int { return geoIPDatEntryCountUnguarded(code) })
}

func geoIPDatEntryCountUnguarded(code string) int {
	code = strings.TrimPrefix(strings.ToLower(strings.TrimSpace(code)), "!")
	if code == "" || code == "lan" {
		return -1
	}
	return geodataCount("geoip-dat", C.Path.GeoIP, code, geodata.CountGeoIP)
}

func compiledSourceIdentity(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return ""
	}
	identity := fmt.Sprintf("%d|%d", info.Size(), info.ModTime().UnixNano())
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		identity += fmt.Sprintf("|%d", stat.Ino)
	}
	return identity
}

func compiledSourceStampPath(artifact string) string { return artifact + ".source" }

func retireCompiledArtifact(artifact string) {
	if err := os.Remove(artifact); err != nil && !os.IsNotExist(err) {
		log.Warnln("[Apple] could not retire the stale compiled list %s (%v)", filepath.Base(artifact), err)
		return
	}
	_ = os.Remove(compiledSourceStampPath(artifact))
}

func compiledFromSource(artifact, identity string) bool {
	if identity == "" {
		return false
	}
	stamp, err := os.ReadFile(compiledSourceStampPath(artifact))
	return err == nil && string(stamp) == identity
}

func stampCompiledSource(artifact, identity string) {
	if identity == "" {
		return
	}
	if err := os.WriteFile(compiledSourceStampPath(artifact), []byte(identity), 0o600); err != nil {
		log.Warnln("[Apple] could not record which database %s was compiled from (%v); it is recompiled next time", filepath.Base(artifact), err)
	}
}
