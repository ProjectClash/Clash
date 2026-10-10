package clash

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/ProjectClash/Clash/component/geodata"
	"github.com/ProjectClash/Clash/component/geodata/compiled"
	"github.com/ProjectClash/Clash/component/mmdb"
	"github.com/ProjectClash/Clash/config"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/log"
	"go.yaml.in/yaml/v3"
)

func GeoIPCountriesIn(content string) []string {
	return geoIPCountriesInDocument(content, nil)
}

func isGeoIPCountryByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z', b >= '0' && b <= '9':
		return true
	case b == '-', b == '_':
		return true
	}
	return false
}

func geoIPCountryName(name string) (string, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.TrimPrefix(name, "!")
	if name == "" {
		return "", false
	}
	if name == "lan" {
		return "", false
	}
	for i := 0; i < len(name); i++ {
		if !isGeoIPCountryByte(name[i]) {
			return "", false
		}
	}
	return name, true
}

func geoIPCountriesInDocument(content string, document *yaml.Node) []string {
	lowered := strings.ToLower(content)

	isCountryByte := isGeoIPCountryByte
	atBoundary := func(index int) bool {
		if index == 0 {
			return true
		}
		previous := lowered[index-1]
		if previous == '-' {
			return true
		}
		return !isCountryByte(previous)
	}
	endsSegment := func(b byte) bool {
		switch b {
		case '\n', '\r', '"', '\'', ':', ']', '#', '(', ')':
			return true
		}
		return false
	}
	isSpace := func(b byte) bool { return b == ' ' || b == '\t' }

	seen := make(map[string]struct{})
	var found []string
	collect := func(name string) {
		name, ok := geoIPCountryName(name)
		if !ok {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		found = append(found, name)
	}

	const word = "geoip"
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
		if next >= len(lowered) || lowered[next] != ',' {
			continue
		}
		start := next + 1
		end := start
		for end < len(lowered) && !endsSegment(lowered[end]) {
			end++
		}
		pieces := strings.Split(lowered[start:end], ",")
		collect(pieces[0])
		offset = end
	}
	collectFallbackFilterGeoIPCodeFrom(content, document, collect)
	return found
}

func collectFallbackFilterGeoIPCode(content string, collect func(string)) {
	var document struct {
		DNS struct {
			FallbackFilter struct {
				GeoIPCode string `yaml:"geoip-code"`
			} `yaml:"fallback-filter"`
		} `yaml:"dns"`
	}
	if yaml.Unmarshal([]byte(content), &document) != nil {
		return
	}
	collect(document.DNS.FallbackFilter.GeoIPCode)
}

func collectFallbackFilterGeoIPCodeFrom(content string, document *yaml.Node, collect func(string)) {
	if document == nil || len(document.Content) == 0 {
		collectFallbackFilterGeoIPCode(content, collect)
		return
	}
	var read struct {
		DNS struct {
			FallbackFilter struct {
				GeoIPCode string `yaml:"geoip-code"`
			} `yaml:"fallback-filter"`
		} `yaml:"dns"`
	}
	if document.Decode(&read) != nil {
		collectFallbackFilterGeoIPCode(content, collect)
		return
	}
	collect(read.DNS.FallbackFilter.GeoIPCode)
}

func PrepareGeoIPCache(content string, geodataMode bool) (string, error) {
	out, err := recoverAppCall("PrepareGeoIPCache", func() (string, error) { return prepareGeoIPCacheUnguarded(content, geodataMode) })
	if err != nil {
		return "", bridgeSafeError(err)
	}
	return bridgeSafeString(out), nil
}

func prepareGeoIPCacheUnguarded(content string, geodataMode bool) (string, error) {
	appParseMu.Lock()
	defer appParseMu.Unlock()
	if !geodataMode {
		return "geoip: skipped, tunnel reads geoip.metadb", nil
	}
	return prepareGeoIPCacheFor(GeoIPCountriesIn(content))
}

func PrepareGeoIPCacheForCountries(countriesJSON string, geodataMode bool) (string, error) {
	out, err := recoverAppCall("PrepareGeoIPCacheForCountries", func() (string, error) {
		var listed []string
		if err := json.Unmarshal([]byte(countriesJSON), &listed); err != nil {
			return "", fmt.Errorf("clash: geoip countries: %w", err)
		}
		countries := make([]string, 0, len(listed))
		seen := make(map[string]struct{}, len(listed))
		for _, name := range listed {
			name, ok := geoIPCountryName(name)
			if !ok {
				continue
			}
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			countries = append(countries, name)
		}
		appParseMu.Lock()
		defer appParseMu.Unlock()
		if !geodataMode {
			return "geoip: skipped, tunnel reads geoip.metadb", nil
		}
		return prepareGeoIPCacheFor(countries)
	})
	if err != nil {
		return "", bridgeSafeError(err)
	}
	return bridgeSafeString(out), nil
}

func prepareGeoIPCacheFor(countries []string) (string, error) {
	if len(countries) == 0 {
		return "geoip: no countries named", nil
	}
	previous := geodata.CompiledGeoIPOnly()
	geodata.SetCompiledGeoIPOnly(false)
	defer geodata.SetCompiledGeoIPOnly(previous)

	sourceModified := time.Time{}
	if info, err := os.Stat(C.Path.GeoIP()); err == nil {
		sourceModified = info.ModTime()
	}
	source := compiledSourceIdentity(C.Path.GeoIP())

	prepared, reused := 0, 0
	var failures []string
	for _, country := range countries {
		if path, err := compiled.IPCIDRPath(geodata.CompiledGeoIPDir(), country); err == nil {
			if info, err := os.Stat(path); err == nil && compiledFromSource(path, source) && info.ModTime().After(sourceModified) {
				if count, err := compiled.EntryCountIPCIDR(
					geodata.CompiledGeoIPDir(), country,
				); err == nil && count > 0 {
					reused++
					continue
				}
			}
		}
		if err := geodata.CompileGeoIP(country); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %s", country, err))
			if path, err := compiled.IPCIDRPath(geodata.CompiledGeoIPDir(), country); err == nil && !compiledFromSource(path, source) {
				retireCompiledArtifact(path)
			}
			continue
		}
		if path, err := compiled.IPCIDRPath(geodata.CompiledGeoIPDir(), country); err == nil {
			stampCompiledSource(path, source)
		}
		prepared++
	}
	summary := fmt.Sprintf("geoip: %d compiled, %d current, %d failed of %d named, dir=%s",
		prepared, reused, len(countries)-prepared-reused, len(countries),
		geodata.CompiledGeoIPDir())
	if len(failures) > 0 {
		summary += " | " + strings.Join(failures, "; ")
		log.Warnln("[Apple] geoip: %d of %d named countries will match nothing (compile failed): %s",
			len(failures), len(countries), strings.Join(failures, "; "))
	}
	log.Infoln("[Apple] %s", summary)
	geodata.ClearGeoIPCache()
	return bridgeSafeString(summary), nil
}

func GeodataModeEnabled(content string) bool {
	return recoverAppCallValue("GeodataModeEnabled", func() bool { return geodataModeEnabledUnguarded(content) })
}

func geodataModeEnabledUnguarded(content string) bool {
	raw, err := config.UnmarshalRawConfig([]byte(content))
	if err != nil {
		return false
	}
	return raw.GeodataMode
}

func GeoIPCountryLines(content string) string {
	return bridgeSafeString(recoverAppCallValue("GeoIPCountryLines", func() string { return geoIPCountryLinesUnguarded(content) }))
}

func geoIPCountryLinesUnguarded(content string) string {
	return bridgeSafeString(strings.Join(GeoIPCountriesIn(content), "\n"))
}

func GeoIPCountryForIP(ip string) *StringBox {
	address, err := netip.ParseAddr(strings.Trim(strings.TrimSpace(ip), "[]"))
	if err != nil {
		return nil
	}
	address = address.Unmap()
	reader := appIPReader()
	if !reader.Available() {
		return nil
	}
	codes := reader.LookupCode(address.AsSlice())
	if len(codes) == 0 || codes[0] == "" {
		return nil
	}
	return WrapString(codes[0])
}

func GeoIPNetworkCount(code string) int {
	return recoverAppCallValueOr("GeoIPNetworkCount", -1, func() int { return geoIPNetworkCountUnguarded(code) })
}

func geoIPNetworkCountUnguarded(code string) int {
	code = strings.ToLower(strings.TrimSpace(code))
	if code == "" || code == "lan" {
		return -1
	}
	counts, ok := appIPReader().NetworkCounts()
	if !ok {
		return -1
	}
	return counts[code]
}

func ASNNetworkCount(asn string) int {
	return recoverAppCallValueOr("ASNNetworkCount", -1, func() int { return asnNetworkCountUnguarded(asn) })
}

func asnNetworkCountUnguarded(asn string) int {
	asn = strings.TrimSpace(asn)
	if asn == "" {
		return -1
	}
	counts, ok := appASNReader().NetworkCounts()
	if !ok {
		return -1
	}
	return counts[asn]
}

func appIPReader() mmdb.IPReader {
	appParseMu.Lock()
	defer appParseMu.Unlock()
	return mmdb.IPInstance()
}

func appASNReader() mmdb.ASNReader {
	appParseMu.Lock()
	defer appParseMu.Unlock()
	return mmdb.ASNInstance()
}
