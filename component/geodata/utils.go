package geodata

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/ProjectClash/Clash/common/singleflight"
	"github.com/ProjectClash/Clash/component/cidr"
	"github.com/ProjectClash/Clash/component/geodata/compiled"
	"github.com/ProjectClash/Clash/component/geodata/router"
	"github.com/ProjectClash/Clash/component/trie"
	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/log"
)

var (
	geoMode        atomic.Bool
	geoLoaderName  = "memconservative"
	geoSiteMatcher = "succinct"

	compiledGeoSiteOnly atomic.Bool

	compiledGeoIPOnly atomic.Bool

	progressReporterValue atomic.Pointer[func(string)]
)

func SetCompiledGeoIPOnly(only bool) {
	compiledGeoIPOnly.Store(only)
}

func CompiledGeoIPOnly() bool {
	return compiledGeoIPOnly.Load()
}

func CompiledGeoIPDir() string {
	return filepath.Join(C.Path.HomeDir(), compiled.IPCIDRDirectoryName)
}

func SetCompiledGeoSiteOnly(only bool) {
	compiledGeoSiteOnly.Store(only)
}

func CompiledGeoSiteOnly() bool {
	return compiledGeoSiteOnly.Load()
}

func CompiledGeoSiteDir() string {
	return filepath.Join(C.Path.HomeDir(), compiled.DirectoryName)
}

//  geoLoaderName = "standard"

func GeodataMode() bool {
	return geoMode.Load()
}

func LoaderName() string {
	return geoLoaderName
}

func SiteMatcherName() string {
	return geoSiteMatcher
}

func SetGeodataMode(newGeodataMode bool) {
	geoMode.Store(newGeodataMode)
}

func SetLoader(newLoader string) {
	if newLoader == "memc" {
		newLoader = "memconservative"
	}
	geoLoaderName = newLoader
}

func SetSiteMatcher(newMatcher string) {
	switch newMatcher {
	case "mph", "hybrid":
		geoSiteMatcher = "mph"
	default:
		geoSiteMatcher = "succinct"
	}
}

func Verify(name string) error {
	switch name {
	case C.GeositeName:
		_, err := LoadGeoSiteMatcher("CN")
		return err
	case C.GeoipName:
		_, err := LoadGeoIPMatcher("CN")
		return err
	default:
		return fmt.Errorf("not support name")
	}
}

var loadGeoSiteMatcherListSF = singleflight.Group[[]*router.Domain]{StoreResult: true}
var loadGeoSiteMatcherSF = singleflight.Group[router.DomainMatcher]{StoreResult: true}

func LoadGeoSiteMatcher(countryCode string) (router.DomainMatcher, error) {
	if countryCode == "" {
		return nil, fmt.Errorf("country code could not be empty")
	}

	not := false
	if countryCode[0] == '!' {
		not = true
		countryCode = countryCode[1:]
		if countryCode == "" {
			return nil, fmt.Errorf("country code could not be empty")
		}
	}
	countryCode = strings.ToLower(countryCode)

	parts := strings.Split(countryCode, "@")
	listName := strings.TrimSpace(parts[0])
	attrVal := parts[1:]
	attrs := parseAttrs(attrVal)

	if listName == "" {
		return nil, fmt.Errorf("empty listname in rule: %s", countryCode)
	}

	matcherName := canonicalGeoSiteKey(listName, attrs)
	matcher, err, shared := loadGeoSiteMatcherSF.Do(matcherName, func() (router.DomainMatcher, error) {
		reportProgress("geosite:" + matcherName)
		if set, count, residual, err := compiled.Load(CompiledGeoSiteDir(), matcherName); err == nil {
			matcher, err := router.NewSuccinctMatcherFromParts(set, count, toRouterResidual(residual))
			if err == nil {
				log.Infoln("Load GeoSite rule: %s (compiled, %d entries)", matcherName, count)
				return matcher, nil
			}
			log.Warnln("compiled GeoSite rule %s could not be assembled (%s); falling back to source",
				matcherName, err)
		} else if !errors.Is(err, compiled.ErrNotCompiled) {
			log.Warnln("compiled GeoSite rule %s could not be read (%s); falling back to source", matcherName, err)
		}
		if compiledGeoSiteOnly.Load() {
			log.Warnln("GeoSite rule %s has not been compiled for this runtime and will match nothing "+
				"(looked in %s): decoding it needs more memory than this process is allowed, "+
				"so the alternative is not starting",
				matcherName, CompiledGeoSiteDir())
			return router.NewUnavailableDomainMatcher(), nil
		}
		log.Infoln("Load GeoSite rule: %s", matcherName)
		domains, err, shared := loadGeoSiteMatcherListSF.Do(listName, func() ([]*router.Domain, error) {
			geoLoader, err := GetGeoDataLoader(geoLoaderName)
			if err != nil {
				return nil, err
			}
			return geoLoader.LoadGeoSite(listName)
		})
		if err != nil {
			if !shared {
				loadGeoSiteMatcherListSF.Forget(listName) // don't store the error result
			}
			return nil, err
		}

		if attrs.IsEmpty() {
			if strings.Contains(countryCode, "@") {
				log.Warnln("empty attribute list: %s", countryCode)
			}
		} else {
			filteredDomains := make([]*router.Domain, 0, len(domains))
			hasAttrMatched := false
			for _, domain := range domains {
				if attrs.Match(domain) {
					hasAttrMatched = true
					filteredDomains = append(filteredDomains, domain)
				}
			}
			if !hasAttrMatched {
				log.Warnln("attribute match no rule: geosite: %s", countryCode)
			}
			domains = filteredDomains
		}

		/**
		linear: linear algorithm
		matcher, err := router.NewDomainMatcher(domains)
		mph：minimal perfect hash algorithm
		*/
		var built router.DomainMatcher
		if geoSiteMatcher == "mph" {
			built, err = router.NewMphMatcherGroup(domains)
		} else {
			built, err = router.NewSuccinctMatcherGroup(domains)
		}
		if geoLoaderName == "memconservative" {
			loadGeoSiteMatcherListSF.Forget(listName)
		}
		return built, err
	})
	if err != nil {
		if !shared {
			loadGeoSiteMatcherSF.Forget(matcherName) // don't store the error result
		}
		return nil, err
	}
	if not && !router.Unavailable(matcher) {
		matcher = router.NewNotDomainMatcherGroup(matcher)
	}

	return matcher, nil
}

var loadGeoIPMatcherSF = singleflight.Group[router.IPMatcher]{StoreResult: true}

func LoadGeoIPMatcher(country string) (router.IPMatcher, error) {
	if len(country) == 0 {
		return nil, fmt.Errorf("country code could not be empty")
	}

	not := false
	if country[0] == '!' {
		not = true
		country = country[1:]
	}
	country = strings.ToLower(country)

	matcher, err, shared := loadGeoIPMatcherSF.Do(country, func() (router.IPMatcher, error) {
		reportProgress("geoip:" + country)
		if set, count, err := compiled.LoadIPCIDR(CompiledGeoIPDir(), country); err == nil {
			matcher, err := router.NewGeoIPMatcherFromCidrSet(set, count)
			if err == nil {
				log.Infoln("Load GeoIP rule: %s (compiled, %d entries)", country, count)
				return matcher, nil
			}
			log.Warnln("compiled GeoIP rule %s could not be assembled (%s); falling back to source",
				country, err)
		} else if !errors.Is(err, compiled.ErrNotCompiled) {
			log.Warnln("compiled GeoIP rule %s could not be read (%s); falling back to source", country, err)
		}
		if compiledGeoIPOnly.Load() {
			log.Warnln("GeoIP rule %s has not been compiled for this runtime and will match nothing "+
				"(looked in %s): decoding it needs more memory than this process is allowed, "+
				"so the alternative is not starting",
				country, CompiledGeoIPDir())
			return router.NewUnavailableIPMatcher(), nil
		}
		log.Infoln("Load GeoIP rule: %s", country)
		geoLoader, err := GetGeoDataLoader(geoLoaderName)
		if err != nil {
			return nil, err
		}
		cidrList, err := geoLoader.LoadGeoIP(country)
		if err != nil {
			return nil, err
		}
		return router.NewGeoIPMatcher(cidrList)
	})
	if err != nil {
		if !shared {
			loadGeoIPMatcherSF.Forget(country) // don't store the error result
			log.Warnln("Load GeoIP rule: %s", country)
		}
		return nil, err
	}
	if not && !router.Unavailable(matcher) {
		matcher = router.NewNotIpMatcherGroup(matcher)
	}
	return matcher, nil
}

func ClearGeoSiteCache() {
	loadGeoSiteMatcherListSF.Reset()
	loadGeoSiteMatcherSF.Reset()
}

func ClearGeoIPCache() {
	loadGeoIPMatcherSF.Reset()
}

func emptyDomainSet() *trie.DomainSet {
	return trie.New[struct{}]().NewDomainSet()
}

func CompileGeoSite(category string) error {
	listName, attrs, domains, err := geoSiteSourceDomains(category)
	if err != nil {
		return err
	}
	if len(domains) == 0 {
		return fmt.Errorf("geosite %s holds no entries", category)
	}
	set, count, residual, err := router.CompileDomains(domains)
	if err != nil {
		return err
	}
	return compiled.Store(
		CompiledGeoSiteDir(), canonicalGeoSiteKey(listName, attrs),
		set, count, fromRouterResidual(residual),
	)
}

func CountGeoSite(category string) (int, error) {
	_, _, domains, err := geoSiteSourceDomains(category)
	if err != nil {
		return 0, err
	}
	if len(domains) == 0 {
		return 0, nil
	}
	_, count, _, err := router.CompileDomains(domains)
	return count, err
}

func geoSiteSourceDomains(category string) (string, *AttributeList, []*router.Domain, error) {
	listName, attrs, err := splitGeoSiteCategory(category)
	if err != nil {
		return "", nil, nil, err
	}
	geoLoader, err := GetGeoDataLoader(geoLoaderName)
	if err != nil {
		return "", nil, nil, err
	}
	domains, err := geoLoader.LoadGeoSite(listName)
	if err != nil {
		return "", nil, nil, err
	}
	if !attrs.IsEmpty() {
		filtered := make([]*router.Domain, 0, len(domains))
		for _, domain := range domains {
			if attrs.Match(domain) {
				filtered = append(filtered, domain)
			}
		}
		domains = filtered
	}
	return listName, attrs, domains, nil
}

func CompiledGeoSiteKey(category string) (string, error) {
	listName, attrs, err := splitGeoSiteCategory(category)
	if err != nil {
		return "", err
	}
	return canonicalGeoSiteKey(listName, attrs), nil
}

func canonicalGeoSiteKey(listName string, attrs *AttributeList) string {
	if attrs.IsEmpty() {
		return listName
	}
	return listName + "@" + attrs.String()
}

func splitGeoSiteCategory(category string) (string, *AttributeList, error) {
	name := strings.ToLower(strings.TrimSpace(category))
	name = strings.TrimPrefix(name, "!")
	parts := strings.Split(name, "@")
	listName := strings.TrimSpace(parts[0])
	if listName == "" {
		return "", nil, fmt.Errorf("empty listname in rule: %s", category)
	}
	return listName, parseAttrs(parts[1:]), nil
}

func toRouterResidual(residual []compiled.Residual) []router.ResidualDomain {
	if len(residual) == 0 {
		return nil
	}
	out := make([]router.ResidualDomain, 0, len(residual))
	for _, entry := range residual {
		out = append(out, router.ResidualDomain{
			Type: router.Domain_Type(entry.Type), Value: entry.Value,
		})
	}
	return out
}

func fromRouterResidual(residual []router.ResidualDomain) []compiled.Residual {
	if len(residual) == 0 {
		return nil
	}
	out := make([]compiled.Residual, 0, len(residual))
	for _, entry := range residual {
		out = append(out, compiled.Residual{Type: int32(entry.Type), Value: entry.Value})
	}
	return out
}

func CompileGeoIP(country string) error {
	name := strings.ToLower(strings.TrimSpace(country))
	if strings.HasPrefix(name, "!") {
		name = name[1:]
	}
	if name == "" {
		return fmt.Errorf("country code could not be empty")
	}
	cidrList, err := geoIPSourceList(name)
	if err != nil {
		return err
	}
	if len(cidrList) == 0 {
		return fmt.Errorf("geoip %s holds no entries", name)
	}
	set := cidr.NewIpCidrSet()
	for _, entry := range cidrList {
		addr, ok := netip.AddrFromSlice(entry.Ip)
		if !ok {
			return fmt.Errorf("geoip %s: invalid IP", name)
		}
		if err := set.AddIpCidr(netip.PrefixFrom(addr, int(entry.Prefix))); err != nil {
			return err
		}
	}
	if err := set.Merge(); err != nil {
		return err
	}
	return compiled.StoreIPCIDR(CompiledGeoIPDir(), name, set, len(cidrList))
}

func CountGeoIP(country string) (int, error) {
	name := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(country)), "!")
	if name == "" {
		return 0, fmt.Errorf("country code could not be empty")
	}
	cidrList, err := geoIPSourceList(name)
	if err != nil {
		return 0, err
	}
	for _, entry := range cidrList {
		addr, ok := netip.AddrFromSlice(entry.Ip)
		if !ok {
			return 0, fmt.Errorf("geoip %s: invalid IP", name)
		}
		if !netip.PrefixFrom(addr, int(entry.Prefix)).IsValid() {
			return 0, fmt.Errorf("geoip %s: invalid prefix", name)
		}
	}
	return len(cidrList), nil
}

func geoIPSourceList(name string) ([]*router.CIDR, error) {
	geoLoader, err := GetGeoDataLoader(geoLoaderName)
	if err != nil {
		return nil, err
	}
	return geoLoader.LoadGeoIP(name)
}

func SetGeodataProgressReporter(report func(string)) {
	if report == nil {
		progressReporterValue.Store(nil)
		return
	}
	progressReporterValue.Store(&report)
}

func reportProgress(resource string) {
	if report := progressReporterValue.Load(); report != nil {
		(*report)(resource)
	}
}

func GeodataProgressReporter() func(string) {
	if report := progressReporterValue.Load(); report != nil {
		return *report
	}
	return nil
}
