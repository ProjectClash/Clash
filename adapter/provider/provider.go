package provider

import (
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/common/convert"
	"github.com/ProjectClash/Clash/common/utils"
	"github.com/ProjectClash/Clash/common/yaml"
	"github.com/ProjectClash/Clash/component/age"
	"github.com/ProjectClash/Clash/component/profile/cachefile"
	"github.com/ProjectClash/Clash/component/resource"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	"github.com/ProjectClash/Clash/tunnel/statistic"

	"github.com/dlclark/regexp2"
	"github.com/metacubex/http"
)

const (
	ReservedName = "default"
)

type ProxySchema struct {
	Proxies []map[string]any `yaml:"proxies"`
}

type providerForApi struct {
	Name             string            `json:"name"`
	Type             string            `json:"type"`
	VehicleType      string            `json:"vehicleType"`
	Proxies          []C.Proxy         `json:"proxies"`
	TestUrl          string            `json:"testUrl"`
	ExpectedStatus   string            `json:"expectedStatus"`
	UpdatedAt        time.Time         `json:"updatedAt,omitempty"`
	SubscriptionInfo *SubscriptionInfo `json:"subscriptionInfo,omitempty"`
}

type baseProvider struct {
	mutex       sync.RWMutex
	name        string
	list        C.ProxyList
	healthCheck *HealthCheck
	version     uint32
}

func (bp *baseProvider) Name() string {
	return bp.name
}

func (bp *baseProvider) Version() uint32 {
	bp.mutex.RLock()
	defer bp.mutex.RUnlock()
	return bp.version
}

func (bp *baseProvider) Initial() error {
	if bp.healthCheck.auto() {
		go bp.healthCheck.process()
	}
	return nil
}

func (bp *baseProvider) HealthCheck() {
	bp.healthCheck.check()
}

func (bp *baseProvider) Type() P.ProviderType {
	return P.Proxy
}

func (bp *baseProvider) Proxies() []C.Proxy {
	return C.ProxiesOf(bp.ProxyList())
}

func (bp *baseProvider) ProxyList() C.ProxyList {
	bp.mutex.RLock()
	defer bp.mutex.RUnlock()
	if bp.list == nil {
		return C.ProxySlice(nil)
	}
	return bp.list
}

func (bp *baseProvider) Count() int {
	return bp.ProxyList().Len()
}

func (bp *baseProvider) Touch() {
	bp.healthCheck.touch()
}

func (bp *baseProvider) HealthCheckURL() string {
	return bp.healthCheck.url
}

func (bp *baseProvider) RegisterHealthCheckTask(url string, expectedStatus utils.IntRanges[uint16], filter string, interval uint) {
	bp.healthCheck.registerHealthCheckTask(url, expectedStatus, filter, interval)
}

func (bp *baseProvider) setProxies(proxies []C.Proxy) {
	bp.setProxyList(C.ProxySlice(proxies))
}

func (bp *baseProvider) setProxyList(proxies C.ProxyList) {
	bp.mutex.Lock()
	defer bp.mutex.Unlock()
	bp.list = proxies
	bp.version += 1
	bp.healthCheck.setProxyList(proxies)
	if bp.healthCheck.auto() {
		go bp.healthCheck.checkLoaded()
	}
}

func (bp *baseProvider) Close() error {
	bp.healthCheck.close()
	return nil
}

// ProxySetProvider for auto gc
type ProxySetProvider struct {
	*proxySetProvider
}

type proxySetProvider struct {
	baseProvider
	*resource.Fetcher[C.ProxyList]
	subscriptionInfo               *SubscriptionInfo
}

func (pp *proxySetProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(providerForApi{
		Name:             pp.Name(),
		Type:             pp.Type().String(),
		VehicleType:      pp.VehicleType().String(),
		Proxies:          pp.Proxies(),
		TestUrl:          pp.healthCheck.url,
		ExpectedStatus:   pp.healthCheck.expectedStatus.String(),
		UpdatedAt:        pp.UpdatedAt(),
		SubscriptionInfo: pp.subscriptionInfo,
	})
}

func (pp *proxySetProvider) Name() string {
	return pp.Fetcher.Name()
}

func (pp *proxySetProvider) SideUpdate(payload []byte) error {
	_, _, err := pp.Fetcher.SideUpdate(payload)
	return err
}

func (pp *proxySetProvider) Update() error {
	_, _, err := pp.Fetcher.Update()
	return err
}

func (pp *proxySetProvider) Initial() error {
	if err := pp.baseProvider.Initial(); err != nil {
		return err
	}
	_, err := pp.Fetcher.Initial()
	if err != nil {
		return err
	}
	if subscriptionInfo := cachefile.Cache().GetSubscriptionInfo(pp.Name()); subscriptionInfo != "" {
		pp.subscriptionInfo = NewSubscriptionInfo(subscriptionInfo)
	}
	pp.closeAllConnections()
	return nil
}

func (pp *proxySetProvider) closeAllConnections() {
	statistic.DefaultManager.Range(func(c statistic.Tracker) bool {
		for _, chain := range c.ProviderChains() {
			if chain == pp.Name() {
				_ = c.Close()
				break
			}
		}
		return true
	})
}

func (pp *proxySetProvider) Close() error {
	_ = pp.baseProvider.Close()
	return pp.Fetcher.Close()
}

func NewProxySetProvider(name string, interval time.Duration, payload []map[string]any, parser resource.Parser[C.ProxyList], vehicle P.Vehicle, hc *HealthCheck) (*ProxySetProvider, error) {
	pd := &proxySetProvider{
		baseProvider: baseProvider{
			name:        name,
			list:        C.ProxySlice{},
			healthCheck: hc,
		},
	}

	if len(payload) > 0 { // using as fallback proxies
		ps := ProxySchema{Proxies: payload}
		buf, err := yaml.Marshal(ps)
		if err != nil {
			return nil, err
		}
		proxies, err := parser(buf)
		if err != nil {
			return nil, err
		}
		pd.list = proxies
		// direct call setProxies on hc to avoid starting a health check process immediately, it should be done by Initial()
		hc.setProxyList(proxies)
	}

	fetcher := resource.NewFetcher[C.ProxyList](name, interval, vehicle, nil, parser, pd.setProxyList)
	pd.Fetcher = fetcher
	if httpVehicle, ok := vehicle.(*resource.HTTPVehicle); ok {
		httpVehicle.SetInRead(func(resp *http.Response) {
			if subscriptionInfo := resp.Header.Get("subscription-userinfo"); subscriptionInfo != "" {
				cachefile.Cache().SetSubscriptionInfo(name, subscriptionInfo)
				pd.subscriptionInfo = NewSubscriptionInfo(subscriptionInfo)
			}
		})
	}

	wrapper := &ProxySetProvider{pd}
	runtime.SetFinalizer(wrapper, (*ProxySetProvider).Close)
	return wrapper, nil
}

func (pp *ProxySetProvider) Close() error {
	runtime.SetFinalizer(pp, nil)
	return pp.proxySetProvider.Close()
}

// InlineProvider for auto gc
type InlineProvider struct {
	*inlineProvider
}

type inlineProvider struct {
	baseProvider
	updateAt time.Time
}

func (ip *inlineProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(providerForApi{
		Name:           ip.Name(),
		Type:           ip.Type().String(),
		VehicleType:    ip.VehicleType().String(),
		Proxies:        ip.Proxies(),
		TestUrl:        ip.healthCheck.url,
		ExpectedStatus: ip.healthCheck.expectedStatus.String(),
		UpdatedAt:      ip.updateAt,
	})
}

func (ip *inlineProvider) VehicleType() P.VehicleType {
	return P.Inline
}

func (ip *inlineProvider) Update() error {
	// make api update happy
	ip.updateAt = time.Now()
	return nil
}

func NewInlineProvider(name string, payload []map[string]any, parser resource.Parser[[]C.Proxy], hc *HealthCheck) (*InlineProvider, error) {
	ps := ProxySchema{Proxies: payload}
	buf, err := yaml.Marshal(ps)
	if err != nil {
		return nil, err
	}
	proxies, err := parser(buf)
	if err != nil {
		return nil, err
	}
	// direct call setProxies on hc to avoid starting a health check process immediately, it should be done by Initial()
	hc.setProxies(proxies)

	ip := &inlineProvider{
		baseProvider: baseProvider{
			name:        name,
			list:        C.ProxySlice(proxies),
			healthCheck: hc,
		},
		updateAt: time.Now(),
	}
	wrapper := &InlineProvider{ip}
	runtime.SetFinalizer(wrapper, (*InlineProvider).Close)
	return wrapper, nil
}

func (ip *InlineProvider) Close() error {
	runtime.SetFinalizer(ip, nil)
	return ip.baseProvider.Close()
}

// CompatibleProvider for auto gc
type CompatibleProvider struct {
	*compatibleProvider
}

type compatibleProvider struct {
	baseProvider
}

func (cp *compatibleProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(providerForApi{
		Name:           cp.Name(),
		Type:           cp.Type().String(),
		VehicleType:    cp.VehicleType().String(),
		Proxies:        cp.Proxies(),
		TestUrl:        cp.healthCheck.url,
		ExpectedStatus: cp.healthCheck.expectedStatus.String(),
	})
}

func (cp *compatibleProvider) Update() error {
	return nil
}

func (cp *compatibleProvider) VehicleType() P.VehicleType {
	return P.Compatible
}

func NewCompatibleProvider(name string, proxies []C.Proxy, hc *HealthCheck) (*CompatibleProvider, error) {
	return NewCompatibleProviderList(name, C.ProxySlice(proxies), hc)
}

func NewCompatibleProviderList(name string, proxies C.ProxyList, hc *HealthCheck) (*CompatibleProvider, error) {
	if proxies.Len() == 0 {
		return nil, errors.New("provider need one proxy at least")
	}

	pd := &compatibleProvider{
		baseProvider: baseProvider{
			name:        name,
			list:        proxies,
			healthCheck: hc,
		},
	}

	wrapper := &CompatibleProvider{pd}
	runtime.SetFinalizer(wrapper, (*CompatibleProvider).Close)
	return wrapper, nil
}

func (cp *CompatibleProvider) Close() error {
	runtime.SetFinalizer(cp, nil)
	return cp.compatibleProvider.Close()
}

func NewProxiesParser(pdName string, tunnel C.Tunnel, filter string, excludeFilter string, excludeType string, dialerProxy string, override overrideSchema, ageSecretKey string) (resource.Parser[[]C.Proxy], error) {
	selectProxies, err := newProxiesSelector(filter, excludeFilter, excludeType, dialerProxy, override, ageSecretKey)
	if err != nil {
		return nil, err
	}
	return func(buf []byte) ([]C.Proxy, error) {
		proxies := []C.Proxy{}
		clashNodes := adapter.NewNodeCatalogSession()
		err := selectProxies(buf, func(mapping map[string]any) error {
			proxy, err := adapter.ParseProxy(mapping, adapter.WithTunnelForAPI(tunnel), adapter.WithProviderName(pdName), adapter.WithNodeCatalogSession(clashNodes))
			if err != nil {
				return err
			}
			proxies = append(proxies, proxy)
			return nil
		})
		_ = clashNodes.Seal()
		if err != nil {
			return nil, err
		}
		return proxies, nil
	}, nil
}

type proxiesSelector func(buf []byte, each func(mapping map[string]any) error) error

func newProxiesSelector(filter string, excludeFilter string, excludeType string, dialerProxy string, override overrideSchema, ageSecretKey string) (proxiesSelector, error) {
	var excludeTypeArray []string
	if excludeType != "" {
		excludeTypeArray = strings.Split(excludeType, "|")
	}

	var excludeFilterRegs []*regexp2.Regexp
	if excludeFilter != "" {
		for _, excludeFilter := range strings.Split(excludeFilter, "`") {
			excludeFilterReg, err := regexp2.Compile(excludeFilter, regexp2.None)
			if err != nil {
				return nil, fmt.Errorf("invalid excludeFilter regex: %w", err)
			}
			excludeFilterRegs = append(excludeFilterRegs, excludeFilterReg)
		}
	}

	var filterRegs []*regexp2.Regexp
	for _, filter := range strings.Split(filter, "`") {
		filterReg, err := regexp2.Compile(filter, regexp2.None)
		if err != nil {
			return nil, fmt.Errorf("invalid filter regex: %w", err)
		}
		filterRegs = append(filterRegs, filterReg)
	}

	if ageSecretKey != "" {
		if err := age.VeritySecretKeys(ageSecretKey); err != nil {
			return nil, fmt.Errorf("invalid age-secret-key: %w", err)
		}
	}

	return func(buf []byte, each func(mapping map[string]any) error) error {
		schema := &ProxySchema{}

		// decrypt config
		buf, err := age.DecryptBytes(buf, ageSecretKey)
		if err != nil {
			return fmt.Errorf("decrypt config error: %w", err)
		}

		if err := clashUnmarshalProxySchema(buf, schema); err != nil {
			proxies, err1 := convert.ConvertsV2Ray(buf)
			if err1 != nil {
				return fmt.Errorf("%w, %w", err, err1)
			}
			schema.Proxies = proxies
		}

		if schema.Proxies == nil {
			return errors.New("file must have a `proxies` field")
		}

		proxiesSet := map[string]struct{}{}
		for _, filterReg := range filterRegs {
		LOOP1:
			for idx, mapping := range schema.Proxies {
				if len(excludeTypeArray) > 0 {
					mType, ok := mapping["type"]
					if !ok {
						continue
					}
					pType, ok := mType.(string)
					if !ok {
						continue
					}
					for _, excludeType := range excludeTypeArray {
						if strings.EqualFold(pType, excludeType) {
							continue LOOP1
						}
					}
				}
				mName, ok := mapping["name"]
				if !ok {
					continue
				}
				name, ok := mName.(string)
				if !ok {
					continue
				}
				if len(excludeFilterRegs) > 0 {
					for _, excludeFilterReg := range excludeFilterRegs {
						if mat, _ := excludeFilterReg.MatchString(name); mat {
							continue LOOP1
						}
					}
				}
				if len(filter) > 0 {
					if mat, _ := filterReg.MatchString(name); !mat {
						continue
					}
				}
				if _, ok := proxiesSet[name]; ok {
					continue
				}

				if len(dialerProxy) > 0 {
					mapping["dialer-proxy"] = dialerProxy
				}

				err := override.Apply(mapping)
				if err != nil {
					return fmt.Errorf("proxy %d override error: %w", idx, err)
				}

				if err := each(mapping); err != nil {
					return fmt.Errorf("proxy %d error: %w", idx, err)
				}

				proxiesSet[name] = struct{}{}
			}
		}

		if len(proxiesSet) == 0 {
			if len(filter) > 0 {
				return errors.New("doesn't match any proxy, please check your filter")
			}
			return errors.New("file doesn't have any proxy")
		}
		return nil
	}, nil
}
