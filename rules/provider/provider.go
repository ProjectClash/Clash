package provider

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ProjectClash/Clash/common/atomic"
	"github.com/ProjectClash/Clash/common/pool"
	"github.com/ProjectClash/Clash/common/yaml"
	"github.com/ProjectClash/Clash/component/resource"
	C "github.com/ProjectClash/Clash/constant"
	P "github.com/ProjectClash/Clash/constant/provider"
	"github.com/ProjectClash/Clash/rules/common"
)

var tunnel P.Tunnel

func SetTunnel(t P.Tunnel) {
	tunnel = t
}

type RulePayload struct {
	/**
	key: Domain or IP Cidr
	value: Rule type or is empty
	*/
	Payload []string `yaml:"payload"`
	Rules   []string `yaml:"rules"`
}

type providerForApi struct {
	Behavior    string    `json:"behavior"`
	Format      string    `json:"format"`
	Name        string    `json:"name"`
	RuleCount   int       `json:"ruleCount"`
	Type        string    `json:"type"`
	VehicleType string    `json:"vehicleType"`
	UpdatedAt   time.Time `json:"updatedAt"`
	Payload     []string  `json:"payload,omitempty"`
}

type ruleStrategy interface {
	Behavior() P.RuleBehavior
	Match(metadata *C.Metadata, helper C.RuleMatchHelper) bool
	Count() int
	Reset()
	Insert(rule string)
	FinishInsert()
}

type mrsRuleStrategy interface {
	ruleStrategy
	FromMrs(r io.Reader, count int) error
	WriteMrs(w io.Writer) error
	DumpMrs(f func(key string) bool)
}

type baseProvider struct {
	behavior P.RuleBehavior
	strategy atomic.TypedValue[ruleStrategy]
}

func (bp *baseProvider) Type() P.ProviderType {
	return P.Rule
}

func (bp *baseProvider) Behavior() P.RuleBehavior {
	return bp.behavior
}

func (bp *baseProvider) Count() int {
	return bp.strategy.Load().Count()
}

func (bp *baseProvider) Match(metadata *C.Metadata, helper C.RuleMatchHelper) bool {
	strategy := bp.strategy.Load()
	return strategy != nil && strategy.Match(metadata, helper)
}

func (bp *baseProvider) Strategy() any {
	return bp.strategy.Load()
}

type ruleSetProvider struct {
	baseProvider
	*resource.Fetcher[ruleStrategy]
	format P.RuleFormat
}

type RuleSetProvider struct {
	*ruleSetProvider
}

func (rp *ruleSetProvider) Initial() error {
	_, err := rp.Fetcher.Initial()
	return err
}

func (rp *ruleSetProvider) Format() P.RuleFormat {
	return rp.format
}

func (rp *ruleSetProvider) SideUpdate(payload []byte) error {
	_, _, err := rp.Fetcher.SideUpdate(payload)
	return err
}

func (rp *ruleSetProvider) Update() error {
	_, _, err := rp.Fetcher.Update()
	return err
}

func (rp *ruleSetProvider) metadataSnapshot() (metadata providerForApi, hash string) {
	rp.ReadLoadedContent(func(loadedHash string, updatedAt time.Time) {
		metadata = providerForApi{
			Behavior: rp.behavior.String(), Format: rp.format.String(), Name: rp.Name(),
			RuleCount: rp.Count(), Type: rp.Type().String(),
			UpdatedAt: updatedAt, VehicleType: rp.VehicleType().String(),
		}
		hash = loadedHash
	})
	return
}

func (rp *ruleSetProvider) LoadedMetadataJSON() ([]byte, error) {
	metadata, hash := rp.metadataSnapshot()
	return json.Marshal(struct {
		providerForApi
		Loaded      bool   `json:"loaded"`
		ContentHash string `json:"contentHash"`
		Algorithm   string `json:"algorithm"`
	}{providerForApi: metadata, Loaded: hash != "", ContentHash: hash, Algorithm: "md5"})
}

func (rp *ruleSetProvider) MarshalJSON() ([]byte, error) {
	metadata, _ := rp.metadataSnapshot()
	return json.Marshal(metadata)
}

func (rp *RuleSetProvider) Close() error {
	runtime.SetFinalizer(rp, nil)
	return rp.ruleSetProvider.Close()
}

func NewRuleSetProvider(name string, behavior P.RuleBehavior, format P.RuleFormat, interval time.Duration, vehicle P.Vehicle, payload []string, bundleFile resource.BundleFile, parse common.ParseRuleFunc) P.RuleProvider {
	rp := &ruleSetProvider{
		baseProvider: baseProvider{
			behavior: behavior,
		},
		format: format,
	}

	onUpdate := func(strategy ruleStrategy) {
		rp.strategy.Store(strategy)
		tunnel.RuleUpdateCallback().Emit(rp)
	}

	strategy := newStrategy(behavior, parse)
	if len(payload) > 0 { // using as fallback rules
		strategy = rulesParseInline(payload, strategy)
	}
	rp.strategy.Store(strategy)
	rp.Fetcher = resource.NewFetcher(name, interval, vehicle, bundleFile, func(bytes []byte) (ruleStrategy, error) {
		strategy := newStrategy(behavior, parse)
		if classical, ok := strategy.(*classicalStrategy); ok {
			classical.indexDirectory = clashClassicalIndexDirectory(vehicle)
		}
		return rulesParse(bytes, strategy, format)
	}, onUpdate)

	wrapper := &RuleSetProvider{
		rp,
	}

	runtime.SetFinalizer(wrapper, (*RuleSetProvider).Close)
	return wrapper
}

func newStrategy(behavior P.RuleBehavior, parse common.ParseRuleFunc) ruleStrategy {
	switch behavior {
	case P.Domain:
		strategy := NewDomainStrategy()
		return strategy
	case P.IPCIDR:
		strategy := NewIPCidrStrategy()
		return strategy
	case P.Classical:
		strategy := NewClassicalStrategy(parse)
		return strategy
	default:
		return nil
	}
}

var (
	ErrNoPayload     = errors.New("file must have a `payload` field")
	ErrInvalidFormat = errors.New("invalid format")
)

func rulesParse(buf []byte, strategy ruleStrategy, format P.RuleFormat) (ruleStrategy, error) {
	strategy.Reset()
	if format == P.MrsRule {
		return rulesMrsParse(buf, strategy)
	}

	schema := &RulePayload{}

	firstLineBuffer := pool.GetBuffer()
	defer pool.PutBuffer(firstLineBuffer)
	firstLineLength := 0

	s := 0 // search start index
	for s < len(buf) {
		// search buffer for a new line.
		line := buf[s:]
		if i := bytes.IndexByte(line, '\n'); i >= 0 {
			i += s
			line = buf[s : i+1]
			s = i + 1
		} else {
			s = len(buf)                                      // stop loop in next step
			if firstLineLength == 0 && format == P.YamlRule { // no head or only one line body
				return nil, ErrNoPayload
			}
		}
		var str string
		switch format {
		case P.TextRule:
			str = string(line)
			str = strings.TrimSpace(str)
			if len(str) == 0 {
				continue
			}
			if str[0] == '#' { // comment
				continue
			}
			if strings.HasPrefix(str, "//") { // comment in Premium core
				continue
			}
		case P.YamlRule:
			trimLine := bytes.TrimSpace(line)
			if len(trimLine) == 0 {
				continue
			}
			if trimLine[0] == '#' { // comment
				continue
			}
			firstLineBuffer.Write(line)
			if firstLineLength == 0 { // find payload head
				firstLineLength = firstLineBuffer.Len()
				firstLineBuffer.WriteString("  - ''") // a test line

				err := yaml.Unmarshal(firstLineBuffer.Bytes(), schema)
				firstLineBuffer.Truncate(firstLineLength)
				if err == nil && (len(schema.Rules) > 0 || len(schema.Payload) > 0) { // found
					continue
				}

				// not found or err!=nil
				firstLineBuffer.Truncate(0)
				firstLineLength = 0
				continue
			}

			// parse payload body
			err := yaml.Unmarshal(firstLineBuffer.Bytes(), schema)
			firstLineBuffer.Truncate(firstLineLength)
			if err != nil {
				continue
			}

			if len(schema.Rules) > 0 {
				str = schema.Rules[0]
			}
			if len(schema.Payload) > 0 {
				str = schema.Payload[0]
			}
		default:
			return nil, ErrInvalidFormat
		}

		if str == "" {
			continue
		}

		strategy.Insert(str)
	}

	strategy.FinishInsert()

	return strategy, nil
}

func rulesParseInline(rs []string, strategy ruleStrategy) ruleStrategy {
	strategy.Reset()
	for _, r := range rs {
		if r != "" {
			strategy.Insert(r)
		}
	}
	strategy.FinishInsert()
	return strategy
}

type InlineProvider struct {
	*inlineProvider
}

type inlineProvider struct {
	baseProvider
	name     string
	updateMu sync.RWMutex
	updateAt time.Time
	payload  []string
}

func (i *inlineProvider) Name() string {
	return i.name
}

func (i *inlineProvider) Initial() error {
	return nil
}

func (i *inlineProvider) Update() error {
	// make api update happy
	i.updateMu.Lock()
	i.updateAt = time.Now()
	i.updateMu.Unlock()
	return nil
}

func (i *inlineProvider) updatedAtSnapshot() time.Time {
	i.updateMu.RLock()
	defer i.updateMu.RUnlock()
	return i.updateAt
}

func (i *inlineProvider) VehicleType() P.VehicleType {
	return P.Inline
}

func (i *inlineProvider) LoadedMetadataJSON() ([]byte, error) {
	return json.Marshal(struct {
		providerForApi
		Loaded bool `json:"loaded"`
	}{providerForApi: providerForApi{
		Behavior: i.behavior.String(), Name: i.Name(), RuleCount: i.Count(),
		Type: i.Type().String(), VehicleType: i.VehicleType().String(), UpdatedAt: i.updatedAtSnapshot(),
	}, Loaded: true})
}

func (i *inlineProvider) MarshalJSON() ([]byte, error) {
	return json.Marshal(
		providerForApi{
			Behavior:    i.behavior.String(),
			Name:        i.Name(),
			RuleCount:   i.Count(),
			Type:        i.Type().String(),
			VehicleType: i.VehicleType().String(),
			UpdatedAt:   i.updatedAtSnapshot(),
			Payload:     i.payload,
		})
}

func NewInlineProvider(name string, behavior P.RuleBehavior, payload []string, parse common.ParseRuleFunc) P.RuleProvider {
	ip := &inlineProvider{
		baseProvider: baseProvider{
			behavior: behavior,
		},
		payload:  payload,
		name:     name,
		updateAt: time.Now(),
	}
	ip.strategy.Store(rulesParseInline(payload, newStrategy(behavior, parse)))

	wrapper := &InlineProvider{
		ip,
	}

	//runtime.SetFinalizer(wrapper, (*InlineProvider).Close)
	return wrapper
}
