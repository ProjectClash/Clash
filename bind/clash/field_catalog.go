package clash

import (
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/ProjectClash/Clash/adapter/outbound"
	"github.com/ProjectClash/Clash/adapter/outboundgroup"
	proxyprovider "github.com/ProjectClash/Clash/adapter/provider"
	"github.com/ProjectClash/Clash/config"
	IN "github.com/ProjectClash/Clash/listener/inbound"
	ruleprovider "github.com/ProjectClash/Clash/rules/provider"
)

type syntaxField struct {
	Path              string                   `json:"path"`
	Kind              string                   `json:"kind"`
	Values            []string                 `json:"values,omitempty"`
	Separator         string                   `json:"separator,omitempty"`
	CaseInsensitive   bool                     `json:"caseInsensitive,omitempty"`
	Ordered           bool                     `json:"ordered,omitempty"`
	Min               *float64                 `json:"min,omitempty"`
	Max               *float64                 `json:"max,omitempty"`
	Unit              string                   `json:"unit,omitempty"`
	Default           string                   `json:"default,omitempty"`
	Format            string                   `json:"format,omitempty"`
	Refers            []string                 `json:"refers,omitempty"`
	UnknownValue      string                   `json:"unknownValue,omitempty"`
	PlatformDecided   bool                     `json:"platformDecided,omitempty"`
	PlatformDecision  *syntaxPlatformDecision  `json:"platformDecision,omitempty"`
	UnavailableValues []syntaxUnavailableValue `json:"unavailableValues,omitempty"`
	Required          bool                     `json:"required,omitempty"`
	Key               *syntaxValue             `json:"key,omitempty"`
	Value             *syntaxValue             `json:"value,omitempty"`
	Source            string                   `json:"-"`
	ValuesSource      string                   `json:"-"`
	Note              string                   `json:"-"`
	ReflectedKind     string                   `json:"-"`
}

type syntaxUnavailableValue struct {
	Value       string `json:"value"`
	Reason      string `json:"reason"`
	Alternative string `json:"alternative,omitempty"`
}

type syntaxValue struct {
	Kind            string   `json:"kind"`
	Values          []string `json:"values,omitempty"`
	CaseInsensitive bool     `json:"caseInsensitive,omitempty"`
	Format          string   `json:"format,omitempty"`
	Refers          []string `json:"refers,omitempty"`
}

type fieldAnnotation struct {
	Pattern         string
	Kind            string
	Values          func() []string
	CaseInsensitive bool
	Ordered         bool
	Min, Max        *float64
	Unit            string
	Default         string
	Format          string
	Refers          []string
	UnknownValue    string
	Extra           bool
	Key, Value      *syntaxValue
	Source          string
	ValuesSource    string
}

func number(v float64) *float64 { return &v }

func fieldKeysOf[V any](m map[string]V) func() []string {
	return func() []string {
		keys := make([]string, 0, len(m))
		for key := range m {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		return keys
	}
}

func fixed(values ...string) func() []string {
	return func() []string { return append([]string(nil), values...) }
}

type fieldTypeEntry struct {
	Name   string
	Option any
}

func fieldProxyTypes() []fieldTypeEntry {
	return []fieldTypeEntry{
		{"ss", outbound.ShadowSocksOption{}}, {"ssr", outbound.ShadowSocksROption{}},
		{"socks5", outbound.Socks5Option{}}, {"http", outbound.HttpOption{}},
		{"vmess", outbound.VmessOption{}}, {"vless", outbound.VlessOption{}},
		{"snell", outbound.SnellOption{}}, {"trojan", outbound.TrojanOption{}},
		{"hysteria", outbound.HysteriaOption{}}, {"hysteria2", outbound.Hysteria2Option{}},
		{"wireguard", outbound.WireGuardOption{}}, {"tuic", outbound.TuicOption{}},
		{"shadowquic", outbound.ShadowQuicOption{}}, {"gost-relay", outbound.GostRelayOption{}},
		{"direct", outbound.DirectOption{}}, {"dns", outbound.DnsOption{}},
		{"reject", outbound.RejectOption{}}, {"rematch", outbound.RematchOption{}},
		{"ssh", outbound.SshOption{}}, {"mieru", outbound.MieruOption{}},
		{"anytls", outbound.AnyTLSOption{}}, {"sudoku", outbound.SudokuOption{}},
		{"masque", outbound.MasqueOption{}}, {"trusttunnel", outbound.TrustTunnelOption{}},
		{"openvpn", outbound.OpenVPNOption{}}, {"tailscale", outbound.TailscaleOption{}},
		{"zerotier", outbound.ZeroTierOption{}}, {"easytier", outbound.EasyTierOption{}},
	}
}

func fieldListenerTypes() []fieldTypeEntry {
	return []fieldTypeEntry{
		{"socks", IN.SocksOption{}}, {"http", IN.HTTPOption{}}, {"tproxy", IN.TProxyOption{}},
		{"redir", IN.RedirOption{}}, {"mixed", IN.MixedOption{}}, {"tunnel", IN.TunnelOption{}},
		{"tun", IN.TunOption{}}, {"shadowsocks", IN.ShadowSocksOption{}}, {"snell", IN.SnellOption{}},
		{"vmess", IN.VmessOption{}}, {"vless", IN.VlessOption{}}, {"trojan", IN.TrojanOption{}},
		{"hysteria2", IN.Hysteria2Option{}}, {"hysteria2-realm", IN.DefaultHysteria2RealmServerOption()},
		{"tuic", IN.TuicOption{}},
		{"shadowquic", IN.ShadowQuicOption{}}, {"anytls", IN.AnyTLSOption{}},
		{"mieru", IN.MieruOption{}}, {"sudoku", IN.SudokuOption{}},
		{"trusttunnel", IN.TrustTunnelOption{}},
	}
}

func fieldGroupTypes() []fieldTypeEntry {
	return []fieldTypeEntry{
		{"select", outboundgroup.SelectorOption{}}, {"url-test", outboundgroup.URLTestOption{}},
		{"fallback", outboundgroup.FallbackOption{}}, {"load-balance", outboundgroup.LoadBalanceOption{}},
	}
}

var (
	fieldListOnce  sync.Once
	fieldListCache []syntaxField
)

func fieldList() []syntaxField {
	fieldListOnce.Do(func() { fieldListCache = buildFieldCatalog() })
	return append([]syntaxField(nil), fieldListCache...)
}

func buildFieldCatalog() []syntaxField {
	var fields []syntaxField
	seen := map[string]bool{}
	add := func(field syntaxField) {
		if !seen[field.Path] {
			seen[field.Path] = true
			fields = append(fields, field)
		}
	}
	walkFields(reflect.TypeOf(config.RawConfig{}), "yaml", "", add)
	proxyTypes := make([]string, 0, len(fieldProxyTypes()))
	for _, t := range fieldProxyTypes() {
		proxyTypes = append(proxyTypes, t.Name)
		prefix := "proxies[" + t.Name + "]."
		add(syntaxField{Path: prefix + "type", Kind: "select", Values: []string{t.Name}})
		walkFields(reflect.TypeOf(t.Option), "proxy", prefix, add)
		add(syntaxField{Path: prefix + "smux", Kind: "object"})
		walkFields(reflect.TypeOf(outbound.SingMuxOption{}), "proxy", prefix+"smux.", add)
	}
	listenerTypes := make([]string, 0, len(fieldListenerTypes()))
	for _, t := range fieldListenerTypes() {
		listenerTypes = append(listenerTypes, t.Name)
		prefix := "listeners[" + t.Name + "]."
		add(syntaxField{Path: prefix + "type", Kind: "select", Values: []string{t.Name}})
		walkFields(reflect.TypeOf(t.Option), "inbound", prefix, add)
	}
	groupTypes := make([]string, 0, len(fieldGroupTypes()))
	for _, t := range fieldGroupTypes() {
		groupTypes = append(groupTypes, t.Name)
		prefix := "proxy-groups[" + t.Name + "]."
		walkFields(reflect.TypeOf(outboundgroup.GroupCommonOption{}), "group", prefix, add)
		walkFields(reflect.TypeOf(t.Option), "group", prefix, add)
	}
	walkFields(proxyprovider.ClashProviderSchemaType(), "provider", "proxy-providers.*.", add)
	walkFields(ruleprovider.ClashRuleProviderSchemaType(), "provider", "rule-providers.*.", add)
	annotations := fieldAnnotations()
	maps := map[string]bool{}
	for _, field := range fields {
		if field.Kind == "map" {
			maps[field.Path] = true
		}
	}
	insideMap := func(pattern string) bool {
		for path := range maps {
			if strings.HasPrefix(pattern, path+"[") || strings.HasPrefix(pattern, path+".") && !strings.HasPrefix(pattern, path+".*") {
				return true
			}
		}
		return false
	}
	for _, annotation := range annotations {
		exact := !strings.Contains(annotation.Pattern, "[*]") && !strings.HasSuffix(annotation.Pattern, ".*")
		if !seen[annotation.Pattern] && exact && (annotation.Extra || insideMap(annotation.Pattern)) {
			add(syntaxField{Path: annotation.Pattern, Kind: annotation.Kind})
		}
	}
	typeSets := map[string][]string{"proxies": proxyTypes, "listeners": listenerTypes, "proxy-groups": groupTypes}
	for i := range fields {
		annotateField(&fields[i], typeSets)
		if fields[i].Kind == "map" {
			describeMap(&fields[i], annotations)
		}
	}
	markPlatformDecided(fields)
	return fields
}

func describeMap(field *syntaxField, annotations []fieldAnnotation) {
	if field.Key == nil {
		field.Key = &syntaxValue{Kind: "text"}
	}
	if field.Value == nil {
		field.Value = &syntaxValue{Kind: "text"}
	}
	if len(field.Values) > 0 {
		field.Key = &syntaxValue{Kind: "select", Values: field.Values, CaseInsensitive: field.CaseInsensitive}
		field.Values = nil
	}
	if format, ok := fieldMapKeyFormat(field.Path); ok {
		field.Key.Format = format
	}
	for _, annotation := range annotations {
		if annotation.Pattern != field.Path+".*" {
			continue
		}
		value := &syntaxValue{Kind: annotation.Kind, Format: annotation.Format, Refers: annotation.Refers, CaseInsensitive: annotation.CaseInsensitive}
		if annotation.Values != nil {
			value.Values = annotation.Values()
		}
		field.Value = value
		return
	}
}

func fieldMapKeyFormat(path string) (string, bool) {
	switch path {
	case "hosts", "dns.nameserver-policy", "dns.proxy-server-nameserver-policy":
		return "domain", true
	case "tuic-server.users":
		return "uuid", true
	}
	return "", false
}

func walkFields(t reflect.Type, tag, prefix string, add func(syntaxField)) {
	walkFieldsDepth(t, tag, prefix, add, 0)
}

func walkFieldsDepth(t reflect.Type, tag, prefix string, add func(syntaxField), depth int) {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || depth > 6 {
		return
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := strings.Split(f.Tag.Get(tag), ",")[0]
		if f.Anonymous && name == "" {
			walkFieldsDepth(f.Type, tag, prefix, add, depth)
			continue
		}
		if name == "" || name == "-" || !f.IsExported() || clashPrivateKey(name) {
			continue
		}
		path := prefix + name
		ft := f.Type
		for ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		field := syntaxField{Path: path, Kind: kindOfType(ft)}
		if tag != "yaml" && !strings.Contains(f.Tag.Get(tag), "omitempty") {
			field.Required = true
		}
		if field.Kind == "map" {
			field.Key = &syntaxValue{Kind: "text"}
			field.Value = &syntaxValue{Kind: kindOfType(elemOf(ft))}
		}
		if field.Kind == "number" && isUnsigned(ft) {
			field.Min = number(0)
		}
		if ft.Kind() == reflect.Uint16 {
			field.Max = number(65535)
		}
		add(field)
		switch field.Kind {
		case "object":
			walkFieldsDepth(ft, tag, path+".", add, depth+1)
		case "objectList":
			walkFieldsDepth(elemOf(ft), tag, path+"[].", add, depth+1)
		case "map":
			if e := elemOf(ft); e.Kind() == reflect.Struct && !opaqueStruct(e) {
				walkFieldsDepth(e, tag, path+".*.", add, depth+1)
			}
		}
	}
}

func elemOf(t reflect.Type) reflect.Type {
	e := t.Elem()
	for e.Kind() == reflect.Pointer {
		e = e.Elem()
	}
	return e
}

func opaqueStruct(t reflect.Type) bool {
	name := t.String()
	return strings.HasPrefix(name, "time.") || strings.HasPrefix(name, "netip.") ||
		strings.Contains(name, "orderedmap") || strings.Contains(name, "regexp")
}

func isUnsigned(t reflect.Type) bool {
	switch t.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return true
	}
	return false
}

func kindOfType(t reflect.Type) string {
	switch t.Kind() {
	case reflect.Bool:
		return "toggle"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return "number"
	case reflect.String:
		return "text"
	case reflect.Slice, reflect.Array:
		e := elemOf(t)
		switch {
		case e.Kind() == reflect.Struct && !opaqueStruct(e):
			return "objectList"
		case e.Kind() == reflect.Map || e.Kind() == reflect.Interface:
			return "objectList"
		}
		return "textList"
	case reflect.Map:
		return "map"
	case reflect.Struct:
		if opaqueStruct(t) {
			return "text"
		}
		return "object"
	}
	return "text"
}

func annotateField(field *syntaxField, typeSets map[string][]string) {
	for _, list := range []string{"proxies", "listeners", "proxy-groups"} {
		if strings.HasPrefix(field.Path, list+"[") && strings.HasSuffix(field.Path, "].type") && strings.Count(field.Path, ".") == 1 {
			field.Kind, field.Values = "select", typeSets[list]
			field.UnknownValue = "refused"
		}
	}
	reflected := field.Kind
	field.ReflectedKind = reflected
	if annotation := firstFieldAnnotation(field.Path); annotation != nil {
		if annotation.Kind != "" {
			field.Kind = annotation.Kind
		}
		if annotation.Values != nil {
			field.Values = annotation.Values()
		}
		field.CaseInsensitive = field.CaseInsensitive || annotation.CaseInsensitive
		field.Ordered = field.Ordered || annotation.Ordered
		if annotation.Min != nil {
			field.Min = annotation.Min
		}
		if annotation.Max != nil {
			field.Max = annotation.Max
		}
		for _, s := range []struct {
			to   *string
			from string
		}{
			{&field.Unit, annotation.Unit}, {&field.Default, annotation.Default}, {&field.Format, annotation.Format},
			{&field.UnknownValue, annotation.UnknownValue}, {&field.Source, annotation.Source}, {&field.ValuesSource, annotation.ValuesSource},
		} {
			if s.from != "" {
				*s.to = s.from
			}
		}
		if annotation.Refers != nil {
			field.Refers = annotation.Refers
		}
		if annotation.Key != nil {
			field.Key = annotation.Key
		}
		if annotation.Value != nil {
			field.Value = annotation.Value
		}
	}
	if field.Kind == "multiSelect" && reflected == "text" {
		field.Separator = fieldJoinedChoices(fieldJoinedChoicesKey(field.Path))
	}
}

func fieldJoinedChoices(key string) string {
	switch key {
	case "proxy-groups[*].exclude-type":
		return "|"
	case "proxy-providers.*.exclude-type":
		return "|"
	}
	return ""
}

func fieldJoinedChoicesKey(path string) string {
	if strings.HasPrefix(path, "proxy-groups[") {
		if end := strings.Index(path, "]"); end > 0 {
			return "proxy-groups[*]" + path[end+1:]
		}
	}
	return path
}

func isFieldPattern(pattern string) bool {
	return strings.HasPrefix(pattern, "**.") || strings.Contains(pattern, "[*]")
}

var fieldPatternRegexps sync.Map

func fieldPatternRegexp(pattern string) *regexp.Regexp {
	if re, ok := fieldPatternRegexps.Load(pattern); ok {
		return re.(*regexp.Regexp)
	}
	body, prefix := pattern, "^"
	if strings.HasPrefix(body, "**.") {
		prefix, body = "^(?:.*\\.)?", strings.TrimPrefix(body, "**.")
	}
	quoted := regexp.QuoteMeta(body)
	quoted = strings.ReplaceAll(quoted, `\[\*\]`, `\[[^\]]+\]`)
	re, _ := fieldPatternRegexps.LoadOrStore(pattern, regexp.MustCompile(prefix+quoted+"$"))
	return re.(*regexp.Regexp)
}

func (a fieldAnnotation) matches(path string) bool {
	if !isFieldPattern(a.Pattern) {
		return a.Pattern == path
	}
	return fieldPatternRegexp(a.Pattern).MatchString(path)
}

func markPlatformDecided(fields []syntaxField) {
	decided := map[string]bool{}
	for _, rule := range deviationRules {
		if !rule.defaultOnly && rule.honouredBy == "" && !rule.ruleScan {
			decided[rule.field] = true
		}
	}
	for i := range fields {
		if decided[fields[i].Path] {
			fields[i].PlatformDecided = true
		}
	}
}
