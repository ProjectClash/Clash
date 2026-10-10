package clash

import (
	"bytes"
	"compress/gzip"
	_ "embed"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"

	C "github.com/ProjectClash/Clash/constant"
	"github.com/ProjectClash/Clash/constant/sniffer"
	"github.com/ProjectClash/Clash/log"
	sscore "github.com/ProjectClash/Clash/transport/shadowsocks/core"
	"github.com/ProjectClash/Clash/transport/tlsmirror"
	T "github.com/ProjectClash/Clash/tunnel"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/metacubex/mipstack"
	ssaead "github.com/metacubex/sing-shadowsocks/shadowaead"
	ssaead2022 "github.com/metacubex/sing-shadowsocks/shadowaead_2022"
	ssaead2 "github.com/metacubex/sing-shadowsocks2/shadowaead"
	ssaead2022v2 "github.com/metacubex/sing-shadowsocks2/shadowaead_2022"
	"github.com/metacubex/sing-shadowsocks2/shadowstream"
	"github.com/metacubex/ssh"
)

// fieldAnnotationTable is what reflection cannot tell about a key (field_catalog.go), one row
// per key or pattern: the runtime columns of the
// table surveyed against the core's code (2026-09-26) that also holds every row's source and
// notes for the document. TestFieldAnnotationRuntimeTableIsTheDocumentsProjection keeps the two
// the same (CLASH_WRITE_FIELD_TABLE=1 rewrites this one). Columns: path, kind, values,
// valueSource, ordered, min, max, unit, default, format, refers, unknownValue, caseInsensitive,
// extra (a key reflection cannot see, which the row adds).
//
// A value set is read from the core wherever it keeps one: valueSource names an entry of
// fieldValueSources, and the row's own values are only the survey's snapshot. A set upstream
// keeps in switch cases is the row's values, and a test holds every one of them to the file the
// full table cites.
//
// It is embedded gzipped (field_annotations_runtime.tsv.gz, about a seventh of the text) and
// unpacked the first time the catalog is built: the packet tunnel links the same framework and
// never builds the catalog (lazy_init.go).
//
//go:embed field_annotations_runtime.tsv.gz
var fieldAnnotationTableGzip []byte

func fieldAnnotationTableText() string {
	reader, err := gzip.NewReader(bytes.NewReader(fieldAnnotationTableGzip))
	if err != nil {
		panic("field_annotations_runtime.tsv.gz: " + err.Error())
	}
	text, err := io.ReadAll(reader)
	if err != nil {
		panic("field_annotations_runtime.tsv.gz: " + err.Error())
	}
	return string(text)
}

var (
	fieldValueSourcesOnce sync.Once
	fieldValueSourceMap   map[string]func(snapshot []string) []string
)

func fieldValueSources() map[string]func(snapshot []string) []string {
	fieldValueSourcesOnce.Do(func() { fieldValueSourceMap = fieldValueSourceTable() })
	return fieldValueSourceMap
}

func fieldValueSourceTable() map[string]func(snapshot []string) []string {
	return map[string]func(snapshot []string) []string{
		"constant.StackTypeMapping":            whole(fieldKeysOf(C.StackTypeMapping)),
		"mipstack.AvailableCongestionControls": whole(mipstack.AvailableCongestionControls),
		"tunnel.ModeMapping":                   whole(fieldKeysOf(T.ModeMapping)),
		"log.LogLevelMapping":                  whole(fieldKeysOf(log.LogLevelMapping)),
		"constant.DNSModeMapping":              whole(fieldKeysOf(C.DNSModeMapping)),
		"constant.FilterModeMapping":           whole(fieldKeysOf(C.FilterModeMapping)),
		"constant/sniffer.List": whole(func() []string {
			names := make([]string, 0, len(sniffer.List))
			for _, protocol := range sniffer.List {
				names = append(names, protocol.String())
			}
			return names
		}),
		"github.com/enfein/mieru/v3/pkg/appctl/appctlpb.MultiplexingLevel_value": whole(fieldKeysOf(appctlpb.MultiplexingLevel_value)),
		"github.com/enfein/mieru/v3/pkg/appctl/appctlpb.HandshakeMode_value":     whole(fieldKeysOf(appctlpb.HandshakeMode_value)),
		"ssh.SupportedAlgorithms": union(func() []string {
			return concat(ssh.SupportedAlgorithms().HostKeys, ssh.InsecureAlgorithms().HostKeys)
		}),
		"sing-shadowsocks2/shadowaead.MethodList": union(func() []string {
			return concat(ssaead2.MethodList, ssaead2022v2.MethodList, shadowstream.MethodList, []string{"none"})
		}),
		"sing-shadowsocks/shadowaead.List": union(func() []string {
			return concat(ssaead.List, ssaead2022.List, []string{"none"}, lower(sscore.ListCipher()))
		}),
		"transport/shadowsocks/core.ListCipher": union(func() []string { return lower(sscore.ListCipher()) }),
		"transport/tlsmirror.RecommendedExplicitNonceCipherSuites": union(func() []string {
			out := make([]string, 0, len(tlsmirror.RecommendedExplicitNonceCipherSuites))
			for _, suite := range tlsmirror.RecommendedExplicitNonceCipherSuites {
				out = append(out, strconv.Itoa(int(suite)))
			}
			return out
		}),
	}
}

func whole(read func() []string) func([]string) []string {
	return func([]string) []string { return read() }
}

func union(read func() []string) func([]string) []string {
	return func(snapshot []string) []string {
		out := append([]string(nil), snapshot...)
		have := map[string]bool{}
		for _, value := range snapshot {
			have[strings.ToLower(value)] = true
		}
		for _, value := range read() {
			if !have[strings.ToLower(value)] {
				have[strings.ToLower(value)] = true
				out = append(out, value)
			}
		}
		return out
	}
}

func concat(lists ...[]string) []string {
	var out []string
	for _, list := range lists {
		out = append(out, list...)
	}
	return out
}

func lower(values []string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.ToLower(value); !strings.HasPrefix(value, "aead_") {
			out = append(out, value)
		}
	}
	return out
}

func fieldValueSourceKey(valuesSource string) string {
	for _, part := range strings.Split(valuesSource, ";") {
		part = strings.TrimSpace(part)
		if !strings.HasPrefix(part, "go:") {
			continue
		}
		key := strings.TrimPrefix(part, "go:")
		for _, prefix := range []string{"github.com/ProjectClash/Clash/", "github.com/metacubex/"} {
			key = strings.TrimPrefix(key, prefix)
		}
		if cut := strings.IndexAny(key, " ("); cut >= 0 {
			key = key[:cut]
		}
		return key
	}
	return ""
}

var (
	fieldAnnotationsOnce    sync.Once
	fieldAnnotationList     []fieldAnnotation
	fieldAnnotationExact    map[string]int
	fieldAnnotationPatterns []int
)

func fieldAnnotations() []fieldAnnotation {
	fieldAnnotationsOnce.Do(func() {
		for i, line := range strings.Split(fieldAnnotationTableText(), "\n") {
			if i == 0 || strings.TrimSpace(line) == "" {
				continue
			}
			columns := strings.Split(line, "\t")
			for len(columns) < 14 {
				columns = append(columns, "")
			}
			annotation := fieldAnnotation{
				Pattern:         strings.NewReplacer("[common]", "[*]").Replace(columns[0]),
				Kind:            columns[1],
				Ordered:         columns[4] == "true",
				Min:             parseFieldNumber(columns[5]),
				Max:             parseFieldNumber(columns[6]),
				Unit:            columns[7],
				Default:         columns[8],
				Format:          columns[9],
				UnknownValue:    columns[11],
				CaseInsensitive: columns[12] == "true",
				Extra:           columns[13] == "true",
			}
			snapshot := splitFieldList(columns[2])
			if len(snapshot) > 0 {
				annotation.Values = func() []string { return append([]string(nil), snapshot...) }
			}
			if key := columns[3]; key != "" {
				if read, ok := fieldValueSources()[key]; ok {
					annotation.Values = func() []string { return read(snapshot) }
				}
			}
			if columns[10] != "" {
				annotation.Refers = expandFieldRefers(splitFieldList(columns[10]))
			}
			fieldAnnotationList = append(fieldAnnotationList, annotation)
		}
		sort.SliceStable(fieldAnnotationList, func(i, j int) bool {
			return !strings.Contains(fieldAnnotationList[i].Pattern, "[*]") && strings.Contains(fieldAnnotationList[j].Pattern, "[*]")
		})
		fieldAnnotationExact = map[string]int{}
		for i, annotation := range fieldAnnotationList {
			if isFieldPattern(annotation.Pattern) {
				fieldPatternRegexp(annotation.Pattern)
				fieldAnnotationPatterns = append(fieldAnnotationPatterns, i)
			} else if _, seen := fieldAnnotationExact[annotation.Pattern]; !seen {
				fieldAnnotationExact[annotation.Pattern] = i
			}
		}
	})
	return fieldAnnotationList
}

func firstFieldAnnotation(path string) *fieldAnnotation {
	list := fieldAnnotations()
	first := len(list)
	if i, ok := fieldAnnotationExact[path]; ok {
		first = i
	}
	for _, i := range fieldAnnotationPatterns {
		if i >= first {
			break
		}
		if list[i].matches(path) {
			first = i
			break
		}
	}
	if first == len(list) {
		return nil
	}
	return &list[first]
}

func splitFieldList(cell string) []string {
	var out []string
	for _, value := range strings.Split(cell, ",") {
		if value = strings.TrimSpace(value); value != "" {
			out = append(out, value)
		}
	}
	return out
}

func parseFieldNumber(cell string) *float64 {
	if cell == "" {
		return nil
	}
	value, err := strconv.ParseFloat(cell, 64)
	if err != nil {
		return nil
	}
	return &value
}

func expandFieldRefers(refers []string) []string {
	var out []string
	for _, refer := range refers {
		if refer == "policy" {
			out = append(out, "proxy", "group", "builtin")
			continue
		}
		out = append(out, refer)
	}
	return out
}
