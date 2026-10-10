package clash

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/config"
	"go.yaml.in/yaml/v3"
)

func dnsFieldsByKind(t *testing.T, kind string) []reflect.StructField {
	t.Helper()
	typ := reflect.TypeOf(config.RawDNS{})
	out := []reflect.StructField{}
	for i := range typ.NumField() {
		field := typ.Field(i)
		tag := strings.Split(field.Tag.Get("yaml"), ",")[0]
		if tag == "" || tag == "-" {
			continue
		}
		if dnsFieldClassification[tag] != kind {
			continue
		}
		isList := field.Type.Kind() == reflect.Slice && field.Type.Elem().Kind() == reflect.String
		isPolicy := strings.Contains(field.Type.String(), "OrderedMap")
		if isList || isPolicy {
			out = append(out, field)
		}
	}
	if len(out) == 0 {
		t.Fatalf("reflected no %q fields able to hold resolvers; the derivation is wrong, not the behaviour", kind)
	}
	return out
}

func normalizedDNSField(t *testing.T, dns map[string]any, fieldName string) any {
	t.Helper()
	document, err := yaml.Marshal(map[string]any{"dns": dns})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	raw, err := config.UnmarshalRawConfig(document)
	if err != nil {
		t.Fatalf("the document does not even parse upstream, so it tests nothing: %v\n%s", err, document)
	}
	normalizeRawConfigForApple(raw, nePolicy())
	value := reflect.ValueOf(raw.DNS).FieldByName(fieldName)
	if !value.IsValid() {
		t.Fatalf("RawDNS has no field %q; the reflection is wrong, not the behaviour", fieldName)
	}
	return value.Interface()
}

func neIncompatibleIn(t *testing.T, v any) []string {
	t.Helper()
	encoded, err := yaml.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var tree any
	if err := yaml.Unmarshal(encoded, &tree); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	hits := []string{}
	walkStrings(tree, func(s string) {
		if isNEIncompatibleNameserver(s) {
			hits = append(hits, s)
		}
	})
	return hits
}

func TestEveryResolverFieldActuallyStripsSystemAndDhcp(t *testing.T) {
	for _, field := range append(dnsFieldsByKind(t, "resolver"), dnsFieldsByKind(t, "bootstrap")...) {
		key := strings.Split(field.Tag.Get("yaml"), ",")[0]
		t.Run(key, func(t *testing.T) {
			var value any = []string{"system", "dhcp://en0", "223.5.5.5"}
			if strings.Contains(field.Type.String(), "OrderedMap") {
				value = map[string]any{"+.example.com": []string{"system", "dhcp://en0", "223.5.5.5"}}
			}
			dns := map[string]any{"enable": true, "nameserver": []string{"223.5.5.5"}}
			dns[key] = value
			if hits := neIncompatibleIn(t, normalizedDNSField(t, dns, field.Name)); len(hits) != 0 {
				t.Errorf("dns.%s is classified as holding resolvers but reached the core still carrying %v -- "+
					"add it to repairApplePacketTunnelDNS, or its classification is wrong", key, hits)
			}
		})
	}
}

func TestFieldsClassifiedNotAResolverReachTheCoreVerbatim(t *testing.T) {
	for _, field := range dnsFieldsByKind(t, "not-a-resolver") {
		key := strings.Split(field.Tag.Get("yaml"), ",")[0]
		t.Run(key, func(t *testing.T) {
			dns := map[string]any{
				"enable":        true,
				"nameserver":    []string{"223.5.5.5"},
				"enhanced-mode": "fake-ip",
			}
			dns[key] = []string{"system", "+.lan"}
			got := normalizedDNSField(t, dns, field.Name)
			hits := neIncompatibleIn(t, got)
			if len(hits) == 0 {
				t.Errorf("dns.%s is classified as NOT holding resolvers, which asserts a 'system' entry there is "+
					"an ordinary value and must reach the core untouched -- it did not (%v). Either the strip now "+
					"reaches this field, or the classification is wrong and dns.%s really is a resolver slot.",
					key, got, key)
			}
		})
	}
}
