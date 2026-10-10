package clash

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"github.com/ProjectClash/Clash/component/geodata"
	"github.com/ProjectClash/Clash/config"
)

func UpstreamScalarDefaultsJSON() (*StringBox, error) {
	appParseMu.Lock()
	defer appParseMu.Unlock()
	rendered, err := renderUpstreamDefaults()
	if err != nil {
		return nil, bridgeSafeError(fmt.Errorf("clash: render upstream defaults: %w", err))
	}
	return WrapString(rendered), nil
}

func collectScalarDefaults(value reflect.Value, prefix string, depth int, into map[string]any) {
	if depth > 3 {
		return
	}
	valueType := value.Type()
	for i := 0; i < valueType.NumField(); i++ {
		field := valueType.Field(i)
		if !field.IsExported() {
			continue
		}
		tag := strings.Split(field.Tag.Get("yaml"), ",")[0]
		if tag == "" || tag == "-" {
			continue
		}
		key := tag
		if prefix != "" {
			key = prefix + "." + tag
		}
		item := value.Field(i)
		if item.Kind() != reflect.Struct && item.CanInterface() {
			if stringer, ok := item.Interface().(fmt.Stringer); ok {
				into[key] = stringer.String()
				continue
			}
		}
		switch item.Kind() {
		case reflect.Bool:
			into[key] = item.Bool()
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			into[key] = item.Int()
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			into[key] = item.Uint()
		case reflect.String:
			into[key] = item.String()
		case reflect.Slice:
			elements := []string{}
			renderable := true
			for j := 0; j < item.Len(); j++ {
				element := item.Index(j)
				switch {
				case element.Kind() == reflect.String:
					elements = append(elements, element.String())
				case element.CanInterface():
					if stringer, ok := element.Interface().(fmt.Stringer); ok {
						elements = append(elements, stringer.String())
					} else {
						renderable = false
					}
				default:
					renderable = false
				}
				if !renderable {
					break
				}
			}
			if renderable && (item.Type().Elem().Kind() == reflect.String ||
				item.Type().Elem().Implements(reflect.TypeOf((*fmt.Stringer)(nil)).Elem())) {
				into[key] = elements
			}
		case reflect.Struct:
			collectScalarDefaults(item, key, depth+1, into)
		}
	}
}

func renderUpstreamDefaults() (string, error) {
	previousGeodataMode := geodata.GeodataMode()
	geodata.SetGeodataMode(false)
	defer geodata.SetGeodataMode(previousGeodataMode)

	defaults := map[string]any{}
	raw := config.DefaultRawConfig()
	collectScalarDefaults(reflect.ValueOf(raw).Elem(), "", 1, defaults)

	keys := make([]string, 0, len(defaults))
	for key := range defaults {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	ordered := make([]map[string]any, 0, len(keys))
	for _, key := range keys {
		ordered = append(ordered, map[string]any{"key": key, "default": defaults[key]})
	}

	encoded, err := json.MarshalIndent(map[string]any{
		"schemaVersion": 1,
		"note": "mihomo's own DefaultRawConfig(), read by reflection over the yaml tags. What " +
			"the core does when neither the profile nor an override says anything. Scalars and " +
			"string lists, three levels deep; an empty list is recorded as []. Regenerate with CLASH_UPDATE_GOLDEN=1 go test ./bind/clash " +
			"-run TestUpstreamScalarDefaults",
		"defaults": ordered,
	}, "", "  ")
	if err != nil {
		return "", err
	}
	return string(encoded) + "\n", nil
}
