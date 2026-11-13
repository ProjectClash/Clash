package clash

import (
	"io"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/adapter"
	"github.com/ProjectClash/Clash/listener"
)

func buildNode(entry map[string]any) error {
	proxy, err := adapter.ParseProxy(entry)
	if err == nil {
		if closer, ok := proxy.(io.Closer); ok {
			_ = closer.Close()
		}
	}
	return err
}

func buildListener(entry map[string]any) error {
	_, err := listener.ParseListener(entry)
	return err
}

func zeroMeansUnsetPins() map[string]func(value int) error {
	zeroTier := func(key string) func(int) error {
		return func(value int) error {
			return buildNode(map[string]any{"name": "z", "type": "zerotier", "network": "8056c2e21c000001", key: value})
		}
	}
	return map[string]func(int) error{
		"listeners[mieru].tcp-idle-timeout": func(value int) error {
			return buildListener(map[string]any{"name": "mieru-in", "type": "mieru", "port": "2999",
				"transport": "TCP", "users": map[string]any{"u": "p"}, "tcp-idle-timeout": value})
		},
		"proxies[zerotier].mtu":          zeroTier("mtu"),
		"proxies[zerotier].physical-mtu": zeroTier("physical-mtu"),
		"proxies[hysteria2].port": func(value int) error {
			return buildNode(map[string]any{"name": "h", "type": "hysteria2", "server": "192.0.2.1", "password": "p",
				"ports": "20000-30000", "port": value})
		},
		"proxies[mieru].port": func(value int) error {
			node := map[string]any{"name": "m", "type": "mieru", "server": "192.0.2.1", "transport": "TCP",
				"username": "u", "password": "p", "port": value}
			if value == 0 {
				node["port-range"] = "2999-3000"
			}
			return buildNode(node)
		},
	}
}

func TestFieldCatalogZeroMeansUnsetIsTheCoresCheck(t *testing.T) {
	setupConfigPipelineTest(t)
	fields, _ := catalogWire(t, RuntimeProfileIOSPacketTunnel)
	pins := zeroMeansUnsetPins()
	for path, field := range fields {
		if _, pinned := pins[path]; field["zeroMeansUnset"] != nil && !pinned {
			t.Errorf("%s is marked zeroMeansUnset and nothing here holds it to the core", path)
		}
	}
	if field := fields["listeners[mieru].tcp-idle-timeout"]; field["min"] != 60.0 || field["unit"] != "s" || field["kind"] != "number" {
		t.Errorf("listeners[mieru].tcp-idle-timeout: %v, want a number, min 60, unit s", field)
	}
	for path, build := range pins {
		field := fields[path]
		if field["zeroMeansUnset"] != true {
			t.Errorf("%s: zeroMeansUnset %v, want true: %v", path, field["zeroMeansUnset"], field)
		}
		minimum, _ := field["min"].(float64)
		if field["kind"] != "number" || minimum <= 0 {
			t.Errorf("%s: %v; zeroMeansUnset is for a number whose min is above 0", path, field)
			continue
		}
		if err := build(0); err != nil {
			if strings.Contains(err.Error(), "no_zerotier") {
				t.Logf("%s: not built into this core (%v)", path, err)
				continue
			}
			t.Errorf("%s: 0 is the key unwritten, and the core refuses it: %v", path, err)
		}
		if under := int(minimum) - 1; under > 0 {
			if err := build(under); err == nil {
				t.Errorf("%s: %d is under min %v, and the core accepts it", path, under, minimum)
			}
		}
		if err := build(int(minimum)); err != nil {
			t.Errorf("%s: min %v is refused: %v", path, minimum, err)
		}
	}
}

type requiredOneOfPin struct {
	members    []string
	entry      map[string]any
	written    map[string]any
	empty      map[string]any
	refusal    string
	refusedToo []requiredOneOfRefusal
	build      func(entry map[string]any) error
}

type requiredOneOfRefusal struct {
	values  map[string]any
	refusal string
}

func requiredOneOfPins() map[string]requiredOneOfPin {
	return map[string]requiredOneOfPin{
		"listeners[shadowsocks]": {
			members: []string{"password", "users"},
			entry:   map[string]any{"name": "ss-in", "type": "shadowsocks", "port": "7891", "cipher": "aes-128-gcm"},
			written: map[string]any{"password": "p", "users": map[string]any{"u": "p"}},
			empty:   map[string]any{"password": "", "users": map[string]any{}},
			refusal: "shadowsocks: missing password",
			build:   buildListener,
		},
		"proxies[mieru]": {
			members: []string{"port", "port-range"},
			entry:   map[string]any{"name": "m", "type": "mieru", "server": "192.0.2.1", "transport": "TCP", "username": "u", "password": "p"},
			written: map[string]any{"port": 2999, "port-range": "2999-3000"},
			empty:   map[string]any{"port": 0, "port-range": ""},
			refusal: "either port or port-range must be set",
			refusedToo: []requiredOneOfRefusal{{map[string]any{"port": 2999, "port-range": "2999-3000"},
				"port and port-range cannot be set at the same time"}},
			build: buildNode,
		},
		"proxies[hysteria2]": {
			members:    []string{"port", "ports"},
			entry:      map[string]any{"name": "h", "type": "hysteria2", "server": "192.0.2.1", "password": "p"},
			written:    map[string]any{"port": 443, "ports": "443-444"},
			empty:      map[string]any{"port": 0, "ports": ""},
			refusal:    "invalid port",
			refusedToo: []requiredOneOfRefusal{{map[string]any{"ports": "*"}, "invalid port"}},
			build:      buildNode,
		},
	}
}

func TestFieldCatalogRequiredOneOfIsTheCoresCheck(t *testing.T) {
	fields, _ := catalogWire(t, RuntimeProfileIOSPacketTunnel)
	pins := requiredOneOfPins()
	for path, field := range fields {
		raw, listed := field["requiredOneOf"]
		if !listed {
			continue
		}
		cut := strings.LastIndex(path, ".")
		entry, key := path[:cut], path[cut+1:]
		pin, pinned := pins[entry]
		if !pinned {
			t.Errorf("%s lists requiredOneOf %v and nothing here holds it to the core", path, raw)
			continue
		}
		if members, _ := raw.([]any); !slices.Contains(members, any(key)) {
			t.Errorf("%s: requiredOneOf %v does not name the key itself", path, raw)
		}
		if len(pin.members) == 0 || !reflect.DeepEqual(raw, membersOf(pin.members)) {
			t.Errorf("%s: requiredOneOf %v; its group is %v", path, raw, pin.members)
		}
	}
	for entry, pin := range pins {
		for _, member := range pin.members {
			field, ok := fields[entry+"."+member]
			if !ok {
				t.Errorf("%s: %s is not a key of the entry", entry, member)
				continue
			}
			if !reflect.DeepEqual(field["requiredOneOf"], membersOf(pin.members)) {
				t.Errorf("%s.%s: requiredOneOf %v, want %v", entry, member, field["requiredOneOf"], pin.members)
			}
			if field["required"] == true {
				t.Errorf("%s.%s is required on its own as well", entry, member)
			}
		}
		with := func(values map[string]any, members ...string) map[string]any {
			built := map[string]any{}
			for k, v := range pin.entry {
				built[k] = v
			}
			for _, member := range members {
				built[member] = values[member]
			}
			return built
		}
		if err := pin.build(with(nil)); err == nil || !strings.Contains(err.Error(), pin.refusal) {
			t.Errorf("%s with none of %v: %v, want the core's %q", entry, pin.members, err, pin.refusal)
		}
		if err := pin.build(with(pin.empty, pin.members...)); err == nil || !strings.Contains(err.Error(), pin.refusal) {
			t.Errorf("%s with each of %v empty: %v, want the core's %q", entry, pin.members, err, pin.refusal)
		}
		for _, member := range pin.members {
			if err := pin.build(with(pin.written, member)); err != nil {
				t.Errorf("%s with %s alone: %v", entry, member, err)
			}
		}
		for _, too := range pin.refusedToo {
			members := make([]string, 0, len(too.values))
			for member := range too.values {
				members = append(members, member)
			}
			if err := pin.build(with(too.values, members...)); err == nil || !strings.Contains(err.Error(), too.refusal) {
				t.Errorf("%s with %v: %v, want the core's %q", entry, too.values, err, too.refusal)
			}
		}
	}
}

func membersOf(members []string) []any {
	out := make([]any, 0, len(members))
	for _, member := range members {
		out = append(out, member)
	}
	return out
}
