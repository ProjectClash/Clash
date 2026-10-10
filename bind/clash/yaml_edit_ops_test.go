package clash

import "testing"

func TestEditYAMLInsertBefore(t *testing.T) {
	original := "dns:\n  nameserver-policy:\n    '+.a.com': 1.1.1.1   # a\n    # b's comment\n    '+.b.com': 8.8.8.8\nmode: rule\n"
	mustEdit(t, original, `["dns","nameserver-policy","+.b.com"]`, "insertBefore", `{"key":"+.c.com","value":"9.9.9.9"}`,
		"dns:\n  nameserver-policy:\n    '+.a.com': 1.1.1.1   # a\n    # b's comment\n    +.c.com: 9.9.9.9\n    '+.b.com': 8.8.8.8\nmode: rule\n")
	mustEdit(t, original, `["mode"]`, "insertBefore", `{"key":"log-level","value":"info"}`,
		"dns:\n  nameserver-policy:\n    '+.a.com': 1.1.1.1   # a\n    # b's comment\n    '+.b.com': 8.8.8.8\nlog-level: info\nmode: rule\n")
	mustEdit(t, original, `["mode"]`, "insertBefore", `{"key":"tun","value":{"enable":true}}`,
		"dns:\n  nameserver-policy:\n    '+.a.com': 1.1.1.1   # a\n    # b's comment\n    '+.b.com': 8.8.8.8\ntun:\n  enable: true\nmode: rule\n")
	for _, c := range []struct{ path, value, code string }{
		{`["mode"]`, `{"key":"dns","value":1}`, "invalidRequest"},
		{`["nope"]`, `{"key":"x","value":1}`, "notFound"},
		{`["mode"]`, `{"key":"x"}`, "invalidRequest"},
		{`["mode"]`, `{"key":"x","value":1,"extra":2}`, "invalidRequest"},
		{`["mode"]`, `["x",1]`, "invalidRequest"},
	} {
		if out := runYAMLEdit(t, original, c.path, "insertBefore", c.value); out.OK || out.Code != c.code {
			t.Errorf("insertBefore %s %s: ok=%v code=%q message=%q, want %q", c.path, c.value, out.OK, out.Code, out.Message, c.code)
		}
	}
	if out := runYAMLEdit(t, "rules:\n  - A\n", `["rules",0]`, "insertBefore", `{"key":"x","value":1}`); out.OK || out.Code != "typeMismatch" {
		t.Errorf("insertBefore into a list: %+v", out)
	}
}

func TestEditYAMLRename(t *testing.T) {
	original := "rule-providers:\n  old-name:   # keep\n    type: http\n    url: https://example.com/a.yaml\n  other: {type: inline, payload: []}\nmode: rule\n"
	mustEdit(t, original, `["rule-providers","old-name"]`, "rename", `"new-name"`,
		"rule-providers:\n  new-name:   # keep\n    type: http\n    url: https://example.com/a.yaml\n  other: {type: inline, payload: []}\nmode: rule\n")
	mustEdit(t, "hosts:\n  a.test: 1.2.3.4\n", `["hosts","a.test"]`, "rename", `"b: c"`, "hosts:\n  'b: c': 1.2.3.4\n")
	mustEdit(t, "hosts:\n  a.test: 1.2.3.4\n", `["hosts","a.test"]`, "rename", `"123"`, "hosts:\n  \"123\": 1.2.3.4\n")
	mustEdit(t, "hosts:\n  \"a.test\" : 1.2.3.4 # c\n", `["hosts","a.test"]`, "rename", `"b.test"`, "hosts:\n  b.test : 1.2.3.4 # c\n")
	for _, c := range []struct{ original, path, value, code string }{
		{original, `["rule-providers","old-name"]`, `"other"`, "invalidRequest"},
		{original, `["rule-providers","old-name"]`, `"old-name"`, "invalidRequest"},
		{original, `["rule-providers","nope"]`, `"x"`, "notFound"},
		{original, `["rule-providers","old-name"]`, `1`, "invalidRequest"},
		{"a: &x 1\n&k b: 2\n", `["b"]`, `"c"`, "anchor"},
		{"base: &b {a: 1}\nuse:\n  <<: *b\n  c: 2\n", `["use","<<"]`, `"m"`, "notFound"},
		{"rules:\n  - A\n", `["rules",0]`, `"x"`, "typeMismatch"},
	} {
		if out := runYAMLEdit(t, c.original, c.path, "rename", c.value); out.OK || out.Code != c.code {
			t.Errorf("rename %s -> %s: ok=%v code=%q message=%q, want %q", c.path, c.value, out.OK, out.Code, out.Message, c.code)
		}
	}
}
