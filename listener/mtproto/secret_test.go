package mtproto

import (
	"strings"
	"testing"
)

func TestParseSecret(t *testing.T) {
	const bare = "0123456789abcdef0123456789abcdef"
	want := [16]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}

	for _, c := range []struct {
		name       string
		in         string
		paddedOnly bool
	}{
		{"bare", bare, false},
		{"bare upper case", strings.ToUpper(bare), false},
		{"dd prefix", "dd" + bare, true},
		{"DD prefix", "DD" + bare, true},
		{"bare starting with ee", "ee" + bare[2:], false},
		{"bare starting with dd", "dd" + bare[2:], false},
		{"surrounding space", "  " + bare + "\n", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, err := ParseSecret(c.in)
			if err != nil {
				t.Fatalf("ParseSecret(%q): %v", c.in, err)
			}
			if s.paddedOnly != c.paddedOnly {
				t.Fatalf("paddedOnly = %v, want %v", s.paddedOnly, c.paddedOnly)
			}
			if !strings.HasPrefix(c.name, "bare starting") && s.key != want {
				t.Fatalf("key = %x, want %x", s.key, want)
			}
		})
	}
}

func TestParseSecretRefuses(t *testing.T) {
	const bare = "0123456789abcdef0123456789abcdef"
	for _, c := range []struct {
		name, in, mention string
	}{
		{"empty", "", "required"},
		{"fake TLS", "ee" + bare + "7777772e676f6f676c652e636f6d", "fake-TLS"},
		{"fake TLS without a domain", "ee" + bare, "fake-TLS"},
		{"short", bare[:30], "32 hex"},
		{"long", bare + "00", "32 hex"},
		{"not hex", "zz" + bare[2:], "32 hex"},
		{"dd with a short body", "dd" + bare[:31], "32 hex"},
		{"base64", "ASNFZ4mrze8BI0VniavN7w==", "32 hex"},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, err := ParseSecret(c.in)
			if err == nil {
				t.Fatalf("ParseSecret(%q) accepted", c.in)
			}
			if !strings.Contains(err.Error(), c.mention) {
				t.Fatalf("ParseSecret(%q) = %q, want it to mention %q", c.in, err, c.mention)
			}
		})
	}
}
