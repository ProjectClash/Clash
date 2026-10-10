package clash

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/ProjectClash/Clash/component/cidr"

	"github.com/ProjectClash/Clash/component/trie"
	P "github.com/ProjectClash/Clash/constant/provider"
)

func TestSuffixDomainMRSIsAcceptedLikeUpstream(t *testing.T) {
	domains := []string{"+.example.com", "+.example.org", "+.example.net"}
	trieBuilder := trie.New[struct{}]()
	for _, domain := range domains {
		if err := trieBuilder.Insert(domain, struct{}{}); err != nil {
			t.Fatal(err)
		}
	}
	set := trieBuilder.NewDomainSet()
	if set == nil {
		t.Fatal("nil domain set")
	}
	leaves := 0
	set.Foreach(func(string) bool { leaves++; return true })
	if leaves <= len(domains) {
		t.Fatalf("fixture does not reproduce the shape: %d leaves for %d rules",
			leaves, len(domains))
	}

	var body bytes.Buffer
	if err := set.WriteBin(&body); err != nil {
		t.Fatal(err)
	}
	decoded := buildDecodedMRSTestPayload(
		t, P.Domain, int64(len(domains)),
		func(buffer *bytes.Buffer) {
			if err := binary.Write(buffer, binary.BigEndian, int64(0)); err != nil {
				t.Fatal(err)
			}
			buffer.Write(body.Bytes())
		},
	)
	payload := compressMRSTestPayload(t, decoded)

	if err := validateMRSForIOS(payload, P.Domain); err != nil {
		t.Fatalf("validator rejected a rule set mihomo itself writes: %v", err)
	}
}

func TestIPCIDRMRSCountIsNotComparedWithItsRanges(t *testing.T) {
	set := cidr.NewIpCidrSet()
	for _, prefix := range []string{"1.0.0.0/8", "9.9.9.9/32", "203.0.113.0/24"} {
		if err := set.AddIpCidrForString(prefix); err != nil {
			t.Fatal(err)
		}
	}
	if err := set.Merge(); err != nil {
		t.Fatal(err)
	}
	var body bytes.Buffer
	if err := set.WriteBin(&body); err != nil {
		t.Fatal(err)
	}
	decoded := buildDecodedMRSTestPayload(t, P.IPCIDR, 1, func(buffer *bytes.Buffer) {
		if err := binary.Write(buffer, binary.BigEndian, int64(0)); err != nil {
			t.Fatal(err)
		}
		buffer.Write(body.Bytes())
	})
	payload := compressMRSTestPayload(t, decoded)

	if err := validateMRSForIOS(payload, P.IPCIDR); err != nil {
		t.Fatalf("validator rejected an IP-CIDR set mihomo itself writes: %v", err)
	}
}

func TestTrailingBytesAreIgnoredLikeUpstream(t *testing.T) {
	trieBuilder := trie.New[struct{}]()
	if err := trieBuilder.Insert("example.com", struct{}{}); err != nil {
		t.Fatal(err)
	}
	set := trieBuilder.NewDomainSet()
	if set == nil {
		t.Fatal("nil domain set")
	}
	var body bytes.Buffer
	if err := set.WriteBin(&body); err != nil {
		t.Fatal(err)
	}
	decoded := buildDecodedMRSTestPayload(t, P.Domain, 1, func(buffer *bytes.Buffer) {
		if err := binary.Write(buffer, binary.BigEndian, int64(0)); err != nil {
			t.Fatal(err)
		}
		buffer.Write(body.Bytes())
		buffer.Write([]byte{'M', 'R', 'S', 2, 0, 0, 0, 0})
	})

	if err := validateMRSForIOS(compressMRSTestPayload(t, decoded), P.Domain); err != nil {
		t.Fatalf("rejected trailing bytes upstream never reads: %v", err)
	}
}

func TestMRSHeaderCountIsNotValidated(t *testing.T) {
	trieBuilder := trie.New[struct{}]()
	if err := trieBuilder.Insert("example.com", struct{}{}); err != nil {
		t.Fatal(err)
	}
	set := trieBuilder.NewDomainSet()
	if set == nil {
		t.Fatal("nil domain set")
	}
	var body bytes.Buffer
	if err := set.WriteBin(&body); err != nil {
		t.Fatal(err)
	}
	for _, count := range []int64{0, 1 << 30} {
		decoded := buildDecodedMRSTestPayload(t, P.Domain, count, func(buffer *bytes.Buffer) {
			if err := binary.Write(buffer, binary.BigEndian, int64(0)); err != nil {
				t.Fatal(err)
			}
			buffer.Write(body.Bytes())
		})
		if err := validateMRSForIOS(compressMRSTestPayload(t, decoded), P.Domain); err != nil {
			t.Errorf("header count %d rejected, but upstream only stores it: %v", count, err)
		}
	}
}

func TestLongDomainNamesAreNotADepthViolation(t *testing.T) {
	label := strings.Repeat("a", 63)
	domain := strings.Join([]string{label, label, label, label}, ".")
	if len(domain) <= maximumMRSDomainDepthProbe {
		t.Fatalf("fixture is not long enough: %d characters", len(domain))
	}

	trieBuilder := trie.New[struct{}]()
	if err := trieBuilder.Insert(domain, struct{}{}); err != nil {
		t.Fatalf("the kernel's own writer accepts this name; fixture invalid: %v", err)
	}
	set := trieBuilder.NewDomainSet()
	if set == nil {
		t.Fatal("nil domain set")
	}
	var body bytes.Buffer
	if err := set.WriteBin(&body); err != nil {
		t.Fatal(err)
	}
	decoded := buildDecodedMRSTestPayload(t, P.Domain, 1, func(buffer *bytes.Buffer) {
		if err := binary.Write(buffer, binary.BigEndian, int64(0)); err != nil {
			t.Fatal(err)
		}
		buffer.Write(body.Bytes())
	})

	if err := validateMRSForIOS(compressMRSTestPayload(t, decoded), P.Domain); err != nil {
		t.Fatalf("rejected a %d-character name the kernel itself writes: %v",
			len(domain), err)
	}
}

const maximumMRSDomainDepthProbe = 253

func TestMalformedDomainTreeIsRejectedByEachGuard(t *testing.T) {
	trieBuilder := trie.New[struct{}]()
	for _, domain := range []string{"example.com", "example.org", "sub.example.net"} {
		if err := trieBuilder.Insert(domain, struct{}{}); err != nil {
			t.Fatal(err)
		}
	}
	set := trieBuilder.NewDomainSet()
	if set == nil {
		t.Fatal("nil domain set")
	}
	var healthy bytes.Buffer
	if err := set.WriteBin(&healthy); err != nil {
		t.Fatal(err)
	}
	base := healthy.Bytes()

	leafWords := int(binary.BigEndian.Uint64(base[1:9]))
	bitmapLenAt := 1 + 8 + leafWords*8
	bitmapWords := int(binary.BigEndian.Uint64(base[bitmapLenAt : bitmapLenAt+8]))
	bitmapAt := bitmapLenAt + 8

	fill := func(value byte) []byte {
		out := append([]byte(nil), base...)
		for i := bitmapAt; i < bitmapAt+bitmapWords*8; i++ {
			out[i] = value
		}
		return out
	}

	cases := []struct {
		name string
		body []byte
		want string
	}{
		{"all-zero bitmap has no node delimiter", fill(0x00), "too many children"},
		{"all-one bitmap gives every node no children", fill(0xFF), "disconnected"},
		{"version is not 1", func() []byte {
			out := append([]byte(nil), base...)
			out[0] = 2
			return out
		}(), "version is invalid"},
		{"bitmap shorter than the labels require", func() []byte {
			out := append([]byte(nil), base...)
			binary.BigEndian.PutUint64(out[bitmapLenAt:bitmapLenAt+8], 1)
			return append(out[:bitmapAt+8], out[bitmapAt+bitmapWords*8:]...)
		}(), "bitmap is too short"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			decoded := buildDecodedMRSTestPayload(t, P.Domain, 3, func(buffer *bytes.Buffer) {
				if err := binary.Write(buffer, binary.BigEndian, int64(0)); err != nil {
					t.Fatal(err)
				}
				buffer.Write(testCase.body)
			})
			var panicked any
			var err error
			func() {
				defer func() { panicked = recover() }()
				err = validateMRSForIOS(compressMRSTestPayload(t, decoded), P.Domain)
			}()
			if panicked != nil {
				t.Fatalf("validator panicked instead of rejecting: %v", panicked)
			}
			if err == nil {
				t.Fatal("malformed domain tree accepted; upstream's Has would index out of range")
			}
			if !strings.Contains(err.Error(), testCase.want) {
				t.Fatalf("error = %q, want it to mention %q -- the fixture is tripping a "+
					"different guard than the one it is written for", err, testCase.want)
			}
		})
	}

	decoded := buildDecodedMRSTestPayload(t, P.Domain, 3, func(buffer *bytes.Buffer) {
		if err := binary.Write(buffer, binary.BigEndian, int64(0)); err != nil {
			t.Fatal(err)
		}
		buffer.Write(base)
	})
	if err := validateMRSForIOS(compressMRSTestPayload(t, decoded), P.Domain); err != nil {
		t.Fatalf("the unmutated control body was rejected: %v", err)
	}
}

func TestProviderEntryCountForIOSReportsTheHeaderVerbatim(t *testing.T) {
	trieBuilder := trie.New[struct{}]()
	suffixes := []string{"+.example.com", "+.example.org", "+.example.net"}
	for _, domain := range suffixes {
		if err := trieBuilder.Insert(domain, struct{}{}); err != nil {
			t.Fatal(err)
		}
	}
	set := trieBuilder.NewDomainSet()
	if set == nil {
		t.Fatal("nil domain set")
	}
	leaves := 0
	set.Foreach(func(string) bool { leaves++; return true })
	if leaves == len(suffixes) {
		t.Fatalf("fixture cannot distinguish header from trie: both are %d", leaves)
	}
	var body bytes.Buffer
	if err := set.WriteBin(&body); err != nil {
		t.Fatal(err)
	}
	build := func(header int64) []byte {
		decoded := buildDecodedMRSTestPayload(t, P.Domain, header, func(buffer *bytes.Buffer) {
			if err := binary.Write(buffer, binary.BigEndian, int64(0)); err != nil {
				t.Fatal(err)
			}
			buffer.Write(body.Bytes())
		})
		return compressMRSTestPayload(t, decoded)
	}

	got, err := ProviderEntryCountForIOS("rule", "domain", "mrs", build(int64(len(suffixes))))
	if err != nil {
		t.Fatalf("ProviderEntryCountForIOS: %v", err)
	}
	if got != len(suffixes) {
		t.Fatalf("count = %d, want the header's %d (the trie holds %d leaves)",
			got, len(suffixes), leaves)
	}

	for _, header := range []int64{-1, 0} {
		got, err := ProviderEntryCountForIOS("rule", "domain", "mrs", build(header))
		if err != nil {
			t.Errorf("header %d: %v", header, err)
			continue
		}
		if got != int(header) {
			t.Errorf("header %d reported as %d; the documented contract is verbatim",
				header, got)
		}
	}
}
