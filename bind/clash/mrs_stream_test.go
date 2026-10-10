package clash

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"strings"
	"testing"

	P "github.com/ProjectClash/Clash/constant/provider"
	ruleprovider "github.com/ProjectClash/Clash/rules/provider"
	"github.com/klauspost/compress/zstd"
)

func streamMRSCIDRFixture(ranges int) []byte {
	var out bytes.Buffer
	out.Write(ruleprovider.MrsMagicBytes[:])
	out.WriteByte(P.IPCIDR.Byte())
	_ = binary.Write(&out, binary.BigEndian, int64(-7))
	_ = binary.Write(&out, binary.BigEndian, int64(0))
	out.WriteByte(1)
	_ = binary.Write(&out, binary.BigEndian, int64(ranges))
	out.Write(make([]byte, 32*ranges))
	return out.Bytes()
}

func streamMRSEncode(t testing.TB, decoded []byte) []byte {
	t.Helper()
	encoder, err := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(1), zstd.WithWindowSize(1<<20), zstd.WithEncoderCRC(true))
	if err != nil {
		t.Fatal(err)
	}
	defer encoder.Close()
	return encoder.EncodeAll(decoded, nil)
}

func TestMRSInspectionAllocationBudget(t *testing.T) {
	payload := streamMRSEncode(t, streamMRSCIDRFixture(1<<18))
	if _, err := inspectMRSForIOS(payload, P.IPCIDR); err != nil {
		t.Fatal(err)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	const runs = 3
	for range runs {
		if count, err := inspectMRSForIOS(payload, P.IPCIDR); err != nil || count != -7 {
			t.Fatalf("count=%d error=%v", count, err)
		}
	}
	runtime.ReadMemStats(&after)
	allocated := (after.TotalAlloc - before.TotalAlloc) / runs
	if allocated > 16<<20 {
		t.Fatalf("inspection allocates %d bytes per 8 MiB provider; budget is 16 MiB", allocated)
	}
}

func BenchmarkMRSInspectLargeIPCIDR(b *testing.B) {
	decoded := streamMRSCIDRFixture(1 << 18)
	payload := streamMRSEncode(b, decoded)
	b.ReportAllocs()
	b.SetBytes(int64(len(decoded)))
	b.ResetTimer()
	for range b.N {
		if _, err := inspectMRSForIOS(payload, P.IPCIDR); err != nil {
			b.Fatal(err)
		}
	}
}

func TestMRSStreamStillChecksTheWholeCompressedPayload(t *testing.T) {
	valid := streamMRSCIDRFixture(1)
	for _, badMagic := range []bool{false, true} {
		decoded := bytes.Clone(valid)
		if badMagic {
			decoded[0] ^= 0xff
		}
		encoded := streamMRSEncode(t, decoded)
		corrupt := bytes.Clone(encoded)
		corrupt[len(corrupt)-1] ^= 0xff
		for name, payload := range map[string][]byte{
			"checksum":           corrupt,
			"truncated checksum": encoded[:len(encoded)-1],
			"invalid next frame": append(bytes.Clone(encoded), 1, 2, 3, 4),
		} {
			t.Run(name+map[bool]string{false: "/valid-body", true: "/bad-magic"}[badMagic], func(t *testing.T) {
				_, err := inspectMRSForIOS(payload, P.IPCIDR)
				if err == nil || !strings.HasPrefix(err.Error(), "decode MRS payload:") {
					t.Fatalf("compressed error must precede structural error: %v", err)
				}
			})
		}
	}
}

func TestMRSStreamDecodedLimitIncludesIgnoredTail(t *testing.T) {
	valid := streamMRSCIDRFixture(1)
	for _, size := range []int{maximumProviderResourceBytes, maximumProviderResourceBytes + 1} {
		for _, badMagic := range []bool{false, true} {
			decoded := make([]byte, size)
			copy(decoded, valid)
			if badMagic {
				decoded[0] ^= 0xff
			}
			_, err := inspectMRSForIOS(streamMRSEncode(t, decoded), P.IPCIDR)
			switch {
			case size > maximumProviderResourceBytes:
				if err == nil || !strings.HasPrefix(err.Error(), "decoded MRS payload exceeds") {
					t.Fatalf("size=%d badMagic=%v: %v", size, badMagic, err)
				}
			case badMagic:
				if err == nil || err.Error() != "MRS magic is invalid" {
					t.Fatalf("within-limit structural error: %v", err)
				}
			case err != nil:
				t.Fatalf("exactly-at-limit valid body and ignored tail: %v", err)
			}
		}
	}
}

func TestMRSStreamTruncationPrecedesInvalidRange(t *testing.T) {
	decoded := streamMRSCIDRFixture(2)
	decoded[len(decoded)-64] = 0xff
	for cut := 1; cut <= 32; cut++ {
		_, err := inspectMRSForIOS(streamMRSEncode(t, decoded[:len(decoded)-cut]), P.IPCIDR)
		if err == nil || err.Error() != "MRS IP-CIDR ranges length exceeds the decoded payload" {
			t.Fatalf("cut=%d: %v", cut, err)
		}
	}
	if _, err := inspectMRSForIOS(streamMRSEncode(t, decoded), P.IPCIDR); err == nil || err.Error() != "MRS IP-CIDR range is invalid" {
		t.Fatalf("complete invalid range: %v", err)
	}
}

func TestMRSStreamConcatenatedFrames(t *testing.T) {
	decoded := streamMRSCIDRFixture(2)
	for split := 1; split < len(decoded); split++ {
		payload := append(streamMRSEncode(t, decoded[:split]), streamMRSEncode(t, decoded[split:])...)
		if count, err := inspectMRSForIOS(payload, P.IPCIDR); err != nil || count != -7 {
			t.Fatalf("split=%d count=%d error=%v", split, count, err)
		}
	}
	payload := append(streamMRSEncode(t, decoded), streamMRSEncode(t, []byte("ignored tail"))...)
	if count, err := inspectMRSForIOS(payload, P.IPCIDR); err != nil || count != -7 {
		t.Fatalf("trailing frame: count=%d error=%v", count, err)
	}
}
