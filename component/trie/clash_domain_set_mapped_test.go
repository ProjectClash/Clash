package trie

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"
	"unsafe"
)

func alignedCopy(data []byte) []byte {
	if len(data) == 0 {
		return []byte{}
	}
	words := make([]uint64, (len(data)+7)/8)
	out := unsafe.Slice((*byte)(unsafe.Pointer(&words[0])), len(data))
	copy(out, data)
	return out
}

func mappedTestDomains(rng *rand.Rand, n int) []string {
	var out []string
	for i := 0; i < n; i++ {
		host := fmt.Sprintf("h%d.z%d.example%d.com", rng.Intn(1<<20), rng.Intn(997), rng.Intn(31))
		switch i % 5 {
		case 0:
			out = append(out, "+."+host)
		case 1:
			out = append(out, "*."+host)
		default:
			out = append(out, host)
		}
	}
	return out
}

func TestAMappedDomainSetAnswersAsTheSetItWasWrittenFrom(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	domains := mappedTestDomains(rng, 20000)
	trie := New[struct{}]()
	for _, domain := range domains {
		if err := trie.Insert(domain, struct{}{}); err != nil {
			t.Fatal(err)
		}
	}
	set := trie.NewDomainSet()
	var buffer bytes.Buffer
	if err := set.WriteMapped(&buffer); err != nil {
		t.Fatal(err)
	}
	mapped, err := OpenMappedDomainSet(alignedCopy(buffer.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	probes := []string{"", "com", "example1.com", "absent.example.org"}
	for _, domain := range domains {
		switch domain[0] {
		case '+', '*':
			base := domain[2:]
			probes = append(probes, base, "a."+base, "a.b."+base, "x"+base)
		default:
			probes = append(probes, domain, "w."+domain, domain[1:])
		}
	}
	for i := 0; i < 5000; i++ {
		probes = append(probes, fmt.Sprintf("h%d.z%d.example%d.com", rng.Intn(1<<20), rng.Intn(997), rng.Intn(31)))
	}
	for _, probe := range probes {
		if got, want := mapped.Has(probe), set.Has(probe); got != want {
			t.Fatalf("%q: mapped %v, built %v", probe, got, want)
		}
	}
}

func TestAMappedDomainSetRefusesBytesThatAreNotOne(t *testing.T) {
	trie := New[struct{}]()
	for _, domain := range []string{"+.example.com", "a.example.net", "*.example.org"} {
		_ = trie.Insert(domain, struct{}{})
	}
	var buffer bytes.Buffer
	if err := trie.NewDomainSet().WriteMapped(&buffer); err != nil {
		t.Fatal(err)
	}
	whole := buffer.Bytes()
	for _, cut := range []int{0, 4, 16, 40, len(whole) / 2, len(whole) - 1} {
		if _, err := OpenMappedDomainSet(alignedCopy(whole[:cut])); err == nil {
			t.Fatalf("a set cut to %d of %d bytes opened", cut, len(whole))
		}
	}
	for _, at := range []int{0, 5, 12, len(whole) / 2, len(whole) - 1} {
		changed := append([]byte(nil), whole...)
		changed[at] ^= 0x40
		if _, err := OpenMappedDomainSet(alignedCopy(changed)); err == nil {
			t.Fatalf("a set with byte %d changed opened", at)
		}
	}
	if _, err := OpenMappedDomainSet(alignedCopy(whole)[1:]); err == nil {
		t.Fatal("a set not 8-byte aligned opened")
	}
}
