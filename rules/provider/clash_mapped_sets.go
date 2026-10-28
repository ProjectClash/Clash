package provider

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/ProjectClash/Clash/component/cidr"
	"github.com/ProjectClash/Clash/component/trie"
	P "github.com/ProjectClash/Clash/constant/provider"
	"github.com/ProjectClash/Clash/log"
)

const (
	ClashDomainSetStubType = "CLASH-DOMAIN-SET"
	ClashIPCidrSetStubType = "CLASH-IPCIDR-SET"
)

func ClashMappedSetStub(stubType, name string, sum [sha256.Size]byte, count int) string {
	return fmt.Sprintf("%s,%s,%s,%d", stubType, url.PathEscape(name), hex.EncodeToString(sum[:]), count)
}

func parseMappedSetStub(line, stubType, directory string) (path string, sum [sha256.Size]byte, count int, ok bool) {
	fields := strings.Split(strings.TrimSpace(line), ",")
	if directory == "" || len(fields) != 4 || fields[0] != stubType || len(fields[2]) != 2*sha256.Size {
		return "", sum, 0, false
	}
	name, err1 := url.PathUnescape(fields[1])
	digest, err2 := hex.DecodeString(fields[2])
	n, err3 := strconv.Atoi(fields[3])
	if err1 != nil || err2 != nil || err3 != nil || n < 0 || !plainFileName(name) {
		return "", sum, 0, false
	}
	return filepath.Join(directory, name), [sha256.Size]byte(digest), n, true
}

type clashSetNotWhole struct{ error }

func (e clashSetNotWhole) Unwrap() error { return e.error }

func mapSetFile(path string, sum *[sha256.Size]byte) ([]byte, error) {
	if info, err := os.Lstat(path); err != nil {
		return nil, err
	} else if !info.Mode().IsRegular() {
		return nil, clashSetNotWhole{errors.New("not a regular file")}
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() < sha256.Size || info.Size() > 1<<31 {
		return nil, clashSetNotWhole{fmt.Errorf("a compiled set of %d bytes", info.Size())}
	}
	data, err := mapClassicalIndex(file, int(info.Size()))
	if err != nil {
		return nil, err
	}
	if sum != nil && !bytes.Equal(data[len(data)-sha256.Size:], sum[:]) {
		unmapClassicalIndex(data)
		return nil, clashSetNotWhole{errors.New("not the set its stub names")}
	}
	return data, nil
}

type mappedDomainSet struct{ set *trie.DomainSet }

func openMappedDomainSet(path string, sum *[sha256.Size]byte) (*mappedDomainSet, error) {
	data, err := mapSetFile(path, sum)
	if err != nil {
		return nil, err
	}
	set, err := trie.OpenMappedDomainSet(data)
	if err != nil {
		unmapClassicalIndex(data)
		return nil, clashSetNotWhole{err}
	}
	m := &mappedDomainSet{set: set}
	runtime.AddCleanup(m, unmapClassicalIndex, data)
	return m, nil
}

type mappedIPSet struct{ set *cidr.MappedIpCidrSet }

func openMappedIPSet(path string, sum *[sha256.Size]byte) (*mappedIPSet, error) {
	data, err := mapSetFile(path, sum)
	if err != nil {
		return nil, err
	}
	set, err := cidr.OpenMappedIpCidrSet(data)
	if err != nil {
		unmapClassicalIndex(data)
		return nil, clashSetNotWhole{err}
	}
	m := &mappedIPSet{set: set}
	runtime.AddCleanup(m, unmapClassicalIndex, data)
	return m, nil
}

type ClashCompiledSet struct {
	Bytes  []byte
	SHA256 [sha256.Size]byte
	Count  int
}

func ClashCompileMappedDomainSet(lines []string) (ClashCompiledSet, error) {
	s := NewDomainStrategy()
	for _, line := range lines {
		s.Insert(line)
	}
	s.FinishInsert()
	var b bytes.Buffer
	if err := s.domainSet.WriteMapped(&b); err != nil {
		return ClashCompiledSet{}, err
	}
	return compiledSet(b.Bytes(), s.count), nil
}

func ClashCompileMappedIPCidrSet(lines []string) (ClashCompiledSet, error) {
	s := NewIPCidrStrategy()
	s.Reset()
	for _, line := range lines {
		s.Insert(line)
	}
	s.FinishInsert()
	var b bytes.Buffer
	if err := s.cidrSet.WriteMapped(&b); err != nil {
		return ClashCompiledSet{}, err
	}
	return compiledSet(b.Bytes(), s.count), nil
}

func compiledSet(data []byte, count int) ClashCompiledSet {
	return ClashCompiledSet{Bytes: data, SHA256: [sha256.Size]byte(data[len(data)-sha256.Size:]), Count: count}
}

func loadMappedSetStub(line, stubType, directory string, open func(path string, sum [sha256.Size]byte) error) bool {
	if directory == "" || !strings.HasPrefix(line, stubType+",") {
		return false
	}
	path, sum, _, ok := parseMappedSetStub(line, stubType, directory)
	if !ok {
		return false
	}
	if err := open(path, sum); err != nil {
		log.Errorln("compiled rule set %s cannot be used, it matches nothing until the App publishes it again: %v", filepath.Base(path), err)
	}
	return true
}

func ClashMappedFromMrs(mrs []byte, behavior P.RuleBehavior) (ClashCompiledSet, error) {
	var b bytes.Buffer
	switch behavior {
	case P.Domain:
		s := NewDomainStrategy()
		if _, err := rulesMrsParse(mrs, s); err != nil {
			return ClashCompiledSet{}, err
		}
		if err := s.domainSet.WriteMapped(&b); err != nil {
			return ClashCompiledSet{}, err
		}
		return compiledSet(b.Bytes(), s.count), nil
	case P.IPCIDR:
		s := NewIPCidrStrategy()
		if _, err := rulesMrsParse(mrs, s); err != nil {
			return ClashCompiledSet{}, err
		}
		if err := s.cidrSet.WriteMapped(&b); err != nil {
			return ClashCompiledSet{}, err
		}
		return compiledSet(b.Bytes(), s.count), nil
	}
	return ClashCompiledSet{}, fmt.Errorf("a %s set has no mapped form", behavior)
}

func ClashMappedSetChecksumOf(path string) ([sha256.Size]byte, bool) {
	var sum [sha256.Size]byte
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() < sha256.Size {
		return sum, false
	}
	file, err := os.Open(path)
	if err != nil {
		return sum, false
	}
	defer file.Close()
	if _, err := file.ReadAt(sum[:], info.Size()-sha256.Size); err != nil {
		return sum, false
	}
	return sum, true
}

func ClashCheckMappedSet(path string, behavior P.RuleBehavior) ([sha256.Size]byte, error) {
	sum, ok := ClashMappedSetChecksumOf(path)
	if !ok {
		return sum, errors.New("not a compiled set")
	}
	data, err := mapSetFile(path, &sum)
	if err != nil {
		return sum, err
	}
	defer unmapClassicalIndex(data)
	switch behavior {
	case P.Domain:
		_, err = trie.OpenMappedDomainSet(data)
	case P.IPCIDR:
		_, err = cidr.OpenMappedIpCidrSet(data)
	default:
		err = fmt.Errorf("a %s set has no mapped form", behavior)
	}
	return sum, err
}
