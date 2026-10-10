package compiled

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/klauspost/compress/zstd"
	"github.com/ProjectClash/Clash/component/trie"
	P "github.com/ProjectClash/Clash/constant/provider"
)

var MagicBytes = [4]byte{'M', 'R', 'S', 1}

const DirectoryName = "compiled-geosite"

var ErrNotCompiled = errors.New("category has not been compiled")

func Path(directory, category string) (string, error) {
	name := strings.ToLower(strings.TrimSpace(category))
	if name == "" {
		return "", errors.New("empty category")
	}
	if strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return "", fmt.Errorf("unsafe category name %q", category)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.', r == '@', r == ',', r == '!':
		default:
			return "", fmt.Errorf("unsafe category name %q", category)
		}
	}
	return filepath.Join(directory, name+".mrs"), nil
}

func Write(w io.Writer, set *trie.DomainSet, count int, residual []Residual) (err error) {
	if set == nil {
		return errors.New("nil domain set")
	}
	encoder, err := zstd.NewWriter(w)
	if err != nil {
		return err
	}
	defer func() {
		closeErr := encoder.Close()
		if err == nil {
			err = closeErr
		}
	}()
	if _, err = encoder.Write(MagicBytes[:]); err != nil {
		return err
	}
	if _, err = encoder.Write([]byte{P.Domain.Byte()}); err != nil {
		return err
	}
	if err = binary.Write(encoder, binary.BigEndian, int64(count)); err != nil {
		return err
	}
	extra := encodeResidual(residual)
	if err = binary.Write(encoder, binary.BigEndian, int64(len(extra))); err != nil {
		return err
	}
	if len(extra) > 0 {
		if _, err = encoder.Write(extra); err != nil {
			return err
		}
	}
	return set.WriteBin(encoder)
}

func Read(r io.Reader) (*trie.DomainSet, int, []Residual, error) {
	decoder, err := zstd.NewReader(r)
	if err != nil {
		return nil, 0, nil, err
	}
	defer decoder.Close()

	var magic [4]byte
	if _, err := io.ReadFull(decoder, magic[:]); err != nil {
		return nil, 0, nil, err
	}
	if magic != MagicBytes {
		return nil, 0, nil, errors.New("not a compiled rule set")
	}
	var behavior [1]byte
	if _, err := io.ReadFull(decoder, behavior[:]); err != nil {
		return nil, 0, nil, err
	}
	if behavior[0] != P.Domain.Byte() {
		return nil, 0, nil, fmt.Errorf("compiled rule set holds %d, want a domain set", behavior[0])
	}
	var count int64
	if err := binary.Read(decoder, binary.BigEndian, &count); err != nil {
		return nil, 0, nil, err
	}
	var extraLength int64
	if err := binary.Read(decoder, binary.BigEndian, &extraLength); err != nil {
		return nil, 0, nil, err
	}
	if extraLength < 0 || extraLength > maximumResidualBytes {
		return nil, 0, nil, errors.New("extra block length is invalid")
	}
	var residual []Residual
	if extraLength > 0 {
		extra := make([]byte, extraLength)
		if _, err := io.ReadFull(decoder, extra); err != nil {
			return nil, 0, nil, err
		}
		residual, err = decodeResidual(extra)
		if err != nil {
			return nil, 0, nil, err
		}
	}
	set, err := trie.ReadDomainSetBin(decoder)
	if err != nil {
		return nil, 0, nil, err
	}
	return set, int(count), residual, nil
}

func Load(directory, category string) (*trie.DomainSet, int, []Residual, error) {
	path, err := Path(directory, category)
	if err != nil {
		return nil, 0, nil, err
	}
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, nil, ErrNotCompiled
		}
		return nil, 0, nil, err
	}
	return Read(bytes.NewReader(content))
}

func Store(
	directory, category string, set *trie.DomainSet, count int, residual []Residual,
) error {
	path, err := Path(directory, category)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".compiling-*")
	if err != nil {
		return err
	}
	defer os.Remove(temporary.Name())
	if err := Write(temporary, set, count, residual); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporary.Name(), path)
}

type Residual struct {
	Type  int32
	Value string
}

const maximumResidualBytes = 1 << 20

func encodeResidual(residual []Residual) []byte {
	if len(residual) == 0 {
		return nil
	}
	var out bytes.Buffer
	for _, entry := range residual {
		if strings.ContainsAny(entry.Value, "\t\n") {
			continue
		}
		fmt.Fprintf(&out, "%d\t%s\n", entry.Type, entry.Value)
	}
	return out.Bytes()
}

func decodeResidual(extra []byte) ([]Residual, error) {
	var residual []Residual
	for _, line := range strings.Split(string(extra), "\n") {
		if line == "" {
			continue
		}
		separator := strings.IndexByte(line, '\t')
		if separator <= 0 {
			return nil, fmt.Errorf("malformed extra entry %q", line)
		}
		kind, err := strconv.ParseInt(line[:separator], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("malformed extra entry %q: %w", line, err)
		}
		residual = append(residual, Residual{Type: int32(kind), Value: line[separator+1:]})
	}
	return residual, nil
}

func EntryCount(directory, category string) (int, error) {
	path, err := Path(directory, category)
	if err != nil {
		return 0, err
	}
	file, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, ErrNotCompiled
		}
		return 0, err
	}
	defer file.Close()
	_, count, _, err := Read(file)
	if err != nil {
		return 0, err
	}
	return count, nil
}
