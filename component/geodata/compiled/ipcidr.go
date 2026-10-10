package compiled


import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/klauspost/compress/zstd"
	"github.com/ProjectClash/Clash/component/cidr"
	P "github.com/ProjectClash/Clash/constant/provider"
)

const IPCIDRDirectoryName = "compiled-geoip"

func IPCIDRPath(directory, country string) (string, error) {
	name := strings.ToLower(strings.TrimSpace(country))
	if name == "" {
		return "", errors.New("empty country code")
	}
	if strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		return "", fmt.Errorf("unsafe country code %q", country)
	}
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '-', r == '_':
		default:
			return "", fmt.Errorf("unsafe country code %q", country)
		}
	}
	return filepath.Join(directory, name+".mrs"), nil
}

func WriteIPCIDR(w io.Writer, set *cidr.IpCidrSet, count int) (err error) {
	if set == nil {
		return errors.New("nil ip set")
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
	if _, err = encoder.Write([]byte{P.IPCIDR.Byte()}); err != nil {
		return err
	}
	if err = binary.Write(encoder, binary.BigEndian, int64(count)); err != nil {
		return err
	}
	if err = binary.Write(encoder, binary.BigEndian, int64(0)); err != nil {
		return err
	}
	return set.WriteBin(encoder)
}

var sharedDecoder = sync.OnceValues(func() (*zstd.Decoder, error) {
	return zstd.NewReader(nil,
		zstd.WithDecoderConcurrency(1),
		zstd.WithDecoderLowmem(true),
	)
})

func ReadIPCIDR(r io.Reader) (*cidr.IpCidrSet, int, error) {
	framed, err := io.ReadAll(r)
	if err != nil {
		return nil, 0, err
	}
	shared, err := sharedDecoder()
	if err != nil {
		return nil, 0, err
	}
	plain, err := shared.DecodeAll(framed, nil)
	if err != nil {
		return nil, 0, err
	}
	decoder := bytes.NewReader(plain)

	var magic [4]byte
	if _, err := io.ReadFull(decoder, magic[:]); err != nil {
		return nil, 0, err
	}
	if magic != MagicBytes {
		return nil, 0, errors.New("not a compiled rule set")
	}
	var behavior [1]byte
	if _, err := io.ReadFull(decoder, behavior[:]); err != nil {
		return nil, 0, err
	}
	if behavior[0] != P.IPCIDR.Byte() {
		return nil, 0, fmt.Errorf("compiled rule set holds behavior %d, want an ip set", behavior[0])
	}
	var count int64
	if err := binary.Read(decoder, binary.BigEndian, &count); err != nil {
		return nil, 0, err
	}
	var extraLength int64
	if err := binary.Read(decoder, binary.BigEndian, &extraLength); err != nil {
		return nil, 0, err
	}
	if extraLength < 0 || extraLength > maximumResidualBytes {
		return nil, 0, errors.New("extra block length is invalid")
	}
	if extraLength > 0 {
		if _, err := io.CopyN(io.Discard, decoder, extraLength); err != nil {
			return nil, 0, err
		}
	}
	set, err := cidr.ReadIpCidrSet(decoder)
	if err != nil {
		return nil, 0, err
	}
	return set, int(count), nil
}

func LoadIPCIDR(directory, country string) (*cidr.IpCidrSet, int, error) {
	path, err := IPCIDRPath(directory, country)
	if err != nil {
		return nil, 0, err
	}
	content, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, ErrNotCompiled
		}
		return nil, 0, err
	}
	return ReadIPCIDR(bytes.NewReader(content))
}

func StoreIPCIDR(directory, country string, set *cidr.IpCidrSet, count int) error {
	path, err := IPCIDRPath(directory, country)
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
	if err := WriteIPCIDR(temporary, set, count); err != nil {
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

func EntryCountIPCIDR(directory, country string) (int, error) {
	path, err := IPCIDRPath(directory, country)
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
	_, count, err := ReadIPCIDR(file)
	if err != nil {
		return 0, err
	}
	return count, nil
}
