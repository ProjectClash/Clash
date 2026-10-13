package clash

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"

	P "github.com/ProjectClash/Clash/constant/provider"
	ruleprovider "github.com/ProjectClash/Clash/rules/provider"
	"github.com/klauspost/compress/zstd"
)

type mrsDecodedReader struct {
	reader io.Reader
	read   int64
	err    error
}

func (r *mrsDecodedReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.read += int64(n)
	if err != nil && err != io.EOF && r.err == nil {
		r.err = err
	}
	return n, err
}

type mrsCursor struct {
	reader  *io.LimitedReader
	scratch [8]byte
}

func (c *mrsCursor) take(size int, label string) ([]byte, error) {
	value := c.scratch[:size]
	if _, err := io.ReadFull(c.reader, value); err != nil {
		return nil, fmt.Errorf("MRS %s exceeds the decoded payload", label)
	}
	return value, nil
}

func (c *mrsCursor) byte(label string) (byte, error) {
	value, err := c.take(1, label)
	if err != nil {
		return 0, err
	}
	return value[0], nil
}

func (c *mrsCursor) int64(label string) (int64, error) {
	value, err := c.take(8, label)
	if err != nil {
		return 0, err
	}
	return int64(binary.BigEndian.Uint64(value)), nil
}

func (c *mrsCursor) size(length int64, unit int, label string, allowEmpty bool) (int64, error) {
	if length < 0 || (!allowEmpty && length == 0) {
		return 0, fmt.Errorf("MRS %s length is invalid", label)
	}
	if unit <= 0 || length > c.reader.N/int64(unit) {
		return 0, fmt.Errorf("MRS %s length exceeds the decoded payload", label)
	}
	return length * int64(unit), nil
}

func (c *mrsCursor) skip(length int64, unit int, label string, allowEmpty bool) error {
	size, err := c.size(length, unit, label, allowEmpty)
	if err != nil {
		return err
	}
	if _, err := io.CopyN(io.Discard, c.reader, size); err != nil {
		return fmt.Errorf("MRS %s length exceeds the decoded payload", label)
	}
	return nil
}

func (c *mrsCursor) sized(length int64, unit int, label string, allowEmpty bool) ([]byte, error) {
	size, err := c.size(length, unit, label, allowEmpty)
	if err != nil {
		return nil, err
	}
	value, err := io.ReadAll(io.LimitReader(c.reader, size))
	if err != nil || int64(len(value)) != size {
		return nil, fmt.Errorf("MRS %s length exceeds the decoded payload", label)
	}
	return value, nil
}

func validateMRSForIOS(payload []byte, expectedBehavior P.RuleBehavior) error {
	_, err := inspectMRSForIOS(payload, expectedBehavior)
	return err
}

func inspectMRSForIOS(payload []byte, expectedBehavior P.RuleBehavior) (int, error) {
	decoder, err := zstd.NewReader(
		bytes.NewReader(payload),
		zstd.WithDecoderMaxMemory(uint64(providerContentBytes())),
	)
	if err != nil {
		return 0, fmt.Errorf("open MRS zstd payload: %w", err)
	}
	defer decoder.Close()
	decoded := &mrsDecodedReader{reader: decoder}
	limited := &io.LimitedReader{R: decoded, N: int64(providerContentBytes()) + 1}
	count, structuralErr := inspectMRSStream(&mrsCursor{reader: limited}, expectedBehavior)
	_, _ = io.Copy(io.Discard, limited)
	if decoded.err != nil {
		return 0, fmt.Errorf("decode MRS payload: %w", decoded.err)
	}
	if decoded.read == 0 || decoded.read > int64(providerContentBytes()) {
		return 0, fmt.Errorf("decoded MRS payload exceeds the %d-byte iOS provider limit", providerContentBytes())
	}
	return count, structuralErr
}

func inspectMRSStream(cursor *mrsCursor, expectedBehavior P.RuleBehavior) (int, error) {
	magic, err := cursor.take(len(ruleprovider.MrsMagicBytes), "magic")
	if err != nil {
		return 0, err
	}
	if !bytes.Equal(magic, ruleprovider.MrsMagicBytes[:]) {
		return 0, fmt.Errorf("MRS magic is invalid")
	}
	behavior, err := cursor.byte("behavior")
	if err != nil {
		return 0, err
	}
	if behavior != expectedBehavior.Byte() {
		return 0, fmt.Errorf("MRS behavior does not match the provider")
	}
	count, err := cursor.int64("rule count")
	if err != nil {
		return 0, err
	}
	extraLength, err := cursor.int64("extra length")
	if err != nil {
		return 0, err
	}
	if err := cursor.skip(extraLength, 1, "extra", true); err != nil {
		return 0, err
	}

	switch expectedBehavior {
	case P.Domain:
		if err := validateDomainMRSBody(cursor); err != nil {
			return 0, err
		}
	case P.IPCIDR:
		if err := validateIPCIDRMRSBody(cursor); err != nil {
			return 0, err
		}
	default:
		return 0, fmt.Errorf("MRS format is unsupported for provider behavior %s", expectedBehavior.String())
	}
	return int(count), nil
}

func validateDomainMRSBody(cursor *mrsCursor) error {
	version, err := cursor.byte("domain-set version")
	if err != nil {
		return err
	}
	if version != 1 {
		return fmt.Errorf("MRS domain-set version is invalid")
	}
	leavesLength, err := cursor.int64("domain leaves length")
	if err != nil {
		return err
	}
	if err := cursor.skip(leavesLength, 8, "domain leaves", false); err != nil {
		return err
	}
	bitmapLength, err := cursor.int64("domain label bitmap length")
	if err != nil {
		return err
	}
	bitmap, err := cursor.sized(bitmapLength, 8, "domain label bitmap", false)
	if err != nil {
		return err
	}
	labelsLength, err := cursor.int64("domain labels length")
	if err != nil {
		return err
	}
	if err := cursor.skip(labelsLength, 1, "domain labels", false); err != nil {
		return err
	}

	nodes := int(labelsLength) + 1
	if leavesLength*64 < int64(nodes) {
		return fmt.Errorf("MRS domain leaves bitmap is too short")
	}
	logicalBitmapBits := 2*int(labelsLength) + 1
	if len(bitmap)/8*64 < logicalBitmapBits {
		return fmt.Errorf("MRS domain label bitmap is too short")
	}

	bitPosition := 0
	childrenSeen := 0
	levelRemaining := 1
	nextLevel := 0
	for node := 0; node < nodes; node++ {
		for bitPosition < logicalBitmapBits && !mrsBit(bitmap, bitPosition) {
			childrenSeen++
			nextLevel++
			bitPosition++
			if childrenSeen > int(labelsLength) {
				return fmt.Errorf("MRS domain tree has too many children")
			}
		}
		if bitPosition >= logicalBitmapBits {
			return fmt.Errorf("MRS domain tree lacks a node delimiter")
		}
		bitPosition++
		levelRemaining--
		if levelRemaining == 0 && node+1 < nodes {
			if nextLevel == 0 {
				return fmt.Errorf("MRS domain tree is disconnected")
			}
			levelRemaining = nextLevel
			nextLevel = 0
		}
	}
	if childrenSeen != int(labelsLength) || bitPosition != logicalBitmapBits || levelRemaining != 0 || nextLevel != 0 {
		return fmt.Errorf("MRS domain tree topology is inconsistent")
	}
	return nil
}

func validateIPCIDRMRSBody(cursor *mrsCursor) error {
	version, err := cursor.byte("IP-CIDR-set version")
	if err != nil {
		return err
	}
	if version != 1 {
		return fmt.Errorf("MRS IP-CIDR-set version is invalid")
	}
	rangeCount, err := cursor.int64("IP-CIDR range count")
	if err != nil {
		return err
	}
	_, err = cursor.size(rangeCount, 32, "IP-CIDR ranges", false)
	if err != nil {
		return err
	}
	invalidRange := false
	var block [8 * 1024]byte
	for remaining := rangeCount; remaining > 0; {
		ranges := min(remaining, int64(len(block)/32))
		data := block[:ranges*32]
		if _, err := io.ReadFull(cursor.reader, data); err != nil {
			return fmt.Errorf("MRS IP-CIDR ranges length exceeds the decoded payload")
		}
		remaining -= ranges
		for offset := 0; offset < len(data); offset += 32 {
			var fromBytes, toBytes [16]byte
			copy(fromBytes[:], data[offset:offset+16])
			copy(toBytes[:], data[offset+16:offset+32])
			from := netip.AddrFrom16(fromBytes).Unmap()
			to := netip.AddrFrom16(toBytes).Unmap()
			if from.BitLen() != to.BitLen() || from.Compare(to) > 0 {
				invalidRange = true
			}
		}
	}
	if invalidRange {
		return fmt.Errorf("MRS IP-CIDR range is invalid")
	}
	return nil
}

func mrsBit(serializedWords []byte, index int) bool {
	wordOffset := index / 64 * 8
	word := binary.BigEndian.Uint64(serializedWords[wordOffset : wordOffset+8])
	return word&(uint64(1)<<uint(index&63)) != 0
}
