// Copyright 2018 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package header

import (
	"encoding/binary"

	"github.com/metacubex/sing-tun/internal/gtcpip"
	"github.com/metacubex/sing-tun/internal/gtcpip/checksum"
	"github.com/metacubex/sing-tun/internal/gtcpip/seqnum"

	"github.com/google/btree"
)

const (
	TCPSrcPortOffset   = 0
	TCPDstPortOffset   = 2
	TCPSeqNumOffset    = 4
	TCPAckNumOffset    = 8
	TCPDataOffset      = 12
	TCPFlagsOffset     = 13
	TCPWinSizeOffset   = 14
	TCPChecksumOffset  = 16
	TCPUrgentPtrOffset = 18
)

const (
	MaxWndScale = 14

	TCPMaxSACKBlocks = 4
)

type TCPFlags uint8

func (f TCPFlags) Intersects(o TCPFlags) bool {
	return f&o != 0
}

func (f TCPFlags) Contains(o TCPFlags) bool {
	return f&o == o
}

func (f TCPFlags) String() string {
	flagsStr := []byte("FSRPAUEC")
	for i := range flagsStr {
		if f&(1<<uint(i)) == 0 {
			flagsStr[i] = ' '
		}
	}
	return string(flagsStr)
}

const (
	TCPFlagFin TCPFlags = 1 << iota
	TCPFlagSyn
	TCPFlagRst
	TCPFlagPsh
	TCPFlagAck
	TCPFlagUrg
	TCPFlagEce
	TCPFlagCwr
)

const (
	TCPOptionEOL           = 0
	TCPOptionNOP           = 1
	TCPOptionMSS           = 2
	TCPOptionWS            = 3
	TCPOptionTS            = 8
	TCPOptionSACKPermitted = 4
	TCPOptionSACK          = 5
)

const (
	TCPOptionMSSLength           = 4
	TCPOptionTSLength            = 10
	TCPOptionWSLength            = 3
	TCPOptionSackPermittedLength = 2
)

type TCPFields struct {
	SrcPort uint16

	DstPort uint16

	SeqNum uint32

	AckNum uint32

	DataOffset uint8

	Flags TCPFlags

	WindowSize uint16

	Checksum uint16

	UrgentPointer uint16
}

type TCPSynOptions struct {
	MSS uint16

	WS int

	TS bool

	TSVal uint32

	TSEcr uint32

	SACKPermitted bool

	Flags TCPFlags
}

type SACKBlock struct {
	Start seqnum.Value

	End seqnum.Value
}

func (r SACKBlock) Less(b btree.Item) bool {
	return r.Start.LessThan(b.(SACKBlock).Start)
}

func (r SACKBlock) Contains(b SACKBlock) bool {
	return r.Start.LessThanEq(b.Start) && b.End.LessThanEq(r.End)
}

type TCPOptions struct {
	TS bool

	TSVal uint32

	TSEcr uint32

	SACKBlocks []SACKBlock
}

type TCP []byte

const (
	TCPMinimumSize = 20

	TCPOptionsMaximumSize = 40

	TCPHeaderMaximumSize = TCPMinimumSize + TCPOptionsMaximumSize

	TCPTotalHeaderMaximumSize = 160

	TCPProtocolNumber tcpip.TransportProtocolNumber = 6

	TCPMinimumMSS = IPv4MaximumHeaderSize + TCPHeaderMaximumSize + MinIPFragmentPayloadSize - IPv4MinimumSize - TCPMinimumSize

	TCPMinimumSendMSS = TCPOptionsMaximumSize + MinIPFragmentPayloadSize

	TCPMaximumMSS = 0xffff

	TCPDefaultMSS = 536
)

func (b TCP) SourcePort() uint16 {
	return binary.BigEndian.Uint16(b[TCPSrcPortOffset:])
}

func (b TCP) DestinationPort() uint16 {
	return binary.BigEndian.Uint16(b[TCPDstPortOffset:])
}

func (b TCP) SequenceNumber() uint32 {
	return binary.BigEndian.Uint32(b[TCPSeqNumOffset:])
}

func (b TCP) AckNumber() uint32 {
	return binary.BigEndian.Uint32(b[TCPAckNumOffset:])
}

func (b TCP) DataOffset() uint8 {
	return (b[TCPDataOffset] >> 4) * 4
}

func (b TCP) Payload() []byte {
	return b[b.DataOffset():]
}

func (b TCP) Flags() TCPFlags {
	return TCPFlags(b[TCPFlagsOffset])
}

func (b TCP) WindowSize() uint16 {
	return binary.BigEndian.Uint16(b[TCPWinSizeOffset:])
}

func (b TCP) Checksum() uint16 {
	return binary.BigEndian.Uint16(b[TCPChecksumOffset:])
}

func (b TCP) UrgentPointer() uint16 {
	return binary.BigEndian.Uint16(b[TCPUrgentPtrOffset:])
}

func (b TCP) SetSourcePort(port uint16) {
	binary.BigEndian.PutUint16(b[TCPSrcPortOffset:], port)
}

func (b TCP) SetDestinationPort(port uint16) {
	binary.BigEndian.PutUint16(b[TCPDstPortOffset:], port)
}

func (b TCP) SetChecksum(xsum uint16) {
	checksum.Put(b[TCPChecksumOffset:], xsum)
}

func (b TCP) SetDataOffset(headerLen uint8) {
	b[TCPDataOffset] = (headerLen / 4) << 4
}

func (b TCP) SetSequenceNumber(seqNum uint32) {
	binary.BigEndian.PutUint32(b[TCPSeqNumOffset:], seqNum)
}

func (b TCP) SetAckNumber(ackNum uint32) {
	binary.BigEndian.PutUint32(b[TCPAckNumOffset:], ackNum)
}

func (b TCP) SetFlags(flags uint8) {
	b[TCPFlagsOffset] = flags
}

func (b TCP) SetWindowSize(rcvwnd uint16) {
	binary.BigEndian.PutUint16(b[TCPWinSizeOffset:], rcvwnd)
}

func (b TCP) SetUrgentPointer(urgentPointer uint16) {
	binary.BigEndian.PutUint16(b[TCPUrgentPtrOffset:], urgentPointer)
}

func (b TCP) CalculateChecksum(partialChecksum uint16) uint16 {
	xsum := checksum.Checksum(b[:TCPChecksumOffset], partialChecksum)
	xsum = checksum.Checksum(b[TCPChecksumOffset+2:b.DataOffset()], xsum)
	return xsum
}

func (b TCP) IsChecksumValid(src, dst tcpip.Address, payloadChecksum, payloadLength uint16) bool {
	xsum := PseudoHeaderChecksum(TCPProtocolNumber, src.AsSlice(), dst.AsSlice(), uint16(b.DataOffset())+payloadLength)
	xsum = checksum.Combine(xsum, payloadChecksum)
	return checksum.Checksum(b[:b.DataOffset()], xsum) == 0xffff
}

func (b TCP) Options() []byte {
	return b[TCPMinimumSize:b.DataOffset()]
}

func (b TCP) ParsedOptions() TCPOptions {
	return ParseTCPOptions(b.Options())
}

func (b TCP) encodeSubset(seq, ack uint32, flags TCPFlags, rcvwnd uint16) {
	binary.BigEndian.PutUint32(b[TCPSeqNumOffset:], seq)
	binary.BigEndian.PutUint32(b[TCPAckNumOffset:], ack)
	b[TCPFlagsOffset] = uint8(flags)
	binary.BigEndian.PutUint16(b[TCPWinSizeOffset:], rcvwnd)
}

func (b TCP) Encode(t *TCPFields) {
	b.encodeSubset(t.SeqNum, t.AckNum, t.Flags, t.WindowSize)
	b.SetSourcePort(t.SrcPort)
	b.SetDestinationPort(t.DstPort)
	b.SetDataOffset(t.DataOffset)
	b.SetChecksum(t.Checksum)
	b.SetUrgentPointer(t.UrgentPointer)
}

func (b TCP) EncodePartial(partialChecksum, length uint16, seqnum, acknum uint32, flags TCPFlags, rcvwnd uint16) {
	tmp := make([]byte, 4)
	binary.BigEndian.PutUint16(tmp, length)
	binary.BigEndian.PutUint16(tmp[2:], uint16(flags))
	xsum := checksum.Checksum(tmp, partialChecksum)

	b.encodeSubset(seqnum, acknum, flags, rcvwnd)

	xsum = checksum.Checksum(b[TCPSeqNumOffset:TCPSeqNumOffset+8], xsum)
	xsum = checksum.Checksum(b[TCPWinSizeOffset:TCPWinSizeOffset+2], xsum)

	b.SetChecksum(^xsum)
}

func (b TCP) SetSourcePortWithChecksumUpdate(new uint16) {
	old := b.SourcePort()
	b.SetSourcePort(new)
	b.SetChecksum(^checksumUpdate2ByteAlignedUint16(^b.Checksum(), old, new))
}

func (b TCP) SetDestinationPortWithChecksumUpdate(new uint16) {
	old := b.DestinationPort()
	b.SetDestinationPort(new)
	b.SetChecksum(^checksumUpdate2ByteAlignedUint16(^b.Checksum(), old, new))
}

func (b TCP) UpdateChecksumPseudoHeaderAddress(old, new tcpip.Address, fullChecksum bool) {
	xsum := b.Checksum()
	if fullChecksum {
		xsum = ^xsum
	}

	xsum = checksumUpdate2ByteAlignedAddress(xsum, old, new)
	if fullChecksum {
		xsum = ^xsum
	}

	b.SetChecksum(xsum)
}

func ParseSynOptions(opts []byte, isAck bool) TCPSynOptions {
	limit := len(opts)

	synOpts := TCPSynOptions{
		MSS: TCPDefaultMSS,
		WS: -1,
	}

	for i := 0; i < limit; {
		switch opts[i] {
		case TCPOptionEOL:
			i = limit
		case TCPOptionNOP:
			i++
		case TCPOptionMSS:
			if i+4 > limit || opts[i+1] != 4 {
				return synOpts
			}
			mss := uint16(opts[i+2])<<8 | uint16(opts[i+3])
			if mss == 0 {
				return synOpts
			}
			synOpts.MSS = mss
			if mss < TCPMinimumSendMSS {
				synOpts.MSS = TCPMinimumSendMSS
			}
			i += 4

		case TCPOptionWS:
			if i+3 > limit || opts[i+1] != 3 {
				return synOpts
			}
			ws := int(opts[i+2])
			if ws > MaxWndScale {
				ws = MaxWndScale
			}
			synOpts.WS = ws
			i += 3

		case TCPOptionTS:
			if i+10 > limit || opts[i+1] != 10 {
				return synOpts
			}
			synOpts.TSVal = binary.BigEndian.Uint32(opts[i+2:])
			if isAck {
				synOpts.TSEcr = binary.BigEndian.Uint32(opts[i+6:])
			}
			synOpts.TS = true
			i += 10
		case TCPOptionSACKPermitted:
			if i+2 > limit || opts[i+1] != 2 {
				return synOpts
			}
			synOpts.SACKPermitted = true
			i += 2

		default:
			if i+2 > limit {
				return synOpts
			}
			l := int(opts[i+1])
			if l < 2 || i+l > limit {
				return synOpts
			}
			i += l
		}
	}

	return synOpts
}

func ParseTCPOptions(b []byte) TCPOptions {
	opts := TCPOptions{}
	limit := len(b)
	for i := 0; i < limit; {
		switch b[i] {
		case TCPOptionEOL:
			i = limit
		case TCPOptionNOP:
			i++
		case TCPOptionTS:
			if i+10 > limit || (b[i+1] != 10) {
				return opts
			}
			opts.TS = true
			opts.TSVal = binary.BigEndian.Uint32(b[i+2:])
			opts.TSEcr = binary.BigEndian.Uint32(b[i+6:])
			i += 10
		case TCPOptionSACK:
			if i+2 > limit {
				return opts
			}
			sackOptionLen := int(b[i+1])
			if i+sackOptionLen > limit || (sackOptionLen-2)%8 != 0 {
				return opts
			}
			numBlocks := (sackOptionLen - 2) / 8
			opts.SACKBlocks = []SACKBlock{}
			for j := 0; j < numBlocks; j++ {
				start := binary.BigEndian.Uint32(b[i+2+j*8:])
				end := binary.BigEndian.Uint32(b[i+2+j*8+4:])
				opts.SACKBlocks = append(opts.SACKBlocks, SACKBlock{
					Start: seqnum.Value(start),
					End:   seqnum.Value(end),
				})
			}
			i += sackOptionLen
		default:
			if i+2 > limit {
				return opts
			}
			l := int(b[i+1])
			if l < 2 || i+l > limit {
				return opts
			}
			i += l
		}
	}
	return opts
}

func EncodeMSSOption(mss uint32, b []byte) int {
	if len(b) < TCPOptionMSSLength {
		return 0
	}
	b[0], b[1], b[2], b[3] = TCPOptionMSS, TCPOptionMSSLength, byte(mss>>8), byte(mss)
	return TCPOptionMSSLength
}

func EncodeWSOption(ws int, b []byte) int {
	if len(b) < TCPOptionWSLength {
		return 0
	}
	b[0], b[1], b[2] = TCPOptionWS, TCPOptionWSLength, uint8(ws)
	return int(b[1])
}

func EncodeTSOption(tsVal, tsEcr uint32, b []byte) int {
	if len(b) < TCPOptionTSLength {
		return 0
	}
	b[0], b[1] = TCPOptionTS, TCPOptionTSLength
	binary.BigEndian.PutUint32(b[2:], tsVal)
	binary.BigEndian.PutUint32(b[6:], tsEcr)
	return int(b[1])
}

func EncodeSACKPermittedOption(b []byte) int {
	if len(b) < TCPOptionSackPermittedLength {
		return 0
	}

	b[0], b[1] = TCPOptionSACKPermitted, TCPOptionSackPermittedLength
	return int(b[1])
}

func EncodeSACKBlocks(sackBlocks []SACKBlock, b []byte) int {
	if len(sackBlocks) == 0 {
		return 0
	}
	l := len(sackBlocks)
	if l > TCPMaxSACKBlocks {
		l = TCPMaxSACKBlocks
	}
	if ll := (len(b) - 2) / 8; ll < l {
		l = ll
	}
	if l == 0 {
		return 0
	}
	b[0] = TCPOptionSACK
	b[1] = byte(l*8 + 2)
	for i := 0; i < l; i++ {
		binary.BigEndian.PutUint32(b[i*8+2:], uint32(sackBlocks[i].Start))
		binary.BigEndian.PutUint32(b[i*8+6:], uint32(sackBlocks[i].End))
	}
	return int(b[1])
}

func EncodeNOP(b []byte) int {
	if len(b) == 0 {
		return 0
	}
	b[0] = TCPOptionNOP
	return 1
}

func AddTCPOptionPadding(options []byte, offset int) int {
	paddingToAdd := -offset & 3
	for i := offset; i < offset+paddingToAdd; i++ {
		options[i] = TCPOptionNOP
	}
	return paddingToAdd
}

func Acceptable(segSeq seqnum.Value, segLen seqnum.Size, rcvNxt, rcvAcc seqnum.Value) bool {
	if rcvNxt == rcvAcc {
		return segLen == 0 && segSeq == rcvNxt
	}
	if segLen == 0 {
		return segSeq.InRange(rcvNxt, rcvAcc.Add(1))
	}
	return rcvNxt.LessThan(segSeq.Add(segLen)) && segSeq.LessThanEq(rcvAcc)
}

func TCPValid(hdr TCP, payloadChecksum func() uint16, payloadSize uint16, srcAddr, dstAddr tcpip.Address, skipChecksumValidation bool) (csum uint16, csumValid, ok bool) {
	if offset := int(hdr.DataOffset()); offset < TCPMinimumSize || offset > len(hdr) {
		return
	}

	if skipChecksumValidation {
		csumValid = true
	} else {
		csum = hdr.Checksum()
		csumValid = hdr.IsChecksumValid(srcAddr, dstAddr, payloadChecksum(), payloadSize)
	}
	return csum, csumValid, true
}
