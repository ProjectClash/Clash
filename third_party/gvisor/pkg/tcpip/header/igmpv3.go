// Copyright 2022 The gVisor Authors.
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
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip"
)

var (
	IGMPv3RoutersAddress = tcpip.AddrFrom4([4]byte{0xe0, 0x00, 0x00, 0x16})
)

const (
	IGMPv3QueryMinimumSize = 12

	igmpv3QueryMaxRespCodeOffset     = 1
	igmpv3QueryGroupAddressOffset    = 4
	igmpv3QueryResvSQRVOffset        = 8
	igmpv3QueryQRVMask               = 0b111
	igmpv3QueryQQICOffset            = 9
	igmpv3QueryNumberOfSourcesOffset = 10
	igmpv3QuerySourcesOffset         = 12
)

type IGMPv3Query IGMP

func (i IGMPv3Query) MaximumResponseCode() uint8 {
	return i[igmpv3QueryMaxRespCodeOffset]
}

func IGMPv3MaximumResponseDelay(codeRaw uint8) time.Duration {
	code := uint16(codeRaw)
	if code < 128 {
		return DecisecondToDuration(code)
	}

	const mantBits = 4
	const expMask = 0b111
	exp := (code >> mantBits) & expMask
	mant := code & ((1 << mantBits) - 1)
	return DecisecondToDuration((mant | 0x10) << (exp + 3))
}

func (i IGMPv3Query) GroupAddress() tcpip.Address {
	return tcpip.AddrFrom4([4]byte(i[igmpv3QueryGroupAddressOffset:][:IPv4AddressSize]))
}

func (i IGMPv3Query) QuerierRobustnessVariable() uint8 {
	return i[igmpv3QueryResvSQRVOffset] & igmpv3QueryQRVMask
}

func (i IGMPv3Query) QuerierQueryInterval() time.Duration {
	return mldv2AndIGMPv3QuerierQueryCodeToInterval(i[igmpv3QueryQQICOffset])
}

func (i IGMPv3Query) Sources() (AddressIterator, bool) {
	return makeAddressIterator(
		i[igmpv3QuerySourcesOffset:],
		binary.BigEndian.Uint16(i[igmpv3QueryNumberOfSourcesOffset:]),
		IPv4AddressSize,
	)
}

type IGMPv3ReportRecordType int

const (
	IGMPv3ReportRecordModeIsInclude       IGMPv3ReportRecordType = 1
	IGMPv3ReportRecordModeIsExclude       IGMPv3ReportRecordType = 2
	IGMPv3ReportRecordChangeToIncludeMode IGMPv3ReportRecordType = 3
	IGMPv3ReportRecordChangeToExcludeMode IGMPv3ReportRecordType = 4
	IGMPv3ReportRecordAllowNewSources     IGMPv3ReportRecordType = 5
	IGMPv3ReportRecordBlockOldSources     IGMPv3ReportRecordType = 6
)

const (
	igmpv3ReportGroupAddressRecordMinimumSize           = 8
	igmpv3ReportGroupAddressRecordTypeOffset            = 0
	igmpv3ReportGroupAddressRecordAuxDataLenOffset      = 1
	igmpv3ReportGroupAddressRecordAuxDataLenUnits       = 4
	igmpv3ReportGroupAddressRecordNumberOfSourcesOffset = 2
	igmpv3ReportGroupAddressRecordGroupAddressOffset    = 4
	igmpv3ReportGroupAddressRecordSourcesOffset         = 8
)

type IGMPv3ReportGroupAddressRecordSerializer struct {
	RecordType   IGMPv3ReportRecordType
	GroupAddress tcpip.Address
	Sources      []tcpip.Address
}

func (s *IGMPv3ReportGroupAddressRecordSerializer) Length() int {
	return igmpv3ReportGroupAddressRecordSourcesOffset + len(s.Sources)*IPv4AddressSize
}

func copyIPv4Address(dst []byte, src tcpip.Address) {
	srcBytes := src.As4()
	if n := copy(dst, srcBytes[:]); n != IPv4AddressSize {
		panic(fmt.Sprintf("got copy(...) = %d, want = %d", n, IPv4AddressSize))
	}
}

func (s *IGMPv3ReportGroupAddressRecordSerializer) SerializeInto(b []byte) {
	b[igmpv3ReportGroupAddressRecordTypeOffset] = byte(s.RecordType)
	b[igmpv3ReportGroupAddressRecordAuxDataLenOffset] = 0
	binary.BigEndian.PutUint16(b[igmpv3ReportGroupAddressRecordNumberOfSourcesOffset:], uint16(len(s.Sources)))
	copyIPv4Address(b[igmpv3ReportGroupAddressRecordGroupAddressOffset:], s.GroupAddress)
	b = b[igmpv3ReportGroupAddressRecordSourcesOffset:]
	for _, source := range s.Sources {
		copyIPv4Address(b, source)
		b = b[IPv4AddressSize:]
	}
}

const (
	igmpv3ReportTypeOffset                        = 0
	igmpv3ReportReserved1Offset                   = 1
	igmpv3ReportReserved2Offset                   = 4
	igmpv3ReportNumberOfGroupAddressRecordsOffset = 6
	igmpv3ReportGroupAddressRecordsOffset         = 8
)

type IGMPv3ReportSerializer struct {
	Records []IGMPv3ReportGroupAddressRecordSerializer
}

func (s *IGMPv3ReportSerializer) Length() int {
	ret := igmpv3ReportGroupAddressRecordsOffset
	for _, record := range s.Records {
		ret += record.Length()
	}
	return ret
}

func (s *IGMPv3ReportSerializer) SerializeInto(b []byte) {
	b[igmpv3ReportTypeOffset] = byte(IGMPv3MembershipReport)
	b[igmpv3ReportReserved1Offset] = 0
	binary.BigEndian.PutUint16(b[igmpv3ReportReserved2Offset:], 0)
	binary.BigEndian.PutUint16(b[igmpv3ReportNumberOfGroupAddressRecordsOffset:], uint16(len(s.Records)))
	recordsBytes := b[igmpv3ReportGroupAddressRecordsOffset:]
	for _, record := range s.Records {
		len := record.Length()
		record.SerializeInto(recordsBytes[:len])
		recordsBytes = recordsBytes[len:]
	}
	binary.BigEndian.PutUint16(b[igmpChecksumOffset:], IGMPCalculateChecksum(b))
}

type IGMPv3ReportGroupAddressRecord []byte

func (r IGMPv3ReportGroupAddressRecord) RecordType() IGMPv3ReportRecordType {
	return IGMPv3ReportRecordType(r[igmpv3ReportGroupAddressRecordTypeOffset])
}

func (r IGMPv3ReportGroupAddressRecord) AuxDataLen() int {
	return int(r[igmpv3ReportGroupAddressRecordAuxDataLenOffset]) * igmpv3ReportGroupAddressRecordAuxDataLenUnits
}

func (r IGMPv3ReportGroupAddressRecord) numberOfSources() uint16 {
	return binary.BigEndian.Uint16(r[igmpv3ReportGroupAddressRecordNumberOfSourcesOffset:])
}

func (r IGMPv3ReportGroupAddressRecord) GroupAddress() tcpip.Address {
	return tcpip.AddrFrom4([4]byte(r[igmpv3ReportGroupAddressRecordGroupAddressOffset:][:IPv4AddressSize]))
}

func (r IGMPv3ReportGroupAddressRecord) Sources() (AddressIterator, bool) {
	expectedLen := int(r.numberOfSources()) * IPv4AddressSize
	b := r[igmpv3ReportGroupAddressRecordSourcesOffset:]
	if len(b) < expectedLen {
		return AddressIterator{}, false
	}
	return AddressIterator{addressSize: IPv4AddressSize, buf: bytes.NewBuffer(b[:expectedLen])}, true
}

type IGMPv3Report []byte

func (i IGMPv3Report) Checksum() uint16 {
	return binary.BigEndian.Uint16(i[igmpChecksumOffset:])
}

type IGMPv3ReportGroupAddressRecordIterator struct {
	recordsLeft uint16
	buf         *bytes.Buffer
}

type IGMPv3ReportGroupAddressRecordIteratorNextDisposition int

const (
	IGMPv3ReportGroupAddressRecordIteratorNextOk IGMPv3ReportGroupAddressRecordIteratorNextDisposition = iota

	IGMPv3ReportGroupAddressRecordIteratorNextDone

	IGMPv3ReportGroupAddressRecordIteratorNextErrBufferTooShort
)

func (it *IGMPv3ReportGroupAddressRecordIterator) Next() (IGMPv3ReportGroupAddressRecord, IGMPv3ReportGroupAddressRecordIteratorNextDisposition) {
	if it.recordsLeft == 0 {
		return IGMPv3ReportGroupAddressRecord{}, IGMPv3ReportGroupAddressRecordIteratorNextDone
	}
	if it.buf.Len() < igmpv3ReportGroupAddressRecordMinimumSize {
		return IGMPv3ReportGroupAddressRecord{}, IGMPv3ReportGroupAddressRecordIteratorNextErrBufferTooShort
	}

	hdr := IGMPv3ReportGroupAddressRecord(it.buf.Bytes())
	expectedLen := igmpv3ReportGroupAddressRecordMinimumSize +
		int(hdr.AuxDataLen()) + int(hdr.numberOfSources())*IPv4AddressSize

	bytes := it.buf.Next(expectedLen)
	if len(bytes) < expectedLen {
		return IGMPv3ReportGroupAddressRecord{}, IGMPv3ReportGroupAddressRecordIteratorNextErrBufferTooShort
	}
	it.recordsLeft--
	return IGMPv3ReportGroupAddressRecord(bytes), IGMPv3ReportGroupAddressRecordIteratorNextOk
}

func (i IGMPv3Report) GroupAddressRecords() IGMPv3ReportGroupAddressRecordIterator {
	return IGMPv3ReportGroupAddressRecordIterator{
		recordsLeft: binary.BigEndian.Uint16(i[igmpv3ReportNumberOfGroupAddressRecordsOffset:]),
		buf:         bytes.NewBuffer(i[igmpv3ReportGroupAddressRecordsOffset:]),
	}
}
