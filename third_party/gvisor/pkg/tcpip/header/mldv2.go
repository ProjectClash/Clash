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

const (
	MLDv2QueryMinimumSize = 24

	mldv2QueryMaximumResponseCodeOffset = 0
	mldv2QueryResvSQRVOffset            = 20
	mldv2QueryQRVMask                   = 0b111
	mldv2QueryQQICOffset                = 21
	mldv2QueryNumberOfSourcesOffset = 22

	MLDv2ReportMinimumSize = 24

	mldv2QuerySourcesOffset = 24
)

var (
	MLDv2RoutersAddress = tcpip.AddrFrom16([16]byte{0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16})
)

type MLDv2Query MLD

func (m MLDv2Query) MaximumResponseCode() uint16 {
	return binary.BigEndian.Uint16(m[mldv2QueryMaximumResponseCodeOffset:])
}

func MLDv2MaximumResponseDelay(codeRaw uint16) time.Duration {
	code := time.Duration(codeRaw)
	if code < 32768 {
		return code * time.Millisecond
	}

	const mantBits = 12
	const expMask = 0b111
	exp := (code >> mantBits) & expMask
	mant := code & ((1 << mantBits) - 1)
	return (mant | 0x1000) << (exp + 3) * time.Millisecond
}

func (m MLDv2Query) MulticastAddress() tcpip.Address {
	return tcpip.AddrFrom16([16]byte(m[mldMulticastAddressOffset:][:IPv6AddressSize]))
}

func (m MLDv2Query) QuerierRobustnessVariable() uint8 {
	return m[mldv2QueryResvSQRVOffset] & mldv2QueryQRVMask
}

func (m MLDv2Query) QuerierQueryInterval() time.Duration {
	return mldv2AndIGMPv3QuerierQueryCodeToInterval(m[mldv2QueryQQICOffset])
}

func (m MLDv2Query) Sources() (AddressIterator, bool) {
	return makeAddressIterator(
		m[mldv2QuerySourcesOffset:],
		binary.BigEndian.Uint16(m[mldv2QueryNumberOfSourcesOffset:]),
		IPv6AddressSize,
	)
}

type MLDv2ReportRecordType int

const (
	MLDv2ReportRecordModeIsInclude       MLDv2ReportRecordType = 1
	MLDv2ReportRecordModeIsExclude       MLDv2ReportRecordType = 2
	MLDv2ReportRecordChangeToIncludeMode MLDv2ReportRecordType = 3
	MLDv2ReportRecordChangeToExcludeMode MLDv2ReportRecordType = 4
	MLDv2ReportRecordAllowNewSources     MLDv2ReportRecordType = 5
	MLDv2ReportRecordBlockOldSources     MLDv2ReportRecordType = 6
)

const (
	mldv2ReportMulticastAddressRecordMinimumSize            = 20
	mldv2ReportMulticastAddressRecordTypeOffset             = 0
	mldv2ReportMulticastAddressRecordAuxDataLenOffset       = 1
	mldv2ReportMulticastAddressRecordAuxDataLenUnits        = 4
	mldv2ReportMulticastAddressRecordNumberOfSourcesOffset  = 2
	mldv2ReportMulticastAddressRecordMulticastAddressOffset = 4
	mldv2ReportMulticastAddressRecordSourcesOffset          = 20
)

type MLDv2ReportMulticastAddressRecordSerializer struct {
	RecordType       MLDv2ReportRecordType
	MulticastAddress tcpip.Address
	Sources          []tcpip.Address
}

func (s *MLDv2ReportMulticastAddressRecordSerializer) Length() int {
	return mldv2ReportMulticastAddressRecordSourcesOffset + len(s.Sources)*IPv6AddressSize
}

func copyIPv6Address(dst []byte, src tcpip.Address) {
	if n := copy(dst, src.AsSlice()); n != IPv6AddressSize {
		panic(fmt.Sprintf("got copy(...) = %d, want = %d", n, IPv6AddressSize))
	}
}

func (s *MLDv2ReportMulticastAddressRecordSerializer) SerializeInto(b []byte) {
	b[mldv2ReportMulticastAddressRecordTypeOffset] = byte(s.RecordType)
	b[mldv2ReportMulticastAddressRecordAuxDataLenOffset] = 0
	binary.BigEndian.PutUint16(b[mldv2ReportMulticastAddressRecordNumberOfSourcesOffset:], uint16(len(s.Sources)))
	copyIPv6Address(b[mldv2ReportMulticastAddressRecordMulticastAddressOffset:], s.MulticastAddress)
	b = b[mldv2ReportMulticastAddressRecordSourcesOffset:]
	for _, source := range s.Sources {
		copyIPv6Address(b, source)
		b = b[IPv6AddressSize:]
	}
}

const (
	mldv2ReportReservedOffset                        = 0
	mldv2ReportNumberOfMulticastAddressRecordsOffset = 2
	mldv2ReportMulticastAddressRecordsOffset         = 4
)

type MLDv2ReportSerializer struct {
	Records []MLDv2ReportMulticastAddressRecordSerializer
}

func (s *MLDv2ReportSerializer) Length() int {
	ret := mldv2ReportMulticastAddressRecordsOffset
	for _, record := range s.Records {
		ret += record.Length()
	}
	return ret
}

func (s *MLDv2ReportSerializer) SerializeInto(b []byte) {
	binary.BigEndian.PutUint16(b[mldv2ReportReservedOffset:], 0)
	binary.BigEndian.PutUint16(b[mldv2ReportNumberOfMulticastAddressRecordsOffset:], uint16(len(s.Records)))
	b = b[mldv2ReportMulticastAddressRecordsOffset:]
	for _, record := range s.Records {
		len := record.Length()
		record.SerializeInto(b[:len])
		b = b[len:]
	}
}

type MLDv2ReportMulticastAddressRecord []byte

func (r MLDv2ReportMulticastAddressRecord) RecordType() MLDv2ReportRecordType {
	return MLDv2ReportRecordType(r[mldv2ReportMulticastAddressRecordTypeOffset])
}

func (r MLDv2ReportMulticastAddressRecord) AuxDataLen() int {
	return int(r[mldv2ReportMulticastAddressRecordAuxDataLenOffset]) * mldv2ReportMulticastAddressRecordAuxDataLenUnits
}

func (r MLDv2ReportMulticastAddressRecord) numberOfSources() uint16 {
	return binary.BigEndian.Uint16(r[mldv2ReportMulticastAddressRecordNumberOfSourcesOffset:])
}

func (r MLDv2ReportMulticastAddressRecord) MulticastAddress() tcpip.Address {
	return tcpip.AddrFrom16([16]byte(r[mldv2ReportMulticastAddressRecordMulticastAddressOffset:][:IPv6AddressSize]))
}

func (r MLDv2ReportMulticastAddressRecord) Sources() (AddressIterator, bool) {
	expectedLen := int(r.numberOfSources()) * IPv6AddressSize
	b := r[mldv2ReportMulticastAddressRecordSourcesOffset:]
	if len(b) < expectedLen {
		return AddressIterator{}, false
	}
	return AddressIterator{addressSize: IPv6AddressSize, buf: bytes.NewBuffer(b[:expectedLen])}, true
}

type MLDv2Report []byte

type MLDv2ReportMulticastAddressRecordIterator struct {
	recordsLeft uint16
	buf         *bytes.Buffer
}

type MLDv2ReportMulticastAddressRecordIteratorNextDisposition int

const (
	MLDv2ReportMulticastAddressRecordIteratorNextOk MLDv2ReportMulticastAddressRecordIteratorNextDisposition = iota

	MLDv2ReportMulticastAddressRecordIteratorNextDone

	MLDv2ReportMulticastAddressRecordIteratorNextErrBufferTooShort
)

func (it *MLDv2ReportMulticastAddressRecordIterator) Next() (MLDv2ReportMulticastAddressRecord, MLDv2ReportMulticastAddressRecordIteratorNextDisposition) {
	if it.recordsLeft == 0 {
		return MLDv2ReportMulticastAddressRecord{}, MLDv2ReportMulticastAddressRecordIteratorNextDone
	}
	if it.buf.Len() < mldv2ReportMulticastAddressRecordMinimumSize {
		return MLDv2ReportMulticastAddressRecord{}, MLDv2ReportMulticastAddressRecordIteratorNextErrBufferTooShort
	}

	hdr := MLDv2ReportMulticastAddressRecord(it.buf.Bytes())
	expectedLen := mldv2ReportMulticastAddressRecordMinimumSize +
		int(hdr.AuxDataLen()) + int(hdr.numberOfSources())*IPv6AddressSize

	bytes := it.buf.Next(expectedLen)
	if len(bytes) < expectedLen {
		return MLDv2ReportMulticastAddressRecord{}, MLDv2ReportMulticastAddressRecordIteratorNextErrBufferTooShort
	}
	it.recordsLeft--
	return MLDv2ReportMulticastAddressRecord(bytes), MLDv2ReportMulticastAddressRecordIteratorNextOk
}

func (m MLDv2Report) MulticastAddressRecords() MLDv2ReportMulticastAddressRecordIterator {
	return MLDv2ReportMulticastAddressRecordIterator{
		recordsLeft: binary.BigEndian.Uint16(m[mldv2ReportNumberOfMulticastAddressRecordsOffset:]),
		buf:         bytes.NewBuffer(m[mldv2ReportMulticastAddressRecordsOffset:]),
	}
}
