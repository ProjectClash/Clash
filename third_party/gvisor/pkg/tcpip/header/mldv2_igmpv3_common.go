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
	"fmt"
	"time"

	"github.com/metacubex/gvisor/pkg/tcpip"
)

func mldv2AndIGMPv3QuerierQueryCodeToInterval(code uint8) time.Duration {
	interval := time.Duration(code)
	if interval < 128 {
		return interval * time.Second
	}

	const expMask = 0b111
	const mantBits = 4
	mant := interval & ((1 << mantBits) - 1)
	exp := (interval >> mantBits) & expMask
	return (mant | 0x10) << (exp + 3) * time.Second
}

func MakeAddressIterator(addressSize int, buf *bytes.Buffer) AddressIterator {
	return AddressIterator{addressSize: addressSize, buf: buf}
}

type AddressIterator struct {
	addressSize int
	buf         *bytes.Buffer
}

func (it *AddressIterator) Done() bool {
	return it.buf.Len() == 0
}

func (it *AddressIterator) Next() (tcpip.Address, bool) {
	if it.Done() {
		var emptyAddress tcpip.Address
		return emptyAddress, false
	}

	b := it.buf.Next(it.addressSize)
	if len(b) != it.addressSize {
		panic(fmt.Sprintf("got len(buf.Next(%d)) = %d, want = %d", it.addressSize, len(b), it.addressSize))
	}

	return tcpip.AddrFromSlice(b), true
}

func makeAddressIterator(b []byte, expectedAddresses uint16, addressSize int) (AddressIterator, bool) {
	expectedLen := int(expectedAddresses) * addressSize
	if len(b) < expectedLen {
		return AddressIterator{}, false
	}
	return MakeAddressIterator(addressSize, bytes.NewBuffer(b[:expectedLen])), true
}
