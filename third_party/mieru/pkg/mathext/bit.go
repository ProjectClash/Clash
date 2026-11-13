// Copyright (C) 2023  mieru authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package mathext

var (
	pdepImpl = pdepGeneric
	pextImpl = pextGeneric
)

func RepeatUint32(v uint32) uint64 {
	return uint64(v)<<32 | uint64(v)
}

func PDEP(x, mask uint64) uint64 {
	return pdepImpl(x, mask)
}

func PEXT(x, mask uint64) uint64 {
	return pextImpl(x, mask)
}

func pdepGeneric(x, mask uint64) uint64 {
	var result uint64
	for srcBit := uint64(1); mask != 0; srcBit <<= 1 {
		maskBit := mask & -mask
		if x&srcBit != 0 {
			result |= maskBit
		}
		mask &= mask - 1
	}
	return result
}

func pextGeneric(x, mask uint64) uint64 {
	var result uint64
	for resultBit := uint64(1); mask != 0; resultBit <<= 1 {
		maskBit := mask & -mask
		if x&maskBit != 0 {
			result |= resultBit
		}
		mask &= mask - 1
	}
	return result
}
