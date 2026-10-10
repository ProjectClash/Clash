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

const (
	typeHLen   = 0
	encapProto = 1
)

type GUEFields struct {
	Type uint8

	Control bool

	HeaderLength uint8

	Protocol uint8
}

type GUE []byte

const (
	GUEMinimumSize = 4
)

func (b GUE) TypeAndControl() uint8 {
	return b[typeHLen] >> 5
}

func (b GUE) HeaderLength() uint8 {
	return 4 + 4*(b[typeHLen]&0x1f)
}

func (b GUE) Protocol() uint8 {
	return b[encapProto]
}

func (b GUE) Encode(i *GUEFields) {
	ctl := uint8(0)
	if i.Control {
		ctl = 1 << 5
	}
	b[typeHLen] = ctl | i.Type<<6 | (i.HeaderLength-4)/4
	b[encapProto] = i.Protocol
}
