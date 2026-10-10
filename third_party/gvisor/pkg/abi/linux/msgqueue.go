// Copyright 2021 The gVisor Authors.
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

package linux

import (
	"github.com/metacubex/gvisor/pkg/common/structs"

	"github.com/metacubex/gvisor/pkg/marshal/primitive"
)

const (
	MSG_STAT     = 11
	MSG_INFO     = 12
	MSG_STAT_ANY = 13
)

const (
	MSG_NOERROR = 010000
	MSG_EXCEPT  = 020000
	MSG_COPY    = 040000
)

const (
	MSGMNI = 32000
	MSGMAX = 8192
	MSGMNB = 16384
)

const (
	MSGPOOL = (MSGMNI * MSGMNB / 1024)
	MSGTQL  = MSGMNB
	MSGMAP  = MSGMNB
	MSGSSZ  = 16

	MSGSEG = 0xffff
)

type MsqidDS struct {
	_         structs.HostLayout
	MsgPerm   IPCPerm
	MsgStime  TimeT
	MsgRtime  TimeT
	MsgCtime  TimeT
	MsgCbytes uint64
	MsgQnum   uint64
	MsgQbytes uint64
	MsgLspid  int32
	MsgLrpid  int32
	unused4   uint64
	unused5   uint64
}

type MsgBuf struct {
	_    structs.HostLayout
	Type primitive.Int64
	Text primitive.ByteSlice `hostlayout:"ignore"`
}

func (b *MsgBuf) SizeBytes() int {
	return b.Type.SizeBytes() + b.Text.SizeBytes()
}

func (b *MsgBuf) MarshalBytes(dst []byte) []byte {
	dst = b.Type.MarshalUnsafe(dst)
	return b.Text.MarshalBytes(dst)
}

func (b *MsgBuf) UnmarshalBytes(src []byte) []byte {
	src = b.Type.UnmarshalUnsafe(src)
	return b.Text.UnmarshalBytes(src)
}

type MsgInfo struct {
	_       structs.HostLayout
	MsgPool int32
	MsgMap  int32
	MsgMax  int32
	MsgMnb  int32
	MsgMni  int32
	MsgSsz  int32
	MsgTql  int32
	MsgSeg  uint16 `marshal:"unaligned"`
}
