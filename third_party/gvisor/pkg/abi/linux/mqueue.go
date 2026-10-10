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
)

const (
	DFLT_QUEUESMAX       = 256
	MIN_MSGMAX           = 1
	DFLT_MSG        uint = 10
	DFLT_MSGMAX          = 10
	HARD_MSGMAX          = 65536
	MIN_MSGSIZEMAX       = 128
	DFLT_MSGSIZE    uint = 8192
	DFLT_MSGSIZEMAX      = 8192
	HARD_MSGSIZEMAX      = (16 * 1024 * 1024)
)

const (
	MQ_PRIO_MAX  = 32768
	MQ_BYTES_MAX = 819200
)

const (
	NOTIFY_NONE    = 0
	NOTIFY_WOKENUP = 1
	NOTIFY_REMOVED = 2

	NOTIFY_COOKIE_LEN = 32
)

type MqAttr struct {
	_         structs.HostLayout
	MqFlags   int64
	MqMaxmsg  int64
	MqMsgsize int64
	MqCurmsgs int64
	_         [4]int64
}
