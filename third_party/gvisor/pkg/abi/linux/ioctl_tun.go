// Copyright 2020 The gVisor Authors.
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

var (
	TUNSETIFF     = IOW('T', 202, 4)
	TUNSETPERSIST = IOW('T', 203, 4)
	TUNGETIFF     = IOR('T', 210, 4)
)

const (
	IFF_TUN      = 0x0001
	IFF_TAP      = 0x0002
	IFF_NO_PI    = 0x1000
	IFF_NOFILTER = 0x1000
	IFF_TUN_EXCL = 0x8000
	IFF_ONE_QUEUE = 0x2000
)
