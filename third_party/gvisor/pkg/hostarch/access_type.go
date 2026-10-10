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

package hostarch

import "golang.org/x/sys/unix"

type AccessType struct {
	Read bool

	Write bool

	Execute bool
}

func (a AccessType) String() string {
	bits := [3]byte{'-', '-', '-'}
	if a.Read {
		bits[0] = 'r'
	}
	if a.Write {
		bits[1] = 'w'
	}
	if a.Execute {
		bits[2] = 'x'
	}
	return string(bits[:])
}

func (a AccessType) Any() bool {
	return a.Read || a.Write || a.Execute
}

func (a AccessType) Prot() int {
	var prot int
	if a.Read {
		prot |= unix.PROT_READ
	}
	if a.Write {
		prot |= unix.PROT_WRITE
	}
	if a.Execute {
		prot |= unix.PROT_EXEC
	}
	return prot
}

func (a AccessType) SupersetOf(other AccessType) bool {
	if !a.Read && other.Read {
		return false
	}
	if !a.Write && other.Write {
		return false
	}
	if !a.Execute && other.Execute {
		return false
	}
	return true
}

func (a AccessType) Intersect(other AccessType) AccessType {
	return AccessType{
		Read:    a.Read && other.Read,
		Write:   a.Write && other.Write,
		Execute: a.Execute && other.Execute,
	}
}

func (a AccessType) Union(other AccessType) AccessType {
	return AccessType{
		Read:    a.Read || other.Read,
		Write:   a.Write || other.Write,
		Execute: a.Execute || other.Execute,
	}
}

func (a AccessType) Effective() AccessType {
	if a.Write || a.Execute {
		a.Read = true
	}
	return a
}

var (
	NoAccess    = AccessType{}
	Read        = AccessType{Read: true}
	Write       = AccessType{Write: true}
	Execute     = AccessType{Execute: true}
	ReadWrite   = AccessType{Read: true, Write: true}
	ReadExecute = AccessType{Read: true, Execute: true}
	AnyAccess   = AccessType{Read: true, Write: true, Execute: true}
)
