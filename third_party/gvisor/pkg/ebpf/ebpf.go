// Copyright 2026 The gVisor Authors.
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

package ebpf

import (
	"github.com/metacubex/gvisor/pkg/abi/linux"
)

type BPFID uint32

type UnverifiedProgram struct {
	instructions []linux.EBPFInstruction
}

func NewUnverifiedProgram(instructions []linux.EBPFInstruction) UnverifiedProgram {
	return UnverifiedProgram{
		instructions: instructions,
	}
}

type Program struct {
	instructions []linux.EBPFInstruction

	id BPFID

	progType linux.BPFProgramType
}

func (p *Program) ID() BPFID {
	return p.id
}

func (p *Program) ProgType() linux.BPFProgramType {
	return p.progType
}

func (uprog *UnverifiedProgram) Validate(id BPFID, progType linux.BPFProgramType) (Program, error) {
	prog := Program{
		instructions: uprog.instructions,
		id:           id,
		progType:     progType,
	}
	return prog, nil
}
