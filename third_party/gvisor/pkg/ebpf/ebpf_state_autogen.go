
package ebpf

import (
	"context"

	"github.com/metacubex/gvisor/pkg/state"
)

func (uprog *UnverifiedProgram) StateTypeName() string {
	return "pkg/ebpf.UnverifiedProgram"
}

func (uprog *UnverifiedProgram) StateFields() []string {
	return []string{
		"instructions",
	}
}

func (uprog *UnverifiedProgram) beforeSave() {}

func (uprog *UnverifiedProgram) StateSave(stateSinkObject state.Sink) {
	uprog.beforeSave()
	stateSinkObject.Save(0, &uprog.instructions)
}

func (uprog *UnverifiedProgram) afterLoad(context.Context) {}

func (uprog *UnverifiedProgram) StateLoad(ctx context.Context, stateSourceObject state.Source) {
	stateSourceObject.Load(0, &uprog.instructions)
}

func (p *Program) StateTypeName() string {
	return "pkg/ebpf.Program"
}

func (p *Program) StateFields() []string {
	return []string{
		"instructions",
		"id",
		"progType",
	}
}

func (p *Program) beforeSave() {}

func (p *Program) StateSave(stateSinkObject state.Sink) {
	p.beforeSave()
	stateSinkObject.Save(0, &p.instructions)
	stateSinkObject.Save(1, &p.id)
	stateSinkObject.Save(2, &p.progType)
}

func (p *Program) afterLoad(context.Context) {}

func (p *Program) StateLoad(ctx context.Context, stateSourceObject state.Source) {
	stateSourceObject.Load(0, &p.instructions)
	stateSourceObject.Load(1, &p.id)
	stateSourceObject.Load(2, &p.progType)
}

func init() {
	state.Register((*UnverifiedProgram)(nil))
	state.Register((*Program)(nil))
}
