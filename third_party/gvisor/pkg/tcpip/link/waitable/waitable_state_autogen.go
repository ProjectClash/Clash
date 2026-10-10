
package waitable

import (
	"context"

	"github.com/metacubex/gvisor/pkg/state"
)

func (e *Endpoint) StateTypeName() string {
	return "pkg/tcpip/link/waitable.Endpoint"
}

func (e *Endpoint) StateFields() []string {
	return []string{
		"dispatchGate",
		"dispatcher",
		"writeGate",
		"lower",
	}
}

func (e *Endpoint) beforeSave() {}

func (e *Endpoint) StateSave(stateSinkObject state.Sink) {
	e.beforeSave()
	stateSinkObject.Save(0, &e.dispatchGate)
	stateSinkObject.Save(1, &e.dispatcher)
	stateSinkObject.Save(2, &e.writeGate)
	stateSinkObject.Save(3, &e.lower)
}

func (e *Endpoint) afterLoad(context.Context) {}

func (e *Endpoint) StateLoad(ctx context.Context, stateSourceObject state.Source) {
	stateSourceObject.Load(0, &e.dispatchGate)
	stateSourceObject.Load(1, &e.dispatcher)
	stateSourceObject.Load(2, &e.writeGate)
	stateSourceObject.Load(3, &e.lower)
}

func init() {
	state.Register((*Endpoint)(nil))
}
