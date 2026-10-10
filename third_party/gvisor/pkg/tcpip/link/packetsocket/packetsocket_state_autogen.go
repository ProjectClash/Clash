
package packetsocket

import (
	"context"

	"github.com/metacubex/gvisor/pkg/state"
)

func (e *Endpoint) StateTypeName() string {
	return "pkg/tcpip/link/packetsocket.Endpoint"
}

func (e *Endpoint) StateFields() []string {
	return []string{
		"Endpoint",
	}
}

func (e *Endpoint) beforeSave() {}

func (e *Endpoint) StateSave(stateSinkObject state.Sink) {
	e.beforeSave()
	stateSinkObject.Save(0, &e.Endpoint)
}

func (e *Endpoint) afterLoad(context.Context) {}

func (e *Endpoint) StateLoad(ctx context.Context, stateSourceObject state.Source) {
	stateSourceObject.Load(0, &e.Endpoint)
}

func init() {
	state.Register((*Endpoint)(nil))
}
