
package noop

import (
	"context"

	"github.com/metacubex/gvisor/pkg/state"
)

func (ep *endpoint) StateTypeName() string {
	return "pkg/tcpip/transport/internal/noop.endpoint"
}

func (ep *endpoint) StateFields() []string {
	return []string{
		"DefaultSocketOptionsHandler",
		"ops",
	}
}

func (ep *endpoint) beforeSave() {}

func (ep *endpoint) StateSave(stateSinkObject state.Sink) {
	ep.beforeSave()
	stateSinkObject.Save(0, &ep.DefaultSocketOptionsHandler)
	stateSinkObject.Save(1, &ep.ops)
}

func (ep *endpoint) afterLoad(context.Context) {}

func (ep *endpoint) StateLoad(ctx context.Context, stateSourceObject state.Source) {
	stateSourceObject.Load(0, &ep.DefaultSocketOptionsHandler)
	stateSourceObject.Load(1, &ep.ops)
}

func init() {
	state.Register((*endpoint)(nil))
}
