
package sniffer

import (
	"context"

	"github.com/metacubex/gvisor/pkg/state"
)

func (e *Endpoint) StateTypeName() string {
	return "pkg/tcpip/link/sniffer.Endpoint"
}

func (e *Endpoint) StateFields() []string {
	return []string{
		"Endpoint",
		"writer",
		"maxPCAPLen",
		"logPrefix",
	}
}

func (e *Endpoint) beforeSave() {}

func (e *Endpoint) StateSave(stateSinkObject state.Sink) {
	e.beforeSave()
	stateSinkObject.Save(0, &e.Endpoint)
	stateSinkObject.Save(1, &e.writer)
	stateSinkObject.Save(2, &e.maxPCAPLen)
	stateSinkObject.Save(3, &e.logPrefix)
}

func (e *Endpoint) afterLoad(context.Context) {}

func (e *Endpoint) StateLoad(ctx context.Context, stateSourceObject state.Source) {
	stateSourceObject.Load(0, &e.Endpoint)
	stateSourceObject.Load(1, &e.writer)
	stateSourceObject.Load(2, &e.maxPCAPLen)
	stateSourceObject.Load(3, &e.logPrefix)
}

func init() {
	state.Register((*Endpoint)(nil))
}
