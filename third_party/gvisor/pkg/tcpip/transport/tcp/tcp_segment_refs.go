package tcp

import (
	"context"
	"fmt"

	"github.com/metacubex/gvisor/pkg/atomicbitops"
	"github.com/metacubex/gvisor/pkg/refs"
)

const segmentenableLogging = false

var segmentobj *segment

type segmentRefs struct {
	refCount atomicbitops.Int64
}

func (r *segmentRefs) InitRefs() {

	r.refCount.RacyStore(1)
	refs.Register(r)
}

func (r *segmentRefs) RefType() string {
	return fmt.Sprintf("%T", segmentobj)[1:]
}

func (r *segmentRefs) LeakMessage() string {
	return fmt.Sprintf("[%s %p] reference count of %d instead of 0", r.RefType(), r, r.ReadRefs())
}

func (r *segmentRefs) LogRefs() bool {
	return segmentenableLogging
}

func (r *segmentRefs) ReadRefs() int64 {
	return r.refCount.Load()
}

// IncRef implements refs.RefCounter.IncRef.
//
//go:nosplit
func (r *segmentRefs) IncRef() {
	v := r.refCount.Add(1)
	if segmentenableLogging {
		refs.LogIncRef(r, v)
	}
	if v <= 1 {
		panic(fmt.Sprintf("Incrementing non-positive count %p on %s", r, r.RefType()))
	}
}

// TryIncRef implements refs.TryRefCounter.TryIncRef.
//
// To do this safely without a loop, a speculative reference is first acquired
// on the object. This allows multiple concurrent TryIncRef calls to distinguish
// other TryIncRef calls from genuine references held.
//
//go:nosplit
func (r *segmentRefs) TryIncRef() bool {
	const speculativeRef = 1 << 32
	if v := r.refCount.Add(speculativeRef); int32(v) == 0 {

		r.refCount.Add(-speculativeRef)
		return false
	}

	v := r.refCount.Add(-speculativeRef + 1)
	if segmentenableLogging {
		refs.LogTryIncRef(r, v)
	}
	return true
}

// DecRef implements refs.RefCounter.DecRef.
//
// Note that speculative references are counted here. Since they were added
// prior to real references reaching zero, they will successfully convert to
// real references. In other words, we see speculative references only in the
// following case:
//
//	A: TryIncRef [speculative increase => sees non-negative references]
//	B: DecRef [real decrease]
//	A: TryIncRef [transform speculative to real]
//
//go:nosplit
func (r *segmentRefs) DecRef(destroy func()) {
	v := r.refCount.Add(-1)
	if segmentenableLogging {
		refs.LogDecRef(r, v)
	}
	switch {
	case v < 0:
		panic(fmt.Sprintf("Decrementing non-positive ref count %p, owned by %s", r, r.RefType()))

	case v == 0:
		refs.Unregister(r)

		if destroy != nil {
			destroy()
		}
	}
}

func (r *segmentRefs) afterLoad(context.Context) {
	if r.ReadRefs() > 0 {
		refs.Register(r)
	}
}
