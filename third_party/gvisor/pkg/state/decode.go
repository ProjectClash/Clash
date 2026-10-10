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

package state

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"reflect"

	"github.com/metacubex/gvisor/pkg/state/wire"
)

type internalCallback interface {
	source() *objectDecodeState

	callbackRun(ds *decodeState)
}

type userCallback func()

func (userCallback) source() *objectDecodeState {
	return nil
}

func (uc userCallback) callbackRun(*decodeState) {
	uc()
}

type objectDecodeState struct {
	id objectID

	typ typeID

	obj reflect.Value

	blockedBy int

	callbacksInline [2]internalCallback

	callbacks []internalCallback

	pendingEntry odsListElem
	leafEntry    odsListElem
}

type odsListElem struct {
	ods *objectDecodeState
	odsEntry
}

func (ods *objectDecodeState) addCallback(ic internalCallback) {
	if ods.callbacks == nil {
		ods.callbacks = ods.callbacksInline[:0]
	}
	ods.callbacks = append(ods.callbacks, ic)
}

func (ods *objectDecodeState) findCycleFor(target *objectDecodeState) []*objectDecodeState {
	for _, ic := range ods.callbacks {
		other := ic.source()
		if other != nil && other == target {
			return []*objectDecodeState{target}
		} else if childList := other.findCycleFor(target); childList != nil {
			return append(childList, other)
		}
	}

	Failf("no deadlock found?")
	panic("unreachable")
}

func (ods *objectDecodeState) findCycle() []*objectDecodeState {
	return append(ods.findCycleFor(ods), ods)
}

func (ods *objectDecodeState) source() *objectDecodeState {
	return ods
}

func (ods *objectDecodeState) callbackRun(ds *decodeState) {
	ods.blockedBy--
	if ods.blockedBy == 0 {
		ds.leaves.PushBack(&ods.leafEntry)
	} else if ods.blockedBy < 0 {
		Failf("object %d has negative blockedBy: %d", ods.id, ods.blockedBy)
	}
}

type decodeState struct {
	ctx context.Context

	r wire.Reader

	types typeDecodeDatabase

	objectsByID []*objectDecodeState

	deferred map[objectID]wire.Object

	pending odsList

	leaves odsList

	stats Stats
}

func (ds *decodeState) lookup(id objectID) *objectDecodeState {
	if len(ds.objectsByID) < int(id) {
		return nil
	}
	return ds.objectsByID[id-1]
}

func (ds *decodeState) checkComplete(ods *objectDecodeState) bool {
	if ods.blockedBy > 0 {
		return false
	}

	if ods.callbacks != nil && ods.typ != 0 {
		ds.stats.start(ods.typ)
		defer ds.stats.done()
	}

	for _, ic := range ods.callbacks {
		ic.callbackRun(ds)
	}

	ods.callbacks = nil
	ds.pending.Remove(&ods.pendingEntry)

	return true
}

func (ds *decodeState) wait(waiter *objectDecodeState, id objectID, callback func()) {
	switch id {
	case waiter.id:
		fallthrough
	case 1:
		if callback != nil {
			callback()
		}
		return
	}

	waiter.blockedBy++
	if waiter.blockedBy == 1 {
		ds.leaves.Remove(&waiter.leafEntry)
	}

	other := ds.lookup(id)
	if callback != nil {
		other.addCallback(userCallback(callback))
	}

	other.addCallback(waiter)
}

func (ds *decodeState) waitObject(ods *objectDecodeState, encoded wire.Object, callback func()) {
	if rv, ok := encoded.(*wire.Ref); ok && rv.Root != 0 {
		ds.wait(ods, objectID(rv.Root), callback)
	} else if sv, ok := encoded.(*wire.Slice); ok && sv.Ref.Root != 0 {
		ds.wait(ods, objectID(sv.Ref.Root), callback)
	} else if iv, ok := encoded.(*wire.Interface); ok {
		ds.waitObject(ods, iv.Value, callback)
	} else if callback != nil {
		callback()
	}
}

func walkChild(path []wire.Dot, obj reflect.Value) reflect.Value {
	for i := len(path) - 1; i >= 0; i-- {
		switch pc := path[i].(type) {
		case *wire.FieldName:
			if obj.Kind() != reflect.Struct {
				Failf("next component in child path is a field name, but the current object is not a struct. Path: %v, current obj: %#v", path, obj)
			}
			obj = obj.FieldByName(string(*pc))
		case wire.Index:
			if obj.Kind() != reflect.Array {
				Failf("next component in child path is an array index, but the current object is not an array. Path: %v, current obj: %#v", path, obj)
			}
			obj = obj.Index(int(pc))
		default:
			panic("unreachable: switch should be exhaustive")
		}
	}
	return obj
}

func (ds *decodeState) growObjectsByID(id objectID) {
	if len(ds.objectsByID) < int(id) {
		ds.objectsByID = append(ds.objectsByID, make([]*objectDecodeState, int(id)-len(ds.objectsByID))...)
	}
}

func (ds *decodeState) addObject(id objectID, obj reflect.Value) *objectDecodeState {
	ods := &objectDecodeState{
		id:  id,
		obj: obj,
	}
	ods.pendingEntry.ods = ods
	ods.leafEntry.ods = ods
	ds.growObjectsByID(id)
	ds.objectsByID[id-1] = ods
	ds.pending.PushBack(&ods.pendingEntry)
	ds.leaves.PushBack(&ods.leafEntry)
	return ods
}

func (ds *decodeState) register(r *wire.Ref, typ reflect.Type) reflect.Value {
	id := objectID(r.Root)

	ds.growObjectsByID(id)
	ods := ds.objectsByID[id-1]
	if ods != nil {
		return walkChild(r.Dots, ods.obj)
	}

	if len(r.Dots) != 0 {
		typ = ds.findType(r.Type)
	}
	v := reflect.New(typ)
	ods = ds.addObject(id, v.Elem())

	if encoded, ok := ds.deferred[id]; ok {
		delete(ds.deferred, id)
		ds.decodeObject(ods, ods.obj, encoded)
	}

	return walkChild(r.Dots, ods.obj)
}

type objectDecoder struct {
	ds *decodeState

	ods *objectDecodeState

	rte *reconciledTypeEntry

	encoded *wire.Struct
}

func (od *objectDecoder) load(slot int, objPtr reflect.Value, wait bool, fn func()) {
	v := *od.encoded.Field(od.rte.FieldOrder[slot])
	od.ds.decodeObject(od.ods, objPtr.Elem(), v)
	if wait {
		od.ds.waitObject(od.ods, v, fn)
	}
}

func (od *objectDecoder) afterLoad(fn func()) {
	od.ods.addCallback(userCallback(fn))
}

func (ds *decodeState) decodeStruct(ods *objectDecodeState, obj reflect.Value, encoded *wire.Struct) {
	if encoded.TypeID == 0 {
		if encoded.Fields() == 0 && obj.NumField() == 0 {
			return
		}

		Failf("empty struct on wire %#v has field mismatch with type %q", encoded, obj.Type().Name())
	}

	rte := ds.types.Lookup(typeID(encoded.TypeID), obj.Type())
	ods.typ = typeID(encoded.TypeID)

	od := objectDecoder{
		ds:      ds,
		ods:     ods,
		rte:     rte,
		encoded: encoded,
	}
	ds.stats.start(ods.typ)
	defer ds.stats.done()
	if sl, ok := obj.Addr().Interface().(SaverLoader); ok {
		sl.StateLoad(ds.ctx, Source{internal: od})
	}
}

func (ds *decodeState) decodeMap(ods *objectDecodeState, obj reflect.Value, encoded *wire.Map) {
	if obj.IsNil() {
		obj.Set(reflect.MakeMap(obj.Type()))
	}
	for i := 0; i < len(encoded.Keys); i++ {
		kv := reflect.New(obj.Type().Key()).Elem()
		vv := reflect.New(obj.Type().Elem()).Elem()
		ds.decodeObject(ods, kv, encoded.Keys[i])
		ds.decodeObject(ods, vv, encoded.Values[i])
		ds.waitObject(ods, encoded.Keys[i], nil)
		ds.waitObject(ods, encoded.Values[i], nil)

		obj.SetMapIndex(kv, vv)
	}
}

func (ds *decodeState) decodeArray(ods *objectDecodeState, obj reflect.Value, encoded *wire.Array) {
	if len(encoded.Contents) != obj.Len() {
		Failf("mismatching array length expect=%d, actual=%d", obj.Len(), len(encoded.Contents))
	}
	for i := 0; i < len(encoded.Contents); i++ {
		ds.decodeObject(ods, obj.Index(i), encoded.Contents[i])
		ds.waitObject(ods, encoded.Contents[i], nil)
	}
}

func (ds *decodeState) findType(t wire.TypeSpec) reflect.Type {
	switch x := t.(type) {
	case wire.TypeID:
		typ := ds.types.LookupType(typeID(x))
		rte := ds.types.Lookup(typeID(x), typ)
		return rte.LocalType
	case *wire.TypeSpecPointer:
		return reflect.PtrTo(ds.findType(x.Type))
	case *wire.TypeSpecArray:
		return reflect.ArrayOf(int(x.Count), ds.findType(x.Type))
	case *wire.TypeSpecSlice:
		return reflect.SliceOf(ds.findType(x.Type))
	case *wire.TypeSpecMap:
		return reflect.MapOf(ds.findType(x.Key), ds.findType(x.Value))
	default:
		Failf("unknown type %#v", t)
	}
	panic("unreachable")
}

func (ds *decodeState) decodeInterface(ods *objectDecodeState, obj reflect.Value, encoded *wire.Interface) {
	if _, ok := encoded.Type.(wire.TypeSpecNil); ok {
		ds.decodeObject(ods, obj, encoded.Value)
		return
	}

	typ := ds.findType(encoded.Type)

	origObj := obj
	obj = reflect.New(typ).Elem()
	defer origObj.Set(obj)

	ds.decodeObject(ods, obj, encoded.Value)
}

func isFloatEq(x float64, y float64) bool {
	switch {
	case math.IsNaN(x):
		return math.IsNaN(y)
	case math.IsInf(x, 1):
		return math.IsInf(y, 1)
	case math.IsInf(x, -1):
		return math.IsInf(y, -1)
	default:
		return x == y
	}
}

func isComplexEq(x complex128, y complex128) bool {
	return isFloatEq(real(x), real(y)) && isFloatEq(imag(x), imag(y))
}

func (ds *decodeState) decodeObject(ods *objectDecodeState, obj reflect.Value, encoded wire.Object) {
	switch x := encoded.(type) {
	case wire.Nil:
	case *wire.Ref:
		if id := objectID(x.Root); id == 0 {
			return
		}

		if obj.Kind() == reflect.Map {
			v := ds.register(x, obj.Type())
			if v.IsNil() {
				v.Set(reflect.MakeMap(v.Type()))
			}
			obj.Set(v)
			return
		}

		v := ds.register(x, obj.Type().Elem())
		obj.Set(reflectValueRWAddr(v))
	case wire.Bool:
		obj.SetBool(bool(x))
	case wire.Int:
		obj.SetInt(int64(x))
		if obj.Int() != int64(x) {
			Failf("signed integer truncated from %v to %v", int64(x), obj.Int())
		}
	case wire.Uint:
		obj.SetUint(uint64(x))
		if obj.Uint() != uint64(x) {
			Failf("unsigned integer truncated from %v to %v", uint64(x), obj.Uint())
		}
	case wire.Float32:
		obj.SetFloat(float64(x))
	case wire.Float64:
		obj.SetFloat(float64(x))
		if !isFloatEq(obj.Float(), float64(x)) {
			Failf("floating point number truncated from %v to %v", float64(x), obj.Float())
		}
	case *wire.Complex64:
		obj.SetComplex(complex128(*x))
	case *wire.Complex128:
		obj.SetComplex(complex128(*x))
		if !isComplexEq(obj.Complex(), complex128(*x)) {
			Failf("complex number truncated from %v to %v", complex128(*x), obj.Complex())
		}
	case *wire.String:
		obj.SetString(string(*x))
	case *wire.Slice:
		if id := objectID(x.Ref.Root); id == 0 {
			return
		}
		typ := reflect.ArrayOf(int(x.Capacity), obj.Type().Elem())
		v := ds.register(&x.Ref, typ)
		obj.Set(reflectValueRWSlice3(v, 0, int(x.Length), int(x.Capacity)))
	case *wire.Array:
		ds.decodeArray(ods, obj, x)
	case *wire.Struct:
		ds.decodeStruct(ods, obj, x)
	case *wire.Map:
		ds.decodeMap(ods, obj, x)
	case *wire.Interface:
		ds.decodeInterface(ods, obj, x)
	default:
		Failf("unknown object %#v for %q", encoded, obj.Type().Name())
	}
}

func (ds *decodeState) Load(obj reflect.Value) {
	ds.stats.init()
	defer ds.stats.fini(func(id typeID) string {
		return ds.types.LookupName(id)
	})

	_ = ds.addObject(1, obj)

	numObjects, object, err := ReadHeader(&ds.r)
	if err != nil {
		Failf("header error: %w", err)
	}
	if !object {
		Failf("object missing")
	}

	var (
		encoded wire.Object
		ods     *objectDecodeState
		id      objectID
	)
	if err := safely(func() {
		for i := uint64(0); i < numObjects; {
			encoded = wire.Load(&ds.r)
			switch we := encoded.(type) {
			case *wire.Type:
				ds.types.Register(we)
				encoded = nil
				continue
			case wire.Uint:
				id = objectID(we)
				i++
				encoded = wire.Load(&ds.r)
				ods = ds.lookup(id)
				if ods != nil {
					ds.decodeObject(ods, ods.obj, encoded)
				} else {
					ds.deferred[id] = encoded
				}
				ods = nil
				encoded = nil
			default:
				Failf("wanted type or object ID, got %T", encoded)
			}
		}
	}); err != nil {
		if ods != nil {
			Failf("error decoding object ID %d (%T) from %#v: %w", id, ods.obj.Interface(), encoded, err)
		} else if encoded != nil {
			Failf("error decoding from %#v: %w", encoded, err)
		} else {
			Failf("general decoding error: %w", err)
		}
	}

	numDeferred := 0
	for id, encoded := range ds.deferred {
		numDeferred++
		if s, ok := encoded.(*wire.Struct); ok && s.TypeID != 0 {
			typ := ds.types.LookupType(typeID(s.TypeID))
			Failf("unused deferred object: ID %d, type %v", id, typ)
		} else {
			Failf("unused deferred object: ID %d, %#v", id, encoded)
		}
	}
	if numDeferred != 0 {
		Failf("still had %d deferred objects", numDeferred)
	}

	if err := safely(func() {
		for elem := ds.leaves.Front(); elem != nil; elem = elem.Next() {
			ods = elem.ods
			ds.checkComplete(elem.ods)
		}
	}); err != nil {
		Failf("error executing callbacks: %w\nfor object %#v", err, ods.obj.Interface())
	}

	if elem := ds.pending.Front(); elem != nil {
		cycle := elem.ods.findCycle()
		var buf bytes.Buffer
		buf.WriteString("dependency cycle: {")
		for i, cycleOS := range cycle {
			if i > 0 {
				buf.WriteString(" => ")
			}
			fmt.Fprintf(&buf, "%q", cycleOS.obj.Type())
		}
		buf.WriteString("}")
		Failf("incomplete graph: %s", buf.String())
	}
}

func ReadHeader(r *wire.Reader) (length uint64, object bool, err error) {
	err = safely(func() {
		length = wire.LoadUint(r)
	})
	if err != nil {
		if sErr, ok := err.(*ErrState); ok {
			return 0, false, sErr.Unwrap()
		}
	}

	object = length&objectFlag != 0
	length &^= objectFlag
	return
}
