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
	"context"
	"reflect"
	"sort"

	"github.com/metacubex/gvisor/pkg/state/wire"
)

type objectEncodeState struct {
	id objectID

	obj reflect.Value

	encoded wire.Object

	how encodeStrategy

	refs []*wire.Ref

	deferredEntry
}

type encodeState struct {
	ctx context.Context

	w wire.Writer

	types typeEncodeDatabase

	lastID objectID

	values addrSet

	zeroValues map[reflect.Type]*objectEncodeState

	deferred deferredList

	pendingTypes []wire.Type

	pending map[objectID]*objectEncodeState

	encodedStructs map[reflect.Value]*wire.Struct

	stats Stats
}

func isSameSizeParent(parent reflect.Value, childType reflect.Type) bool {
	switch parent.Kind() {
	case reflect.Struct:
		for i := 0; i < parent.NumField(); i++ {
			field := parent.Field(i)
			if field.Type() == childType {
				return true
			}
			if isSameSizeParent(field, childType) {
				return true
			}
		}
		return false
	case reflect.Array:
		return parent.Len() > 0 && isSameSizeParent(parent.Index(0), childType)
	default:
		return false
	}
}

func (es *encodeState) nextID() objectID {
	es.lastID++
	return objectID(es.lastID)
}

var dummyAddr = reflect.ValueOf(new(struct{})).Pointer()

func (es *encodeState) resolve(obj reflect.Value, ref *wire.Ref) {
	addr := obj.Pointer()

	if obj.Kind() == reflect.Map {
		if addr == 0 {
			return
		}
		seg, gap := es.values.Find(addr)
		if seg.Ok() {
			existing := seg.Value()
			if existing.obj.Type() != obj.Type() {
				Failf("overlapping map objects at 0x%x: [new object] %#v [existing object type] %s", addr, obj, existing.obj)
			}

			ref.Root = wire.Uint(existing.id)
			return
		}

		r := addrRange{addr, addr + 1}
		oes := &objectEncodeState{
			id:  es.nextID(),
			obj: obj,
			how: encodeMapAsValue,
		}
		if !raceEnabled {
			es.values.InsertWithoutMergingUnchecked(gap, r, oes)
		} else {
			es.values.Insert(gap, r, oes)
		}
		es.pending[oes.id] = oes
		es.deferred.PushBack(oes)

		ref.Root = wire.Uint(oes.id)
		return
	}

	if obj.Kind() != reflect.Ptr {
		Failf("attempt to record non-map and non-pointer object %#v", obj)
	}

	obj = obj.Elem()

	typ := obj.Type()
	size := typ.Size()
	if size == 0 {
		if addr == dummyAddr {
			oes, ok := es.zeroValues[typ]
			if !ok {
				oes = &objectEncodeState{
					id:  es.nextID(),
					obj: obj,
				}
				es.zeroValues[typ] = oes
				es.pending[oes.id] = oes
				es.deferred.PushBack(oes)
			}

			ref.Root = wire.Uint(oes.id)
			return
		}
		size = 1
	}

	end := addr + size
	r := addrRange{addr, end}
	seg := es.values.LowerBoundSegment(addr)
	var (
		oes *objectEncodeState
		gap addrGapIterator
	)

	if seg.Ok() && seg.Start() < end {
		existing := seg.Value()

		if seg.Range() == r && typ == existing.obj.Type() {
			ref.Root = wire.Uint(existing.id)
			existing.refs = append(existing.refs, ref)
			return
		}

		if seg.Range().IsSupersetOf(r) && (seg.Range() != r || isSameSizeParent(existing.obj, typ)) {
			ref.Root = wire.Uint(existing.id)
			ref.Dots = traverse(existing.obj.Type(), typ, seg.Start(), addr)
			ref.Type = es.findType(existing.obj.Type())
			existing.refs = append(existing.refs, ref)
			return
		}

		oes := &objectEncodeState{
			id:  existing.id,
			obj: obj,
		}
		type elementEncodeState struct {
			addr uintptr
			typ  reflect.Type
			refs []*wire.Ref
		}
		var (
			elems []elementEncodeState
			gap   addrGapIterator
		)
		for {
			if raceEnabled && !r.IsSupersetOf(seg.Range()) {
				Failf("containing object %#v does not contain existing object %#v", obj, existing.obj)
			}
			elems = append(elems, elementEncodeState{
				addr: seg.Start(),
				typ:  existing.obj.Type(),
				refs: existing.refs,
			})
			delete(es.pending, existing.id)
			es.deferred.Remove(existing)
			gap = es.values.Remove(seg)
			seg = gap.NextSegment()
			if !seg.Ok() || seg.Start() >= end {
				break
			}
			existing = seg.Value()
		}
		wt := es.findType(typ)
		for _, elem := range elems {
			dots := traverse(typ, elem.typ, addr, elem.addr)
			for _, ref := range elem.refs {
				ref.Root = wire.Uint(oes.id)
				ref.Dots = append(ref.Dots, dots...)
				ref.Type = wt
			}
			oes.refs = append(oes.refs, elem.refs...)
		}
		if !raceEnabled {
			es.values.InsertWithoutMergingUnchecked(gap, r, oes)
		} else {
			es.values.Insert(gap, r, oes)
		}
		es.pending[oes.id] = oes
		es.deferred.PushBack(oes)
		ref.Root = wire.Uint(oes.id)
		oes.refs = append(oes.refs, ref)
		return
	}

	oes = &objectEncodeState{
		id:  es.nextID(),
		obj: obj,
	}
	if seg.Ok() {
		gap = seg.PrevGap()
	} else {
		gap = es.values.LastGap()
	}
	if !raceEnabled {
		es.values.InsertWithoutMergingUnchecked(gap, r, oes)
	} else {
		es.values.Insert(gap, r, oes)
	}
	es.pending[oes.id] = oes
	es.deferred.PushBack(oes)
	ref.Root = wire.Uint(oes.id)
	oes.refs = append(oes.refs, ref)
}

func traverse(rootType, targetType reflect.Type, rootAddr, targetAddr uintptr) []wire.Dot {
	if targetType == rootType && targetAddr == rootAddr {
		return nil
	}

	switch rootType.Kind() {
	case reflect.Struct:
		offset := targetAddr - rootAddr
		for i := rootType.NumField(); i > 0; i-- {
			field := rootType.Field(i - 1)
			if field.Offset <= offset {
				dots := traverse(field.Type, targetType, rootAddr+field.Offset, targetAddr)
				fieldName := wire.FieldName(field.Name)
				return append(dots, &fieldName)
			}
		}
		Failf("no field in root type %v contains target type %v", rootType, targetType)

	case reflect.Array:
		elemSize := int(rootType.Elem().Size())
		n := int(targetAddr-rootAddr) / elemSize
		if rootType.Len() < n {
			Failf("traversal target of type %v @%x is beyond the end of the array type %v @%x with %v elements",
				targetType, targetAddr, rootType, rootAddr, rootType.Len())
		}
		dots := traverse(rootType.Elem(), targetType, rootAddr+uintptr(n*elemSize), targetAddr)
		return append(dots, wire.Index(n))

	default:
		Failf("traverse failed for root type %v and target type %v", rootType, targetType)
	}
	panic("unreachable")
}

func (es *encodeState) encodeMap(obj reflect.Value, dest *wire.Object) {
	if obj.IsNil() {
		*dest = wire.Nil{}
		return
	}
	l := obj.Len()
	m := &wire.Map{
		Keys:   make([]wire.Object, l),
		Values: make([]wire.Object, l),
	}
	*dest = m
	for i, k := range obj.MapKeys() {
		v := obj.MapIndex(k)
		es.encodeObject(k, encodeAsValue, &m.Keys[i])
		es.encodeObject(v, encodeAsValue, &m.Values[i])
	}
}

type objectEncoder struct {
	es *encodeState

	encoded *wire.Struct
}

func (oe *objectEncoder) save(slot int, obj reflect.Value) {
	fieldValue := oe.encoded.Field(slot)
	oe.es.encodeObject(obj, encodeDefault, fieldValue)
}

func (es *encodeState) encodeStruct(obj reflect.Value, dest *wire.Object) {
	if s, ok := es.encodedStructs[obj]; ok {
		*dest = s
		return
	}
	s := &wire.Struct{}
	*dest = s
	es.encodedStructs[obj] = s

	if !obj.CanAddr() {
		localObj := reflect.New(obj.Type())
		localObj.Elem().Set(obj)
		obj = localObj.Elem()
	}

	te, ok := es.types.Lookup(obj.Type())
	if te == nil {
		if obj.NumField() == 0 {
			s.Alloc(0)
			return
		}
		Failf("struct %T does not implement SaverLoader", obj.Interface())
	}
	if !ok {
		es.pendingTypes = append(es.pendingTypes, te.Type)
	}

	s.TypeID = wire.TypeID(te.ID)
	s.Alloc(len(te.Fields))
	oe := objectEncoder{
		es:      es,
		encoded: s,
	}
	es.stats.start(te.ID)
	defer es.stats.done()
	if sl, ok := obj.Addr().Interface().(SaverLoader); ok {
		sl.StateSave(Sink{internal: oe})
	}
}

func (es *encodeState) encodeArray(obj reflect.Value, dest *wire.Object) {
	l := obj.Len()
	a := &wire.Array{
		Contents: make([]wire.Object, l),
	}
	*dest = a
	for i := 0; i < l; i++ {
		es.encodeObject(obj.Index(i), encodeAsValue, &a.Contents[i])
	}
}

func (es *encodeState) findType(typ reflect.Type) wire.TypeSpec {
	te, ok := es.types.Lookup(typ)
	if te != nil {
		if !ok {
			es.pendingTypes = append(es.pendingTypes, te.Type)
		}
		return wire.TypeID(te.ID)
	}

	switch typ.Kind() {
	case reflect.Ptr:
		return &wire.TypeSpecPointer{
			Type: es.findType(typ.Elem()),
		}
	case reflect.Slice:
		return &wire.TypeSpecSlice{
			Type: es.findType(typ.Elem()),
		}
	case reflect.Array:
		return &wire.TypeSpecArray{
			Count: wire.Uint(typ.Len()),
			Type:  es.findType(typ.Elem()),
		}
	case reflect.Map:
		return &wire.TypeSpecMap{
			Key:   es.findType(typ.Key()),
			Value: es.findType(typ.Elem()),
		}
	default:
		Failf("type %q is not known", typ)
	}
	panic("unreachable")
}

func (es *encodeState) encodeInterface(obj reflect.Value, dest *wire.Object) {
	obj = obj.Elem()
	if !obj.IsValid() {
		*dest = &wire.Interface{
			Type:  wire.TypeSpecNil{},
			Value: wire.Nil{},
		}
		return
	}

	i := &wire.Interface{
		Type: es.findType(obj.Type()),
	}
	*dest = i
	es.encodeObject(obj, encodeAsValue, &i.Value)
}

func isPrimitiveZero(typ reflect.Type) bool {
	switch typ.Kind() {
	case reflect.Ptr:
		return true
	case reflect.Bool:
		return true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return true
	case reflect.Float32, reflect.Float64:
		return true
	case reflect.Complex64, reflect.Complex128:
		return true
	case reflect.String:
		return true
	case reflect.Slice:
		return true
	case reflect.Array:
		return isPrimitiveZero(typ.Elem())
	case reflect.Interface:
		return true
	case reflect.Struct:
		return false
	case reflect.Map:
		return true
	default:
		Failf("unknown type %q", typ.Name())
	}
	panic("unreachable")
}

type encodeStrategy int

const (
	encodeDefault encodeStrategy = iota

	encodeAsValue

	encodeMapAsValue
)

func (es *encodeState) encodeObject(obj reflect.Value, how encodeStrategy, dest *wire.Object) {
	if how == encodeDefault && isPrimitiveZero(obj.Type()) && obj.IsZero() {
		*dest = wire.Nil{}
		return
	}
	switch obj.Kind() {
	case reflect.Ptr:
		r := new(wire.Ref)
		*dest = r
		if obj.IsNil() {
			return
		}
		es.resolve(obj, r)
	case reflect.Bool:
		*dest = wire.Bool(obj.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		*dest = wire.Int(obj.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		*dest = wire.Uint(obj.Uint())
	case reflect.Float32:
		*dest = wire.Float32(obj.Float())
	case reflect.Float64:
		*dest = wire.Float64(obj.Float())
	case reflect.Complex64:
		c := wire.Complex64(obj.Complex())
		*dest = &c
	case reflect.Complex128:
		c := wire.Complex128(obj.Complex())
		*dest = &c
	case reflect.String:
		s := wire.String(obj.String())
		*dest = &s
	case reflect.Array:
		es.encodeArray(obj, dest)
	case reflect.Slice:
		s := &wire.Slice{
			Capacity: wire.Uint(obj.Cap()),
			Length:   wire.Uint(obj.Len()),
		}
		*dest = s
		if obj.IsNil() {
			return
		}
		es.resolve(arrayFromSlice(obj), &s.Ref)
	case reflect.Interface:
		es.encodeInterface(obj, dest)
	case reflect.Struct:
		es.encodeStruct(obj, dest)
	case reflect.Map:
		if how == encodeMapAsValue {
			es.encodeMap(obj, dest)
			return
		}
		r := new(wire.Ref)
		*dest = r
		es.resolve(obj, r)
	default:
		Failf("unknown object %#v", obj.Interface())
		panic("unreachable")
	}
}

func (es *encodeState) Save(obj reflect.Value) {
	es.stats.init()
	defer es.stats.fini(func(id typeID) string {
		return es.pendingTypes[id-1].Name
	})

	var root wire.Ref
	es.resolve(obj.Addr(), &root)

	var oes *objectEncodeState
	if err := safely(func() {
		for oes = es.deferred.Front(); oes != nil; oes = es.deferred.Front() {
			es.deferred.Remove(oes)
			es.encodeObject(oes.obj, oes.how, &oes.encoded)
		}
	}); err != nil {
		if oes != nil && oes.obj.IsValid() {
			Failf("encoding error: %w\nfor object %#v", err, oes.obj.Interface())
		}
		Failf("encoding error: %w", err)
	}

	if len(es.pending) == 0 {
		Failf("pending is empty?")
	}

	if err := WriteHeader(&es.w, uint64(len(es.pending)), true); err != nil {
		Failf("error writing header: %w", err)
	}

	if err := safely(func() {
		for _, wt := range es.pendingTypes {
			wire.Save(&es.w, &wt)
		}
		ids := make([]objectID, 0, len(es.pending))
		for id := range es.pending {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool {
			return ids[i] < ids[j]
		})
		for _, id := range ids {
			oes = nil
			wire.Save(&es.w, wire.Uint(id))
			oes = es.pending[id]
			wire.Save(&es.w, oes.encoded)
		}
	}); err != nil {
		if oes != nil {
			Failf("error serializing object %#v: %w", oes.encoded, err)
		} else {
			Failf("error serializing type or ID: %w", err)
		}
	}
}

const objectFlag uint64 = 1 << 63

func WriteHeader(w *wire.Writer, length uint64, object bool) error {
	if length&objectFlag != 0 {
		Failf("impossibly huge length: %d", length)
	}
	if object {
		length |= objectFlag
	}

	return safely(func() {
		wire.SaveUint(w, length)
	})
}

type addrSetFunctions struct{}

func (addrSetFunctions) MinKey() uintptr {
	return 0
}

func (addrSetFunctions) MaxKey() uintptr {
	return ^uintptr(0)
}

func (addrSetFunctions) ClearValue(val **objectEncodeState) {
	*val = nil
}

func (addrSetFunctions) Merge(r1 addrRange, val1 *objectEncodeState, r2 addrRange, val2 *objectEncodeState) (*objectEncodeState, bool) {
	if val1.obj == val2.obj {
		Failf("unexpected merge in addrSet @ %v and %v: %#v and %#v", r1, r2, val1.obj, val2.obj)
	}
	return val1, false
}

func (addrSetFunctions) Split(r addrRange, val *objectEncodeState, _ uintptr) (*objectEncodeState, *objectEncodeState) {
	Failf("unexpected split in addrSet @ %v: %#v", r, val.obj)
	panic("unreachable")
}
