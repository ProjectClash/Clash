package net

import "testing"

type valueLayer struct {
	inner any
}

func TestSameLayerDoesNotPanicOnALayerThatCannotBeCompared(t *testing.T) {
	layer := valueLayer{inner: []byte("not comparable")}
	var same bool
	panicked := func() (out bool) {
		defer func() {
			if recover() != nil {
				out = true
			}
		}()
		same = sameLayer(layer, layer)
		return false
	}()
	if panicked {
		t.Fatal("sameLayer panicked on a layer == cannot compare")
	}
	if same {
		t.Fatal("two uncomparable layers were taken for one")
	}
	pointer := &valueLayer{inner: []byte("x")}
	if !sameLayer(pointer, pointer) {
		t.Fatal("one pointer layer reached by both walks is not the same layer")
	}
}
