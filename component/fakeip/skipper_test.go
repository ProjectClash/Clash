package fakeip

import (
	"testing"

	"github.com/ProjectClash/Clash/component/trie"
	C "github.com/ProjectClash/Clash/constant"

	"github.com/stretchr/testify/assert"
)

func TestSkipper_BlackList(t *testing.T) {
	var builder trie.DomainSetBuilder
	assert.NoError(t, builder.Insert("example.com"))
	assert.False(t, builder.IsEmpty())
	skipper := &Skipper{
		Host: []C.DomainMatcher{builder.Build()},
	}
	assert.True(t, skipper.ShouldSkipped("example.com"))
	assert.False(t, skipper.ShouldSkipped("foo.com"))
	assert.False(t, skipper.shouldSkipped("baz.com"))
}

func TestSkipper_WhiteList(t *testing.T) {
	var builder trie.DomainSetBuilder
	assert.NoError(t, builder.Insert("example.com"))
	assert.False(t, builder.IsEmpty())
	skipper := &Skipper{
		Host: []C.DomainMatcher{builder.Build()},
		Mode: C.FilterWhiteList,
	}
	assert.False(t, skipper.ShouldSkipped("example.com"))
	assert.True(t, skipper.ShouldSkipped("foo.com"))
	assert.True(t, skipper.ShouldSkipped("baz.com"))
}
