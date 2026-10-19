// Copyright 2023 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.


package http

import (
	"strings"
)

type routingNode struct {
	pattern *pattern
	handler Handler

	children   mapping[string, *routingNode]
	multiChild *routingNode
	emptyChild *routingNode
}

func (root *routingNode) addPattern(p *pattern, h Handler) {
	n := root.addChild(p.host)
	n = n.addChild(p.method)
	n.addSegments(p.segments, p, h)
}

func (n *routingNode) addSegments(segs []segment, p *pattern, h Handler) {
	if len(segs) == 0 {
		n.set(p, h)
		return
	}
	seg := segs[0]
	if seg.multi {
		if len(segs) != 1 {
			panic("multi wildcard not last")
		}
		c := &routingNode{}
		n.multiChild = c
		c.set(p, h)
	} else if seg.wild {
		n.addChild("").addSegments(segs[1:], p, h)
	} else {
		n.addChild(seg.s).addSegments(segs[1:], p, h)
	}
}

func (n *routingNode) set(p *pattern, h Handler) {
	if n.pattern != nil || n.handler != nil {
		panic("non-nil leaf fields")
	}
	n.pattern = p
	n.handler = h
}

func (n *routingNode) addChild(key string) *routingNode {
	if key == "" {
		if n.emptyChild == nil {
			n.emptyChild = &routingNode{}
		}
		return n.emptyChild
	}
	if c := n.findChild(key); c != nil {
		return c
	}
	c := &routingNode{}
	n.children.add(key, c)
	return c
}

func (n *routingNode) findChild(key string) *routingNode {
	if key == "" {
		return n.emptyChild
	}
	r, _ := n.children.find(key)
	return r
}

func (root *routingNode) match(host, method, path string) (*routingNode, []string) {
	if host != "" {
		if l, m := root.findChild(host).matchMethodAndPath(method, path); l != nil {
			return l, m
		}
	}
	return root.emptyChild.matchMethodAndPath(method, path)
}

func (n *routingNode) matchMethodAndPath(method, path string) (*routingNode, []string) {
	if n == nil {
		return nil, nil
	}
	if l, m := n.findChild(method).matchPath(path, nil); l != nil {
		return l, m
	}
	if method == "HEAD" {
		if l, m := n.findChild("GET").matchPath(path, nil); l != nil {
			return l, m
		}
	}
	return n.emptyChild.matchPath(path, nil)
}

func (n *routingNode) matchPath(path string, matches []string) (*routingNode, []string) {
	if n == nil {
		return nil, nil
	}
	if path == "" {
		if n.pattern == nil {
			return nil, nil
		}
		return n, matches
	}
	seg, rest := firstSegment(path)
	if n, m := n.findChild(seg).matchPath(rest, matches); n != nil {
		return n, m
	}
	if seg != "/" {
		if n, m := n.emptyChild.matchPath(rest, append(matches, seg)); n != nil {
			return n, m
		}
	}
	if c := n.multiChild; c != nil {
		if c.pattern.lastSegment().s != "" {
			matches = append(matches, pathUnescape(path[1:]))
		}
		return c, matches
	}
	return nil, nil
}

func firstSegment(path string) (seg, rest string) {
	if path == "/" {
		return "/", ""
	}
	path = path[1:]
	i := strings.IndexByte(path, '/')
	if i < 0 {
		i = len(path)
	}
	return pathUnescape(path[:i]), path[i:]
}

func (root *routingNode) matchingMethods(host, path string, methodSet map[string]bool) {
	if host != "" {
		root.findChild(host).matchingMethodsPath(path, methodSet)
	}
	root.emptyChild.matchingMethodsPath(path, methodSet)
	if methodSet["GET"] {
		methodSet["HEAD"] = true
	}
}

func (n *routingNode) matchingMethodsPath(path string, set map[string]bool) {
	if n == nil {
		return
	}
	n.children.eachPair(func(method string, c *routingNode) bool {
		if p, _ := c.matchPath(path, nil); p != nil {
			set[method] = true
		}
		return true
	})
}
