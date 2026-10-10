package clash

import (
	"fmt"
	"strings"

	"go.yaml.in/yaml/v3"
)

const (
	astralStandInFirst = 0xE000
	astralStandInLast  = 0xF8FF
)

func isAstralStandIn(r rune) bool { return r >= astralStandInFirst && r <= astralStandInLast }

type astralStandIns struct {
	to, back map[rune]rune
}

func newAstralStandIns(texts func(yield func(string))) *astralStandIns {
	used := map[rune]bool{}
	var astral []rune
	seen := map[rune]bool{}
	texts(func(text string) {
		for _, r := range text {
			switch {
			case isAstralStandIn(r):
				used[r] = true
			case r > 0xFFFF && !seen[r]:
				seen[r] = true
				astral = append(astral, r)
			}
		}
	})
	if len(astral) == 0 {
		return nil
	}
	standIns := &astralStandIns{to: map[rune]rune{}, back: map[rune]rune{}}
	next := rune(astralStandInFirst)
	for _, r := range astral {
		for next <= astralStandInLast && used[next] {
			next++
		}
		if next > astralStandInLast {
			return nil
		}
		standIns.to[r], standIns.back[next] = next, r
		next++
	}
	return standIns
}

func (s *astralStandIns) standIn(text string) string {
	if s == nil {
		return text
	}
	return strings.Map(func(r rune) rune {
		if standIn, ok := s.to[r]; ok {
			return standIn
		}
		return r
	}, text)
}

func (s *astralStandIns) restore(text string) string {
	if s == nil {
		return text
	}
	return strings.Map(func(r rune) rune {
		if original, ok := s.back[r]; ok {
			return original
		}
		return r
	}, text)
}

func (s *astralStandIns) escapedIn(text string) bool {
	if s == nil {
		return false
	}
	for standIn := range s.back {
		if strings.Contains(text, fmt.Sprintf(`\u%04X`, standIn)) {
			return true
		}
	}
	return false
}

func standInAstralInNode(root *yaml.Node) *astralStandIns {
	var visit func(*yaml.Node, func(string))
	visit = func(node *yaml.Node, yield func(string)) {
		for _, text := range []string{node.Value, node.Anchor, node.Tag, node.HeadComment, node.LineComment, node.FootComment} {
			yield(text)
		}
		for _, child := range node.Content {
			visit(child, yield)
		}
	}
	standIns := newAstralStandIns(func(yield func(string)) { visit(root, yield) })
	if standIns == nil {
		return nil
	}
	var write func(*yaml.Node)
	write = func(node *yaml.Node) {
		node.Value = standIns.standIn(node.Value)
		for _, child := range node.Content {
			write(child)
		}
	}
	write(root)
	return standIns
}

func (s *astralStandIns) restoreInNode(root *yaml.Node) {
	if s == nil {
		return
	}
	var write func(*yaml.Node)
	write = func(node *yaml.Node) {
		node.Value = s.restore(node.Value)
		for _, child := range node.Content {
			write(child)
		}
	}
	write(root)
}

func standInAstralInValue(value any) (any, *astralStandIns) {
	var visit func(any, func(string))
	visit = func(value any, yield func(string)) {
		switch v := value.(type) {
		case string:
			yield(v)
		case map[string]any:
			for key, item := range v {
				yield(key)
				visit(item, yield)
			}
		case []any:
			for _, item := range v {
				visit(item, yield)
			}
		}
	}
	standIns := newAstralStandIns(func(yield func(string)) { visit(value, yield) })
	if standIns == nil {
		return value, nil
	}
	var copyOf func(any) any
	copyOf = func(value any) any {
		switch v := value.(type) {
		case string:
			return standIns.standIn(v)
		case map[string]any:
			out := make(map[string]any, len(v))
			for key, item := range v {
				out[standIns.standIn(key)] = copyOf(item)
			}
			return out
		case []any:
			out := make([]any, len(v))
			for i, item := range v {
				out[i] = copyOf(item)
			}
			return out
		}
		return value
	}
	return copyOf(value), standIns
}

func copyYAMLNode(node *yaml.Node) *yaml.Node {
	copied := *node
	copied.Content = make([]*yaml.Node, len(node.Content))
	for i, child := range node.Content {
		copied.Content[i] = copyYAMLNode(child)
	}
	return &copied
}
