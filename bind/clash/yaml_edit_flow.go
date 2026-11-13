package clash

import (
	"encoding/json"
	"strings"

	"go.yaml.in/yaml/v3"
)

func (d *yamlEditDocument) flowAncestor(path []any) (k int, flow *yaml.Node, ok bool) {
	node := d.root
	if node == nil || node.Style&yaml.FlowStyle != 0 {
		return 0, nil, false
	}
	for step := 0; step < len(path)-1; step++ {
		child := flowChild(node, path[step])
		if child == nil || child.Kind == yaml.AliasNode {
			return 0, nil, false
		}
		if child.Style&yaml.FlowStyle != 0 {
			return step + 1, child, true
		}
		node = child
	}
	return 0, nil, false
}

func (d *yamlEditDocument) applyInFlow(path []any, k int, op string, value any) *yamlEditError {
	if op != "set" && op != "insert" && op != "delete" {
		return refuseEdit("unsupportedStyle", "%s inside a flow collection", op)
	}
	outer, refusal := d.locate(path[:k])
	if refusal != nil {
		return refusal
	}
	if refusesAnchors(outer.node) {
		return refuseEdit("anchor", "the flow collection holds an anchor, alias or merge key")
	}
	container := outer.node
	for _, part := range path[k : len(path)-1] {
		container = flowChild(container, part)
		if container == nil {
			return refuseEdit("notFound", "no such entry inside the flow collection")
		}
	}
	first := outer.node.Line - 1
	if first < 0 || first >= len(d.lines) {
		return refuseEdit("unsupportedStyle", "the flow collection could not be located")
	}
	var (
		window []string
		text   string
		at     func(*yaml.Node) int
	)
	read := func(count int) {
		window = d.lines[first : first+count]
		text = strings.Join(window, "\n")
		offsets := lineOffsets(window)
		lines := window
		starts := make([][]int, len(lines))
		at = func(node *yaml.Node) int {
			line := node.Line - 1 - first
			if line < 0 || line >= len(lines) || node.Column < 1 {
				return -1
			}
			if starts[line] == nil {
				starts[line] = make([]int, 0, len(lines[line])+1)
				for offset := range lines[line] {
					starts[line] = append(starts[line], offset)
				}
				starts[line] = append(starts[line], len(lines[line]))
			}
			column := min(node.Column-1, len(starts[line])-1)
			return offsets[line] + starts[line][column]
		}
	}
	outerEnd := -1
	for span := 1; outerEnd < 0; span *= 2 {
		read(min(span, len(d.lines)-first))
		if end, closed := flowNodeEnd(text, outer.node, at); closed {
			outerEnd = end
		} else if first+span >= len(d.lines) {
			return refuseEdit("unsupportedStyle", "the flow collection could not be located")
		}
	}
	if closing := strings.Count(text[:outerEnd], "\n") + 1; closing < len(window) {
		read(closing)
	}
	replace := func(edited string) {
		lines := make([]string, 0, len(d.lines)+strings.Count(edited, "\n")-len(window)+1)
		lines = append(lines, d.lines[:first]...)
		lines = append(lines, strings.Split(edited, "\n")...)
		d.lines = append(lines, d.lines[first+len(window):]...)
	}
	outerStart := flowContentStart(text, at(outer.node))
	if outerStart < 0 {
		return refuseEdit("unsupportedStyle", "the flow collection could not be located")
	}
	filler, located := flowFiller(text, outer.node, at, outerStart, outerEnd)
	if !located {
		return refuseEdit("unsupportedStyle", "a value inside the flow collection could not be located")
	}
	if filler.explicitKey {
		return refuseEdit("unsupportedStyle", "the flow collection has an explicit `?` key")
	}
	start := flowContentStart(text, at(container))
	if start < 0 || (text[start] != '{' && text[start] != '[') {
		return refuseEdit("unsupportedStyle", "the flow collection could not be located")
	}
	containerEnd, located := flowNodeEnd(text, container, at)
	if !located {
		return refuseEdit("unsupportedStyle", "the flow collection could not be located")
	}
	if op != "set" && filler.commentIn(start, containerEnd) {
		return refuseEdit("unsupportedStyle", "the flow collection holds a comment")
	}
	commentOnLines := func(from, to int) bool {
		lineStart := strings.LastIndexByte(text[:from], '\n') + 1
		lineEnd := len(text)
		if newline := strings.IndexByte(text[to:], '\n'); newline >= 0 {
			lineEnd = to + newline
		}
		if filler.commentIn(lineStart, lineEnd) {
			return true
		}
		return outerEnd >= lineStart && outerEnd <= lineEnd && strings.Contains(text[outerEnd:lineEnd], "#")
	}
	entries, ok := flowEntries(text, container, at)
	if !ok {
		return refuseEdit("unsupportedStyle", "an entry of the flow collection could not be located")
	}
	last := path[len(path)-1]
	index := -1
	switch part := last.(type) {
	case string:
		if container.Kind != yaml.MappingNode {
			return refuseEdit("typeMismatch", "path element %d is a key but the node is not a mapping", len(path)-1)
		}
		for i := 0; i+1 < len(container.Content); i += 2 {
			if container.Content[i].Value == part {
				index = i / 2
				break
			}
		}
	case float64:
		if container.Kind != yaml.SequenceNode {
			return refuseEdit("typeMismatch", "path element %d is an index but the node is not a list", len(path)-1)
		}
		index = int(part)
		if index < 0 || index > len(entries) || (index == len(entries) && op != "insert") {
			return refuseEdit("notFound", "no item %d", index)
		}
		if op == "insert" {
			rendered, refusal := renderFlowValue(value)
			if refusal != nil {
				return refusal
			}
			if index == len(entries) && index > 0 {
				if last := entries[index-1]; commentOnLines(last.end, last.end) {
					if _, alone := aloneOnItsLine(text, last.start); alone {
						return refuseEdit("unsupportedStyle", "a comment stands on the line the insert splits")
					}
				}
			}
			replace(insertInFlow(text, start, entries, index, rendered))
			return nil
		}
	}
	if op == "insert" {
		if index >= 0 {
			return refuseEdit("invalidRequest", "key %q already exists; use set", last)
		}
		key, refusal := renderFlowValue(last.(string))
		if refusal != nil {
			return refusal
		}
		rendered, refusal := renderFlowValue(value)
		if refusal != nil {
			return refusal
		}
		if len(entries) > 0 {
			if last := entries[len(entries)-1]; commentOnLines(last.end, last.end) {
				if _, alone := aloneOnItsLine(text, last.start); alone {
					return refuseEdit("unsupportedStyle", "a comment stands on the line the insert splits")
				}
			}
		}
		replace(insertInFlow(text, start, entries, len(entries), key+": "+rendered))
		return nil
	}
	if index < 0 || index >= len(entries) {
		return refuseEdit("notFound", "no key %q", last)
	}
	entry := entries[index]
	if op == "set" {
		rendered, refusal := renderFlowValue(value)
		if refusal != nil {
			return refusal
		}
		if filler.commentIn(entry.valueStart, entry.end) {
			return refuseEdit("unsupportedStyle", "the value to replace holds a comment")
		}
		if entry.end < len(text) && text[entry.end] == '#' {
			rendered += " "
		}
		replace(text[:entry.valueStart] + rendered + text[entry.end:])
		return nil
	}
	from, to := entry.start, entry.end
	switch {
	case index+1 < len(entries):
		to = entries[index+1].start
		if newline := strings.IndexByte(text[entry.end:to], '\n'); newline >= 0 && strings.Contains(text[entry.end:entry.end+newline], ",") {
			if lineStart, alone := aloneOnItsLine(text, entry.start); alone {
				from, to = lineStart, entry.end+newline+1
			} else {
				from, to = len(strings.TrimRight(text[:entry.start], " \t")), entry.end+newline
			}
		}
	case index > 0:
		from = entries[index-1].end
	default:
		after := to
		for after < len(text) && isFlowSpace(text[after]) {
			after++
		}
		if after < len(text) && text[after] == ',' {
			to = after + 1
			for to < len(text) && isFlowSpace(text[to]) {
				to++
			}
		}
		if lineStart, alone := aloneOnItsLine(text, entry.start); alone {
			rest := to
			for rest < len(text) && isFlowSpace(text[rest]) {
				rest++
			}
			switch {
			case rest == len(text) || text[rest] == '\n':
				from, to = lineStart, min(rest+1, len(text))
			case text[rest] == '}' || text[rest] == ']':
				from, to = lineStart, rest
			}
		}
	}
	removed := text[from:to]
	wholeLines := (from == 0 || text[from-1] == '\n') && (to == len(text) || text[to-1] == '\n')
	if strings.Contains(removed, "\n") && !wholeLines && commentOnLines(from, to) {
		return refuseEdit("unsupportedStyle", "a comment stands on a line the delete joins to another")
	}
	replace(text[:from] + text[to:])
	return nil
}

func insertInFlow(text string, start int, entries []flowEntry, index int, entry string) string {
	switch {
	case len(entries) == 0:
		return text[:start+1] + entry + text[start+1:]
	case index < len(entries):
		at := entries[index].start
		if lineStart, alone := aloneOnItsLine(text, at); alone {
			return text[:at] + entry + ",\n" + text[lineStart:at] + text[at:]
		}
		return text[:at] + entry + ", " + text[at:]
	default:
		last := entries[len(entries)-1]
		if lineStart, alone := aloneOnItsLine(text, last.start); alone {
			return text[:last.end] + ",\n" + text[lineStart:last.start] + entry + text[last.end:]
		}
		return text[:last.end] + ", " + entry + text[last.end:]
	}
}

func aloneOnItsLine(text string, at int) (lineStart int, alone bool) {
	lineStart = strings.LastIndexByte(text[:at], '\n') + 1
	return lineStart, lineStart > 0 && strings.Trim(text[lineStart:at], " \t") == ""
}

func lineOffsets(lines []string) []int {
	offsets := make([]int, len(lines))
	offset := 0
	for i, line := range lines {
		offsets[i] = offset
		offset += len(line) + 1
	}
	return offsets
}

func flowChild(node *yaml.Node, part any) *yaml.Node {
	switch key := part.(type) {
	case string:
		if node.Kind != yaml.MappingNode {
			return nil
		}
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value == key {
				return node.Content[i+1]
			}
		}
	case float64:
		index := int(key)
		if node.Kind == yaml.SequenceNode && float64(index) == key && index >= 0 && index < len(node.Content) {
			return node.Content[index]
		}
	}
	return nil
}

type flowEntry struct {
	start, valueStart, end int
}

func flowEntries(text string, container *yaml.Node, at func(*yaml.Node) int) ([]flowEntry, bool) {
	var entries []flowEntry
	if container.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(container.Content); i += 2 {
			key, value := container.Content[i], container.Content[i+1]
			keyStart, valueStart := at(key), at(value)
			if keyStart < 0 || valueStart <= keyStart || isImplicitNull(value) {
				return nil, false
			}
			end, ok := flowNodeEnd(text, value, at)
			if !ok {
				return nil, false
			}
			entries = append(entries, flowEntry{start: keyStart, valueStart: valueStart, end: end})
		}
		return entries, true
	}
	for _, item := range container.Content {
		itemStart := at(item)
		if itemStart < 0 || isImplicitNull(item) {
			return nil, false
		}
		end, ok := flowNodeEnd(text, item, at)
		if !ok {
			return nil, false
		}
		entries = append(entries, flowEntry{start: itemStart, valueStart: itemStart, end: end})
	}
	return entries, true
}

func isImplicitNull(node *yaml.Node) bool {
	return node.Kind == yaml.ScalarNode && node.Tag == "!!null" && node.Value == "" && node.Style == 0
}

func flowNodeEnd(text string, node *yaml.Node, at func(*yaml.Node) int) (int, bool) {
	start := flowContentStart(text, at(node))
	if start < 0 {
		return 0, false
	}
	switch node.Kind {
	case yaml.MappingNode, yaml.SequenceNode:
		closing := byte('}')
		if node.Kind == yaml.SequenceNode {
			closing = ']'
		}
		if text[start] != '{' && text[start] != '[' {
			if node.Kind != yaml.MappingNode || len(node.Content) != 2 {
				return 0, false
			}
			return flowNodeEnd(text, node.Content[1], at)
		}
		position := start + 1
		if len(node.Content) > 0 {
			end, ok := flowNodeEnd(text, node.Content[len(node.Content)-1], at)
			if !ok {
				return 0, false
			}
			position = skipFlowFiller(text, end)
			if position < len(text) && text[position] == ',' {
				position++
			}
		}
		position = skipFlowFiller(text, position)
		if position >= len(text) || text[position] != closing {
			return 0, false
		}
		return position + 1, true
	case yaml.ScalarNode:
		if quote := text[start]; quote == '"' || quote == '\'' {
			if closing := closingQuote(text[start:], quote); closing > 0 {
				return start + closing + 1, true
			}
			return 0, false
		}
		end := start
		for i := start; i < len(text); i++ {
			c := text[i]
			if c == ',' || c == '[' || c == ']' || c == '{' || c == '}' || c == '\n' || (c == '#' && i > start && isFlowSpace(text[i-1])) {
				break
			}
			if c == ':' && (i+1 == len(text) || isFlowSpace(text[i+1]) || text[i+1] == '\n') {
				break
			}
			if !isFlowSpace(c) {
				end = i + 1
			}
		}
		return end, end > start
	}
	return 0, false
}

func isFlowSpace(c byte) bool { return c == ' ' || c == '\t' }

func flowContentStart(text string, start int) int {
	if start < 0 || start >= len(text) {
		return -1
	}
	if text[start] == '!' {
		for start < len(text) && !isFlowSpace(text[start]) && text[start] != '\n' {
			start++
		}
		start = skipFlowFiller(text, start)
		if start >= len(text) {
			return -1
		}
	}
	return start
}

type flowFillerMarks struct {
	comments    []int
	explicitKey bool
}

func (m flowFillerMarks) commentIn(from, to int) bool {
	for _, at := range m.comments {
		if at >= from && at < to {
			return true
		}
	}
	return false
}

func flowFiller(text string, node *yaml.Node, at func(*yaml.Node) int, from, to int) (marks flowFillerMarks, ok bool) {
	scalar := make([]bool, to-from)
	var cover func(*yaml.Node) bool
	cover = func(n *yaml.Node) bool {
		switch n.Kind {
		case yaml.ScalarNode:
			if isImplicitNull(n) {
				return true
			}
			start := flowContentStart(text, at(n))
			end, located := flowNodeEnd(text, n, at)
			if start < from || !located || end > to || end <= start {
				return false
			}
			for i := start; i < end; i++ {
				scalar[i-from] = true
			}
			return true
		case yaml.MappingNode, yaml.SequenceNode:
			for _, child := range n.Content {
				if !cover(child) {
					return false
				}
			}
			return true
		}
		return false
	}
	if !cover(node) {
		return flowFillerMarks{}, false
	}
	for i := from; i < to; i++ {
		if scalar[i-from] {
			continue
		}
		switch text[i] {
		case '#':
			marks.comments = append(marks.comments, i)
			for i < to && text[i] != '\n' {
				i++
			}
		case '?':
			marks.explicitKey = true
		}
	}
	return marks, true
}

func skipFlowFiller(text string, position int) int {
	for position < len(text) {
		switch c := text[position]; {
		case c == ' ' || c == '\t' || c == '\n':
			position++
		case c == '#':
			for position < len(text) && text[position] != '\n' {
				position++
			}
		default:
			return position
		}
	}
	return position
}

func renderFlowValue(value any) (string, *yamlEditError) {
	var node *yaml.Node
	switch v := value.(type) {
	case orderedValue:
		node = copyYAMLNode(v.node)
	default:
		node = new(yaml.Node)
		if err := node.Encode(value); err != nil {
			return "", refuseEdit("invalidRequest", "the value cannot be written as YAML: %v", err)
		}
	}
	return renderFlowNode(node)
}

func renderFlowNode(node *yaml.Node) (string, *yamlEditError) {
	switch node.Kind {
	case yaml.DocumentNode:
		if len(node.Content) == 1 {
			return renderFlowNode(node.Content[0])
		}
	case yaml.MappingNode:
		parts := make([]string, 0, len(node.Content)/2)
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, refusal := renderFlowNode(node.Content[i])
			if refusal != nil {
				return "", refusal
			}
			value, refusal := renderFlowNode(node.Content[i+1])
			if refusal != nil {
				return "", refusal
			}
			parts = append(parts, key+": "+value)
		}
		return "{" + strings.Join(parts, ", ") + "}", nil
	case yaml.SequenceNode:
		parts := make([]string, 0, len(node.Content))
		for _, item := range node.Content {
			value, refusal := renderFlowNode(item)
			if refusal != nil {
				return "", refusal
			}
			parts = append(parts, value)
		}
		return "[" + strings.Join(parts, ", ") + "]", nil
	case yaml.ScalarNode:
		return renderFlowScalar(node)
	}
	return "", refuseEdit("invalidRequest", "the value cannot be written inside a flow collection")
}

func renderFlowScalar(node *yaml.Node) (string, *yamlEditError) {
	scalar := copyYAMLNode(node)
	scalar.Style &^= yaml.LiteralStyle | yaml.FoldedStyle
	scalar.HeadComment, scalar.LineComment, scalar.FootComment = "", "", ""
	standIns := standInAstralInNode(scalar)
	list := &yaml.Node{Kind: yaml.SequenceNode, Style: yaml.FlowStyle, Content: []*yaml.Node{scalar}}
	encoded, err := yaml.Marshal(list)
	if err != nil {
		return "", refuseEdit("invalidRequest", "the value cannot be written as YAML: %v", err)
	}
	text := strings.TrimSuffix(standIns.restore(string(encoded)), "\n")
	if strings.HasPrefix(text, "[") && strings.HasSuffix(text, "]") && !strings.ContainsAny(text, "\n\u0085\u2028\u2029") {
		return text[1 : len(text)-1], nil
	}
	if node.Tag == "!!str" || node.Tag == "" {
		var quoted strings.Builder
		encoder := json.NewEncoder(&quoted)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(node.Value); err == nil {
			return strings.ReplaceAll(strings.TrimSuffix(quoted.String(), "\n"), "\u0085", `\u0085`), nil
		}
	}
	return "", refuseEdit("unsupportedStyle", "the value cannot be written on one line inside a flow collection")
}
