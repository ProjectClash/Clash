package clash

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

func EditYAMLForIOS(original, pathJSON, op, valueJSON string) (*StringBox, error) {
	out, err := recoverAppCall("EditYAMLForIOS", func() (*StringBox, error) {
		return editYAMLForIOSUnguarded(original, pathJSON, op, valueJSON)
	})
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return out, nil
}

type yamlEditAnswer struct {
	OK      bool   `json:"ok"`
	Text    string `json:"text,omitempty"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

type yamlEditError struct {
	code    string
	message string
}

func (e *yamlEditError) Error() string { return e.code + ": " + e.message }

func refuseEdit(code, format string, args ...any) *yamlEditError {
	return &yamlEditError{code: code, message: fmt.Sprintf(format, args...)}
}

func editYAMLForIOSUnguarded(original, pathJSON, op, valueJSON string) (*StringBox, error) {
	answer := yamlEditAnswer{OK: true}
	text, err := editYAML(original, pathJSON, op, valueJSON)
	if err != nil {
		var refusal *yamlEditError
		if !errors.As(err, &refusal) {
			refusal = refuseEdit("unsafeEdit", "%v", err)
		}
		answer = yamlEditAnswer{Code: refusal.code, Message: refusal.message}
	} else {
		answer.Text = text
	}
	encoded, err := json.Marshal(answer)
	if err != nil {
		return nil, bridgeSafeError(err)
	}
	return WrapString(string(encoded)), nil
}

type yamlEditDocument struct {
	lines []string
	eol   string
	final bool
	root  *yaml.Node
	node  *yaml.Node

	directivesRead bool
	directivesText string
	bom            string
}

func parseYAMLForEdit(original string) (*yamlEditDocument, *yamlEditError) {
	trimmed := strings.TrimSpace(original)
	if strings.HasPrefix(trimmed, "age-encryption.org/") || strings.Contains(original, "-----BEGIN AGE ENCRYPTED FILE-----") {
		return nil, refuseEdit("encrypted", "the configuration is age-encrypted")
	}
	if strings.Contains(original, "\r") {
		return nil, refuseEdit("unsupportedStyle", "the text uses carriage returns")
	}
	if strings.Contains(strings.TrimPrefix(original, "\ufeff"), "\ufeff") {
		return nil, refuseEdit("unsupportedStyle", "the text holds a byte-order mark after its start")
	}
	if strings.ContainsAny(original, "\u0085\u2028\u2029") {
		return nil, refuseEdit("unsupportedStyle", "the text uses Unicode line separators")
	}
	for _, line := range strings.Split(original, "\n") {
		line = strings.TrimPrefix(line, "\ufeff")
		if line == "..." || strings.HasPrefix(line, "... ") || strings.HasPrefix(line, "...\t") {
			return nil, refuseEdit("unsupportedStyle", "the text holds a document-end marker")
		}
	}
	decoder := yaml.NewDecoder(strings.NewReader(original))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil {
		return nil, refuseEdit("invalidRequest", "the configuration does not parse: %v", err)
	}
	var second yaml.Node
	if err := decoder.Decode(&second); err != io.EOF {
		return nil, refuseEdit("multiDocument", "the text holds more than one YAML document")
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, refuseEdit("typeMismatch", "the top level is not a mapping")
	}
	if document.Content[0].Style&yaml.FlowStyle != 0 {
		return nil, refuseEdit("unsupportedStyle", "the top level is a flow mapping")
	}
	lines := strings.Split(original, "\n")
	final := strings.HasSuffix(original, "\n")
	if final {
		lines = lines[:len(lines)-1]
	}
	bom := ""
	if len(lines) > 0 && strings.HasPrefix(lines[0], "\ufeff") {
		bom, lines[0] = "\ufeff", strings.TrimPrefix(lines[0], "\ufeff")
	}
	return &yamlEditDocument{lines: lines, eol: "\n", final: final, root: document.Content[0], node: &document, bom: bom}, nil
}

func (d *yamlEditDocument) text() string {
	out := d.bom + strings.Join(d.lines, d.eol)
	if d.final {
		out += d.eol
	}
	return out
}

func (d *yamlEditDocument) keyIsExplicit(key *yaml.Node) bool {
	_, _, _, ok := d.keyToken(key)
	return !ok
}

func (d *yamlEditDocument) keyToken(key *yaml.Node) (start, end int, properties bool, ok bool) {
	if key.Kind != yaml.ScalarNode {
		return 0, 0, false, false
	}
	line := d.lines[key.Line-1]
	offset := byteOffsetOfColumn(line, key.Column)
	before := strings.TrimRight(line[:offset], " \t")
	if strings.HasSuffix(before, "?") {
		return 0, 0, false, false
	}
	rest := line[offset:]
	for strings.HasPrefix(rest, "&") || strings.HasPrefix(rest, "!") {
		properties = true
		cut := strings.IndexAny(rest, " \t")
		if rest[0] == '&' {
			cut = 1
			for cut < len(rest) && isAnchorByte(rest[cut]) {
				cut++
			}
		}
		if cut < 0 {
			return 0, 0, properties, false
		}
		trimmed := strings.TrimLeft(rest[cut:], " \t")
		offset += len(rest) - len(trimmed)
		rest = trimmed
	}
	var length int
	switch {
	case key.Style&yaml.DoubleQuotedStyle != 0:
		closing := closingQuote(rest, '"')
		if closing < 0 {
			return 0, 0, properties, false
		}
		length = closing + 1
	case key.Style&yaml.SingleQuotedStyle != 0:
		closing := closingQuote(rest, '\'')
		if closing < 0 {
			return 0, 0, properties, false
		}
		length = closing + 1
	case key.Style&(yaml.LiteralStyle|yaml.FoldedStyle|yaml.FlowStyle) != 0:
		return 0, 0, properties, false
	default:
		if !strings.HasPrefix(rest, key.Value) {
			return 0, 0, properties, false
		}
		length = len(key.Value)
	}
	if !strings.HasPrefix(strings.TrimLeft(rest[length:], " \t"), ":") {
		return 0, 0, properties, false
	}
	return offset, offset + length, properties, true
}

func isAnchorByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_'
}

func closingQuote(text string, quote byte) int {
	if text == "" || text[0] != quote {
		return -1
	}
	for i := 1; i < len(text); i++ {
		switch {
		case quote == '"' && text[i] == '\\':
			i++
		case text[i] == quote:
			if quote == '\'' && i+1 < len(text) && text[i+1] == '\'' {
				i++
				continue
			}
			return i
		}
	}
	return -1
}

func yamlTrim(text string) string { return strings.Trim(text, " \t") }

func (d *yamlEditDocument) lineIsFiller(line int) bool {
	trimmed := yamlTrim(d.lines[line-1])
	return trimmed == "" || strings.HasPrefix(trimmed, "#")
}

func (d *yamlEditDocument) lastContentLine(start, limit int, threshold int, keepBlank bool) int {
	end := limit - 1
	for end > start && d.lineIsFiller(end) {
		if threshold > 0 && yamlTrim(d.lines[end-1]) != "" && runeColumnOfFirstNonSpace(d.lines[end-1]) > threshold {
			break
		}
		end--
	}
	if keepBlank {
		for end+1 < limit && yamlTrim(d.lines[end]) == "" {
			end++
		}
	}
	return end
}

var blockScalarIndicator = &lazyRegexp{expr: `^(?:[!&]\S*\s+)*[|>][+-]?([1-9])`}

func (d *yamlEditDocument) blockScalarEnd(scalar *yaml.Node, contentColumn, limit int, keep bool) int {
	last := scalar.Line
	if contentColumn > 0 {
		for line := scalar.Line + 1; line < limit && line <= len(d.lines); line++ {
			text := d.lines[line-1]
			if yamlTrim(text) == "" {
				if utf8.RuneCountInString(text) >= contentColumn {
					last = line
				}
				continue
			}
			if runeColumnOfFirstNonSpace(text) < contentColumn {
				break
			}
			last = line
		}
	}
	if keep {
		for last+1 < limit && last+1 <= len(d.lines) && yamlTrim(d.lines[last]) == "" {
			last++
		}
	}
	return last
}

func (d *yamlEditDocument) blockScalarHeaderOnItsLine(scalar *yaml.Node) bool {
	header := d.lines[scalar.Line-1]
	return blockScalarHeader.get().MatchString(header[byteOffsetOfColumn(header, scalar.Column):])
}

func (d *yamlEditDocument) blockScalarKeepsTrailingLines(scalar *yaml.Node) bool {
	header := d.lines[scalar.Line-1]
	match := blockScalarHeader.get().FindStringSubmatch(header[byteOffsetOfColumn(header, scalar.Column):])
	return match != nil && strings.Contains(match[1], "+")
}

var blockScalarHeader = &lazyRegexp{expr: `^(?:[!&]\S*\s+)*[|>]([+-]?[1-9]?[+-]?)`}

func trailingBlockScalar(value *yaml.Node, ownerColumn int) (*yaml.Node, int) {
	for value != nil {
		switch value.Kind {
		case yaml.ScalarNode:
			if value.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
				return value, ownerColumn
			}
			return nil, 0
		case yaml.MappingNode:
			if len(value.Content) < 2 || value.Style&yaml.FlowStyle != 0 {
				return nil, 0
			}
			ownerColumn = value.Content[len(value.Content)-2].Column
			value = value.Content[len(value.Content)-1]
		case yaml.SequenceNode:
			if len(value.Content) == 0 || value.Style&yaml.FlowStyle != 0 {
				return nil, 0
			}
			ownerColumn = value.Column
			value = value.Content[len(value.Content)-1]
		default:
			return nil, 0
		}
	}
	return nil, 0
}

func (d *yamlEditDocument) blockScalarContentColumn(scalar *yaml.Node, ownerColumn, limit int) int {
	if header := d.lines[scalar.Line-1]; true {
		if indicator := blockScalarIndicator.get().FindStringSubmatch(header[byteOffsetOfColumn(header, scalar.Column):]); indicator != nil {
			n, _ := strconv.Atoi(indicator[1])
			return ownerColumn + n
		}
	}
	for line := scalar.Line + 1; line < limit && line <= len(d.lines); line++ {
		if yamlTrim(d.lines[line-1]) == "" {
			continue
		}
		if column := runeColumnOfFirstNonSpace(d.lines[line-1]); column > ownerColumn {
			return column
		}
		return 0
	}
	return 0
}

type yamlSpan struct{ start, end int }

func (d *yamlEditDocument) childSpans(node *yaml.Node, limit int) ([]yamlSpan, *yamlEditError) {
	var starts []int
	var values []*yaml.Node
	var owners []int
	switch node.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(node.Content); i += 2 {
			if d.keyIsExplicit(node.Content[i]) {
				return nil, refuseEdit("unsupportedStyle", "the mapping uses an explicit key")
			}
			starts = append(starts, node.Content[i].Line)
			values = append(values, node.Content[i+1])
			owners = append(owners, node.Content[i].Column)
		}
	case yaml.SequenceNode:
		dashColumn := node.Column
		previous := node.Line
		for _, item := range node.Content {
			start := -1
			for line := item.Line; line >= previous && line >= 1; line-- {
				text := d.lines[line-1]
				if column := runeColumnOfFirstNonSpace(text); column == dashColumn && strings.HasPrefix(yamlTrim(text), "-") {
					start = line
					break
				}
			}
			if start < 0 {
				return nil, refuseEdit("unsupportedStyle", "a list item's dash could not be located")
			}
			starts = append(starts, start)
			values = append(values, item)
			owners = append(owners, dashColumn)
			previous = start + 1
		}
	default:
		return nil, refuseEdit("typeMismatch", "not a collection")
	}
	spans := make([]yamlSpan, len(starts))
	for i, start := range starts {
		next := limit
		if i+1 < len(starts) {
			next = starts[i+1]
		}
		threshold, keepBlank := 0, false
		if scalar, owner := trailingBlockScalar(values[i], owners[i]); scalar != nil {
			if !d.blockScalarHeaderOnItsLine(scalar) {
				return nil, refuseEdit("unsupportedStyle", "a block scalar's header is split over lines")
			}
			threshold = d.blockScalarContentColumn(scalar, owner, next) - 1
			keepBlank = d.blockScalarKeepsTrailingLines(scalar)
			spans[i] = yamlSpan{start: start, end: d.blockScalarEnd(scalar, threshold+1, next, keepBlank)}
			continue
		}
		spans[i] = yamlSpan{start: start, end: d.lastContentLine(start, next, threshold, keepBlank)}
	}
	return spans, nil
}

func (d *yamlEditDocument) requireExact(container *yaml.Node, spans []yamlSpan, indices ...int) *yamlEditError {
	for _, i := range indices {
		if i < 0 || i >= len(spans) {
			continue
		}
		value, column := container.Content[i], container.Column
		if container.Kind == yaml.MappingNode {
			value, column = container.Content[2*i+1], container.Content[2*i].Column
		}
		if !d.spanHoldsExactly(spans[i], column, container.Kind, value) {
			return refuseEdit("unsupportedStyle", "an entry's text could not be told apart from what follows it")
		}
	}
	return nil
}

func (d *yamlEditDocument) spanHoldsExactly(span yamlSpan, column int, kind yaml.Kind, value *yaml.Node) bool {
	if !holdsQuotedOrFlow(value) {
		return true
	}
	trimmedComment := false
	for line := span.end + 1; line <= len(d.lines) && d.lineIsFiller(line); line++ {
		if yamlTrim(d.lines[line-1]) != "" {
			trimmedComment = true
			break
		}
	}
	if !trimmedComment {
		return true
	}
	source := d.lines[span.start-1 : span.end]
	if aliases := aliasesUnder(value); len(aliases) > 0 {
		var ok bool
		if source, ok = d.linesWithAliasesAsEmpty(span, aliases); !ok {
			return false
		}
		value = withAliasesAsEmpty(value)
	}
	lines := make([]string, 0, span.end-span.start+1)
	for n, line := range source {
		if n == 0 {
			lines = append(lines, line[byteOffsetOfColumn(line, column):])
			continue
		}
		cut := 0
		for cut < column-1 && cut < len(line) && line[cut] == ' ' {
			cut++
		}
		lines = append(lines, line[cut:])
	}
	var whole any
	if value.Decode(&whole) != nil {
		return false
	}
	excerpt := strings.Join(lines, "\n")
	if span.end < len(d.lines) || d.final {
		excerpt += "\n"
	}
	if directives := d.directives(); directives != "" {
		excerpt = directives + "---\n" + excerpt
	}
	text := []byte(excerpt)
	switch kind {
	case yaml.MappingNode:
		var alone map[string]any
		if yaml.Unmarshal(text, &alone) != nil || len(alone) != 1 {
			return false
		}
		for _, read := range alone {
			return reflect.DeepEqual(normalizeYAMLValue(read), normalizeYAMLValue(whole))
		}
	case yaml.SequenceNode:
		var alone []any
		if yaml.Unmarshal(text, &alone) != nil || len(alone) != 1 {
			return false
		}
		return reflect.DeepEqual(normalizeYAMLValue(alone[0]), normalizeYAMLValue(whole))
	}
	return false
}

func (d *yamlEditDocument) directives() string {
	if !d.directivesRead {
		d.directivesText, d.directivesRead = d.scanDirectives(), true
	}
	return d.directivesText
}

func (d *yamlEditDocument) scanDirectives() string {
	var out strings.Builder
	for _, line := range d.lines {
		if strings.HasPrefix(strings.TrimPrefix(line, "\ufeff"), "---") {
			return out.String()
		}
		if strings.HasPrefix(strings.TrimPrefix(line, "\ufeff"), "%") {
			out.WriteString(line + "\n")
		}
	}
	return ""
}

func aliasesUnder(node *yaml.Node) []*yaml.Node {
	var aliases []*yaml.Node
	keyed := false
	var walk func(*yaml.Node, bool)
	walk = func(node *yaml.Node, isKey bool) {
		if node.Kind == yaml.AliasNode {
			keyed = keyed || isKey
			aliases = append(aliases, node)
			return
		}
		for i, child := range node.Content {
			walk(child, node.Kind == yaml.MappingNode && i%2 == 0)
		}
	}
	walk(node, false)
	if keyed {
		return []*yaml.Node{{Kind: yaml.AliasNode}}
	}
	return aliases
}

func (d *yamlEditDocument) linesWithAliasesAsEmpty(span yamlSpan, aliases []*yaml.Node) ([]string, bool) {
	lines := append([]string(nil), d.lines[span.start-1:span.end]...)
	sorted := append([]*yaml.Node(nil), aliases...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Line != sorted[j].Line {
			return sorted[i].Line < sorted[j].Line
		}
		return sorted[i].Column > sorted[j].Column
	})
	for _, alias := range sorted {
		if alias.Line < span.start || alias.Line > span.end || alias.Value == "" {
			return nil, false
		}
		line := lines[alias.Line-span.start]
		start := byteOffsetOfColumn(line, alias.Column)
		token := "*" + alias.Value
		if start < 0 || !strings.HasPrefix(line[start:], token) {
			return nil, false
		}
		lines[alias.Line-span.start] = line[:start] + "{}" + line[start+len(token):]
	}
	return lines, true
}

func withAliasesAsEmpty(node *yaml.Node) *yaml.Node {
	if node.Kind == yaml.AliasNode {
		return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Style: yaml.FlowStyle, Line: node.Line, Column: node.Column}
	}
	copied := *node
	copied.Content = make([]*yaml.Node, len(node.Content))
	for i, child := range node.Content {
		copied.Content[i] = withAliasesAsEmpty(child)
	}
	return &copied
}

func holdsQuotedOrFlow(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	if node.Style&(yaml.DoubleQuotedStyle|yaml.SingleQuotedStyle|yaml.FlowStyle) != 0 {
		return true
	}
	for _, child := range node.Content {
		if holdsQuotedOrFlow(child) {
			return true
		}
	}
	return false
}

func runeColumnOfFirstNonSpace(text string) int {
	column := 1
	for _, r := range text {
		if r != ' ' {
			return column
		}
		column++
	}
	return -1
}

func byteOffsetOfColumn(text string, column int) int {
	offset := 0
	for i := 1; i < column && offset < len(text); i++ {
		_, size := utf8.DecodeRuneInString(text[offset:])
		offset += size
	}
	return offset
}

func keyLineComment(line string, candidates ...*yaml.Node) (string, bool) {
	comment := ""
	for _, node := range candidates {
		if comment = lastLineComment(node); comment != "" {
			break
		}
	}
	if comment == "" {
		return "", true
	}
	body := strings.TrimRight(line, " \t")
	comment = strings.TrimRight(comment, " \t")
	if !strings.HasSuffix(body, comment) {
		return "", false
	}
	start := len(body) - len(comment)
	for start > 0 && (body[start-1] == ' ' || body[start-1] == '\t') {
		start--
	}
	if start == len(body)-len(comment) {
		return " " + line[start:], true
	}
	return line[start:], true
}

func lastLineComment(node *yaml.Node) string {
	for node != nil {
		if node.LineComment != "" {
			return node.LineComment
		}
		if node.Style&yaml.FlowStyle == 0 || len(node.Content) == 0 {
			return ""
		}
		node = node.Content[len(node.Content)-1]
	}
	return ""
}

func valueEndsOnKeyLine(line string, keyColumn int, value *yaml.Node) bool {
	var alone map[string]any
	if yaml.Unmarshal([]byte(line[byteOffsetOfColumn(line, keyColumn):]), &alone) != nil || len(alone) != 1 {
		return false
	}
	var whole any
	if value.Decode(&whole) != nil {
		return false
	}
	for _, read := range alone {
		return reflect.DeepEqual(normalizeYAMLValue(read), normalizeYAMLValue(whole))
	}
	return false
}

func refusesAnchors(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	if node.Anchor != "" || node.Kind == yaml.AliasNode {
		return true
	}
	if node.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(node.Content); i += 2 {
			if node.Content[i].Value == "<<" && node.Content[i].Tag == "!!merge" {
				return true
			}
		}
	}
	for _, child := range node.Content {
		if refusesAnchors(child) {
			return true
		}
	}
	return false
}

func renderYAMLValue(value any) ([]string, error) {
	var standIns *astralStandIns
	if ordered, isOrdered := value.(orderedValue); isOrdered {
		node := copyYAMLNode(ordered.node)
		standIns = standInAstralInNode(node)
		value = node
	} else {
		value, standIns = standInAstralInValue(value)
	}
	var buffer bytes.Buffer
	encoder := yaml.NewEncoder(&buffer)
	encoder.SetIndent(2)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	_ = encoder.Close()
	text := strings.TrimSuffix(standIns.restore(buffer.String()), "\n")
	return strings.Split(text, "\n"), nil
}

func isCollection(value any) bool {
	switch v := value.(type) {
	case orderedValue:
		return (v.node.Kind == yaml.MappingNode || v.node.Kind == yaml.SequenceNode) && len(v.node.Content) > 0
	case map[string]any:
		return len(v) > 0
	case []any:
		return len(v) > 0
	}
	return false
}

func indentLines(lines []string, spaces int) []string {
	prefix := strings.Repeat(" ", spaces)
	out := make([]string, len(lines))
	for i, line := range lines {
		if line == "" {
			out[i] = line
		} else {
			out[i] = prefix + line
		}
	}
	return out
}

type located struct {
	node   *yaml.Node
	span   yamlSpan
	key    *yaml.Node
	parent *yaml.Node
	index  int
	limit  int
}

func (d *yamlEditDocument) locate(path []any) (*located, *yamlEditError) {
	current := &located{node: d.root, span: yamlSpan{1, len(d.lines)}, limit: len(d.lines) + 1}
	for step, part := range path {
		node := current.node
		if node.Kind == yaml.AliasNode || node.Anchor != "" || refusesMerge(node) {
			return nil, refuseEdit("anchor", "the path passes through an anchor, alias or merge key")
		}
		if node.Style&yaml.FlowStyle != 0 {
			return nil, refuseEdit("unsupportedStyle", "the path passes through a flow collection")
		}
		switch key := part.(type) {
		case string:
			if node.Kind != yaml.MappingNode {
				return nil, refuseEdit("typeMismatch", "path element %d is a key but the node is not a mapping", step)
			}
			spans, err := d.childSpans(node, current.limit)
			if err != nil {
				return nil, err
			}
			found := -1
			for i := 0; i+1 < len(node.Content); i += 2 {
				if node.Content[i].Value == key {
					found = i / 2
					break
				}
			}
			if found < 0 {
				return nil, refuseEdit("notFound", "no key %q", key)
			}
			if refusal := d.requireExact(node, spans, found); refusal != nil {
				return nil, refusal
			}
			current = &located{
				node: node.Content[found*2+1], key: node.Content[found*2], parent: node,
				index: found, span: spans[found], limit: spans[found].end + 1,
			}
		case float64:
			index := int(key)
			if float64(index) != key {
				return nil, refuseEdit("invalidRequest", "path element %d is not a whole number", step)
			}
			if node.Kind != yaml.SequenceNode {
				return nil, refuseEdit("typeMismatch", "path element %d is an index but the node is not a list", step)
			}
			if index < 0 || index >= len(node.Content) {
				return nil, refuseEdit("notFound", "no item %d", index)
			}
			spans, err := d.childSpans(node, current.limit)
			if err != nil {
				return nil, err
			}
			if refusal := d.requireExact(node, spans, index); refusal != nil {
				return nil, refusal
			}
			current = &located{node: node.Content[index], parent: node, index: index, span: spans[index], limit: spans[index].end + 1}
		default:
			return nil, refuseEdit("invalidRequest", "path element %d is neither a key nor an index", step)
		}
	}
	return current, nil
}

func refusesMerge(node *yaml.Node) bool {
	if node.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == "<<" && node.Content[i].Tag == "!!merge" {
			return true
		}
	}
	return false
}

func (d *yamlEditDocument) replaceLines(span yamlSpan, with []string) {
	lines := append([]string{}, d.lines[:span.start-1]...)
	lines = append(lines, with...)
	lines = append(lines, d.lines[span.end:]...)
	d.lines = lines
}

func (d *yamlEditDocument) insertLines(before int, with []string) {
	lines := append([]string{}, d.lines[:before-1]...)
	lines = append(lines, with...)
	lines = append(lines, d.lines[before-1:]...)
	d.lines = lines
}

func (d *yamlEditDocument) setEntryValue(at *located, value any) *yamlEditError {
	keyLine := d.lines[at.key.Line-1]
	keyIndent := at.key.Column - 1
	rendered, err := renderYAMLValue(value)
	if err != nil {
		return refuseEdit("invalidRequest", "the value cannot be written as YAML: %v", err)
	}
	var prefix, comment string
	node := at.node
	inline := node.Line == at.key.Line && node.Style&(yaml.LiteralStyle|yaml.FoldedStyle) == 0
	if inline {
		offset := byteOffsetOfColumn(keyLine, node.Column)
		if at.span.end != at.key.Line || !valueEndsOnKeyLine(keyLine, at.key.Column, node) {
			return refuseEdit("unsupportedStyle", "the value runs over several lines")
		}
		prefix = strings.TrimRight(keyLine[:offset], " ")
		var ok bool
		if comment, ok = keyLineComment(keyLine, at.key, node); !ok {
			return refuseEdit("unsupportedStyle", "the comment on the key's line could not be located")
		}
	} else {
		colon := strings.Index(keyLine[byteOffsetOfColumn(keyLine, at.key.Column):], ":")
		if colon < 0 {
			return refuseEdit("unsupportedStyle", "the key's colon could not be located")
		}
		end := byteOffsetOfColumn(keyLine, at.key.Column) + colon + 1
		prefix = keyLine[:end]
		candidates := []*yaml.Node{at.key}
		if node.Kind == yaml.ScalarNode {
			candidates = append(candidates, node)
		}
		var ok bool
		if comment, ok = keyLineComment(keyLine, candidates...); !ok {
			return refuseEdit("unsupportedStyle", "the comment on the key's line could not be located")
		}
	}
	var replacement []string
	if isCollection(value) {
		replacement = append([]string{prefix + comment}, indentLines(rendered, keyIndent+2)...)
	} else {
		replacement = append([]string{prefix + " " + rendered[0] + comment}, indentLines(rendered[1:], keyIndent)...)
	}
	d.replaceLines(yamlSpan{at.key.Line, at.span.end}, replacement)
	return nil
}

func (d *yamlEditDocument) itemLines(dashIndent int, value any) ([]string, *yamlEditError) {
	rendered, err := renderYAMLValue(value)
	if err != nil {
		return nil, refuseEdit("invalidRequest", "the value cannot be written as YAML: %v", err)
	}
	lines := []string{strings.Repeat(" ", dashIndent) + "- " + rendered[0]}
	return append(lines, indentLines(rendered[1:], dashIndent+2)...), nil
}

func (d *yamlEditDocument) entryLines(indent int, key string, value any) ([]string, *yamlEditError) {
	rendered, err := renderYAMLValue(inMapping(key, value))
	if err != nil {
		return nil, refuseEdit("invalidRequest", "the value cannot be written as YAML: %v", err)
	}
	return indentLines(rendered, indent), nil
}

func editYAML(original, pathJSON, op, valueJSON string) (string, error) {
	edited, _, err := editYAMLParsed(original, pathJSON, op, valueJSON)
	return edited, err
}

func editYAMLParsed(original, pathJSON, op, valueJSON string) (string, *parsedYAML, error) {
	return editYAMLParsedFrom(nil, true, original, pathJSON, op, valueJSON)
}

func editYAMLParsedFrom(held *parsedYAML, remember bool, original, pathJSON, op, valueJSON string) (string, *parsedYAML, error) {
	var path []any
	pathDecoder := json.NewDecoder(strings.NewReader(pathJSON))
	pathDecoder.UseNumber()
	if err := pathDecoder.Decode(&path); err != nil || len(path) == 0 {
		return "", nil, refuseEdit("invalidRequest", "the path must be a non-empty JSON array")
	}
	if _, err := pathDecoder.Token(); err != io.EOF {
		return "", nil, refuseEdit("invalidRequest", "trailing data after the path")
	}
	for step, part := range path {
		if number, isNumber := part.(json.Number); isNumber {
			index, err := strconv.Atoi(string(number))
			if err != nil || index < 0 || index > math.MaxInt32 {
				return "", nil, refuseEdit("invalidRequest", "path element %d is not a list index", step)
			}
			path[step] = float64(index)
		}
	}
	var value any
	switch op {
	case "set", "insert", "move":
		decoded, err := decodeJSONValueExactly(valueJSON)
		if err != nil {
			return "", nil, refuseEdit("invalidRequest", "the value is not JSON: %v", err)
		}
		value = decoded
	case "insertBefore":
		decoded, err := decodeJSONValueExactly(valueJSON)
		object, isObject := decoded.(map[string]any)
		key, hasKey := object["key"].(string)
		entry, hasValue := object["value"]
		if err != nil || !isObject || len(object) != 2 || !hasKey || !hasValue {
			return "", nil, refuseEdit("invalidRequest", `insertBefore takes {"key": string, "value": any}`)
		}
		value = insertBeforeValue{key: key, value: entry}
	case "rename":
		decoded, err := decodeJSONValueExactly(valueJSON)
		name, isString := decoded.(string)
		if err != nil || !isString {
			return "", nil, refuseEdit("invalidRequest", "rename takes the new key as a JSON string")
		}
		value = name
	case "delete":
	default:
		return "", nil, refuseEdit("invalidRequest", "unknown operation %q", op)
	}
	parsed := held
	if parsed == nil || !parsed.editable || parsed.text != original {
		var refusal *yamlEditError
		if parsed, refusal = parseYAMLForEditCached(original); refusal != nil {
			return "", nil, refusal
		}
	}
	document := parsed.document()
	before, err := parsed.decoded()
	if err != nil {
		return "", nil, refuseEdit("invalidRequest", "the configuration does not parse: %v", err)
	}
	var render any = value
	if op == "set" || op == "insert" || op == "insertBefore" {
		if node, err := decodeJSONOrdered(valueJSON); err == nil {
			render = orderedValue{node: node}
			if op == "insertBefore" {
				render = insertBeforeValue{key: value.(insertBeforeValue).key, value: orderedValue{node: orderedMember(node, "value")}}
			}
		}
	}
	if op == "insert" && len(path) == 2 {
		if top, isMap := before.(map[string]any); isMap {
			if key, isKey := path[0].(string); isKey {
				if existing, exists := top[key]; !exists || existing == nil {
					built := true
					switch child := path[1].(type) {
					case float64:
						built = child == 0
						if built {
							path, value = path[:1], []any{value}
							render = inSequence(render)
						}
					case string:
						path, value = path[:1], map[string]any{child: value}
						render = inMapping(child, render)
					}
					if built && exists {
						op = "set"
					}
				}
			}
		}
	}
	expected, refusal := applyGenericEdit(before, path, op, value)
	if refusal != nil {
		return "", nil, refusal
	}
	topKey, _ := path[0].(string)
	topSpan, topFound := document.topLevelSpan(topKey)

	if refusal := document.apply(path, op, render); refusal != nil {
		return "", nil, refusal
	}
	edited := document.text()
	if yamlEditSurgeryFault != nil {
		edited = yamlEditSurgeryFault(edited)
	}

	after, err := parseYAMLForCheck(edited)
	if err != nil {
		return "", nil, refuseEdit("unsafeEdit", "the edited text does not parse: %v", err)
	}
	if !after.meansExactly(expected, parsed, topKey, topSpan, topFound) {
		return "", nil, refuseEdit("unsafeEdit", "the edited text would not mean exactly the requested change")
	}
	if after.editable && remember {
		rememberParsedYAML(after)
	}
	return edited, after, nil
}

type parsedYAML struct {
	text     string
	root     *yaml.Node
	lines    []string
	final    bool
	bom      string
	valueMu  sync.Mutex
	value    any
	editable bool
	aliases  bool
}

func (p *parsedYAML) decoded() (any, error) {
	p.valueMu.Lock()
	defer p.valueMu.Unlock()
	if p.value != nil || p.root == nil {
		return p.value, nil
	}
	var value any
	if err := p.root.Decode(&value); err != nil {
		return nil, err
	}
	p.value = normalizeYAMLValue(value)
	return p.value, nil
}

func (p *parsedYAML) meansExactly(expected any, before *parsedYAML, topKey string, topSpan yamlSpan, topFound bool) bool {
	expectedMap, isMap := expected.(map[string]any)
	if isMap && p.root != nil && !p.aliases && !before.aliases && topFound {
		if head, tail, kept := p.keptOtherEntries(before, topSpan); kept {
			if matched, decided := p.changedEntriesMatch(expectedMap, head, tail); decided {
				return matched
			}
		}
	}
	value, err := p.decoded()
	return err == nil && reflect.DeepEqual(value, expected)
}

func (p *parsedYAML) changedEntriesMatch(expected map[string]any, head, tail int) (matched, decided bool) {
	if len(p.root.Content)/2 != len(expected) {
		return false, false
	}
	keys := make(map[string]bool, len(expected))
	for i := 0; i+1 < len(p.root.Content); i += 2 {
		key := p.root.Content[i].Value
		if _, ok := expected[key]; !ok || keys[key] {
			return false, false
		}
		keys[key] = true
	}
	document := p.document()
	spans, refusal := document.childSpans(document.root, len(document.lines)+1)
	if refusal != nil || len(spans) != len(p.root.Content)/2 {
		return false, false
	}
	unchangedFrom := len(p.lines) - tail + 1
	for i := 0; i+1 < len(p.root.Content); i += 2 {
		start, end := p.root.Content[i].Line, spans[i/2].end
		if end <= head || start >= unchangedFrom {
			continue
		}
		var value any
		if err := p.root.Content[i+1].Decode(&value); err != nil {
			return false, true
		}
		if !reflect.DeepEqual(normalizeYAMLValue(value), expected[p.root.Content[i].Value]) {
			return false, true
		}
	}
	return true, true
}

func (p *parsedYAML) keptOtherEntries(before *parsedYAML, topSpan yamlSpan) (head, tail int, kept bool) {
	if p.bom != before.bom || p.final != before.final {
		return 0, 0, false
	}
	head = topSpan.start - 1
	tail = len(before.lines) - topSpan.end
	if head+tail > len(p.lines) {
		return 0, 0, false
	}
	for i := 0; i < head; i++ {
		if p.lines[i] != before.lines[i] {
			return 0, 0, false
		}
	}
	for i := 1; i <= tail; i++ {
		if p.lines[len(p.lines)-i] != before.lines[len(before.lines)-i] {
			return 0, 0, false
		}
	}
	return head, tail, true
}

func (p *parsedYAML) document() *yamlEditDocument {
	return &yamlEditDocument{lines: append([]string(nil), p.lines...), eol: "\n", final: p.final, root: p.root, bom: p.bom}
}

func (d *yamlEditDocument) topLevelSpan(key string) (yamlSpan, bool) {
	spans, refusal := d.childSpans(d.root, len(d.lines)+1)
	if refusal != nil {
		return yamlSpan{}, false
	}
	for i := 0; i+1 < len(d.root.Content); i += 2 {
		if d.root.Content[i].Value == key {
			return yamlSpan{start: d.root.Content[i].Line, end: spans[i/2].end}, true
		}
	}
	return yamlSpan{}, false
}

func holdsAliases(node *yaml.Node) bool {
	if node == nil {
		return false
	}
	if node.Anchor != "" || node.Kind == yaml.AliasNode || (node.Kind == yaml.ScalarNode && node.Tag == "!!merge") {
		return true
	}
	for _, child := range node.Content {
		if holdsAliases(child) {
			return true
		}
	}
	return false
}

var (
	parsedYAMLCacheMu sync.Mutex
	parsedYAMLCache   *parsedYAML
)

func rememberParsedYAML(p *parsedYAML) {
	parsedYAMLCacheMu.Lock()
	defer parsedYAMLCacheMu.Unlock()
	parsedYAMLCache = p
	if parsedYAMLCacheTimer != nil {
		parsedYAMLCacheTimer.Stop()
		parsedYAMLCacheTimer = nil
	}
	if p != nil {
		var timer *time.Timer
		timer = time.AfterFunc(parsedYAMLCacheIdle, func() {
			parsedYAMLCacheMu.Lock()
			if parsedYAMLCache == p {
				parsedYAMLCache = nil
			}
			if parsedYAMLCacheTimer == timer {
				parsedYAMLCacheTimer = nil
			}
			parsedYAMLCacheMu.Unlock()
		})
		parsedYAMLCacheTimer = timer
	}
}

var parsedYAMLCacheIdle = 5 * time.Minute

var editTextReads atomic.Int64

var parsedYAMLCacheTimer *time.Timer

func parseYAMLForEditCached(original string) (*parsedYAML, *yamlEditError) {
	parsedYAMLCacheMu.Lock()
	cached := parsedYAMLCache
	parsedYAMLCacheMu.Unlock()
	if cached != nil && cached.editable && cached.text == original {
		return cached, nil
	}
	editTextReads.Add(1)
	document, refusal := parseYAMLForEdit(original)
	if refusal != nil {
		return nil, refusal
	}
	parsed := &parsedYAML{
		text: original, root: document.root, lines: document.lines, final: document.final, bom: document.bom,
		editable: true, aliases: holdsAliases(document.root),
	}
	if _, err := parsed.decoded(); err != nil {
		return nil, refuseEdit("invalidRequest", "the configuration does not parse: %v", err)
	}
	return parsed, nil
}

func parseYAMLForCheck(text string) (*parsedYAML, error) {
	if document, refusal := parseYAMLForEdit(text); refusal == nil {
		return &parsedYAML{
			text: text, root: document.root, lines: document.lines, final: document.final, bom: document.bom,
			editable: true, aliases: holdsAliases(document.root),
		}, nil
	}
	var value any
	if err := yaml.Unmarshal([]byte(text), &value); err != nil {
		return nil, err
	}
	return &parsedYAML{text: text, value: normalizeYAMLValue(value)}, nil
}

var yamlEditSurgeryFault func(string) string

func (d *yamlEditDocument) apply(path []any, op string, value any) *yamlEditError {
	parentPath, last := path[:len(path)-1], path[len(path)-1]
	parent, refusal := d.locate(parentPath)
	if refusal != nil {
		return refusal
	}
	container := parent.node
	if container.Kind == yaml.AliasNode || container.Anchor != "" || refusesMerge(container) {
		return refuseEdit("anchor", "the edit touches an anchor, alias or merge key")
	}

	switch op {
	case "set":
		target, refusal := d.locate(path)
		if refusal != nil {
			return refusal
		}
		if refusesAnchors(target.node) {
			return refuseEdit("anchor", "the node holds an anchor or alias")
		}
		if container.Style&yaml.FlowStyle != 0 {
			return refuseEdit("unsupportedStyle", "the value sits in a flow collection")
		}
		if target.key != nil {
			return d.setEntryValue(target, value)
		}
		lines, refusal := d.itemLines(container.Column-1, value)
		if refusal != nil {
			return refusal
		}
		if target.span.start == target.span.end {
			comment, ok := keyLineComment(d.lines[target.span.start-1], target.node)
			if !ok {
				return refuseEdit("unsupportedStyle", "the comment on the item's line could not be located")
			}
			lines[0] += comment
		}
		d.replaceLines(target.span, lines)
		return nil

	case "delete":
		target, refusal := d.locate(path)
		if refusal != nil {
			return refusal
		}
		if refusesAnchors(target.node) || (target.key != nil && target.key.Value == "<<") {
			return refuseEdit("anchor", "the node holds an anchor or alias")
		}
		if container.Style&yaml.FlowStyle != 0 {
			return refuseEdit("unsupportedStyle", "the item sits in a flow collection")
		}
		remaining := len(container.Content)
		if container.Kind == yaml.MappingNode {
			remaining /= 2
		}
		if remaining == 1 && len(parentPath) > 0 && parent.key != nil {
			empty := any([]any{})
			if container.Kind == yaml.MappingNode {
				empty = map[string]any{}
			}
			itemStart := target.span.start
			if target.key != nil {
				itemStart = target.key.Line
			}
			var kept []string
			for line := parent.key.Line + 1; line <= parent.span.end; line++ {
				if line >= itemStart && line <= target.span.end {
					continue
				}
				if text := d.lines[line-1]; strings.HasPrefix(yamlTrim(text), "#") {
					kept = append(kept, text)
				}
			}
			if err := d.setEntryValue(parent, empty); err != nil {
				return err
			}
			if len(kept) > 0 {
				d.insertLines(parent.key.Line+1, kept)
			}
			return nil
		}
		start := target.span.start
		if target.key != nil {
			start = target.key.Line
		}
		d.replaceLines(yamlSpan{start, target.span.end}, nil)
		return nil

	case "insert":
		if refusesAnchors(container) {
			return refuseEdit("anchor", "the collection holds an anchor or alias")
		}
		switch key := last.(type) {
		case string:
			if container.Kind != yaml.MappingNode {
				return refuseEdit("typeMismatch", "a key cannot be inserted into a list")
			}
			for i := 0; i+1 < len(container.Content); i += 2 {
				if container.Content[i].Value == key {
					return refuseEdit("invalidRequest", "key %q already exists; use set", key)
				}
			}
			if len(container.Content) == 0 || container.Style&yaml.FlowStyle != 0 {
				if parent.key == nil || len(container.Content) != 0 {
					return refuseEdit("unsupportedStyle", "the mapping is written in flow style")
				}
				return d.setEntryValue(parent, inMapping(key, value))
			}
			spans, refusal := d.childSpans(container, parent.limit)
			if refusal != nil {
				return refusal
			}
			if refusal := d.requireExact(container, spans, len(spans)-1); refusal != nil {
				return refusal
			}
			lines, refusal := d.entryLines(container.Content[0].Column-1, key, value)
			if refusal != nil {
				return refusal
			}
			d.insertLines(spans[len(spans)-1].end+1, lines)
			return nil
		case float64:
			index := int(key)
			if container.Kind != yaml.SequenceNode {
				return refuseEdit("typeMismatch", "an item cannot be inserted into a mapping")
			}
			if index < 0 || index > len(container.Content) || float64(index) != key {
				return refuseEdit("notFound", "no position %v", key)
			}
			if len(container.Content) == 0 || container.Style&yaml.FlowStyle != 0 {
				if parent.key == nil || len(container.Content) != 0 {
					return refuseEdit("unsupportedStyle", "the list is written in flow style")
				}
				return d.setEntryValue(parent, inSequence(value))
			}
			spans, refusal := d.childSpans(container, parent.limit)
			if refusal != nil {
				return refusal
			}
			if refusal := d.requireExact(container, spans, index, len(spans)-1); refusal != nil {
				return refusal
			}
			lines, refusal := d.itemLines(container.Column-1, value)
			if refusal != nil {
				return refusal
			}
			if index < len(spans) {
				d.insertLines(spans[index].start, lines)
			} else {
				d.insertLines(spans[len(spans)-1].end+1, lines)
			}
			return nil
		}
		return refuseEdit("invalidRequest", "the last path element is neither a key nor an index")

	case "move":
		from, ok := last.(float64)
		toIndex, toOK := jsonIndex(value)
		to := float64(toIndex)
		if !ok || !toOK || container.Kind != yaml.SequenceNode {
			return refuseEdit("typeMismatch", "move reorders a list: the path ends in an index and the value is the destination")
		}
		if container.Style&yaml.FlowStyle != 0 {
			return refuseEdit("unsupportedStyle", "the list is written in flow style")
		}
		if refusesAnchors(container) {
			return refuseEdit("anchor", "the list holds an anchor or alias")
		}
		count := len(container.Content)
		source, destination := int(from), int(to)
		if source < 0 || source >= count || destination < 0 || destination >= count {
			return refuseEdit("notFound", "no item %d or position %d", source, destination)
		}
		if source == destination {
			return nil
		}
		spans, refusal := d.childSpans(container, parent.limit)
		if refusal != nil {
			return refusal
		}
		if refusal := d.requireExact(container, spans, source, destination, destination+1, count-1); refusal != nil {
			return refusal
		}
		moved := append([]string{}, d.lines[spans[source].start-1:spans[source].end]...)
		d.replaceLines(spans[source], nil)
		removed := spans[source].end - spans[source].start + 1
		var at int
		if destination < source {
			at = spans[destination].start
		} else if destination+1 < count {
			at = spans[destination+1].start - removed
		} else {
			at = spans[count-1].end - removed + 1
		}
		d.insertLines(at, moved)
		return nil
	case "insertBefore", "rename":
		if container.Kind != yaml.MappingNode {
			return refuseEdit("typeMismatch", "%s applies to mapping keys", op)
		}
		if container.Style&yaml.FlowStyle != 0 {
			return refuseEdit("unsupportedStyle", "the mapping is written in flow style")
		}
		target, refusal := d.locate(path)
		if refusal != nil {
			return refusal
		}
		key := target.key
		line := d.lines[key.Line-1]
		if yamlTrim(line[:byteOffsetOfColumn(line, key.Column)]) != "" {
			return refuseEdit("unsupportedStyle", "the key shares its line with a list item's dash")
		}
		if op == "insertBefore" {
			if refusesAnchors(container) {
				return refuseEdit("anchor", "the mapping holds an anchor or alias")
			}
			entry := value.(insertBeforeValue)
			lines, refusal := d.entryLines(key.Column-1, entry.key, entry.value)
			if refusal != nil {
				return refusal
			}
			d.insertLines(key.Line, lines)
			return nil
		}
		start, end, properties, ok := d.keyToken(key)
		if !ok {
			return refuseEdit("unsupportedStyle", "the key's text could not be located")
		}
		if properties || key.Value == "<<" || key.Tag == "!!merge" {
			return refuseEdit("anchor", "the key carries an anchor or tag, or is a merge key")
		}
		rendered, err := renderYAMLValue(value.(string))
		if err != nil || len(rendered) != 1 || strings.HasPrefix(rendered[0], "|") || strings.HasPrefix(rendered[0], ">") {
			return refuseEdit("unsupportedStyle", "the new key cannot be written on one line")
		}
		d.lines[key.Line-1] = line[:start] + rendered[0] + line[end:]
		return nil
	}
	return refuseEdit("invalidRequest", "unknown operation %q", op)
}

type insertBeforeValue struct {
	key   string
	value any
}

func normalizeYAMLValue(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[key] = normalizeYAMLValue(item)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[fmt.Sprint(key)] = normalizeYAMLValue(item)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = normalizeYAMLValue(item)
		}
		return out
	case int:
		return exactInteger{strconv.FormatInt(int64(v), 10)}
	case int64:
		return exactInteger{strconv.FormatInt(v, 10)}
	case uint64:
		return exactInteger{strconv.FormatUint(v, 10)}
	case float32:
		return normalizeYAMLValue(float64(v))
	case float64:
		if v == math.Trunc(v) && math.Abs(v) <= 1<<53 {
			return exactInteger{strconv.FormatInt(int64(v), 10)}
		}
	}
	return value
}

func jsonIndex(value any) (int, bool) {
	switch v := value.(type) {
	case int64:
		return int(v), v >= math.MinInt32 && v <= math.MaxInt32
	case uint64:
		return int(v), v <= math.MaxInt32
	case float64:
		return int(v), v == math.Trunc(v) && math.Abs(v) <= math.MaxInt32
	}
	return 0, false
}

type exactInteger struct{ decimal string }

func decodeJSONValueExactly(text string) (any, error) {
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing data after the value")
	}
	return exactJSONNumbers(value)
}

type orderedValue struct{ node *yaml.Node }

func decodeJSONOrdered(text string) (*yaml.Node, error) {
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.UseNumber()
	node, err := jsonTokenNode(decoder)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, fmt.Errorf("trailing data after the value")
	}
	return node, nil
}

func jsonTokenNode(decoder *json.Decoder) (*yaml.Node, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch t := token.(type) {
	case json.Delim:
		node := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
		if t == '{' {
			node = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		}
		for decoder.More() {
			if t == '{' {
				key, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				node.Content = append(node.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: fmt.Sprint(key)})
			}
			item, err := jsonTokenNode(decoder)
			if err != nil {
				return nil, err
			}
			node.Content = append(node.Content, item)
		}
		if _, err := decoder.Token(); err != nil {
			return nil, err
		}
		return node, nil
	case string:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: t}, nil
	case json.Number:
		tag := "!!int"
		if strings.ContainsAny(string(t), ".eE") {
			tag = "!!float"
		}
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: tag, Value: string(t)}, nil
	case bool:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!bool", Value: strconv.FormatBool(t)}, nil
	case nil:
		return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null"}, nil
	}
	return nil, fmt.Errorf("unexpected JSON token %v", token)
}

func inMapping(key string, value any) any {
	if ordered, isOrdered := value.(orderedValue); isOrdered {
		return orderedValue{node: &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map", Content: []*yaml.Node{
			{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, ordered.node,
		}}}
	}
	return map[string]any{key: value}
}

func inSequence(value any) any {
	if ordered, isOrdered := value.(orderedValue); isOrdered {
		return orderedValue{node: &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq", Content: []*yaml.Node{ordered.node}}}
	}
	return []any{value}
}

func orderedMember(node *yaml.Node, key string) *yaml.Node {
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: "null"}
}

func exactJSONNumbers(value any) (any, error) {
	switch v := value.(type) {
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return i, nil
		}
		if u, err := strconv.ParseUint(string(v), 10, 64); err == nil {
			return u, nil
		}
		if !strings.ContainsAny(string(v), ".eE") {
			return nil, fmt.Errorf("the integer %s does not fit in 64 bits", v)
		}
		return v.Float64()
	case map[string]any:
		for key, item := range v {
			converted, err := exactJSONNumbers(item)
			if err != nil {
				return nil, err
			}
			v[key] = converted
		}
	case []any:
		for i, item := range v {
			converted, err := exactJSONNumbers(item)
			if err != nil {
				return nil, err
			}
			v[i] = converted
		}
	}
	return value, nil
}

func applyGenericEdit(document any, path []any, op string, value any) (any, *yamlEditError) {
	if len(path) == 0 {
		return nil, refuseEdit("invalidRequest", "empty path")
	}
	head, rest := path[0], path[1:]
	switch container := document.(type) {
	case map[string]any:
		key, ok := head.(string)
		if !ok {
			return nil, refuseEdit("typeMismatch", "an index into a mapping")
		}
		out := make(map[string]any, len(container))
		for k, v := range container {
			out[k] = v
		}
		if len(rest) == 0 {
			_, exists := out[key]
			switch op {
			case "set":
				if !exists {
					return nil, refuseEdit("notFound", "no key %q", key)
				}
				out[key] = normalizeYAMLValue(value)
			case "insert":
				if exists {
					return nil, refuseEdit("invalidRequest", "key %q already exists; use set", key)
				}
				out[key] = normalizeYAMLValue(value)
			case "delete":
				if !exists {
					return nil, refuseEdit("notFound", "no key %q", key)
				}
				delete(out, key)
			case "insertBefore":
				entry := value.(insertBeforeValue)
				if !exists {
					return nil, refuseEdit("notFound", "no key %q", key)
				}
				if _, taken := out[entry.key]; taken {
					return nil, refuseEdit("invalidRequest", "key %q already exists", entry.key)
				}
				out[entry.key] = normalizeYAMLValue(entry.value)
			case "rename":
				name := value.(string)
				if !exists {
					return nil, refuseEdit("notFound", "no key %q", key)
				}
				if _, taken := out[name]; taken || name == key {
					return nil, refuseEdit("invalidRequest", "key %q already exists", name)
				}
				out[name] = out[key]
				delete(out, key)
			default:
				return nil, refuseEdit("typeMismatch", "%s applies to list items", op)
			}
			return out, nil
		}
		child, exists := out[key]
		if !exists {
			return nil, refuseEdit("notFound", "no key %q", key)
		}
		edited, refusal := applyGenericEdit(child, rest, op, value)
		if refusal != nil {
			return nil, refusal
		}
		out[key] = edited
		return out, nil
	case []any:
		number, ok := head.(float64)
		if !ok {
			return nil, refuseEdit("typeMismatch", "a key into a list")
		}
		index := int(number)
		out := append([]any{}, container...)
		if len(rest) == 0 {
			switch op {
			case "set":
				if index < 0 || index >= len(out) {
					return nil, refuseEdit("notFound", "no item %d", index)
				}
				out[index] = normalizeYAMLValue(value)
			case "insert":
				if index < 0 || index > len(out) {
					return nil, refuseEdit("notFound", "no position %d", index)
				}
				out = append(out[:index], append([]any{normalizeYAMLValue(value)}, out[index:]...)...)
			case "delete":
				if index < 0 || index >= len(out) {
					return nil, refuseEdit("notFound", "no item %d", index)
				}
				out = append(out[:index], out[index+1:]...)
			case "move":
				to, ok := jsonIndex(value)
				if !ok || index < 0 || index >= len(out) || to < 0 || to >= len(out) {
					return nil, refuseEdit("notFound", "no item %d or position %v", index, value)
				}
				item := out[index]
				out = append(out[:index], out[index+1:]...)
				destination := to
				out = append(out[:destination], append([]any{item}, out[destination:]...)...)
			default:
				return nil, refuseEdit("typeMismatch", "%s applies to mapping keys", op)
			}
			return out, nil
		}
		if index < 0 || index >= len(out) {
			return nil, refuseEdit("notFound", "no item %d", index)
		}
		edited, refusal := applyGenericEdit(out[index], rest, op, value)
		if refusal != nil {
			return nil, refusal
		}
		out[index] = edited
		return out, nil
	}
	return nil, refuseEdit("typeMismatch", "path element is inside a scalar")
}
