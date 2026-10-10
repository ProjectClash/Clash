package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
)

const entryStruct = "RawConfig"

const scope = "ios"

var wrapperStructs = map[string]bool{"General": true, "Inbound": true}

type field struct {
	Path   string `json:"path"`
	Key    string `json:"key"`
	GoType string `json:"goType"`
}

type evidence struct {
	Selector string `json:"selector"`
	Path     string `json:"path,omitempty"`
	Kind     string `json:"kind"`
	Guarded  bool   `json:"guarded"`
	Value    string `json:"value,omitempty"`
	File     string `json:"file"`
	Line     int    `json:"line"`
	Resolved bool   `json:"resolved"`
}

type output struct {
	SchemaVersion int        `json:"schemaVersion"`
	Scope         string     `json:"scope"`
	Entry         string     `json:"entry"`
	Fields        []field    `json:"fields"`
	Enforcement   []evidence `json:"enforcement"`
}

type member struct {
	goName string
	key    string
	typ    ast.Expr
	nested string
}

type generator struct {
	fset    *token.FileSet
	structs map[string]*ast.StructType
	members map[string][]member
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gen_config_inventory:", err)
		os.Exit(1)
	}
}

func run() error {
	configDir := "config"
	bindDir := "bind/clash"
	if len(os.Args) > 1 {
		configDir = os.Args[1]
	}
	if len(os.Args) > 2 {
		bindDir = os.Args[2]
	}
	gen, err := newGenerator(configDir)
	if err != nil {
		return err
	}
	fields, err := gen.collect(entryStruct, "", map[string]bool{})
	if err != nil {
		return err
	}
	enf, err := gen.enforcement(bindDir)
	if err != nil {
		return err
	}
	out := output{SchemaVersion: 1, Scope: scope, Entry: entryStruct, Fields: fields, Enforcement: enf}
	enc, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	os.Stdout.Write(enc)
	os.Stdout.Write([]byte("\n"))
	return nil
}

func (g *generator) enforcement(bindDir string) ([]evidence, error) {
	var all []evidence
	ov, err := g.assignEvidence(filepath.Join(bindDir, "override.go"), "cfg", true, nil, "clearTunForNonPacketTunnel")
	if err != nil {
		return nil, err
	}
	ovTun, err := g.assignEvidence(filepath.Join(bindDir, "override.go"), "tun", true, []string{"Tun"}, "clearTunForNonPacketTunnel")
	if err != nil {
		return nil, err
	}
	cp, err := g.assignEvidence(
		filepath.Join(bindDir, "config_pipeline.go"),
		"raw",
		false,
		nil,
		"clearRawTunForNonPacketTunnel",
		"normalizeDHCPNameserversToSystem",
		"repairMacOSPacketTunnelDNS",
	)
	if err != nil {
		return nil, err
	}
	rj, err := g.rejectEvidence(filepath.Join(bindDir, "validate.go"), "validateRawNetworkExtensionIntentForApple")
	if err != nil {
		return nil, err
	}
	all = append(all, ov...)
	all = append(all, ovTun...)
	all = append(all, cp...)
	all = append(all, rj...)
	sort.Slice(all, func(i, j int) bool {
		if all[i].File != all[j].File {
			return all[i].File < all[j].File
		}
		return all[i].Line < all[j].Line
	})
	return all, nil
}

func newGenerator(dir string) (*generator, error) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", dir, err)
	}
	gen := &generator{fset: fset, structs: map[string]*ast.StructType{}, members: map[string][]member{}}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				genDecl, ok := decl.(*ast.GenDecl)
				if !ok || genDecl.Tok != token.TYPE {
					continue
				}
				for _, spec := range genDecl.Specs {
					typeSpec, ok := spec.(*ast.TypeSpec)
					if !ok {
						continue
					}
					if st, ok := typeSpec.Type.(*ast.StructType); ok {
						gen.structs[typeSpec.Name.Name] = st
					}
				}
			}
		}
	}
	for name, st := range gen.structs {
		gen.members[name] = gen.indexMembers(st)
	}
	return gen, nil
}

func (g *generator) indexMembers(st *ast.StructType) []member {
	var out []member
	for _, af := range st.Fields.List {
		if len(af.Names) == 0 {
			continue
		}
		key, ok := yamlKey(af.Tag)
		if !ok {
			continue
		}
		nested := ""
		if base := baseTypeName(af.Type); base != "" {
			if _, isStruct := g.structs[base]; isStruct {
				nested = base
			}
		}
		for _, n := range af.Names {
			if !n.IsExported() {
				continue
			}
			out = append(out, member{goName: n.Name, key: key, typ: af.Type, nested: nested})
		}
	}
	return out
}

func (g *generator) collect(structName, prefix string, seen map[string]bool) ([]field, error) {
	if _, ok := g.structs[structName]; !ok {
		return nil, fmt.Errorf("struct %q not found in config package", structName)
	}
	if seen[structName] {
		return nil, fmt.Errorf("recursive struct %q", structName)
	}
	seen[structName] = true
	defer delete(seen, structName)

	var fields []field
	for _, m := range g.members[structName] {
		path := m.key
		if prefix != "" {
			path = prefix + "." + m.key
		}
		if m.nested != "" {
			nested, err := g.collect(m.nested, path, seen)
			if err != nil {
				return nil, err
			}
			fields = append(fields, nested...)
			continue
		}
		fields = append(fields, field{Path: path, Key: m.key, GoType: g.renderType(m.typ)})
	}
	return fields, nil
}

func parseGoFile(file string) (*ast.File, *token.FileSet, error) {
	src, err := os.ReadFile(file)
	if err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", file, err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, file, src, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", file, err)
	}
	return f, fset, nil
}

func (g *generator) assignEvidence(file, root string, flatten bool, chainPrefix []string, excludedFunctions ...string) ([]evidence, error) {
	f, fset, err := parseGoFile(file)
	if err != nil {
		return nil, err
	}
	excludedNames := make(map[string]struct{}, len(excludedFunctions))
	for _, name := range excludedFunctions {
		excludedNames[name] = struct{}{}
	}
	type sourceRange struct{ start, end token.Pos }
	excludedRanges := make([]sourceRange, 0, len(excludedNames))
	for _, declaration := range f.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Body == nil {
			continue
		}
		if _, excluded := excludedNames[function.Name.Name]; excluded {
			excludedRanges = append(excludedRanges, sourceRange{start: function.Body.Pos(), end: function.Body.End()})
		}
	}
	isExcluded := func(position token.Pos) bool {
		for _, source := range excludedRanges {
			if source.start <= position && position <= source.end {
				return true
			}
		}
		return false
	}
	var ev []evidence
	type guardRange struct {
		cond       ast.Expr
		start, end token.Pos
	}
	var guardRanges []guardRange
	ast.Inspect(f, func(n ast.Node) bool {
		if ifStmt, ok := n.(*ast.IfStmt); ok && ifStmt.Body != nil {
			guardRanges = append(guardRanges, guardRange{ifStmt.Cond, ifStmt.Body.Pos(), ifStmt.Body.End()})
		}
		return true
	})
	ast.Inspect(f, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || isExcluded(as.Pos()) || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		guarded := false
		for _, g := range guardRanges {
			if g.start <= as.Pos() && as.Pos() <= g.end && referencesSelector(g.cond, as.Lhs[0]) {
				guarded = true
				break
			}
		}
		chain, ok := selectorChain(as.Lhs[0], root)
		if !ok {
			return true
		}
		if len(chainPrefix) > 0 {
			chain = append(append([]string{}, chainPrefix...), chain...)
		}
		path, resolved := g.resolveSelector(chain, flatten)
		ev = append(ev, evidence{
			Selector: strings.Join(chain, "."),
			Path:     path,
			Kind:     assignKind(as.Lhs[0], as.Rhs[0], guarded),
			Guarded:  guarded,
			Value:    g.renderNode(fset, as.Rhs[0]),
			File:     file,
			Line:     fset.Position(as.Pos()).Line,
			Resolved: resolved,
		})
		return true
	})
	return ev, nil
}

func (g *generator) rejectEvidence(file, funcName string) ([]evidence, error) {
	f, fset, err := parseGoFile(file)
	if err != nil {
		return nil, err
	}
	var fn *ast.FuncDecl
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Name.Name == funcName {
			fn = fd
			break
		}
	}
	if fn == nil {
		return nil, fmt.Errorf("%s: reject function %q not found", file, funcName)
	}
	seen := map[string]bool{}
	var ev []evidence
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		chain, ok := selectorChain(sel, "raw")
		if !ok {
			return true
		}
		path, resolved := g.resolveSelector(chain, false)
		if !resolved || seen[path] {
			return true
		}
		seen[path] = true
		ev = append(ev, evidence{
			Selector: strings.Join(chain, "."),
			Path:     path,
			Kind:     "reject",
			File:     file,
			Line:     fset.Position(sel.Pos()).Line,
			Resolved: true,
		})
		return true
	})
	return ev, nil
}

func (g *generator) resolveSelector(chain []string, flatten bool) (string, bool) {
	cur := entryStruct
	var parts []string
	for _, seg := range chain {
		m, ok := findMember(g.members[cur], seg)
		if !ok {
			if flatten && cur == entryStruct && wrapperStructs[seg] {
				continue
			}
			return "", false
		}
		parts = append(parts, m.key)
		if m.nested == "" {
			return strings.Join(parts, "."), true
		}
		cur = m.nested
	}
	return strings.Join(parts, "."), false
}

func findMember(members []member, goName string) (member, bool) {
	for _, m := range members {
		if m.goName == goName {
			return m, true
		}
	}
	return member{}, false
}

func selectorChain(expr ast.Expr, root string) ([]string, bool) {
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	var chain []string
	for {
		sel, ok := expr.(*ast.SelectorExpr)
		if !ok {
			break
		}
		chain = append([]string{sel.Sel.Name}, chain...)
		expr = sel.X
	}
	if id, ok := expr.(*ast.Ident); ok && id.Name == root && len(chain) > 0 {
		return chain, true
	}
	return nil, false
}

func assignKind(lhs, rhs ast.Expr, guarded bool) string {
	if _, ok := rhs.(*ast.CallExpr); ok {
		if guarded || referencesSelector(rhs, lhs) {
			return "normalized"
		}
		return "forced"
	}
	if isZeroValue(rhs) {
		return "cleared"
	}
	return "forced"
}

func referencesSelector(expr, target ast.Expr) bool {
	want := selectorText(target)
	if want == "" {
		return false
	}
	found := false
	ast.Inspect(expr, func(n ast.Node) bool {
		if found {
			return false
		}
		if candidate, ok := n.(ast.Expr); ok && selectorText(candidate) == want {
			found = true
			return false
		}
		return true
	})
	return found
}

func selectorText(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.SelectorExpr:
		base := selectorText(t.X)
		if base == "" {
			return ""
		}
		return base + "." + t.Sel.Name
	case *ast.StarExpr:
		return selectorText(t.X)
	}
	return ""
}

func isZeroValue(expr ast.Expr) bool {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name == "false" || t.Name == "nil"
	case *ast.BasicLit:
		return t.Value == "0" || t.Value == `""`
	case *ast.CompositeLit:
		return len(t.Elts) == 0
	}
	return false
}

func baseTypeName(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return baseTypeName(t.X)
	case *ast.ArrayType:
		return baseTypeName(t.Elt)
	default:
		return ""
	}
}

func (g *generator) renderType(expr ast.Expr) string { return g.renderNode(g.fset, expr) }

func (g *generator) renderNode(fset *token.FileSet, node ast.Node) string {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, node); err != nil {
		return ""
	}
	return strings.Join(strings.Fields(buf.String()), " ")
}

func yamlKey(tag *ast.BasicLit) (string, bool) {
	if tag == nil {
		return "", false
	}
	raw, err := strconv.Unquote(tag.Value)
	if err != nil {
		return "", false
	}
	value, ok := reflect.StructTag(raw).Lookup("yaml")
	if !ok {
		return "", false
	}
	name, _, _ := strings.Cut(value, ",")
	if name == "" || name == "-" {
		return "", false
	}
	return name, true
}
