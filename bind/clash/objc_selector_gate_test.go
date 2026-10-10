package clash

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
	"unicode"
)

var nsObjectSelectors = map[string]bool{
	"class": true, "superclass": true, "description": true, "debugDescription": true,
	"hash": true, "self": true, "copy": true, "mutableCopy": true, "init": true, "zone": true,
	"retain": true, "release": true, "autorelease": true, "retainCount": true, "isProxy": true,
	"dealloc": true, "finalize": true, "new": true, "alloc": true, "isEqual": true,
}

func bridgedObjCName(goName string) string {
	runes := []rune(goName)
	runes[0] = unicode.ToLower(runes[0])
	return string(runes)
}

func TestNoExportedNameShadowsNSObject(t *testing.T) {
	fset := token.NewFileSet()
	packages, err := parser.ParseDir(fset, ".", func(info os.FileInfo) bool {
		return !strings.HasSuffix(info.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	var violations []string
	check := func(pos token.Pos, owner, name string) {
		if ast.IsExported(name) && nsObjectSelectors[bridgedObjCName(name)] {
			violations = append(violations, fset.Position(pos).String()+": "+owner+"."+name+
				" bridges as -"+bridgedObjCName(name)+", shadowing NSObject")
		}
	}
	for _, pkg := range packages {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				switch d := decl.(type) {
				case *ast.GenDecl:
					for _, spec := range d.Specs {
						typeSpec, ok := spec.(*ast.TypeSpec)
						if !ok || !typeSpec.Name.IsExported() {
							continue
						}
						structType, ok := typeSpec.Type.(*ast.StructType)
						if !ok {
							continue
						}
						for _, field := range structType.Fields.List {
							for _, name := range field.Names {
								check(name.Pos(), typeSpec.Name.Name, name.Name)
							}
						}
					}
				case *ast.FuncDecl:
					if d.Recv == nil || len(d.Recv.List) != 1 {
						continue
					}
					owner := receiverTypeName(d.Recv.List[0].Type)
					if ast.IsExported(owner) {
						check(d.Name.Pos(), owner, d.Name.Name)
					}
				}
			}
		}
	}
	sort.Strings(violations)
	for _, violation := range violations {
		t.Error(violation)
	}
}
