package clash

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

const (
	clashInitBytesBudget  = 4 << 10
	clashInitAllocsBudget = 48
)

func TestBindClashInitStaysWithinItsBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and runs a probe binary")
	}
	tags := iPhoneSliceTags(t)
	bytes, allocs := measureClashInit(t, tags)
	t.Logf("bind/clash init (tags %s, every export held): %d bytes in %d allocations", tags, bytes, allocs)
	if bytes > clashInitBytesBudget || allocs > clashInitAllocsBudget {
		t.Errorf("loading bind/clash costs %d bytes in %d allocations, over the budget of %d in %d: a package-level "+
			"value the tunnel never uses is being built at load -- make it a lazyValue or lazyRegexp (lazy_init.go)",
			bytes, allocs, clashInitBytesBudget, clashInitAllocsBudget)
	}
}

func iPhoneSliceTags(t *testing.T) string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "..", "cmd", "build_libbox", "main.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{}
	ast.Inspect(file, func(node ast.Node) bool {
		spec, ok := node.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for i, name := range spec.Names {
			if i < len(spec.Values) {
				if literal, ok := spec.Values[i].(*ast.BasicLit); ok {
					values[name.Name], _ = strconv.Unquote(literal.Value)
				}
			}
		}
		return true
	})
	if values["baseTags"] == "" || values["notMacosTags"] == "" {
		t.Fatalf("cmd/build_libbox no longer declares baseTags and notMacosTags: %v", values)
	}
	return values["baseTags"] + "," + values["notMacosTags"]
}

func measureClashInit(t *testing.T, tags string) (int, int) {
	t.Helper()
	dir := t.TempDir()
	main := filepath.Join(dir, "main.go")
	if err := os.WriteFile(main, []byte(initProbeMain(t, tags)), 0o644); err != nil {
		t.Fatal(err)
	}
	target, err := filepath.Abs(filepath.Join("internal", "initprobe", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	overlay, _ := json.Marshal(map[string]map[string]string{"Replace": {target: main}})
	overlayPath := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(overlayPath, overlay, 0o644); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "initprobe")
	build := exec.Command("go", "build", "-overlay", overlayPath, "-tags", tags, "-o", binary, "./internal/initprobe")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the probe: %v\n%s", err, output)
	}
	run := exec.Command(binary)
	run.Env = append(os.Environ(), "GODEBUG=inittrace=1")
	output, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("running the probe: %v\n%s", err, output)
	}
	line := regexp.MustCompile(`(?m)^init github\.com/ProjectClash/Clash/bind/clash @.* ([0-9]+) bytes, ([0-9]+) allocs$`).FindSubmatch(output)
	if line == nil {
		t.Fatalf("no init line for bind/clash in:\n%s", output)
	}
	bytes, _ := strconv.Atoi(string(line[1]))
	allocs, _ := strconv.Atoi(string(line[2]))
	return bytes, allocs
}

func initProbeMain(t *testing.T, tags string) string {
	t.Helper()
	loaded, err := packages.Load(&packages.Config{Mode: packages.NeedName | packages.NeedTypes, BuildFlags: []string{"-tags", tags}}, ".")
	if err != nil || len(loaded) != 1 || loaded[0].Types == nil {
		t.Fatalf("loading the package: %v", err)
	}
	scope := loaded[0].Types.Scope()
	var held []string
	for _, name := range scope.Names() {
		switch object := scope.Lookup(name).(type) {
		case *types.Func:
			if object.Exported() && object.Type().(*types.Signature).TypeParams() == nil {
				held = append(held, "clash."+name)
			}
		case *types.Var:
			if object.Exported() {
				held = append(held, "&clash."+name)
			}
		case *types.TypeName:
			named, ok := object.Type().(*types.Named)
			if !ok || !object.Exported() || object.IsAlias() || named.TypeParams() != nil {
				continue
			}
			if iface, isInterface := named.Underlying().(*types.Interface); isInterface {
				for i := 0; i < iface.NumMethods(); i++ {
					if method := iface.Method(i); method.Exported() {
						held = append(held, "clash."+name+"."+method.Name())
					}
				}
				continue
			}
			seen := map[string]bool{}
			for _, receiver := range []types.Type{types.NewPointer(named), named} {
				methods := types.NewMethodSet(receiver)
				for i := 0; i < methods.Len(); i++ {
					method := methods.At(i).Obj()
					if !method.Exported() || seen[method.Name()] {
						continue
					}
					seen[method.Name()] = true
					held = append(held, "(*clash."+name+")."+method.Name())
				}
			}
		}
	}
	sort.Strings(held)
	if len(held) < 150 {
		t.Fatalf("only %d exports found: the probe would not hold what gomobile holds", len(held))
	}
	return fmt.Sprintf(`package main

import (
	"fmt"
	"os"

	clash "github.com/ProjectClash/Clash/bind/clash"
)

var held = []any{
	%s,
}

func main() {
	if len(os.Args) > 1<<20 {
		fmt.Println(held...)
	}
}
`, strings.Join(held, ",\n\t"))
}

func TestEveryLazyRegexpCompiles(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	set := token.NewFileSet()
	count := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(set, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			literal, ok := node.(*ast.CompositeLit)
			if !ok {
				return true
			}
			if ident, ok := literal.Type.(*ast.Ident); !ok || ident.Name != "lazyRegexp" {
				return true
			}
			for _, element := range literal.Elts {
				pair, ok := element.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if key, ok := pair.Key.(*ast.Ident); !ok || key.Name != "expr" {
					continue
				}
				value, ok := pair.Value.(*ast.BasicLit)
				if !ok {
					t.Errorf("%s: a lazyRegexp's expr is not a literal", set.Position(pair.Pos()))
					continue
				}
				expr, err := strconv.Unquote(value.Value)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := regexp.Compile(expr); err != nil {
					t.Errorf("%s: %v", set.Position(pair.Pos()), err)
				}
				count++
			}
			return true
		})
	}
	if count < 15 {
		t.Fatalf("found only %d lazy expressions", count)
	}
}
