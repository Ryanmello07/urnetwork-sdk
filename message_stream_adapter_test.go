package sdk

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/messagegroup"
	"github.com/urnetwork/connect/mls"
)

// ----------------------------------------------------------------------------------------------
// the fixtures
// ----------------------------------------------------------------------------------------------

// streamAdapterTestReserver opens a real store in a fresh directory and hands back the production
// adapter over it, plus the store itself for the cases that have to look at the disk.
func streamAdapterTestReserver(t *testing.T) (messagegroup.StreamIndexReserver, *StreamStore) {
	t.Helper()
	store := streamTestOpen(t, t.TempDir())
	reserver := NewStreamIndexReserver(store)
	if reserver == nil {
		t.Fatal("NewStreamIndexReserver answered nil for a live store")
	}
	return reserver, store
}

// streamAdapterTestKey builds one StreamKey through the store's own octet flattening, so that a
// case naming a stream and a case naming a row are naming the same thing by construction.
func streamAdapterTestKey(t *testing.T, seed byte) (messagegroup.StreamKey, [][]byte) {
	t.Helper()
	parts := streamTestKeyOctets(t, seed)
	key, err := streamKeyFromOctets(parts...)
	if err != nil {
		t.Fatalf("build the stream key: %v", err)
	}
	return key, parts
}

func streamAdapterTestConcrete(t *testing.T, reserver messagegroup.StreamIndexReserver) *streamIndexReserver {
	t.Helper()
	concrete, ok := reserver.(*streamIndexReserver)
	if !ok {
		t.Fatalf("the adapter is %T, and this package's own cases reach its unexported halves", reserver)
	}
	return concrete
}

// ----------------------------------------------------------------------------------------------
// the syntax-tree helpers these gates share
// ----------------------------------------------------------------------------------------------

// streamAdapterDeclaration is one production function or method declaration, with the facts the
// gates below decide on.
type streamAdapterDeclaration struct {
	file     string
	name     string
	receiver string
	position string
	node     *ast.FuncDecl
}

func (self streamAdapterDeclaration) label() string {
	if self.receiver == "" {
		return fmt.Sprintf("%s (%s)", self.name, self.position)
	}
	return fmt.Sprintf("(%s).%s (%s)", self.receiver, self.name, self.position)
}

// streamAdapterParse parses every production file of package sdk's own directory and answers the
// file set, the parsed files and every function declaration in them.
func streamAdapterParse(t *testing.T) (*token.FileSet, map[string]*ast.File, []streamAdapterDeclaration) {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read the package directory: %v", err)
	}
	fileSet := token.NewFileSet()
	parsed := map[string]*ast.File{}
	declarations := []streamAdapterDeclaration{}
	production := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		if strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		production += 1
		file, err := parser.ParseFile(fileSet, entry.Name(), nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", entry.Name(), err)
		}
		parsed[entry.Name()] = file
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok {
				continue
			}
			declarations = append(declarations, streamAdapterDeclaration{
				file:     entry.Name(),
				name:     function.Name.Name,
				receiver: streamAdapterReceiverName(function),
				position: fileSet.Position(function.Pos()).String(),
				node:     function,
			})
		}
	}
	if production == 0 {
		t.Fatal("this gate read no production source, so it is holding nothing")
	}
	if len(declarations) == 0 {
		t.Fatal("this gate found no function declaration at all, so it is holding nothing")
	}
	return fileSet, parsed, declarations
}

func streamAdapterReceiverName(function *ast.FuncDecl) string {
	if function.Recv == nil || len(function.Recv.List) == 0 {
		return ""
	}
	expression := function.Recv.List[0].Type
	if star, ok := expression.(*ast.StarExpr); ok {
		expression = star.X
	}
	if identifier, ok := expression.(*ast.Ident); ok {
		return identifier.Name
	}
	return fmt.Sprintf("%T", function.Recv.List[0].Type)
}

// streamAdapterCallsSelector answers whether the node contains a call whose function is a
// selector with one of these names, and the names it found.
func streamAdapterCallsSelector(node ast.Node, names map[string]bool) []string {
	found := map[string]bool{}
	ast.Inspect(node, func(inner ast.Node) bool {
		call, ok := inner.(*ast.CallExpr)
		if !ok {
			return true
		}
		if selector, ok := call.Fun.(*ast.SelectorExpr); ok && names[selector.Sel.Name] {
			found[selector.Sel.Name] = true
		}
		return true
	})
	return slices.Sorted(maps.Keys(found))
}

// streamAdapterResultTypes answers every result type of a declaration, as source text.
func streamAdapterResultTypes(function *ast.FuncDecl) []string {
	types := []string{}
	if function.Type.Results == nil {
		return types
	}
	for _, result := range function.Type.Results.List {
		text := streamAdapterTypeText(result.Type)
		count := len(result.Names)
		if count == 0 {
			count = 1
		}
		for range count {
			types = append(types, text)
		}
	}
	return types
}

func streamAdapterTypeText(expression ast.Expr) string {
	switch typed := expression.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.StarExpr:
		return "*" + streamAdapterTypeText(typed.X)
	case *ast.ArrayType:
		if typed.Len == nil {
			return "[]" + streamAdapterTypeText(typed.Elt)
		}
		return "[" + streamAdapterTypeText(typed.Len) + "]" + streamAdapterTypeText(typed.Elt)
	case *ast.SelectorExpr:
		return streamAdapterTypeText(typed.X) + "." + typed.Sel.Name
	case *ast.BasicLit:
		return typed.Value
	case *ast.Ellipsis:
		return "..." + streamAdapterTypeText(typed.Elt)
	case *ast.MapType:
		return "map[" + streamAdapterTypeText(typed.Key) + "]" + streamAdapterTypeText(typed.Value)
	case *ast.InterfaceType:
		return "interface{...}"
	case *ast.FuncType:
		return "func(...)"
	case *ast.ChanType:
		return "chan " + streamAdapterTypeText(typed.Value)
	}
	return fmt.Sprintf("%T", expression)
}

// streamAdapterPackageVarNames answers every package-level variable name of package sdk's
// production files, so that a declaration that stows octets in one is visible to a gate.
func streamAdapterPackageVarNames(parsed map[string]*ast.File) map[string]bool {
	names := map[string]bool{}
	for _, file := range parsed {
		for _, declaration := range file.Decls {
			general, ok := declaration.(*ast.GenDecl)
			if !ok || general.Tok != token.VAR {
				continue
			}
			for _, spec := range general.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, name := range value.Names {
					names[name.Name] = true
				}
			}
		}
	}
	return names
}

// streamAdapterAssignsOutward answers the targets a declaration assigns to that OUTLIVE the call:
// a struct field, or a package-level variable. A local is neither.
func streamAdapterAssignsOutward(node ast.Node, packageVars map[string]bool) []string {
	targets := map[string]bool{}
	ast.Inspect(node, func(inner ast.Node) bool {
		assign, ok := inner.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, target := range assign.Lhs {
			switch typed := target.(type) {
			case *ast.SelectorExpr:
				targets[streamAdapterTypeText(typed)] = true
			case *ast.IndexExpr:
				targets[streamAdapterTypeText(typed.X)+"[...]"] = true
			case *ast.Ident:
				if packageVars[typed.Name] {
					targets[typed.Name] = true
				}
			}
		}
		return true
	})
	return slices.Sorted(maps.Keys(targets))
}

func streamAdapterTypeName(t *testing.T) string {
	t.Helper()
	store := streamTestOpen(t, t.TempDir())
	reserver := NewStreamIndexReserver(store)
	concrete := reflect.TypeOf(reserver)
	for concrete.Kind() == reflect.Pointer {
		concrete = concrete.Elem()
	}
	if concrete.Name() == "" {
		t.Fatal("the adapter's concrete type has no name, so a gate cannot say which declarations are its methods")
	}
	return concrete.Name()
}

// ----------------------------------------------------------------------------------------------
// Property 1 -- every flattening in sdk is the adapter's, and so is every call that carries one
// into the store.
// ----------------------------------------------------------------------------------------------

// CLASS: every production declaration of package sdk that READS A StreamKey VALUE'S FIELDS. The
// derivation is complete rather than a heuristic, and the completeness rests on a gate this file
// does not own: TestNoProductionSourceOfPackageSdkSpellsAStreamKeyFieldName holds the count of
// production sources that spell GroupId or SenderHandle at ZERO, so the only remaining way for
// production code in this package to reach a StreamKey's contents is reflection over its fields.
// The class is therefore every declaration containing a reflective field read.
//
// SCOPE, derived separately (R3): the whole of package sdk's own production files, and not the
// two files this task creates. A gate scoped to the adapter's file cannot see the second
// flattening, which is the only thing it exists to see.
//
// THE COUNT IS NOT THE FINDING. A correct implementation writes the flattening once as a helper
// and the class has one new member; a correct implementation that inlines it into each of Reserve
// and HighWater has two. Both are correct, so the gate convicts a MEMBER and never a number: a
// member is a finding unless it is a method of the adapter type, or it is inert -- it hands no
// octets out through its results and it assigns to nothing that outlives the call.
//
// WHAT THE INERTNESS NARROWING REMOVES is printed below rather than asserted away: the store's own
// key derivations read the same fields and are not flattenings onto section 8.2's pair, because
// what leaves them is a row name, a digest or a StreamKey. The residual this gate carries, named
// rather than discovered: a second flattening that neither returns its octets nor stores them --
// one that, say, passed them straight to a closure argument -- is inert to this gate and is also
// inert to the program, because nothing outside it could observe the pair it built.
func TestEveryStreamKeyFlatteningInPackageSdkIsTheAdapters(t *testing.T) {
	adapterType := streamAdapterTypeName(t)
	_, parsed, declarations := streamAdapterParse(t)
	packageVars := streamAdapterPackageVarNames(parsed)
	reflectiveReads := map[string]bool{"Field": true, "FieldByName": true, "FieldByIndex": true}

	t.Logf("SCOPE: %d production file(s) of package sdk, %d function declaration(s)", len(parsed), len(declarations))
	t.Logf("CLASS: declarations containing a reflective field read %v", slices.Sorted(maps.Keys(reflectiveReads)))
	t.Logf("the adapter type, read by calling the producer rather than written down: %s", adapterType)

	members := 0
	inert := []string{}
	adapters := []string{}
	for _, declaration := range declarations {
		reads := streamAdapterCallsSelector(declaration.node, reflectiveReads)
		if len(reads) == 0 {
			continue
		}
		members += 1
		results := streamAdapterResultTypes(declaration.node)
		octetsOut := false
		for _, result := range results {
			if result == "[]byte" || result == "[][]byte" {
				octetsOut = true
			}
		}
		outward := streamAdapterAssignsOutward(declaration.node, packageVars)
		isAdapter := declaration.receiver == adapterType
		switch {
		case isAdapter:
			adapters = append(adapters, fmt.Sprintf("%s reads %v, results %v", declaration.label(), reads, results))
		case !octetsOut && len(outward) == 0:
			inert = append(inert, fmt.Sprintf("%s reads %v, results %v, assigns nothing outward", declaration.label(), reads, results))
		default:
			t.Errorf(
				"%s reads a StreamKey's fields %v and lets octets out (results %v, outward assignments %v), and it is not a method of %s. That is a SECOND flattening of one mapping: two derivations of which row a stream's indices land in, and the day they disagree the second stream is handed indices the first has already spent",
				declaration.label(),
				reads,
				results,
				outward,
				adapterType,
			)
		}
	}
	if members == 0 {
		t.Fatal("the class is empty, so this gate read no reflective field access at all and is holding nothing")
	}
	t.Logf("CLASS MEMBERS: %d", members)
	t.Logf("  the adapter's (%d):", len(adapters))
	for _, line := range adapters {
		t.Logf("    %s", line)
	}
	t.Logf("  COMPLEMENT the inertness narrowing removed (%d) -- these read the same fields and hand no octets out:", len(inert))
	for _, line := range inert {
		t.Logf("    %s", line)
	}
	if len(adapters) == 0 {
		t.Errorf("no method of %s reads a StreamKey's fields, so the flattening this task produces is not in the class this gate reads and the gate is holding nothing", adapterType)
	}
	if len(inert) == 0 {
		t.Log("NOTE: the inertness narrowing removed nothing on this tree, so every member is an adapter method. The narrowing is still stated because the store's own key derivations are the members it was written for")
	}
}

// The second half of Property 1: a flattening that never reaches the store is inert, so the gate
// above is paired with one over the CALL, and the call sites are where a second flattening
// actually does its damage.
//
// CLASS: the methods of *StreamStore whose SHAPE is section 8.2's key-shaped pair --
// (groupId, senderHandle []byte) answering (uint64, error) -- read off the type's own method set
// through reflection rather than written down, so a third method of that shape added tomorrow is
// in the class on the day it arrives.
// SCOPE, derived separately: every call expression in package sdk's production files.
func TestTheAdapterIsTheOnlyProductionCallerOfTheStoresKeyShapedMethods(t *testing.T) {
	adapterType := streamAdapterTypeName(t)
	storeType := reflect.TypeOf((*StreamStore)(nil))
	octets := reflect.TypeOf([]byte(nil))
	keyShaped := map[string]bool{}
	complement := []string{}
	for i := range storeType.NumMethod() {
		method := storeType.Method(i)
		shape := method.Type
		matches := shape.NumIn() == 3 && shape.In(1) == octets && shape.In(2) == octets &&
			shape.NumOut() == 2 && shape.Out(0).Kind() == reflect.Uint64 &&
			shape.Out(1) == reflect.TypeOf((*error)(nil)).Elem()
		if matches {
			keyShaped[method.Name] = true
			continue
		}
		complement = append(complement, fmt.Sprintf("%s%s", method.Name, shape.String()))
	}
	t.Logf("CLASS: %d key-shaped method(s) of *StreamStore, read off the method set: %v",
		len(keyShaped), slices.Sorted(maps.Keys(keyShaped)))
	t.Logf("COMPLEMENT the shape narrowing removed (%d exported method(s) of *StreamStore):", len(complement))
	for _, line := range complement {
		t.Logf("    %s", line)
	}
	if len(keyShaped) == 0 {
		t.Fatal("no method of *StreamStore has section 8.2's key shape, so this gate is holding nothing")
	}
	if len(complement) == 0 {
		t.Error("the complement is empty, so the shape narrowing removed no method at all and this gate is not the gate it says it is")
	}

	_, _, declarations := streamAdapterParse(t)
	callers := 0
	for _, declaration := range declarations {
		calls := streamAdapterCallsSelector(declaration.node, keyShaped)
		if len(calls) == 0 {
			continue
		}
		callers += 1
		if declaration.receiver != adapterType {
			t.Errorf(
				"%s calls the store's key-shaped method(s) %v and is not a method of %s; the two []byte it passes came from somewhere, and the only place in this package that may turn a StreamKey into them is the adapter",
				declaration.label(),
				calls,
				adapterType,
			)
			continue
		}
		t.Logf("  caller: %s calls %v", declaration.label(), calls)
	}
	if callers == 0 {
		t.Error("no production declaration calls the store's key-shaped methods, so nothing in this build reaches the durable reservation and this gate is holding nothing")
	}
}

// The third half, and it is the sentence the adapter's header makes: the adapter is the ONLY place
// a store failure becomes a messagegroup sentinel.
//
// CLASS: every production reference to an exported identifier of connect/messagegroup whose name
// begins with Err. The package's local name is read from each file's own import spec rather than
// assumed, so an aliased import cannot walk past this.
// SCOPE, derived separately: every production file of package sdk.
func TestTheAdapterIsTheOnlyProductionSourceThatNamesAMessagegroupSentinel(t *testing.T) {
	adapterType := streamAdapterTypeName(t)
	fileSet, parsed, declarations := streamAdapterParse(t)

	local := map[string]string{}
	for name, file := range parsed {
		for _, imported := range file.Imports {
			path, err := strconv.Unquote(imported.Path.Value)
			if err != nil || path != "github.com/urnetwork/connect/messagegroup" {
				continue
			}
			if imported.Name != nil {
				local[name] = imported.Name.Name
			} else {
				local[name] = "messagegroup"
			}
		}
	}
	t.Logf("SCOPE: %d production file(s); %d import connect/messagegroup: %v",
		len(parsed), len(local), slices.Sorted(maps.Keys(local)))
	if len(local) == 0 {
		t.Fatal("no production file imports connect/messagegroup, so this gate read no file in which a messagegroup sentinel could appear")
	}

	sentinelSites := map[string][]string{}
	otherSites := map[string]bool{}
	for name, file := range parsed {
		packageName, ok := local[name]
		if !ok {
			continue
		}
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			identifier, ok := selector.X.(*ast.Ident)
			if !ok || identifier.Name != packageName {
				return true
			}
			if strings.HasPrefix(selector.Sel.Name, "Err") {
				position := fileSet.Position(selector.Pos()).String()
				sentinelSites[selector.Sel.Name] = append(sentinelSites[selector.Sel.Name], position)
				return true
			}
			otherSites[selector.Sel.Name] = true
			return true
		})
	}
	t.Logf("CLASS: %d distinct messagegroup sentinel(s) named in production: %v",
		len(sentinelSites), slices.Sorted(maps.Keys(sentinelSites)))
	t.Logf("COMPLEMENT the Err narrowing removed (%d other messagegroup identifier(s) named in production): %v",
		len(otherSites), slices.Sorted(maps.Keys(otherSites)))
	if len(sentinelSites) == 0 {
		t.Fatal("no production source names a messagegroup sentinel, so nothing maps a store failure onto one and a store refusal reaches SenderRatchet.Next classified as retryable")
	}
	if len(otherSites) == 0 {
		t.Error("the complement is empty, which means the Err narrowing removed nothing and this gate is not the gate it says it is")
	}

	for _, declaration := range declarations {
		named := map[string]bool{}
		ast.Inspect(declaration.node, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			identifier, ok := selector.X.(*ast.Ident)
			if !ok {
				return true
			}
			if identifier.Name == local[declaration.file] && strings.HasPrefix(selector.Sel.Name, "Err") {
				named[selector.Sel.Name] = true
			}
			return true
		})
		if len(named) == 0 {
			continue
		}
		if declaration.receiver != adapterType {
			t.Errorf(
				"%s names the messagegroup sentinel(s) %v and is not a method of %s; a second mapping site is a second answer to the one question SenderRatchet.Next asks, and the two only have to disagree once",
				declaration.label(),
				slices.Sorted(maps.Keys(named)),
				adapterType,
			)
			continue
		}
		t.Logf("  mapping site: %s names %v", declaration.label(), slices.Sorted(maps.Keys(named)))
	}
}

// ----------------------------------------------------------------------------------------------
// Property 2 -- the adapter copies the key at the boundary.
// ----------------------------------------------------------------------------------------------

// StreamKey is comparable deliberately twice over, and section 8.2's []byte pair is neither
// comparable nor immutable. Nothing outside the adapter may come to hold a slice that names a
// row's identity, and no two calls may hand out the same array: a row's identity is which indices
// a stream has already spent.
func TestTheAdapterCopiesTheKeyAtTheBoundary(t *testing.T) {
	reserver, store := streamAdapterTestReserver(t)
	concrete := streamAdapterTestConcrete(t, reserver)
	key, parts := streamAdapterTestKey(t, 0x81)
	rowName := streamRowName(key)

	first, err := concrete.keyOctets(key)
	if err != nil {
		t.Fatalf("the flattening refused a well formed key: %v", err)
	}
	second, err := concrete.keyOctets(key)
	if err != nil {
		t.Fatalf("the flattening refused a well formed key on its second call: %v", err)
	}
	if len(first) != len(parts) {
		t.Fatalf("the flattening produced %d part(s), want %d", len(first), len(parts))
	}
	for i := range first {
		if !bytes.Equal(first[i], parts[i]) {
			t.Errorf("part %d is %x, want %x; the adapter's flattening and the store's must be inverses", first[i], parts[i], i)
		}
		if &first[i][0] == &second[i][0] {
			t.Errorf("part %d of two calls shares one backing array at %p; a buffer hoisted out of the call makes two flattenings alias, which is the same defect as not copying at all", i, &first[i][0])
		}
	}
	for i := range first {
		for j := range first {
			if i != j && &first[i][0] == &first[j][0] {
				t.Errorf("parts %d and %d of one call share a backing array", i, j)
			}
		}
	}

	// the observable: scribbling on what the flattening handed back must not move the row a
	// later call names.
	if index, err := reserver.Reserve(key); err != nil || index != 1 {
		t.Fatalf("the first allocation answered (%d, %v), want (1, nil)", index, err)
	}
	for i := range first {
		for j := range first[i] {
			first[i][j] ^= 0xFF
		}
	}
	if index, err := reserver.Reserve(key); err != nil || index != 2 {
		t.Fatalf("the allocation after the caller scribbled on the flattening's output answered (%d, %v), want (2, nil)", index, err)
	}
	length := streamTestRowLength(t, filepath.Join(store.rowDir, rowName))
	if length != 2*streamRecordWidth {
		t.Errorf("row %s is %d octets, want %d; both allocations must have landed on the SAME row, and a moved row is two ladders under one key", rowName, length, 2*streamRecordWidth)
	}
	entries, err := os.ReadDir(store.rowDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		names := []string{}
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Errorf("the row directory holds %d row(s) %v, want exactly 1; a second row is the scribble having moved the stream", len(entries), names)
	}
}

// ----------------------------------------------------------------------------------------------
// Property 3 -- the sentinel mapping, and the class it must be total over.
// ----------------------------------------------------------------------------------------------

// streamAdapterSentinelDeclarations reads package sdk's production syntax tree for every
// PACKAGE-LEVEL variable initialised by errors.New, and answers name -> message. It also answers
// the COMPLEMENT that narrowing removed: every other errors.New call site in production.
func streamAdapterSentinelDeclarations(t *testing.T) (map[string]string, []string) {
	t.Helper()
	fileSet, parsed, _ := streamAdapterParse(t)
	declared := map[string]string{}
	packageLevel := map[token.Pos]bool{}
	for _, file := range parsed {
		for _, declaration := range file.Decls {
			general, ok := declaration.(*ast.GenDecl)
			if !ok || general.Tok != token.VAR {
				continue
			}
			for _, spec := range general.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range value.Names {
					if len(value.Values) <= i {
						continue
					}
					message, ok := streamAdapterErrorsNewMessage(value.Values[i])
					if !ok {
						continue
					}
					declared[name.Name] = message
					packageLevel[value.Values[i].Pos()] = true
				}
			}
		}
	}
	complement := []string{}
	for name, file := range parsed {
		ast.Inspect(file, func(node ast.Node) bool {
			expression, ok := node.(ast.Expr)
			if !ok {
				return true
			}
			message, ok := streamAdapterErrorsNewMessage(expression)
			if !ok {
				return true
			}
			if packageLevel[expression.Pos()] {
				return true
			}
			complement = append(complement, fmt.Sprintf("%s: errors.New(%q) in %s",
				fileSet.Position(expression.Pos()).String(), message, name))
			return true
		})
	}
	slices.Sort(complement)
	return declared, complement
}

func streamAdapterErrorsNewMessage(expression ast.Expr) (string, bool) {
	call, ok := expression.(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return "", false
	}
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || selector.Sel.Name != "New" {
		return "", false
	}
	identifier, ok := selector.X.(*ast.Ident)
	if !ok || identifier.Name != "errors" {
		return "", false
	}
	literal, ok := call.Args[0].(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return "", false
	}
	text, err := strconv.Unquote(literal.Value)
	if err != nil {
		return "", false
	}
	return text, true
}

// CLASS: every error sentinel package sdk DECLARES -- every package-level variable initialised by
// errors.New, read off the syntax tree. It is deliberately the whole package and not a name
// prefix: the brief asks that a THIRD sentinel added later must not silently pass through, and a
// class narrowed to names containing "Stream" would let a sentinel spelled any other way do
// exactly that. Over-reach is the safe direction here -- an unrelated sentinel added to sdk fails
// this gate until somebody rules on it, which is a decision being asked for rather than skipped.
//
// SCOPE, derived separately: the declarations, not the uses. What a gate over uses would answer is
// which sentinels the store RAISES; what this has to answer is which sentinels EXIST, because the
// one that reaches the adapter unclassified is the one nothing raised yet.
func TestTheStoreSentinelClassIsTotalOverTheAdaptersMapping(t *testing.T) {
	declared, complement := streamAdapterSentinelDeclarations(t)
	t.Logf("CLASS: %d error sentinel(s) declared by package sdk: %v", len(declared), slices.Sorted(maps.Keys(declared)))
	t.Logf("COMPLEMENT the package-level narrowing removed (%d errors.New call site(s) that are not sentinels):", len(complement))
	for _, line := range complement {
		t.Logf("    %s", line)
	}
	if len(declared) == 0 {
		t.Fatal("this gate found no error sentinel at all, so it is holding nothing")
	}
	if len(complement) == 0 {
		t.Error("the complement is empty, which means the package-level narrowing removed no errors.New call at all and this gate is not the gate it says it is")
	}

	ruled := map[string]streamStoreSentinelRuling{}
	for _, ruling := range streamStoreSentinelRulings {
		if _, already := ruled[ruling.name]; already {
			t.Errorf("the adapter's mapping names %s twice", ruling.name)
		}
		ruled[ruling.name] = ruling
	}
	unclassified := []string{}
	for name := range declared {
		if _, ok := ruled[name]; !ok {
			unclassified = append(unclassified, name)
		}
	}
	stale := []string{}
	for name := range ruled {
		if _, ok := declared[name]; !ok {
			stale = append(stale, name)
		}
	}
	slices.Sort(unclassified)
	slices.Sort(stale)
	if len(unclassified) != 0 {
		t.Errorf(
			"%d sentinel(s) package sdk declares carry no ruling in the adapter's mapping: %v. An unclassified sentinel is forwarded as TRANSIENT, so a permanent refusal spelled this way would tell SenderRatchet.Next to retry forever and pay a durable write per attempt",
			len(unclassified), unclassified,
		)
	}
	if len(stale) != 0 {
		t.Errorf("the adapter's mapping rules on %d name(s) package sdk no longer declares: %v", len(stale), stale)
	}

	// and the ruling is bound to the VALUE and not only to the name: the message the declaration
	// carries must be the message the ruled sentinel answers.
	for _, ruling := range streamStoreSentinelRulings {
		message, ok := declared[ruling.name]
		if !ok {
			continue
		}
		if ruling.sentinel == nil {
			t.Errorf("the ruling for %s carries a nil sentinel", ruling.name)
			continue
		}
		if ruling.sentinel.Error() != message {
			t.Errorf(
				"the ruling named %s holds a sentinel whose message is %q, and the declaration of that name is errors.New(%q); a ruling bound to the wrong value classifies a refusal nobody raises and leaves the one it was written for unclassified",
				ruling.name, ruling.sentinel.Error(), message,
			)
		}
	}
	permanent, transient, rewound := 0, 0, 0
	for _, ruling := range streamStoreSentinelRulings {
		if ruling.permanent {
			permanent += 1
		} else {
			transient += 1
		}
		if ruling.rewound {
			rewound += 1
		}
		t.Logf("  %-30s permanent=%-5v rewound=%-5v %s", ruling.name, ruling.permanent, ruling.rewound, ruling.ruling)
	}
	t.Logf("VERDICTS: %d permanent, %d transient, %d rewound", permanent, transient, rewound)
	if permanent == 0 || transient == 0 {
		t.Error("the mapping rules every sentinel the same way, so the exactness case below cannot tell the two answers apart and neither can a ratchet")
	}
}

// The mapping is exact IN BOTH DIRECTIONS, and the two errors it must not make are opposites.
//
// A PERMANENT refusal forwarded as transient tells SenderRatchet.Next to retry a wedged ladder
// forever, paying a durable write per attempt. A TRANSIENT one forwarded as permanent wedges a
// healthy ladder over a full disk, which is the case connect/messagegroup's own ratchet names as
// the one that must stay a retry. This drives every member of the class, and both directions.
func TestNoPermanentRefusalIsForwardedAsTransientAndNoTransientOneIsWedged(t *testing.T) {
	reserver, _ := streamAdapterTestReserver(t)
	concrete := streamAdapterTestConcrete(t, reserver)

	// the reviewer's finding, executable: not one of the store's own sentinels is findable as
	// either messagegroup name, so an adapter that forwarded a store error unchanged would
	// classify the store's PERMANENT refusal as retryable.
	for _, ruling := range streamStoreSentinelRulings {
		if errors.Is(ruling.sentinel, messagegroup.ErrStreamIndexConsumed) {
			t.Errorf("%s is already findable as messagegroup.ErrStreamIndexConsumed, so the mapping this adapter performs is not load-bearing and this case is measuring nothing", ruling.name)
		}
		if errors.Is(ruling.sentinel, messagegroup.ErrStreamIndexRewound) {
			t.Errorf("%s is already findable as messagegroup.ErrStreamIndexRewound", ruling.name)
		}
	}

	for _, ruling := range streamStoreSentinelRulings {
		t.Run(ruling.name, func(t *testing.T) {
			raised := fmt.Errorf("row deadbeef: %w", ruling.sentinel)
			mapped := concrete.classify(raised)
			if mapped == nil {
				t.Fatal("the mapping answered nil for a refusal")
			}
			if !errors.Is(mapped, ruling.sentinel) {
				t.Errorf("the mapped error does not carry %s underneath; the store's own refusal must survive the wrap, or a caller that wanted to know WHICH refusal it met has lost it", ruling.name)
			}
			if !strings.Contains(mapped.Error(), "row deadbeef") {
				t.Errorf("the mapped error is %q and does not carry the store's own message", mapped.Error())
			}
			consumed := errors.Is(mapped, messagegroup.ErrStreamIndexConsumed)
			if consumed != ruling.permanent {
				t.Errorf(
					"%s maps to errors.Is(messagegroup.ErrStreamIndexConsumed) = %v and its ruling says permanent = %v. SenderRatchet.Next reads exactly that call: true stops the ladder forever, false retries it. The ruling is %q",
					ruling.name, consumed, ruling.permanent, ruling.ruling,
				)
			}
			rewound := errors.Is(mapped, messagegroup.ErrStreamIndexRewound)
			if rewound != ruling.rewound {
				t.Errorf("%s maps to errors.Is(messagegroup.ErrStreamIndexRewound) = %v and its ruling says rewound = %v", ruling.name, rewound, ruling.rewound)
			}
		})
	}

	// the control: an error carrying no member of the class is forwarded, and it is forwarded as
	// transient. That is safe only because the class above is total.
	foreign := errors.New("a refusal no sentinel of this package names")
	mapped := concrete.classify(foreign)
	if !errors.Is(mapped, foreign) {
		t.Error("an unclassified refusal lost its cause")
	}
	if errors.Is(mapped, messagegroup.ErrStreamIndexConsumed) || errors.Is(mapped, messagegroup.ErrStreamIndexRewound) {
		t.Errorf("an unclassified refusal was given a messagegroup sentinel: %v", mapped)
	}
	if mapped := concrete.classify(nil); mapped != nil {
		t.Errorf("the mapping answered %v for a nil error", mapped)
	}
}

// TWO OF THE EIGHT RULINGS ARE UNREACHABLE, and the unreachability is measured here rather than
// asserted in a comment beside them.
//
// This is what the mapping's own mutation set turned up. Flipping ErrStreamStoreLocked's verdict
// and flipping errStreamInjectedFlushFailure's verdict each left the whole stream and adapter
// suite green, where flipping any of the other six turned it red -- so those two verdicts are not
// answers anything consults, and a comment claiming they were would be exactly the undriven clause
// this pass exists to remove. They stay in the table because the class must be TOTAL: a sentinel
// with no ruling is forwarded as transient, and totality is what keeps a permanent refusal out of
// that bucket. What they do not get is a claim that something checks them.
//
// The reasons are different and both are observable.
func TestTheTwoRulingsNoErrorChainReaches(t *testing.T) {
	reserver, store := streamAdapterTestReserver(t)
	key, _ := streamAdapterTestKey(t, 0x89)

	// errStreamInjectedFlushFailure: writeOneRecord formats it with %v and not %w, so it is in
	// the MESSAGE and not in the CHAIN, and errors.Is cannot find it.
	streamTestSetInterrupt(t, store, streamAppendFailTheFlush)
	_, err := reserver.Reserve(key)
	if err == nil {
		t.Fatal("a failed flush was not refused")
	}
	if errors.Is(err, errStreamInjectedFlushFailure) {
		t.Errorf("a failed flush IS findable as errStreamInjectedFlushFailure (%v), so its ruling is reachable after all and the table's own note is stale", err)
	}
	if !strings.Contains(err.Error(), errStreamInjectedFlushFailure.Error()) {
		t.Errorf("a failed flush does not even carry the injected failure's text: %v", err)
	}
	if !errors.Is(err, ErrStreamStoreState) {
		t.Errorf("a failed flush is classified through %v instead", err)
	}
	t.Logf("errStreamInjectedFlushFailure is in the MESSAGE and not in the CHAIN: %v", err)

	// ErrStreamStoreLocked: OpenStreamStore raises it, and a reserver is built from a store
	// that is already open, so it cannot travel through either of the adapter's methods.
	second, err := OpenStreamStore(store.dir)
	if !errors.Is(err, ErrStreamStoreLocked) {
		if second != nil {
			second.Close()
		}
		t.Fatalf("a second store over one directory answered %v, want ErrStreamStoreLocked", err)
	}
	if second != nil {
		t.Error("a refused open answered a store as well as an error")
	}
	if reserver := NewStreamIndexReserver(second); reserver != nil {
		t.Error("a reserver was built over the store a locked open did not produce")
	}
	t.Logf("ErrStreamStoreLocked is raised before a reserver exists: %v", err)
}

// The two seats, through the REAL store rather than through a synthesised error. A rewind seen by
// a reader is ErrStreamIndexRewound and is NOT permanent; the same rewind met by an allocator is
// both, because the next position is one the store has already returned.
//
// Ledger item 171 turns on the difference, and mapping a rewind onto the consumed name alone would
// wedge a ladder whose store merely answered a query.
func TestTheReaderSeatIsRewoundAloneAndTheAllocatorSeatIsAlsoConsumed(t *testing.T) {
	reserver, store := streamAdapterTestReserver(t)
	key, _ := streamAdapterTestKey(t, 0x82)
	rowName := streamRowName(key)
	for want := uint64(1); want <= 3; want += 1 {
		if index, err := reserver.Reserve(key); err != nil || index != want {
			t.Fatalf("reserve answered (%d, %v), want (%d, nil)", index, err, want)
		}
	}
	path := filepath.Join(store.rowDir, rowName)
	if length := streamTestRowLength(t, path); length != 3*streamRecordWidth {
		t.Fatalf("the row is %d octets, want %d", length, 3*streamRecordWidth)
	}
	if err := os.Truncate(path, streamRecordWidth); err != nil {
		t.Fatalf("truncate the row: %v", err)
	}
	if length := streamTestRowLength(t, path); length != streamRecordWidth {
		t.Fatalf("the truncation did not land: the row is %d octets", length)
	}

	highWater, err := reserver.HighWater(key)
	if !errors.Is(err, messagegroup.ErrStreamIndexRewound) {
		t.Errorf("HighWater answered (%d, %v) for a row that went backwards, want messagegroup.ErrStreamIndexRewound", highWater, err)
	}
	if errors.Is(err, messagegroup.ErrStreamIndexConsumed) {
		t.Errorf("HighWater answered %v, which errors.Is finds ErrStreamIndexConsumed in. The reader's seat reports that the number moved; claiming the ladder is permanently wedged is the allocator's sentence and a ratchet built on this query would refuse every send for the life of the session", err)
	}
	if highWater != 0 {
		t.Errorf("a refused query answered %d beside its error", highWater)
	}

	index, err := reserver.Reserve(key)
	if !errors.Is(err, messagegroup.ErrStreamIndexRewound) {
		t.Errorf("Reserve answered (%d, %v), want messagegroup.ErrStreamIndexRewound", index, err)
	}
	if !errors.Is(err, messagegroup.ErrStreamIndexConsumed) {
		t.Errorf("Reserve answered %v, which errors.Is does not find ErrStreamIndexConsumed in; the allocator's next position is one it has already returned and no later call can make another", err)
	}
	if !errors.Is(err, ErrStreamStoreRewound) {
		t.Errorf("the mapped refusal lost the store's own sentinel: %v", err)
	}
	if index != 0 {
		t.Errorf("a refused allocation answered index %d beside its error", index)
	}
}

// A transient store failure is NOT the permanent refusal, and the ladder it happened on is still
// allocatable afterwards. This is the control for a mapping that over-reports: a mapping that
// called every failure permanent would wedge a healthy ladder over one failed flush.
func TestATransientStoreFailureIsNotTheConsumedSentinel(t *testing.T) {
	reserver, store := streamAdapterTestReserver(t)
	key, _ := streamAdapterTestKey(t, 0x83)

	streamTestSetInterrupt(t, store, streamAppendFailTheFlush)
	index, err := reserver.Reserve(key)
	if err == nil {
		t.Fatalf("a failed flush answered (%d, nil)", index)
	}
	if errors.Is(err, messagegroup.ErrStreamIndexConsumed) {
		t.Errorf("a failed flush answered %v, which errors.Is finds ErrStreamIndexConsumed in; connect/messagegroup's own ratchet names a full disk as the case that must stay a retry, and a ladder wedged on one never sends again", err)
	}
	if errors.Is(err, messagegroup.ErrStreamIndexRewound) {
		t.Errorf("a failed flush answered %v, which errors.Is finds ErrStreamIndexRewound in", err)
	}
	if !errors.Is(err, ErrStreamStoreState) {
		t.Errorf("the mapped refusal lost the store's own sentinel: %v", err)
	}
	if index != 0 {
		t.Errorf("a refused allocation answered index %d beside its error", index)
	}

	streamTestSetInterrupt(t, store, streamAppendUninterrupted)
	next, err := reserver.Reserve(key)
	if err != nil {
		t.Fatalf("the retry after a transient failure was refused: %v; a transient refusal a retry cannot clear is a permanent one wearing the wrong name", err)
	}
	if next != 2 {
		t.Errorf("the retry answered %d, want 2; the index the failed flush wrote is burned, and the server enforces monotonicity and not contiguity", next)
	}

	// the other synthetic interruption, so that BOTH of the mapping's unexported rulings are
	// driven through the adapter rather than only asserted against themselves.
	streamTestSetInterrupt(t, store, streamAppendTearBeforeFlush)
	torn, err := reserver.Reserve(key)
	if err == nil {
		t.Fatalf("an interrupted append answered (%d, nil)", torn)
	}
	if errors.Is(err, messagegroup.ErrStreamIndexConsumed) {
		t.Errorf("an interrupted append answered %v, which errors.Is finds ErrStreamIndexConsumed in; the next append overwrites the torn tail in place and succeeds, so it is a retry", err)
	}
	if !errors.Is(err, errStreamAppendInterrupted) {
		t.Errorf("the mapped refusal lost the interruption underneath: %v", err)
	}
	streamTestSetInterrupt(t, store, streamAppendUninterrupted)
	if after, err := reserver.Reserve(key); err != nil || after != 3 {
		t.Errorf("the retry after an interrupted append answered (%d, %v), want (3, nil)", after, err)
	}
}

// A ROW THIS BUILD CANNOT KEY IS PERMANENT, through the adapter. Ledger item 170's refusal is
// deliberately coarse -- one foreign-tagged row refuses every key in the directory -- and no retry
// rewrites it, so a ratchet told to keep asking would pay a durable write per attempt against a
// directory that will answer the same way forever.
func TestARowOfAnotherKeySpaceIsPermanentThroughTheAdapter(t *testing.T) {
	dir := t.TempDir()
	parts := streamTestKeyOctets(t, 0x88)
	key, err := streamKeyFromOctets(parts...)
	if err != nil {
		t.Fatal(err)
	}
	preA1 := streamKeyPreA1{}
	copy(preA1.GroupId[:], parts[0])
	copy(preA1.SenderHandle[:], parts[1])
	preA1.RetentionWire = 1
	foreignName := streamRowNameOf(reflect.ValueOf(preA1))
	if strings.HasPrefix(foreignName, streamKeySpaceTagOf(streamKeyType())) {
		t.Fatalf("the pre-A1 field set derives this build's own key-space tag, so this case cannot plant a foreign row")
	}
	streamTestPlantRow(t, dir, foreignName, streamTestRowBody(foreignName, 1, 2, 3))
	reserver := NewStreamIndexReserver(streamTestOpen(t, dir))

	for attempt := 1; attempt <= 3; attempt += 1 {
		index, err := reserver.Reserve(key)
		if !errors.Is(err, ErrStreamKeySpace) {
			t.Fatalf("attempt %d answered (%d, %v), want ErrStreamKeySpace underneath", attempt, index, err)
		}
		if !errors.Is(err, messagegroup.ErrStreamIndexConsumed) {
			t.Errorf("attempt %d answered %v, which errors.Is does not find ErrStreamIndexConsumed in; a foreign key space is not a state a retry leaves", err, attempt)
		}
	}
	if highWater, err := reserver.HighWater(key); !errors.Is(err, messagegroup.ErrStreamIndexConsumed) {
		t.Errorf("the query answered (%d, %v), want the permanent sentinel", highWater, err)
	}
}

// The store's PERMANENT refusal reaches a ratchet as the name it branches on, over the real store.
func TestTheStoresPermanentRefusalReachesTheRatchetAsTheConsumedSentinel(t *testing.T) {
	dir := t.TempDir()
	key, parts := streamAdapterTestKey(t, 0x84)
	rowName := streamRowName(key)
	streamTestPlantRow(t, dir, rowName, streamTestRowBody(rowName, ^uint64(0)))
	store := streamTestOpen(t, dir)
	reserver := NewStreamIndexReserver(store)

	if highWater, err := reserver.HighWater(key); err != nil || highWater != ^uint64(0) {
		t.Fatalf("high water answered (%d, %v), want (%d, nil)", highWater, err, ^uint64(0))
	}
	for attempt := 1; attempt <= 3; attempt += 1 {
		index, err := reserver.Reserve(key)
		if !errors.Is(err, messagegroup.ErrStreamIndexConsumed) {
			t.Fatalf("attempt %d answered (%d, %v), want messagegroup.ErrStreamIndexConsumed", attempt, index, err)
		}
		if !errors.Is(err, ErrStreamStoreConsumed) {
			t.Errorf("attempt %d lost the store's own sentinel: %v", attempt, err)
		}
	}
	// the same store, reached without the adapter, answers an error no ratchet can classify.
	_, raw := store.ReserveStreamIndex(parts[0], parts[1])
	if errors.Is(raw, messagegroup.ErrStreamIndexConsumed) {
		t.Error("the store's own refusal is already findable as messagegroup.ErrStreamIndexConsumed, so this adapter's mapping is not load-bearing")
	}
	t.Logf("WITHOUT the adapter, the same permanent refusal is %v -- errors.Is(messagegroup.ErrStreamIndexConsumed) = %v, which SenderRatchet.Next reads as RETRYABLE and would retry forever, paying a durable write per attempt",
		raw, errors.Is(raw, messagegroup.ErrStreamIndexConsumed))
}

// ----------------------------------------------------------------------------------------------
// Property 4 -- a wrong-width StreamKey cannot exist, and a wrong-width []byte cannot pass.
// ----------------------------------------------------------------------------------------------

// The StreamKey direction is total by construction, which is what the array types buy; this is the
// other half, re-checked AT THE ADAPTER so it is safe when it is the entry point rather than the
// exit. A flattening that truncated a field would otherwise reach the store as two well-formed
// slices naming a row that is not this stream's.
func TestAWrongWidthKeyParameterIsRefusedAtTheAdapter(t *testing.T) {
	reserver, _ := streamAdapterTestReserver(t)
	concrete := streamAdapterTestConcrete(t, reserver)
	key, parts := streamAdapterTestKey(t, 0x85)

	if err := concrete.refuseWrongWidth(parts); err != nil {
		t.Fatalf("the width check refused a correct flattening: %v", err)
	}
	keyType := streamKeyType()
	t.Logf("CLASS: %d field(s) of %s, each with its own width, read through reflection: this gate offers a wrong width for each in turn", keyType.NumField(), keyType.String())

	for i := range keyType.NumField() {
		width := keyType.Field(i).Type.Len()
		for _, wrong := range []int{width - 1, width + 1, 0} {
			bad := [][]byte{}
			for j, part := range parts {
				if j == i {
					bad = append(bad, make([]byte, wrong))
					continue
				}
				bad = append(bad, part)
			}
			err := concrete.refuseWrongWidth(bad)
			if !errors.Is(err, ErrStreamKeyWidth) {
				t.Errorf("a %d-octet parameter %d (the field is %d wide) answered %v, want ErrStreamKeyWidth at the adapter; a short key padded or a long key truncated collides two streams onto one row", wrong, i, width, err)
			}
			if mapped := concrete.classify(err); !errors.Is(mapped, messagegroup.ErrStreamIndexConsumed) {
				t.Errorf("the adapter's width refusal maps to %v, which is not permanent; a key of the wrong width is the wrong width on every retry", mapped)
			}
		}
	}

	// and a parameter COUNT that is not the count the store takes.
	short := parts[:len(parts)-1]
	if err := concrete.refuseWrongWidth(short); !errors.Is(err, ErrStreamKeyWidth) {
		t.Errorf("a flattening of %d parameter(s) answered %v, want ErrStreamKeyWidth", len(short), err)
	}
	long := append(append([][]byte{}, parts...), make([]byte, 8))
	if err := concrete.refuseWrongWidth(long); !errors.Is(err, ErrStreamKeyWidth) {
		t.Errorf("a flattening of %d parameter(s) answered %v, want ErrStreamKeyWidth", len(long), err)
	}
	// the correct key still allocates, so the check above refuses nothing it should not.
	if index, err := reserver.Reserve(key); err != nil || index != 1 {
		t.Errorf("a correct key answered (%d, %v), want (1, nil)", index, err)
	}

	// AND THE CHECK IS WIRED IN, which no input can drive: the StreamKey direction is total by
	// construction, so on a correct build nothing a caller can pass reaches this refusal through
	// the flattening. Deleting the CALL would therefore leave every case above green while the
	// adapter stopped checking anything -- which is the undriven-clause shape this whole pass is
	// about -- so the wiring is read off the syntax tree instead. Both ends are identified by
	// SHAPE and neither is named: the producer is the adapter method that hands octets out, the
	// checker is the adapter method that takes them and answers only an error.
	adapterType := streamAdapterTypeName(t)
	_, _, declarations := streamAdapterParse(t)
	producers := []streamAdapterDeclaration{}
	checkers := []streamAdapterDeclaration{}
	for _, declaration := range declarations {
		if declaration.receiver != adapterType {
			continue
		}
		results := streamAdapterResultTypes(declaration.node)
		parameters := []string{}
		if declaration.node.Type.Params != nil {
			for _, parameter := range declaration.node.Type.Params.List {
				parameters = append(parameters, streamAdapterTypeText(parameter.Type))
			}
		}
		if slices.Contains(results, "[][]byte") {
			producers = append(producers, declaration)
		}
		if len(parameters) == 1 && parameters[0] == "[][]byte" && len(results) == 1 && results[0] == "error" {
			checkers = append(checkers, declaration)
		}
	}
	t.Logf("the flattening's producers (%d) and the width checkers (%d), both read by shape off the adapter's method set", len(producers), len(checkers))
	if len(producers) == 0 || len(checkers) == 0 {
		t.Fatalf("the wiring gate found %d producer(s) and %d checker(s), so it is holding nothing", len(producers), len(checkers))
	}
	names := map[string]bool{}
	for _, checker := range checkers {
		names[checker.name] = true
	}
	for _, producer := range producers {
		calls := streamAdapterCallsSelector(producer.node, names)
		if len(calls) == 0 {
			t.Errorf(
				"%s hands octets out and calls none of the adapter's width checks %v; the StreamKey direction is total by construction, so a flattening that skipped the check would pass every input this gate can offer and would hand the store a truncated key that names another stream's row",
				producer.label(), slices.Sorted(maps.Keys(names)),
			)
			continue
		}
		t.Logf("  %s calls %v", producer.label(), calls)
	}
}

// ----------------------------------------------------------------------------------------------
// the interface's own contract, through the adapter rather than through the store
// ----------------------------------------------------------------------------------------------

// Clause 4: the store is total over its key space, so a stream never seen answers 0 with no error
// and the first allocation is 1. Clause 5: Reserve is not idempotent; two calls are two indices.
// Clause 2: HighWater never rewinds across a restart.
func TestTheAdapterIsTotalOverAStreamNeverSeenAndNeverRewindsAcrossARestart(t *testing.T) {
	dir := t.TempDir()
	store := streamTestOpen(t, dir)
	reserver := NewStreamIndexReserver(store)
	first, _ := streamAdapterTestKey(t, 0x86)
	second, _ := streamAdapterTestKey(t, 0x87)

	highWater, err := reserver.HighWater(first)
	if err != nil || highWater != 0 {
		t.Fatalf("a stream never seen answered (%d, %v), want (0, nil); the absence of an error is what clause 4 requires", highWater, err)
	}
	seen := map[uint64]bool{}
	for want := uint64(1); want <= 4; want += 1 {
		index, err := reserver.Reserve(first)
		if err != nil || index != want {
			t.Fatalf("allocation %d answered (%d, %v)", want, index, err)
		}
		if seen[index] {
			t.Fatalf("index %d was handed out twice", index)
		}
		seen[index] = true
	}
	// a second stream is a second counter: a shared one would answer 5 here.
	if index, err := reserver.Reserve(second); err != nil || index != 1 {
		t.Errorf("the first allocation of a second stream answered (%d, %v), want (1, nil); two streams sharing one row is two ladders on one counter", index, err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	reopened := streamTestOpen(t, dir)
	restarted := NewStreamIndexReserver(reopened)
	if highWater, err := restarted.HighWater(first); err != nil || highWater != 4 {
		t.Errorf("after a restart the first stream answered (%d, %v), want (4, nil); the ratchet resumes at highWater + 1 and never at a recomputed value", highWater, err)
	}
	if index, err := restarted.Reserve(first); err != nil || index != 5 {
		t.Errorf("the first allocation after a restart answered (%d, %v), want (5, nil)", index, err)
	}
}

// A nil store answers a nil reserver, and the refusal that owes is the one that already exists.
func TestANilStoreAnswersNoReserverAndNewGroupSessionRefusesIt(t *testing.T) {
	reserver := NewStreamIndexReserver(nil)
	if reserver != nil {
		t.Fatalf("NewStreamIndexReserver(nil) answered %#v, want a nil interface; a reserver over no store is a seal gated by nothing", reserver)
	}
	_, err := messagegroup.NewGroupSession(streamAdapterRealGroup(t), []byte("not the reserver under test"), nil,
		reserver, func() int64 { return 1 }, []byte("nonce"))
	if !errors.Is(err, messagegroup.ErrNilStreamIndexReserver) {
		t.Fatalf("NewGroupSession over a nil reserver answered %v, want ErrNilStreamIndexReserver; section 5.6 has the constructor take the sink to make it explicit, and that refusal is what gates every seal", err)
	}
	t.Logf("the refusal a nil store lands on, and it is messagegroup's rather than a second one here: %v", err)
}

// ----------------------------------------------------------------------------------------------
// HOW FAR THIS NOW REACHES, measured rather than asserted.
// ----------------------------------------------------------------------------------------------

// streamAdapterMlsStore is mls.StateStore in a map. It is declared in a _test.go file, so no
// production build of this package can reach it.
type streamAdapterMlsStore struct {
	lock        sync.Mutex
	groupStates map[string][]byte
	privateKeys map[string][]byte
	keyPackages map[string][3][]byte
}

func newStreamAdapterMlsStore() *streamAdapterMlsStore {
	return &streamAdapterMlsStore{
		groupStates: map[string][]byte{},
		privateKeys: map[string][]byte{},
		keyPackages: map[string][3][]byte{},
	}
}

func (self *streamAdapterMlsStore) PutGroupState(groupId []byte, epoch uint64, state []byte) error {
	self.lock.Lock()
	defer self.lock.Unlock()
	self.groupStates[fmt.Sprintf("%x/%d", groupId, epoch)] = append([]byte(nil), state...)
	return nil
}

func (self *streamAdapterMlsStore) GetGroupState(groupId []byte, epoch uint64) ([]byte, error) {
	self.lock.Lock()
	defer self.lock.Unlock()
	state, held := self.groupStates[fmt.Sprintf("%x/%d", groupId, epoch)]
	if !held {
		return nil, fmt.Errorf("no group state for %x at epoch %d", groupId, epoch)
	}
	return append([]byte(nil), state...), nil
}

func (self *streamAdapterMlsStore) DeleteGroupStateBefore(groupId []byte, epoch uint64) error {
	self.lock.Lock()
	defer self.lock.Unlock()
	for at := uint64(0); at < epoch; at += 1 {
		delete(self.groupStates, fmt.Sprintf("%x/%d", groupId, at))
	}
	return nil
}

func (self *streamAdapterMlsStore) PutPrivateKey(pub []byte, priv []byte) error {
	self.lock.Lock()
	defer self.lock.Unlock()
	self.privateKeys[fmt.Sprintf("%x", pub)] = append([]byte(nil), priv...)
	return nil
}

func (self *streamAdapterMlsStore) GetPrivateKey(pub []byte) ([]byte, error) {
	self.lock.Lock()
	defer self.lock.Unlock()
	priv, held := self.privateKeys[fmt.Sprintf("%x", pub)]
	if !held {
		return nil, fmt.Errorf("no private key for %x", pub)
	}
	return append([]byte(nil), priv...), nil
}

func (self *streamAdapterMlsStore) DeletePrivateKey(pub []byte) error {
	self.lock.Lock()
	defer self.lock.Unlock()
	delete(self.privateKeys, fmt.Sprintf("%x", pub))
	return nil
}

func (self *streamAdapterMlsStore) PutKeyPackage(ref []byte, kp []byte, initPriv []byte, encPriv []byte) error {
	self.lock.Lock()
	defer self.lock.Unlock()
	self.keyPackages[fmt.Sprintf("%x", ref)] = [3][]byte{
		append([]byte(nil), kp...), append([]byte(nil), initPriv...), append([]byte(nil), encPriv...),
	}
	return nil
}

func (self *streamAdapterMlsStore) TakeKeyPackage(ref []byte) ([]byte, []byte, []byte, error) {
	self.lock.Lock()
	defer self.lock.Unlock()
	held, ok := self.keyPackages[fmt.Sprintf("%x", ref)]
	if !ok {
		return nil, nil, nil, fmt.Errorf("no key package for %x", ref)
	}
	delete(self.keyPackages, fmt.Sprintf("%x", ref))
	return held[0], held[1], held[2], nil
}

// streamAdapterRealGroup founds a real one-member MLS group with real keys: a real crypto
// provider, a real signature key pair, a real X-Wing leaf key. The two things standing in are the
// two the fixture in connect/messagegroup also stands in for and names -- the mls state store,
// which is a map, and the clock, which is a constant.
func streamAdapterRealGroup(t *testing.T) messagegroup.GroupHandle {
	t.Helper()
	crypto, err := mls.NewCryptoProvider(mls.CipherSuiteX25519ChaCha20Sha256Ed25519)
	if err != nil {
		t.Fatalf("the crypto provider: %v", err)
	}
	signer, _, err := crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("the signature key pair: %v", err)
	}
	_, identityPub, err := crypto.SignatureKeyPair()
	if err != nil {
		t.Fatalf("the credential identity: %v", err)
	}
	xwing, err := messagegroup.XwingGenerateKey(bytes.NewReader(crypto.Random(messagegroup.XwingSeedSize)))
	if err != nil {
		t.Fatalf("the x-wing leaf key: %v", err)
	}
	leafKeys, err := (&mls.LeafKeysExtension{
		AlgId:          mls.AlgIdXwing,
		DeviceXwingPub: xwing.Public().Bytes(),
	}).Encode()
	if err != nil {
		t.Fatalf("encode the leaf keys: %v", err)
	}
	engine, err := messagegroup.NewConnectMlsEngine(crypto, newStreamAdapterMlsStore(), signer,
		mls.BasicCredential(identityPub), leafKeys.ExtensionData)
	if err != nil {
		t.Fatalf("the engine: %v", err)
	}
	policy := &mls.GroupPolicyExtension{
		Roles: []mls.RoleEntry{{MemberId: identityPub, Role: mls.RoleOwner}},
	}
	if err := policy.Canonicalize(); err != nil {
		t.Fatalf("canonicalize the policy: %v", err)
	}
	encoded, err := policy.Encode()
	if err != nil {
		t.Fatalf("encode the policy: %v", err)
	}
	groupId := make([]byte, 32)
	copy(groupId, "sdk-stream-adapter-reach")
	handle, err := engine.CreateGroup(groupId, encoded.ExtensionData, leafKeys.ExtensionData)
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	return handle
}

// THE FIRST PRODUCTION PATH FROM A GroupSession TO A DURABLE RESERVATION, and this case is the
// measurement of how far it reaches.
//
// Everything on the key path is real: a real MLS group, a real epoch exporter, real epoch read and
// write keys, a real record key ladder, and a real *sdk.StreamStore on a real directory reached
// through the production adapter this task produces. The stand-ins are named rather than left to
// be found -- the mls state store is a map, the clock is a constant, pq_secret is drawn by the
// production NewPqSecret but is not delivered by anything, and server_nonce is a constant because
// there is no connection to have chosen one.
//
// WHAT IT PROVES: the reservation the seal rests on is ON DISK before the record exists, and it
// survives the process that made it -- a fresh store over the same directory answers the same
// high water. WHAT IT DOES NOT PROVE is in the log line at the end.
func TestAGroupSessionSealsADurableRecordOverTheProductionStore(t *testing.T) {
	handle := streamAdapterRealGroup(t)
	dir := t.TempDir()
	store := streamTestOpen(t, dir)
	reserver := NewStreamIndexReserver(store)

	pqSecret, err := messagegroup.NewPqSecret(rand.Reader)
	if err != nil {
		t.Fatalf("NewPqSecret: %v", err)
	}
	serverNonce := []byte("sdk-stream-adapter-has-no-connection")
	session, err := messagegroup.NewGroupSession(handle, pqSecret, nil, reserver,
		func() int64 { return 1_700_000_000_000 }, serverNonce)
	if err != nil {
		t.Fatalf("NewGroupSession over the production reserver: %v", err)
	}
	defer session.Close()

	senderHandle, err := session.SenderHandle()
	if err != nil {
		t.Fatalf("SenderHandle: %v", err)
	}
	key, err := streamKeyFromOctets(handle.GroupId(), senderHandle[:])
	if err != nil {
		t.Fatalf("the stream this session will allocate on: %v", err)
	}
	rowName := streamRowName(key)
	path := filepath.Join(store.rowDir, rowName)
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the row exists before the seal: %v", err)
	}

	record, err := session.SealRecord(message.RetentionDurable, 0, false,
		[]byte("head"), []byte("a real durable record"), 0, nil)
	if err != nil {
		t.Fatalf("SealRecord over a durable reserver: %v", err)
	}
	if record == nil {
		t.Fatal("SealRecord answered no record and no error")
	}
	if record.Header.StreamIndex != 1 {
		t.Errorf("the sealed record carries stream_index %d, want 1", record.Header.StreamIndex)
	}
	if len(record.CtBody) == 0 || record.WriteAuth == ([32]byte{}) {
		t.Error("the record carries no ciphertext or no write_auth")
	}

	// the reservation is DURABLE and it was durable before the record existed.
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the row the seal reserved on: %v", err)
	}
	if int64(len(body)) != streamRecordWidth {
		t.Errorf("the row is %d octets after one seal, want %d", len(body), streamRecordWidth)
	}
	if index := streamRecordIndex(body); index != record.Header.StreamIndex {
		t.Errorf("the row records index %d and the record carries stream_index %d", index, record.Header.StreamIndex)
	}
	if !verifyStreamRecord(rowName, body) {
		t.Error("the row's record does not verify under its own name")
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close the store: %v", err)
	}
	reopened := streamTestOpen(t, dir)
	if highWater, err := NewStreamIndexReserver(reopened).HighWater(key); err != nil || highWater != 1 {
		t.Errorf("a fresh store over the same directory answered (%d, %v), want (1, nil)", highWater, err)
	}

	keys, err := session.EpochKeys()
	if err != nil {
		t.Fatalf("EpochKeys: %v", err)
	}
	epoch, err := keys.Epoch()
	if err != nil {
		t.Fatalf("the epoch these keys were expanded at: %v", err)
	}
	writeKey, err := keys.WriteKey()
	if err != nil {
		t.Fatalf("the epoch write key: %v", err)
	}
	if len(writeKey) == 0 {
		t.Error("the epoch write key is empty")
	}
	t.Logf("REACHED: a real MLS group at epoch %d, a real epoch write key of %d octets, a real record key ladder, and a DURABLE reservation at index %d on disk at %s",
		epoch, len(writeKey), record.Header.StreamIndex, path)
	t.Logf("WHAT STANDS BETWEEN THIS RECORD AND msgrepo's Submit, measured on this tree:")
	t.Logf("  1. THE PROJECTION. api/submit.go takes a *protocol.SubmitRequest whose records are *protocol.Record, and re-projects ParseRecord(record_bytes) itself to compare with proto.Equal. Package sdk has ZERO production references to protocol.Record or protocol.SubmitRequest, so this sealed *message.Record has no wire form at all. This is the first missing piece and it is the plan's Task 8")
	t.Logf("  2. THE TRANSPORT. There is no connect.Client binding in sdk at any section 10.1 code point, no request_id correlation and no section 4.6 fragmentation, so there is nothing to carry a request even once one exists")
	t.Logf("  3. THE SERVER NONCE. write_auth is a mac over the submitting connection's nonce. This case supplies a constant because there is no connection; Hello is what supplies a real one, and GroupSession.RebindServerNonce -- which exists and has zero production call sites anywhere in these three trees -- is what installs it. A record sealed under a constant nonce is refused by check 7")
	t.Log("  and none of the three is built here")
}
