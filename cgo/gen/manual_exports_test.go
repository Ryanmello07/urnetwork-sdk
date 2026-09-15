package main

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// exportDirective is gen.go's own scan pattern, character for character. `\r?$` rather than `$`
// because a CRLF checkout is what core.autocrlf=true gives every Windows clone, and under `$`
// this matched nothing at all there -- which would make every case below pass vacuously.
var exportDirective = regexp.MustCompile(`(?m)^//export (\w+)[ \t]*\r?$`)

// THE .def IS A PROMISE ABOUT WHAT THE SHIPPED LIBRARY CONTAINS, AND manualExports READS RAW FILE
// BYTES.
//
// An MSVC import library is generated from include/urnetwork_sdk.def. A .def that names a symbol
// the dll does not export is a link error at the consumer, and manualExports has no compiler in
// it: it greps //export out of every hand-written .go file in the package directory, build tags
// and all. So a file that is compiled out of the shipping library would still put its exports in
// the .def unless something stops it. inAnyShippedBuild is that something and this is its gate.
func TestAFileNoShippedBuildCompilesContributesNoExportedSymbol(t *testing.T) {
	for _, c := range []struct {
		name   string
		source string
		want   bool
	}{
		{"no constraint at all", "package main\n\n//export urnet_x\nfunc urnet_x() {}\n", true},
		{"a tag nobody passes", "//go:build urnet_message_loopback\n\npackage main\n", false},
		{"a tag nobody passes, negated", "//go:build !urnet_message_loopback\n\npackage main\n", true},
		{"a goos that is not this one", "//go:build js\n\npackage main\n", true},
		{"not a goos", "//go:build !js\n\npackage main\n", true},
		{"unix", "//go:build unix\n\npackage main\n", true},
		{"an and of a real tag and a made up one", "//go:build unix && urnet_message_loopback\n\npackage main\n", false},
		{"an or of a real tag and a made up one", "//go:build unix || urnet_message_loopback\n\npackage main\n", true},
		{"crlf line endings", "//go:build urnet_message_loopback\r\n\r\npackage main\r\n", false},
		{"a comment that only looks like one", "// go:build urnet_message_loopback\n\npackage main\n", true},
		{
			"a constraint below the package clause is not a constraint",
			"package main\n\n//go:build urnet_message_loopback\n",
			true,
		},
		{"an unparseable constraint is not published", "//go:build && ||\n\npackage main\n", false},
	} {
		if got := inAnyShippedBuild(c.source); got != c.want {
			t.Errorf("%s: inAnyShippedBuild answered %v, want %v", c.name, got, c.want)
		}
	}
}

// And the same property held against the REAL file rather than against a string written here: the
// loopback world is the only build-tag-gated file in this package today, it really does carry
// //export directives, and not one of them may reach the .def.
//
// The second half of this -- that the file HAS exports -- is what keeps the first half from
// passing vacuously if the harness is ever deleted or renamed.
func TestTheLoopbackHarnessIsNotInTheShippingLibrarysDef(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not resolve test path")
	}
	path := filepath.Join(filepath.Dir(filename), "..", "loopback_test_world.go")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the loopback harness is not where this test expects it: %v", err)
	}
	source := string(b)

	exports := exportDirective.FindAllStringSubmatch(source, -1)
	if len(exports) == 0 {
		t.Fatal("loopback_test_world.go declares no //export, so this case proves nothing")
	}
	for _, m := range exports {
		if !strings.HasPrefix(m[1], "urnet_message_loopback_") {
			t.Errorf("the harness exports %q, which is not under the urnet_message_loopback_ prefix "+
				"the shipping-library check in ctest/run.sh greps for", m[1])
		}
	}
	if inAnyShippedBuild(source) {
		t.Fatalf("the harness's %d exports would reach include/urnetwork_sdk.def, and they are in "+
			"no shipped library", len(exports))
	}

	// and the .def as it stands names none of them
	defBytes, err := os.ReadFile(filepath.Join(filepath.Dir(filename), "..", "include", "urnetwork_sdk.def"))
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range exports {
		if strings.Contains(string(defBytes), m[1]) {
			t.Errorf("include/urnetwork_sdk.def names the harness symbol %q", m[1])
		}
	}

	// THROUGH manualExports ITSELF, not only through inAnyShippedBuild. The generator runs from the
	// cgo module root, so this goes there and calls the real function. Without these lines,
	// deleting the `if !inAnyShippedBuild(...)` guard from manualExports leaves every case in this
	// file green -- which was true of this test until it grew them.
	t.Chdir(filepath.Join(filepath.Dir(filename), ".."))
	manual := manualExports()
	if len(manual) == 0 {
		t.Fatal("manualExports found nothing at all, so the two checks below prove nothing")
	}
	byName := map[string]bool{}
	for _, name := range manual {
		byName[name] = true
	}
	for _, m := range exports {
		if byName[m[1]] {
			t.Errorf("manualExports published the harness symbol %q, which no shipped library exports", m[1])
		}
	}
	// and the hand-written messaging surface, which DOES ship, is still found -- the control that
	// says the exclusion above is about the build tag rather than about the scan being broken
	if !byName["urnet_message_group_send"] {
		t.Errorf("manualExports did not find urnet_message_group_send among its %d names; on a CRLF "+
			"checkout that is the `\\r?$` in its scan pattern having been lost", len(manual))
	}
}

// The messaging surface is hand-written and the .def is generated, so the .def is STALE with
// respect to it until someone runs `make generate`. That is stated in exports_message.go and it
// is harmless -- a .def is only read to build an MSVC import library -- but it must be a known
// staleness rather than a surprise, so this case names the size of it.
func TestTheDefIsStaleWithRespectToTheHandWrittenMessagingSurface(t *testing.T) {
	_, filename, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not resolve test path")
	}
	root := filepath.Join(filepath.Dir(filename), "..")
	b, err := os.ReadFile(filepath.Join(root, "exports_message.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !inAnyShippedBuild(string(b)) {
		t.Fatal("exports_message.go is behind a build constraint, so the messaging abi does not ship")
	}
	exports := exportDirective.FindAllStringSubmatch(string(b), -1)
	if len(exports) == 0 {
		t.Fatal("exports_message.go declares no //export")
	}
	defBytes, err := os.ReadFile(filepath.Join(root, "include", "urnetwork_sdk.def"))
	if err != nil {
		t.Fatal(err)
	}
	present := 0
	for _, m := range exports {
		if strings.Contains(string(defBytes), "\n\t"+m[1]+"\n") {
			present += 1
		}
	}
	// This is the state today and it is the state the commit describes. If someone regenerates,
	// present becomes len(exports) and this case says so rather than passing quietly on both.
	switch present {
	case 0:
		t.Logf("include/urnetwork_sdk.def names 0 of the %d messaging exports; `make generate` is owed",
			len(exports))
	case len(exports):
		t.Logf("include/urnetwork_sdk.def names all %d messaging exports; the generator has been run",
			len(exports))
	default:
		t.Errorf("include/urnetwork_sdk.def names %d of the %d messaging exports, which is neither "+
			"the pre-generate state nor the post-generate one", present, len(exports))
	}
}
