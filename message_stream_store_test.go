package sdk

import (
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
	"testing"

	"github.com/urnetwork/connect/messagegroup"
)

// ----------------------------------------------------------------------------------------------
// fixtures
// ----------------------------------------------------------------------------------------------

// streamKeyPreA1 is the key wave 1 shipped, BEFORE ruling A1 removed the retention-class byte.
// It exists here and only here, so a test can write what a pre-A1 build would have written by
// handing the production derivation the pre-A1 FIELD SET rather than by reimplementing that
// derivation. Nothing in production may name these fields; see
// TestNoProductionSourceOfPackageSdkSpellsAStreamKeyFieldName.
type streamKeyPreA1 struct {
	GroupId       [32]byte
	SenderHandle  [16]byte
	RetentionWire byte
}

func streamTestOctets(width int, seed byte) []byte {
	octets := make([]byte, width)
	for i := range octets {
		octets[i] = seed + byte(i)
	}
	return octets
}

func streamTestKeyOctets(t *testing.T, seed byte) [][]byte {
	t.Helper()
	keyType := streamKeyType()
	parts := make([][]byte, 0, keyType.NumField())
	for i := range keyType.NumField() {
		parts = append(parts, streamTestOctets(keyType.Field(i).Type.Len(), seed+byte(17*i)))
	}
	return parts
}

func streamTestRowName(t *testing.T, parts [][]byte) string {
	t.Helper()
	key, err := streamKeyFromOctets(parts...)
	if err != nil {
		t.Fatalf("the fixture's own key would not flatten: %v", err)
	}
	return streamRowName(key)
}

// streamTestRowBody builds a row carrying one whole verifying record per index, in order.
func streamTestRowBody(rowName string, indices ...uint64) []byte {
	body := make([]byte, 0, len(indices)*streamRecordWidth)
	for _, index := range indices {
		record := encodeStreamRecord(rowName, index)
		body = append(body, record[:]...)
	}
	return body
}

// streamTestCorruptRecord overwrites one whole record's octets IN PLACE, leaving the row's
// length unchanged, so that record fails its checksum.
func streamTestCorruptRecord(body []byte, position int) {
	for i := (position - 1) * streamRecordWidth; i < position*streamRecordWidth; i += 1 {
		body[i] ^= 0xff
	}
}

func streamTestPlantRow(t *testing.T, dir string, rowName string, body []byte) string {
	t.Helper()
	rowDir := filepath.Join(dir, streamRowDirName)
	if err := os.MkdirAll(rowDir, 0o700); err != nil {
		t.Fatalf("plant the row directory: %v", err)
	}
	path := filepath.Join(rowDir, rowName)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatalf("plant row %s: %v", rowName, err)
	}
	return path
}

// streamTestAppendOneRecord is the ONE append an allocation performs, simulated here because the
// allocation path -- ReserveStreamIndex, its fsync boundary and its two sentinels -- is the next
// task's and does not exist yet. It uses the production encoder, appends exactly one whole
// record at EOF and flushes, which is the discipline classifyStreamRow's case-2 bound is derived
// from.
func streamTestAppendOneRecord(t *testing.T, path string, rowName string, index uint64) {
	t.Helper()
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatalf("open %s to append: %v", path, err)
	}
	defer file.Close()
	record := encodeStreamRecord(rowName, index)
	if _, err := file.Write(record[:]); err != nil {
		t.Fatalf("append a record to %s: %v", path, err)
	}
	if err := file.Sync(); err != nil {
		t.Fatalf("flush %s: %v", path, err)
	}
}

func streamTestRowLength(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	return info.Size()
}

func streamTestOpen(t *testing.T, dir string) *StreamStore {
	t.Helper()
	store, err := OpenStreamStore(dir)
	if err != nil {
		t.Fatalf("open the store at %s: %v", dir, err)
	}
	t.Cleanup(func() {
		store.Close()
	})
	return store
}

// ----------------------------------------------------------------------------------------------
// Property 1 -- a row is identified by exactly the fields the RESERVATION is keyed by, and the
// identity is DERIVED from StreamKey's own field set rather than spelled.
// ----------------------------------------------------------------------------------------------

// CLASS: the fields of connect/messagegroup.StreamKey.
// SCOPE, derived separately: the type StreamKey as connect/messagegroup declares it TODAY, read
// through reflection at test time -- not a copy of its field names kept in sdk. A gate that
// listed GroupId and SenderHandle would survive the day a third field returns and is therefore
// not this gate. The gate REPORTS the number of fields it read, so a field added or removed in
// connect fails here rather than silently re-keying every row.
func TestStreamRowIdentityIsDerivedFromStreamKeysOwnFieldSet(t *testing.T) {
	keyType := streamKeyType()
	fieldCount := keyType.NumField()
	t.Logf("CLASS: %d field(s) of %s", fieldCount, keyType.String())
	t.Logf(
		"SCOPE: the 1 type connect/messagegroup declares today, read through reflection at test time; 0 lists of field names kept in sdk were read",
	)
	if fieldCount == 0 {
		t.Fatalf("%s declares no fields, so this gate read nothing", keyType.String())
	}

	// the key-space tag the store carries is the tag of the type connect declares, and not of
	// anything sdk keeps a copy of.
	dir := t.TempDir()
	store := streamTestOpen(t, dir)
	wantTag := streamKeySpaceTagOf(keyType)
	if store.keySpaceTag != wantTag {
		t.Errorf(
			"the store's key-space tag is %q and the tag of %s (%d fields, read by reflection here) is %q; the store is keying rows off some other field set",
			store.keySpaceTag,
			keyType.String(),
			fieldCount,
			wantTag,
		)
	}

	// the row name is TAG then IDENTITY, fixed width, tag first.
	parts := streamTestKeyOctets(t, 1)
	rowName := streamTestRowName(t, parts)
	if len(rowName) != streamRowNameLen {
		t.Errorf("a row name is %d characters, want %d (a %d-character tag then a %d-character identity)",
			len(rowName), streamRowNameLen, streamKeySpaceTagLen, streamRowIdentityLen)
	}
	if !strings.HasPrefix(rowName, wantTag) {
		t.Errorf(
			"the row name %q does not begin with the key-space tag %q; a tag that is not a fixed-width prefix cannot be read off a foreign row's name, and a foreign row that cannot be read is an absent row answered (0, nil)",
			rowName,
			wantTag,
		)
	}

	// EVERY field separates a row, derived off the type rather than written as the cases this
	// type happens to have today.
	for i := range fieldCount {
		field := keyType.Field(i)
		base := reflect.New(keyType)
		apart := reflect.New(keyType)
		differing := apart.Elem().Field(i)
		if differing.Kind() != reflect.Array {
			differing.SetUint(1)
		} else {
			differing.Index(0).SetUint(1)
		}
		if base.Elem().Interface() == apart.Elem().Interface() {
			t.Fatalf("%s.%s could not be made to differ, so this case cannot judge it", keyType.String(), field.Name)
		}
		if streamRowNameOf(base.Elem()) == streamRowNameOf(apart.Elem()) {
			t.Errorf(
				"two keys differing only in %s.%s derive the SAME row name, so the two streams share one row and the second is handed indices the first has already used",
				keyType.String(),
				field.Name,
			)
		}
	}

	// the flattening takes exactly as many positional parameters as the type declares fields.
	if _, err := streamKeyFromOctets(parts...); err != nil {
		t.Errorf("the flattening refused %d well-formed key parameters: %v", fieldCount, err)
	}
	for _, wrong := range []int{fieldCount - 1, fieldCount + 1} {
		if wrong < 0 {
			continue
		}
		offered := make([][]byte, 0, wrong)
		for i := range wrong {
			width := 32
			if i < fieldCount {
				width = keyType.Field(i).Type.Len()
			}
			offered = append(offered, streamTestOctets(width, 9))
		}
		_, err := streamKeyFromOctets(offered...)
		if !errors.Is(err, ErrStreamKeyWidth) {
			t.Errorf(
				"the flattening answered %v for %d key parameters when %s declares %d fields; a field added or removed in connect must arrive here as a refusal and not as a zero-valued field nobody passed",
				err,
				wrong,
				keyType.String(),
				fieldCount,
			)
		}
	}
}

// The other half of Property 1, and the half that is the ledger-21 defect if it is missing: the
// derivation must be a DERIVATION and not two spelled names that happen to agree with it today.
//
// CLASS: the field names of connect/messagegroup.StreamKey, read through reflection at test
// time. Not a list.
// SCOPE, derived separately: every non-test .go file in package sdk's own directory. The
// narrowing this gate performs is production-versus-test, and its complement -- the test files,
// which MAY spell a field name because a test is where a pre-A1 fixture is built -- is printed
// below with its size, together with the assertion that scope and complement partition the
// directory's .go files exactly.
// Comments are NOT read: a comment cannot key a row, and the package doc in message.go names
// both fields deliberately.
func TestNoProductionSourceOfPackageSdkSpellsAStreamKeyFieldName(t *testing.T) {
	keyType := streamKeyType()
	names := map[string]bool{}
	for i := range keyType.NumField() {
		names[keyType.Field(i).Name] = true
	}
	t.Logf("CLASS: %d field name(s) of %s, read through reflection at test time: %v", len(names), keyType.String(), slices.Sorted(maps.Keys(names)))
	if len(names) == 0 {
		t.Fatalf("%s declares no fields, so this gate looked for nothing", keyType.String())
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read the package directory: %v", err)
	}
	all := []string{}
	scope := []string{}
	complement := []string{}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		all = append(all, entry.Name())
		if strings.HasSuffix(entry.Name(), "_test.go") {
			complement = append(complement, entry.Name())
		} else {
			scope = append(scope, entry.Name())
		}
	}
	t.Logf("SCOPE: %d production .go file(s) in package sdk's own directory", len(scope))
	t.Logf("COMPLEMENT removed by this narrowing: %d test .go file(s): %v", len(complement), complement)
	if len(scope) == 0 {
		t.Fatal("the scope is empty, so this gate read no production source at all")
	}
	if len(complement) == 0 {
		t.Fatal("the complement is empty, which means the production/test narrowing removed nothing and this gate is not the gate it says it is")
	}
	if len(all) != len(scope)+len(complement) {
		t.Fatalf("the narrowing does not partition the directory: %d .go files, %d in scope, %d in the complement", len(all), len(scope), len(complement))
	}

	fileSet := token.NewFileSet()
	sawTheKeyType := []string{}
	for _, name := range scope {
		parsed, err := parser.ParseFile(fileSet, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, imported := range parsed.Imports {
			path, err := strconv.Unquote(imported.Path.Value)
			if err == nil && path == "github.com/urnetwork/connect/messagegroup" {
				sawTheKeyType = append(sawTheKeyType, name)
			}
		}
		ast.Inspect(parsed, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.Ident:
				if names[typed.Name] {
					t.Errorf(
						"%s spells the identifier %s, which is a field name of %s read by reflection in this test; the row derivation must read the field set rather than name it, or a field added or removed in connect silently re-keys every row instead of failing here",
						fileSet.Position(typed.Pos()),
						typed.Name,
						keyType.String(),
					)
				}
			case *ast.BasicLit:
				if typed.Kind != token.STRING {
					return true
				}
				value, err := strconv.Unquote(typed.Value)
				if err == nil && names[value] {
					t.Errorf(
						"%s carries the string literal %q, which is a field name of %s read by reflection in this test",
						fileSet.Position(typed.Pos()),
						value,
						keyType.String(),
					)
				}
			}
			return true
		})
	}
	if len(sawTheKeyType) == 0 {
		t.Errorf(
			"no production file in the scope imports connect/messagegroup, so this gate read no file in which a %s field could appear at all",
			keyType.String(),
		)
	} else {
		t.Logf("production files that can name a %s: %v", keyType.String(), sawTheKeyType)
	}
}

// ----------------------------------------------------------------------------------------------
// Property 2 -- a row whose key space this build did not produce is REFUSED, never answered zero.
// ----------------------------------------------------------------------------------------------

// This is ledger item 170, executable. A store holding rows under the pre-A1 three-field key
// answers HighWater 0 for an A1 key unless something refuses; the ladder then resumes at 1 and
// re-issues record_key[1] under a class key that has not moved, which is a repeated (key, nonce)
// on BOTH of a record's AEADs.
//
// CLASS: the three partitions of a name in the row directory -- (a) this build's tag, (b) a
// fixed-width tag that is not this build's whatever its value, (c) anything else.
// SCOPE, derived separately: the ROW DIRECTORY's entries, enumerated, and not the single path a
// key names. A gate written over one stat cannot see (b) at all.
func TestARowOfAnotherKeySpaceIsRefusedAndNeverAnsweredZero(t *testing.T) {
	parts := streamTestKeyOctets(t, 3)

	preA1 := streamKeyPreA1{}
	copy(preA1.GroupId[:], parts[0])
	copy(preA1.SenderHandle[:], parts[1])
	preA1.RetentionWire = 1
	foreignName := streamRowNameOf(reflect.ValueOf(preA1))
	thisTag := streamKeySpaceTagOf(streamKeyType())

	if len(foreignName) != streamRowNameLen {
		t.Fatalf(
			"the pre-A1 row name is %d characters and this build's is %d; if a foreign row does not parse as tag-then-identity it falls into partition (c) and would be owed an error the store does not produce for it",
			len(foreignName),
			streamRowNameLen,
		)
	}
	if strings.HasPrefix(foreignName, thisTag) {
		t.Fatalf("the pre-A1 field set derives this build's key-space tag %q, so the fixture cannot plant a foreign row at all", thisTag)
	}
	t.Logf("this build's key-space tag is %q; the pre-A1 (three-field) tag is %q", thisTag, foreignName[:streamKeySpaceTagLen])
	exercised := map[streamRowClass]int{}
	planted := 0

	dir := t.TempDir()
	streamTestPlantRow(t, dir, foreignName, streamTestRowBody(foreignName, 1, 2, 3))
	store := streamTestOpen(t, dir)
	planted += 1

	highWater, err := store.streamHighWater(parts[0], parts[1])
	if !errors.Is(err, ErrStreamKeySpace) {
		t.Errorf(
			"a row written under the pre-A1 key derivation was answered (%d, %v); want ErrStreamKeySpace. A (0, nil) here is ledger item 170 reproduced in sdk: the ladder restarts at index 1 under a class key that has not moved, which is a reused nonce under a reused record_key",
			highWater,
			err,
		)
	}
	if errors.Is(err, ErrStreamStoreState) {
		t.Errorf(
			"a foreign-key-space row was answered ErrStreamStoreState (%v); partition (b) is a row this build cannot KEY, not an entry that is not a row, and collapsing the two loses the only refusal that names the transition rule",
			err,
		)
	}
	if highWater != 0 {
		t.Errorf("the refusal carried a high water of %d; a refusal answers no index", highWater)
	}

	// partition (c): an entry in the row directory that is not a row under any tag.
	exercised[store.classifyStreamRowName(foreignName)] += 1
	exercised[store.classifyStreamRowName(streamTestRowName(t, parts))] += 1
	for _, notARow := range []string{
		"notarow",
		strings.Repeat("z", streamRowNameLen),
		strings.Repeat("a", streamRowNameLen-1),
	} {
		exercised[store.classifyStreamRowName(notARow)] += 1
		other := t.TempDir()
		streamTestPlantRow(t, other, notARow, []byte("x"))
		otherStore := streamTestOpen(t, other)
		planted += 1
		_, err := otherStore.streamHighWater(parts[0], parts[1])
		if !errors.Is(err, ErrStreamStoreState) {
			t.Errorf("%q in the row directory was answered %v; an entry that is not a row under any tag is ErrStreamStoreState", notARow, err)
		}
		if errors.Is(err, ErrStreamKeySpace) {
			t.Errorf("%q in the row directory was answered ErrStreamKeySpace; it parses as no tag at all", notARow)
		}
	}

	// and a non-regular entry: the row directory holds rows and nothing else, by
	// construction, so the exclusion the next task adds sits beside it and never in it.
	nested := t.TempDir()
	if err := os.MkdirAll(filepath.Join(nested, streamRowDirName, "subdir"), 0o700); err != nil {
		t.Fatalf("plant a directory inside the row directory: %v", err)
	}
	nestedStore := streamTestOpen(t, nested)
	planted += 1
	if _, err := nestedStore.streamHighWater(parts[0], parts[1]); !errors.Is(err, ErrStreamStoreState) {
		t.Errorf("a directory inside the row directory was answered %v; want ErrStreamStoreState", err)
	}

	// and the case the name cannot catch: a DIRECTORY whose name parses as an ordinary row
	// of some OTHER key. Nothing about the name is wrong, so only "the row directory holds
	// regular files and nothing else" refuses it -- and without that refusal the entry is
	// skipped and the answer is the silent (0, nil) this whole property exists to prevent.
	otherParts := streamTestKeyOctets(t, 71)
	shaped := streamTestRowName(t, otherParts)
	if shaped == streamTestRowName(t, parts) {
		t.Fatal("the two fixture keys derive one row name, so this case cannot judge anything")
	}
	shapedDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(shapedDir, streamRowDirName, shaped), 0o700); err != nil {
		t.Fatalf("plant a row-shaped directory: %v", err)
	}
	shapedStore := streamTestOpen(t, shapedDir)
	planted += 1
	exercised[shapedStore.classifyStreamRowName(shaped)] += 1
	exercised[shapedStore.classifyStreamRowName("subdir")] += 1
	t.Logf(
		"CLASS: the 3 partitions a name in the row directory falls into -- (a) this build's tag, (b) a fixed-width tag that is not this build's whatever its value, (c) anything else -- exercised %d(a) / %d(b) / %d(c)",
		exercised[streamRowOfThisKeySpace],
		exercised[streamRowOfAnotherKeySpace],
		exercised[streamRowNotARow],
	)
	t.Logf(
		"SCOPE: the row directory's entries, ENUMERATED -- a gate written over the single path a key names cannot see partition (b) at all -- over %d planted store(s)",
		planted,
	)
	for partition, name := range map[streamRowClass]string{
		streamRowOfThisKeySpace:    "(a)",
		streamRowOfAnotherKeySpace: "(b)",
		streamRowNotARow:           "(c)",
	} {
		if exercised[partition] == 0 {
			t.Errorf("partition %s was exercised by no entry at all, so this gate judged only part of the class it derived", name)
		}
	}
	if highWater, err := shapedStore.streamHighWater(parts[0], parts[1]); !errors.Is(err, ErrStreamStoreState) {
		t.Errorf(
			"a directory named %q in the row directory was answered (%d, %v); it is not a row, and skipping it answers a stream that may well have been written to with the error-free zero contract clause 4 reserves for a stream never seen",
			shaped,
			highWater,
			err,
		)
	}
}

// ----------------------------------------------------------------------------------------------
// Property 3 -- a key of the wrong width is refused at the boundary, before anything derives
// from it.
// ----------------------------------------------------------------------------------------------

// CLASS: every field of StreamKey, and for each of them every width that is not the one the
// field holds -- derived from the field's own array length, never from the numbers 32 and 16.
// SCOPE, derived separately: the flattening, which is the single place in package sdk where a
// []byte becomes a StreamKey, reached here through the store's own read path so a store that
// checked the width somewhere other than the boundary is still caught.
//
// This is not hygiene. messagegroup.GroupHandleKey and messagegroup.SenderHandle PANIC on a
// wrong-width input, defended by the argument that nothing there is reachable from the network.
// A durable store is what makes such a value a row read off a disk. S2-8.
func TestAKeyOfTheWrongWidthIsRefusedAtTheBoundary(t *testing.T) {
	keyType := streamKeyType()
	if keyType.NumField() != 2 {
		t.Fatalf(
			"%s declares %d fields and section 8.2's read path takes two positional parameters; the arity half of this is TestStreamRowIdentityIsDerivedFromStreamKeysOwnFieldSet, and this case cannot be driven through the store until the read path's own arity moves with it",
			keyType.String(),
			keyType.NumField(),
		)
	}
	dir := t.TempDir()
	store := streamTestOpen(t, dir)
	good := streamTestKeyOctets(t, 5)
	refusalsExercised := 0

	if _, err := store.streamHighWater(good[0], good[1]); err != nil {
		t.Fatalf("well-formed key octets were refused: %v", err)
	}

	for i := range keyType.NumField() {
		field := keyType.Field(i)
		want := field.Type.Len()
		for _, offeredWidth := range []int{0, want - 1, want + 1, 2 * want} {
			if offeredWidth == want {
				continue
			}
			offered := make([][]byte, len(good))
			copy(offered, good)
			offered[i] = streamTestOctets(offeredWidth, 7)
			refusalsExercised += 1
			_, err := store.streamHighWater(offered[0], offered[1])
			if !errors.Is(err, ErrStreamKeyWidth) {
				t.Errorf(
					"a %d-octet value offered for %s.%s (which holds %d) was answered %v; a short key silently padded or a long key silently truncated collides two streams onto one row, and the second stream is then handed indices the first has already used",
					offeredWidth,
					keyType.String(),
					field.Name,
					want,
					err,
				)
				continue
			}
			message := err.Error()
			for _, owed := range []string{
				field.Name,
				fmt.Sprintf("%d", offeredWidth),
				fmt.Sprintf("%d", want),
			} {
				if !strings.Contains(message, owed) {
					t.Errorf("the width refusal %q does not name %q; the refusal owes which parameter it refused and what width it had", message, owed)
				}
			}
		}
		// nil is not a width of zero by accident: it must take the same refusal.
		offered := make([][]byte, len(good))
		copy(offered, good)
		offered[i] = nil
		refusalsExercised += 1
		if _, err := store.streamHighWater(offered[0], offered[1]); !errors.Is(err, ErrStreamKeyWidth) {
			t.Errorf("a nil value offered for %s.%s was answered %v; want ErrStreamKeyWidth", keyType.String(), field.Name, err)
		}
	}
	t.Logf(
		"CLASS: %d wrong-width value(s), derived as every field's own array length plus and minus one, zero, doubled, and nil, over the %d field(s) of %s",
		refusalsExercised,
		keyType.NumField(),
		keyType.String(),
	)
	t.Logf("SCOPE: the 1 flattening in package sdk, reached through the store's own read path rather than called directly")
	if refusalsExercised == 0 {
		t.Fatal("this gate exercised no refusal at all, which is a gate that read nothing rather than a clean one")
	}
}

// ----------------------------------------------------------------------------------------------
// Property 4 -- a present-but-unreadable row is an error, it is a DIFFERENT error from an absent
// one, and a TORN TAIL is neither.
// ----------------------------------------------------------------------------------------------

// CLASS: the three cases of the decision procedure in classifyStreamRow, and the discriminator
// between them is POSITION and SIZE, never content -- derived here from the record width the
// format declares, so a change to the width moves every fixture with it.
// SCOPE, derived separately: a row's bytes as they lie on disk, read back through the store's
// own read path after a real OpenStreamStore, so the open-time repair is inside the scope rather
// than beside it.
//
// The two NUMBERS this property reports, because the truncation-versus-skip position is
// invisible to every assertion that reads only an answer: the row writes OpenStreamStore
// performs (0 when it found no torn tail, 1 when it found one) and the row writes the read path
// performs (always 0).
func TestARowsThreeCasesAndTheDiscriminatorBetweenThem(t *testing.T) {
	parts := streamTestKeyOctets(t, 11)
	rowName := streamTestRowName(t, parts)
	half := streamRecordWidth / 2

	intact := streamTestRowBody(rowName, 1, 2, 3)

	tornPartial := append(streamTestRowBody(rowName, 1, 2), streamTestRowBody(rowName, 3)[:half]...)

	tornWhole := streamTestRowBody(rowName, 1, 2, 3)
	streamTestCorruptRecord(tornWhole, 3)

	noVerifyingRecord := streamTestRowBody(rowName, 1)
	streamTestCorruptRecord(noVerifyingRecord, 1)

	twoFailingWhole := streamTestRowBody(rowName, 1, 2, 3)
	streamTestCorruptRecord(twoFailingWhole, 2)
	streamTestCorruptRecord(twoFailingWhole, 3)

	failingWithVerifyingAfter := streamTestRowBody(rowName, 1, 2, 3)
	streamTestCorruptRecord(failingWithVerifyingAfter, 2)

	cutToHalf := streamTestRowBody(rowName, 1, 2, 3)[:3*streamRecordWidth/2]

	oneFailingWholeThenPartial := append(
		append(streamTestRowBody(rowName, 1), streamTestRowBody(rowName, 2)[:half]...),
		streamTestRowBody(rowName, 2)...,
	)

	cases := map[string]int{}
	for _, testCase := range []struct {
		name string
		// plant is nil for an absent row.
		plant []byte
		// wantPresent says whether a row file should exist at all.
		wantPresent   bool
		wantHighWater uint64
		wantErr       error
		// wantShape is the shape of case 3 the refusal owes by name. Two of case 3's
		// shapes carry the SAME error value, so a gate that reads only errors.Is cannot
		// tell "a failing record with a verifying record after it" from "a failing suffix
		// of two whole records" -- and a store that stopped looking for the verifying
		// record would answer the second for the first and go unnoticed.
		wantShape         string
		wantLength        int64
		wantOpenRowWrites int
		why               string
	}{
		{
			name:        "case 1: an absent row",
			wantPresent: false,
			wantErr:     nil,
			why:         "contract clause 4: a stream never seen is 0 with no error, so the first allocation is 1",
		},
		{
			name:              "case 2: a present zero-length row",
			plant:             []byte{},
			wantPresent:       true,
			wantErr:           nil,
			wantLength:        0,
			wantOpenRowWrites: 0,
			why:               "a row carrying no verifying record is the state a row is in before an index for its key has been handed out, which is the state a stream never seen is in",
		},
		{
			name:              "an intact row",
			plant:             intact,
			wantPresent:       true,
			wantHighWater:     3,
			wantErr:           nil,
			wantLength:        3 * streamRecordWidth,
			wantOpenRowWrites: 0,
			why:               "every record verifies and the length is a whole multiple of the record width, so nothing is owed and nothing is written",
		},
		{
			name:              "case 2: a trailing partial with every whole record verifying",
			plant:             tornPartial,
			wantPresent:       true,
			wantHighWater:     2,
			wantErr:           nil,
			wantLength:        2 * streamRecordWidth,
			wantOpenRowWrites: 1,
			why:               "an interrupted append leaves a partial; refusing it would leave a row no later process could open, on exactly the path the durability exists to survive",
		},
		{
			name:              "case 2: a final whole record torn within its own octets",
			plant:             tornWhole,
			wantPresent:       true,
			wantHighWater:     2,
			wantErr:           nil,
			wantLength:        2 * streamRecordWidth,
			wantOpenRowWrites: 1,
			why:               "the second of the two shapes one interrupted append can leave",
		},
		{
			name:              "case 2: no verifying record at all",
			plant:             noVerifyingRecord,
			wantPresent:       true,
			wantHighWater:     0,
			wantErr:           nil,
			wantLength:        0,
			wantOpenRowWrites: 1,
			why:               "f == 1, so the answer is (0, nil) and the row is truncated to nothing",
		},
		{
			name:              "case 2: a three-record row cut to half its length",
			plant:             cutToHalf,
			wantPresent:       true,
			wantHighWater:     1,
			wantErr:           nil,
			wantLength:        streamRecordWidth,
			wantOpenRowWrites: 1,
			why:               "a truncated row and an interrupted append are the SAME BYTES; no function of the length, the width and the checksum verdicts can answer them differently, so both are case 2 and a store that refuses this wedges every open after any crash mid-append",
		},
		{
			name:              "case 3: a failing suffix of two whole records",
			plant:             twoFailingWhole,
			wantPresent:       true,
			wantErr:           ErrStreamStoreState,
			wantShape:         "failing suffix of 2 whole records",
			wantLength:        3 * streamRecordWidth,
			wantOpenRowWrites: 0,
			why:               "one interrupted append can damage exactly one record, so two is corruption; answering the last verifying record here is an index handed out twice",
		},
		{
			name:              "case 3: a failing record with a verifying record after it",
			plant:             failingWithVerifyingAfter,
			wantPresent:       true,
			wantErr:           ErrStreamStoreState,
			wantShape:         "a verifying record at position 3",
			wantLength:        3 * streamRecordWidth,
			wantOpenRowWrites: 0,
			why:               "a failure with a verifying record after it is a corrupt body however small it is",
		},
		{
			name:              "case 3: one failing whole record with a partial after it",
			plant:             oneFailingWholeThenPartial,
			wantPresent:       true,
			wantErr:           ErrStreamStoreState,
			wantShape:         "partial after it",
			wantLength:        int64(len(oneFailingWholeThenPartial)),
			wantOpenRowWrites: 0,
			why:               "two records' worth of damage, which no single interrupted append produces; admitting it to case 2 answers R1 after every restart, which is one stream_index handed out for the life of the row",
		},
	} {
		cases[strings.SplitN(testCase.name, ":", 2)[0]] += 1
		t.Run(testCase.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, streamRowDirName, rowName)
			if testCase.wantPresent {
				streamTestPlantRow(t, dir, rowName, testCase.plant)
			}
			store := streamTestOpen(t, dir)
			openRowWrites := store.rowWriteCount()
			t.Logf("OpenStreamStore performed %d row write(s)", openRowWrites)
			if openRowWrites != testCase.wantOpenRowWrites {
				t.Errorf(
					"OpenStreamStore performed %d row write(s), want %d. %s",
					openRowWrites,
					testCase.wantOpenRowWrites,
					testCase.why,
				)
			}
			if testCase.wantPresent {
				if got := streamTestRowLength(t, path); got != testCase.wantLength {
					t.Errorf(
						"after OpenStreamStore the row is %d octets, want %d; the discard is a truncation performed by the writer at open, so that the row's length is a whole multiple of %d at every moment an append begins",
						got,
						testCase.wantLength,
						streamRecordWidth,
					)
				}
			}

			before := store.rowWriteCount()
			highWater, err := store.streamHighWater(parts[0], parts[1])
			after := store.rowWriteCount()
			t.Logf("the read path performed %d row write(s)", after-before)
			if after != before {
				t.Errorf(
					"the read path performed %d row write(s), want 0; a repair done lazily in the read path answers every question this property asks correctly and turns a read into a second writer to one row inside one store",
					after-before,
				)
			}

			if testCase.wantErr == nil {
				if err != nil {
					t.Fatalf("answered %v, want (%d, nil). %s", err, testCase.wantHighWater, testCase.why)
				}
				if highWater != testCase.wantHighWater {
					t.Errorf("answered high water %d, want %d. %s", highWater, testCase.wantHighWater, testCase.why)
				}
				return
			}
			if !errors.Is(err, testCase.wantErr) {
				t.Fatalf("answered (%d, %v), want %v. %s", highWater, err, testCase.wantErr, testCase.why)
			}
			if testCase.wantShape != "" && !strings.Contains(err.Error(), testCase.wantShape) {
				t.Errorf(
					"the refusal %q does not name the shape it found (%q); case 3's shapes share one error value, so a refusal that does not name its shape cannot tell them apart and a store that stopped discriminating between them would answer one for another unnoticed",
					err.Error(),
					testCase.wantShape,
				)
			}
			if highWater != 0 {
				t.Errorf(
					"the refusal carried a high water of %d; a refusal answers no index, and answering the last surviving record's value here is exactly the index reuse the refusal exists to prevent",
					highWater,
				)
			}
		})
	}
	total := 0
	for _, count := range cases {
		total += count
	}
	t.Logf("CLASS: %d row fixture(s) over the decision procedure's cases: %v", total, cases)
	t.Logf(
		"SCOPE: a row's bytes as they lie on disk, read back through %d real OpenStreamStore call(s) and %d read-path call(s), so the open-time repair is inside the scope rather than beside it",
		total,
		total,
	)
	if total == 0 {
		t.Fatal("this gate walked no fixture at all, which is a gate that read nothing rather than a clean one")
	}
}

// The half of Property 4 that no answer can see: WHERE THE NEXT APPEND LANDS.
//
// Plant R1 then half of R2 at L = 1.5W, open, allocate once, close, reopen. Under a store that
// SKIPS the torn octets instead of truncating them, the first open writes nothing and the row
// becomes R1, half-R2, R2' at L = 2.5W -- and the second open sees k = 2 with R_2 spanning
// half-R2 and the head of R2', which is one failing whole record with a partial after it. Under
// the bound this store used to read, that answers R1 AGAIN, after every restart, for the life of
// the row: one stream_index handed out twice, which spec A section 5.6 calls "a total break of
// both AEADs for that record".
func TestATornTailIsTruncatedBeforeTheNextAppendLands(t *testing.T) {
	parts := streamTestKeyOctets(t, 23)
	rowName := streamTestRowName(t, parts)
	half := streamRecordWidth / 2

	dir := t.TempDir()
	torn := append(streamTestRowBody(rowName, 1), streamTestRowBody(rowName, 2)[:half]...)
	path := streamTestPlantRow(t, dir, rowName, torn)
	if got := streamTestRowLength(t, path); got != int64(streamRecordWidth+half) {
		t.Fatalf("the fixture is %d octets, want %d (one whole record and half of another)", got, streamRecordWidth+half)
	}

	store := streamTestOpen(t, dir)
	if got := store.rowWriteCount(); got != 1 {
		t.Errorf(
			"OpenStreamStore performed %d row write(s) on a row with a torn tail, want 1; a store that leaves the torn octets on disk and appends at EOF hands out the same index after every restart",
			got,
		)
	}
	if got := streamTestRowLength(t, path); got != streamRecordWidth {
		t.Errorf("after the open the row is %d octets, want %d; the discard is a truncation and not a skip", got, streamRecordWidth)
	}
	if highWater, err := store.streamHighWater(parts[0], parts[1]); err != nil || highWater != 1 {
		t.Errorf("the repaired row answered (%d, %v), want (1, nil)", highWater, err)
	}

	// the ONE append an allocation performs.
	streamTestAppendOneRecord(t, path, rowName, 2)
	if err := store.Close(); err != nil {
		t.Fatalf("close the store: %v", err)
	}

	reopened, err := OpenStreamStore(dir)
	if err != nil {
		t.Fatalf("reopen the store: %v", err)
	}
	defer reopened.Close()
	if got := reopened.rowWriteCount(); got != 0 {
		t.Errorf("the reopen performed %d row write(s) on a row nothing had torn, want 0", got)
	}
	highWater, err := reopened.streamHighWater(parts[0], parts[1])
	if err != nil {
		t.Fatalf(
			"after a repair, one append and a restart the row answered %v; a store that skipped the discard leaves R1, half-R2, R2' on disk, which is one failing whole record with a partial after it",
			err,
		)
	}
	if highWater != 2 {
		t.Errorf(
			"after a repair, one append and a restart the row answered %d, want 2; answering 1 here is the index handed out before the restart handed out again",
			highWater,
		)
	}
}

// The closed store answers no index, and specifically not a zero. Contract clause 4's error-free
// zero is correct for a stream never seen and catastrophic for a store that cannot look.
func TestAClosedStoreRefusesRatherThanAnsweringZero(t *testing.T) {
	parts := streamTestKeyOctets(t, 31)
	dir := t.TempDir()
	store, err := OpenStreamStore(dir)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	highWater, err := store.streamHighWater(parts[0], parts[1])
	if !errors.Is(err, ErrStreamStoreState) {
		t.Errorf("a closed store answered (%d, %v), want ErrStreamStoreState", highWater, err)
	}
	if highWater != 0 {
		t.Errorf("the refusal carried a high water of %d", highWater)
	}
}

// The store's own directory holds the row directory, and the row directory is a DIFFERENT
// directory from the one the next task's exclusion is held in -- so nothing has to be exempted
// by name from the enumeration, and the rule "an entry in the row directory that is not a row is
// a finding" stays categorical. Task 2a Property 1 names this back.
func TestTheEnumeratedDirectoryIsNotTheStoresOwnDirectory(t *testing.T) {
	dir := t.TempDir()
	store := streamTestOpen(t, dir)
	if store.rowDir == store.dir {
		t.Fatal("the enumerated row directory IS the store's directory, so the next task's exclusion entry would have to be exempted from the enumeration by name -- an ignore-list, which goes on silently ignoring the second non-row somebody writes there tomorrow")
	}
	if filepath.Dir(store.rowDir) != filepath.Clean(store.dir) {
		t.Errorf("the row directory %s is not directly inside the store's directory %s; a guard outside dir puts this store's lock in a directory the store does not own", store.rowDir, store.dir)
	}

	// an entry beside the row directory is not read by the enumeration at all.
	beside := filepath.Join(dir, "exclusion")
	if err := os.WriteFile(beside, []byte("held by the operating system"), 0o600); err != nil {
		t.Fatalf("write an entry beside the row directory: %v", err)
	}
	reopened := streamTestOpen(t, dir)
	parts := streamTestKeyOctets(t, 41)
	if highWater, err := reopened.streamHighWater(parts[0], parts[1]); err != nil || highWater != 0 {
		t.Errorf("an entry beside the row directory was answered (%d, %v); the enumeration reads the row directory and nothing else", highWater, err)
	}
}

// A row's records carry a checksum bound to THE ROW'S OWN NAME, so a row moved or copied under
// another key's name does not verify there. Without that binding a row file placed under another
// key's name is adopted whole, and the key it lands on takes that row's high water -- which may
// be BEHIND the index its own ladder has already spent. A high water that moves backwards under
// a key that has already sealed at a higher index is a stream_index handed out twice, which is
// the one thing this store exists to make impossible.
func TestARowsRecordsDoNotVerifyUnderAnotherRowsName(t *testing.T) {
	left := streamTestKeyOctets(t, 61)
	right := streamTestKeyOctets(t, 97)
	leftName := streamTestRowName(t, left)
	rightName := streamTestRowName(t, right)
	if leftName == rightName {
		t.Fatal("the two fixture keys derive one row name, so this case cannot judge anything")
	}

	dir := t.TempDir()
	// the LEFT key's row, written under the RIGHT key's name.
	streamTestPlantRow(t, dir, rightName, streamTestRowBody(leftName, 1, 2, 3))
	store := streamTestOpen(t, dir)

	highWater, err := store.streamHighWater(right[0], right[1])
	if err == nil && highWater == 3 {
		t.Fatalf(
			"a row written for %s and placed under %s's name was adopted whole and answered high water 3; the record checksum must be bound to the row's own name, or a row moved between keys carries its counter with it",
			leftName,
			rightName,
		)
	}
	if !errors.Is(err, ErrStreamStoreState) {
		t.Errorf("a foreign row's records under this key's name answered (%d, %v); want ErrStreamStoreState", highWater, err)
	}
	if highWater != 0 {
		t.Errorf("the refusal carried a high water of %d", highWater)
	}
}

// messagegroup.StreamKey is the type this store keys on, and this asserts the consumed shape
// rather than trusting the plan's spelling of it. R2.
func TestTheConsumedStreamKeyIsTheOneConnectDeclares(t *testing.T) {
	var key messagegroup.StreamKey
	if got := streamRowName(key); len(got) != streamRowNameLen {
		t.Errorf("the zero key derives a %d-character row name, want %d", len(got), streamRowNameLen)
	}
	keyType := reflect.TypeOf(key)
	for i := range keyType.NumField() {
		field := keyType.Field(i)
		if field.Type.Kind() != reflect.Array || field.Type.Elem().Kind() != reflect.Uint8 {
			t.Errorf(
				"%s.%s is %s; the flattening in this package takes octets for every field and refuses a key it cannot fill, so a field of another kind must arrive as a refusal rather than as a zero value",
				keyType.String(),
				field.Name,
				field.Type.String(),
			)
		}
	}
}
