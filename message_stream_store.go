package sdk

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"os"
	"path/filepath"
	"reflect"
	"sync"

	"github.com/urnetwork/connect/messagegroup"
)

// StreamStore is the durable stream-index reservation store spec A section 8.2 assigns to sdk,
// and the first one that has ever existed in any tree.
//
// What this file owns is the ROW: what identifies it, what key space it belongs to, what shape
// its bytes have, and what the store answers for a row it cannot read. Allocation -- the
// exported ReserveStreamIndex and StreamHighWater, the fsync boundary and the two allocation
// sentinels -- is the next task's, and it is built on classifyStreamRow and streamKeyFromOctets
// below.
//
// THE ROW IS ONE FILE PER STREAM KEY, INSIDE A DIRECTORY THAT HOLDS ROWS AND NOTHING ELSE.
// dir is this store's own directory. Inside it OpenStreamStore creates the ROW DIRECTORY, and
// the single-writer exclusion the next task adds sits BESIDE that directory in dir, never inside
// it. That is a construction rather than an ignore-list: because nothing but a row is ever
// written into the row directory, the rule "an entry in the row directory that is not a row is a
// finding" can be categorical, with no name exempted from it. An exemption by name is the shape
// that goes on silently ignoring the second non-row somebody writes there tomorrow.
//
// One file per key rather than one file for every key is not a performance choice. It makes the
// next task's flush a single-file flush, and it makes a damaged row cost one stream instead of
// every stream.
type StreamStore struct {
	dir    string
	rowDir string

	// keySpaceTag is this build's key-space version tag: the fixed-width, self-delimiting
	// PREFIX of every row name. See streamKeySpaceTagOf.
	keySpaceTag string

	stateMutex sync.Mutex
	closed     bool

	// rowWrites counts every write this store performs against a row file. It is incremented
	// at the write site and nowhere else, so it measures WHERE the work happens rather than
	// where somebody says it happens: a store that moved the open-time repair into the read
	// path would move this counter with it.
	rowWrites int
}

const (
	// the row directory. The spelling is not normative; what is normative is that this
	// directory holds rows and nothing else, by construction.
	streamRowDirName = "rows"

	// The key-space tag is 8 octets of the shape digest, hex encoded, and it is FIXED WIDTH
	// and SELF-DELIMITING for one specific reason: a row written by another build must be
	// separable from a row of this build's by the NAME ALONE, without computing an identity
	// this build cannot compute. Fold the tag into the identity hash instead and a foreign
	// row becomes a file whose name this build simply never computes -- an absent row --
	// StreamHighWater answers (0, nil), and ledger item 170's hazard is back, silently.
	streamKeySpaceTagOctets = 8
	streamKeySpaceTagLen    = 2 * streamKeySpaceTagOctets

	// The identity is a SHA-256 over the key's field set, so its width is a property of the
	// FORMAT and not of the field count. That is what keeps a three-field pre-A1 row parsing
	// as "tag then identity" -- with a tag that is not this build's -- rather than falling
	// off the end of the name shape into "not a row at all", which would be the wrong
	// refusal for it.
	streamRowIdentityLen = 2 * sha256.Size

	streamRowNameLen = streamKeySpaceTagLen + streamRowIdentityLen

	// one record: the allocated index, then a checksum bound to the row that holds it.
	streamRecordIndexOctets = 8
	streamRecordSumOctets   = 8
	streamRecordWidth       = streamRecordIndexOctets + streamRecordSumOctets
)

// streamKeyType is connect/messagegroup.StreamKey as that package declares it TODAY, read
// through reflection. Every derivation below goes through this and none of them spells a field
// name, so a field added or removed in connect changes the key-space tag -- and refuses every
// row written under the old one -- rather than silently re-keying them.
func streamKeyType() reflect.Type {
	return reflect.TypeOf(messagegroup.StreamKey{})
}

func writeStreamLengthPrefixed(digest hash.Hash, octets []byte) {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(octets)))
	digest.Write(size[:])
	digest.Write(octets)
}

// streamKeyShapeDigestOf derives the key space from a key type's FIELD SET: the number of
// fields, and each field's name and type in declaration order. Nothing else -- not the type's
// own name, not the package it lives in -- so "the same field set" and "the same key space" are
// the same statement. That is what lets a test derive what a pre-A1 build would have written by
// handing this the pre-A1 field set, rather than by reimplementing this function.
func streamKeyShapeDigestOf(keyType reflect.Type) [sha256.Size]byte {
	digest := sha256.New()
	digest.Write([]byte("urnetwork/sdk message stream row key space\x00"))
	var fieldCount [4]byte
	binary.BigEndian.PutUint32(fieldCount[:], uint32(keyType.NumField()))
	digest.Write(fieldCount[:])
	for i := range keyType.NumField() {
		field := keyType.Field(i)
		writeStreamLengthPrefixed(digest, []byte(field.Name))
		writeStreamLengthPrefixed(digest, []byte(field.Type.String()))
	}
	var out [sha256.Size]byte
	copy(out[:], digest.Sum(nil))
	return out
}

func streamKeySpaceTagOf(keyType reflect.Type) string {
	shape := streamKeyShapeDigestOf(keyType)
	return hex.EncodeToString(shape[:streamKeySpaceTagOctets])
}

// streamRowIdentityOf hashes the key's VALUES, field by field, under the same field set the tag
// is derived from. Every field separates a row: two streams differing in any one field get two
// rows, because a merged row hands the second stream indices the first has already used.
func streamRowIdentityOf(key reflect.Value) string {
	keyType := key.Type()
	shape := streamKeyShapeDigestOf(keyType)
	digest := sha256.New()
	digest.Write([]byte("urnetwork/sdk message stream row identity\x00"))
	digest.Write(shape[:])
	addressable := reflect.New(keyType)
	addressable.Elem().Set(key)
	for i := range keyType.NumField() {
		field := keyType.Field(i)
		value := addressable.Elem().Field(i)
		var position [4]byte
		binary.BigEndian.PutUint32(position[:], uint32(i))
		digest.Write(position[:])
		writeStreamLengthPrefixed(digest, []byte(field.Name))
		writeStreamLengthPrefixed(digest, []byte(field.Type.String()))
		switch {
		case field.Type.Kind() == reflect.Array && field.Type.Elem().Kind() == reflect.Uint8:
			writeStreamLengthPrefixed(digest, value.Slice(0, field.Type.Len()).Bytes())
		case field.Type.Kind() == reflect.Slice && field.Type.Elem().Kind() == reflect.Uint8:
			writeStreamLengthPrefixed(digest, value.Bytes())
		case value.CanUint():
			var scalar [8]byte
			binary.BigEndian.PutUint64(scalar[:], value.Uint())
			writeStreamLengthPrefixed(digest, scalar[:])
		case value.CanInt():
			var scalar [8]byte
			binary.BigEndian.PutUint64(scalar[:], uint64(value.Int()))
			writeStreamLengthPrefixed(digest, scalar[:])
		default:
			// A field kind this derivation has no octet encoding for. It is still
			// SEPARATED -- the shape digest above has already changed, so every row
			// written under the old field set is refused as a foreign key space and
			// nothing is silently re-keyed -- and the fallback only has to be
			// deterministic for the new one.
			writeStreamLengthPrefixed(digest, []byte(fmt.Sprintf("%v", value.Interface())))
		}
	}
	return hex.EncodeToString(digest.Sum(nil))
}

// streamRowNameOf is TAG THEN IDENTITY, in that order and never the other way, so the key space
// is readable off the name without computing the identity.
func streamRowNameOf(key reflect.Value) string {
	return streamKeySpaceTagOf(key.Type()) + streamRowIdentityOf(key)
}

func streamRowName(key messagegroup.StreamKey) string {
	return streamRowNameOf(reflect.ValueOf(key))
}

// streamKeyFromOctets is THE flattening: spec A section 8.2's positional []byte parameters onto
// StreamKey's fields, in declaration order, and this package has no other.
//
// It is also the width boundary, and the width check here is not hygiene. Both
// messagegroup.GroupHandleKey and messagegroup.SenderHandle PANIC rather than return on a
// wrong-width input, defended in that package by the argument that "nothing here is reachable
// from the network: the key is this member's own persisted derivation." A durable store is the
// thing that makes such a value a row read off a disk. This check is what keeps that argument
// true, and a panic is not a substitute for it. S2-8.
//
// The parameter COUNT is checked against the type's field count for the same reason the identity
// is derived rather than spelled: a field added or removed in connect must arrive here as a
// refusal, not as a zero-valued field nobody passed.
func streamKeyFromOctets(parts ...[]byte) (messagegroup.StreamKey, error) {
	var zero messagegroup.StreamKey
	keyType := streamKeyType()
	if len(parts) != keyType.NumField() {
		return zero, fmt.Errorf(
			"%w: the store was handed %d key parameters and %s declares %d fields",
			ErrStreamKeyWidth,
			len(parts),
			keyType.String(),
			keyType.NumField(),
		)
	}
	built := reflect.New(keyType)
	for i := range keyType.NumField() {
		field := keyType.Field(i)
		if field.Type.Kind() != reflect.Array || field.Type.Elem().Kind() != reflect.Uint8 {
			return zero, fmt.Errorf(
				"%w: parameter %d maps onto %s.%s, which is %s and holds no octets",
				ErrStreamKeyWidth,
				i,
				keyType.String(),
				field.Name,
				field.Type.String(),
			)
		}
		want := field.Type.Len()
		if len(parts[i]) != want {
			return zero, fmt.Errorf(
				"%w: parameter %d (%s.%s) is %d octets, want exactly %d; a short key padded or a long key truncated collides two streams onto one row",
				ErrStreamKeyWidth,
				i,
				keyType.String(),
				field.Name,
				len(parts[i]),
				want,
			)
		}
		reflect.Copy(built.Elem().Field(i), reflect.ValueOf(parts[i]))
	}
	key, ok := built.Elem().Interface().(messagegroup.StreamKey)
	if !ok {
		return zero, fmt.Errorf(
			"%w: the flattening did not produce a %s",
			ErrStreamKeyWidth,
			keyType.String(),
		)
	}
	return key, nil
}

// encodeStreamRecord is the row's whole format: the allocated index, then a checksum over a
// domain separator, THE ROW'S OWN NAME and the index. Binding the checksum to the name means a
// row copied under another name does not verify, so a key space cannot be laundered by a rename.
func encodeStreamRecord(rowName string, index uint64) [streamRecordWidth]byte {
	var record [streamRecordWidth]byte
	binary.BigEndian.PutUint64(record[0:streamRecordIndexOctets], index)
	digest := sha256.New()
	digest.Write([]byte("urnetwork/sdk message stream row record\x00"))
	writeStreamLengthPrefixed(digest, []byte(rowName))
	digest.Write(record[0:streamRecordIndexOctets])
	copy(record[streamRecordIndexOctets:], digest.Sum(nil)[:streamRecordSumOctets])
	return record
}

func streamRecordIndex(record []byte) uint64 {
	return binary.BigEndian.Uint64(record[0:streamRecordIndexOctets])
}

// verifyStreamRecord recomputes the record rather than checking a stored checksum against a
// second implementation of one, so the writer and the reader cannot drift apart.
func verifyStreamRecord(rowName string, record []byte) bool {
	if len(record) != streamRecordWidth {
		return false
	}
	expected := encodeStreamRecord(rowName, streamRecordIndex(record))
	differing := byte(0)
	for i := range streamRecordWidth {
		differing |= expected[i] ^ record[i]
	}
	return differing == 0
}

// streamRowClass is the three-way partition of a name in the row directory, taken over the
// NAME'S OWN SHAPE and never over intent. The tag is fixed-width and self-delimiting, so (b) and
// (c) are separated by the name alone and by nothing a build has to remember.
type streamRowClass int

const (
	// (a) a name that parses as tag then identity under THIS build's tag: an ordinary row.
	streamRowOfThisKeySpace streamRowClass = iota
	// (b) a name that parses as tag then identity under a fixed-width tag that is NOT this
	// build's, whatever its value. This is the answer a pre-A1 row gets, and it is
	// ErrStreamKeySpace. Reading this partition as "the two tags the codebase knows about"
	// would send a pre-A1 row to (c) and demand an error the store does not produce for it.
	streamRowOfAnotherKeySpace
	// (c) anything else in the row directory. Nothing legitimate is ever written there, so
	// anything found here is a real finding: ErrStreamStoreState.
	streamRowNotARow
)

func (self *StreamStore) classifyStreamRowName(name string) streamRowClass {
	if len(name) != streamRowNameLen {
		return streamRowNotARow
	}
	for i := range len(name) {
		c := name[i]
		if !('0' <= c && c <= '9') && !('a' <= c && c <= 'f') {
			return streamRowNotARow
		}
	}
	if name[:streamKeySpaceTagLen] != self.keySpaceTag {
		return streamRowOfAnotherKeySpace
	}
	return streamRowOfThisKeySpace
}

// classifyStreamRow is the decision procedure over the three cases a row's bytes can be in. It
// is a function of the row's LENGTH, the record width and the per-record checksum verdicts, and
// it has no other input -- which is a statement about the format rather than about this
// implementation.
//
// Let W be the record width and L the row's length; k = L div W and r = L mod W, so the row is
// records R_1 .. R_k at offsets 0, W, .., (k-1)W followed by an r-octet partial when r > 0. Let
// f be the least j whose R_j fails its checksum, or k+1 if every record verifies.
//
//  1. an ABSENT row is (0, nil) and never reaches here; a row that is present and zero length is
//     not case 1, it is case 2's no-verifying-record sub-case and takes the same answer.
//  2. any R_j with j > f verifies                     -> case 3, corrupt body
//  3. k-f+1 >= 2, or (k-f+1 == 1 and r > 0)           -> case 3, corrupt body
//  4. otherwise                                       -> case 2, torn tail: truncate to (f-1)W
//     and answer R_{f-1}, or (0, nil) when f == 1
//
// WHY CASE 2's BOUND IS THE TWO SHAPES IN STEP 4 AND NOT "at most one failing whole record".
// The allocation path appends ONE record of exactly W octets at a W-aligned offset and flushes,
// so an interrupted append leaves exactly two shapes and no others: a trailing partial with
// every whole record verifying (k-f+1 == 0, r > 0), or a final whole record torn within its own
// octets (k-f+1 == 1, r == 0). One failing whole record WITH a partial after it is two records'
// worth of damage, which no single interrupted append can produce, so it is corruption. The
// bound is derived from the append discipline; a batched allocation that appended two records
// per flush would invalidate it without touching a line of this comment. S2-22.
//
// AND THE ONE THING THIS PROCEDURE DOES NOT DO, stated because a reader will look for it: IT
// DOES NOT DETECT TRUNCATION. A three-record row cut to half its length is R1 followed by half
// of R2. A two-record row whose second append flushed halfway is R1 followed by half of R2.
// They are BYTE-IDENTICAL, and the format admits no third input -- no header, no record count,
// no external length authority, and exactly one forced flush on the allocation path, so there is
// no second durable object that could hold a count even if one were wanted. No function of the
// row's length, the record width and the checksum verdicts can answer them differently, so this
// one does not try. Both are case 2. A rule that claims to detect truncation on this format is a
// rule that has invented an input. What that costs: an out-of-band truncation that removes whole
// FLUSHED records rewinds the high water silently, and across a restart there is nothing left to
// compare against. That is a priced residual, S2-23, not a gap.
//
// truncateTo is the length the row must be repaired to; it equals the row's current length when
// nothing is owed.
func classifyStreamRow(rowName string, content []byte) (highWater uint64, truncateTo int64, err error) {
	length := len(content)
	wholeRecords := length / streamRecordWidth
	partial := length % streamRecordWidth

	firstFailing := wholeRecords + 1
	for j := 1; j <= wholeRecords; j += 1 {
		if !verifyStreamRecord(rowName, content[(j-1)*streamRecordWidth:j*streamRecordWidth]) {
			firstFailing = j
			break
		}
	}
	for j := firstFailing + 1; j <= wholeRecords; j += 1 {
		if verifyStreamRecord(rowName, content[(j-1)*streamRecordWidth:j*streamRecordWidth]) {
			return 0, 0, fmt.Errorf(
				"%w: row %s holds a record at position %d that does not verify and a verifying record at position %d after it; a failure with a verifying record after it is a corrupt body however small it is, and no interrupted append can leave one",
				ErrStreamStoreState,
				rowName,
				firstFailing,
				j,
			)
		}
	}

	failingWhole := 0
	if firstFailing <= wholeRecords {
		failingWhole = wholeRecords - firstFailing + 1
	}
	if 2 <= failingWhole {
		return 0, 0, fmt.Errorf(
			"%w: row %s ends in a failing suffix of %d whole records; one interrupted append can damage exactly one, so this is a corrupt body",
			ErrStreamStoreState,
			rowName,
			failingWhole,
		)
	}
	if failingWhole == 1 && 0 < partial {
		return 0, 0, fmt.Errorf(
			"%w: row %s ends in one failing whole record with a %d-octet partial after it, which is two records' worth of damage and is not a shape one interrupted append can leave",
			ErrStreamStoreState,
			rowName,
			partial,
		)
	}

	truncateTo = int64(firstFailing-1) * streamRecordWidth
	if firstFailing == 1 {
		// A row carrying no verifying record is the state a row is in before an index for
		// its key has been handed out, which is the same state a stream never seen is in.
		return 0, truncateTo, nil
	}
	lastVerifying := content[(firstFailing-2)*streamRecordWidth : (firstFailing-1)*streamRecordWidth]
	return streamRecordIndex(lastVerifying), truncateTo, nil
}

// OpenStreamStore opens, and if necessary repairs, the durable stream store rooted at dir.
//
// dir is this store's OWN directory. It is never sdk's shared LocalState home, because the next
// task's single-writer exclusion is held on an entry beside the row directory inside it, and two
// stores' guards in one shared home would collide by name and would no longer sit on the tree
// they protect.
//
// THE REPAIR IS A TRUNCATION, PERFORMED BY THE WRITER, AT OPEN, EXACTLY ONCE, BEFORE ANY INDEX
// HAS BEEN HANDED OUT, AND FORCED DURABLE BEFORE THIS RETURNS. Three consequences are the whole
// argument for putting it here:
//
//  1. It keeps the high-water read a READ. Every later classification sees a row whose length is
//     already a whole multiple of the record width and writes nothing. A repair performed lazily
//     inside the read path makes a read a write, puts a second writer to one row inside one
//     store beside a live allocation, and makes the repair's timing data-dependent.
//  2. It is on the open path, so it moves neither of the next task's two allocation-path
//     numbers. It is not a forced flush on the allocation path and it is not a directory-entry
//     mutation at all: it is a truncation of a file that already exists.
//  3. Its own durability is not load-bearing, which is what makes it safe to do at open at all.
//     The repair hands out nothing, so a crash between the truncation and its flush leaves a row
//     the next open repairs identically. THE REPAIR IS IDEMPOTENT; AN ALLOCATION IS NOT.
//
// AND WHY IT IS A TRUNCATION RATHER THAN A SKIP, which is a safety property and not tidiness.
// Leave the torn octets in place and append at EOF instead: a crash mid-append leaves R1 then
// half of R2 at L = 1.5W; the reopened store answers R1, correctly; the next allocation appends
// a whole record at EOF, so the row becomes R1, half-R2, R2' at L = 2.5W. On the NEXT open k = 2,
// R_1 verifies, R_2 spans half-R2 and the head of R2' and fails, r = W/2, f = 2. Under a bound
// that admits one failing whole record whatever r is, the store answers R1 again -- SO IT HANDS
// OUT THE SAME INDEX IT HANDED OUT BEFORE THE RESTART, AFTER EVERY RESTART, FOR THE LIFE OF THE
// ROW. That is a reused stream_index under a reused record_key, which spec A section 5.6 calls
// "a total break of both AEADs for that record". The truncation here and the tightened bound in
// classifyStreamRow compose: under the truncation the row's length is a whole multiple of W at
// every moment an append begins, so k-f+1 == 1 with r > 0 is unreachable for a correct writer
// and is corruption when it is seen.
//
// A row whose bytes are a corrupt body is NOT repaired here. It is left exactly as it was found
// and the refusal is the reader's: a store that cannot be opened cannot be inspected, and the
// answer to a damaged row belongs where the answer is produced.
//
// Whether this repair is a sixth section 8.2 contract clause on OpenStreamStore is filed rather
// than assumed: S2-24.
func OpenStreamStore(dir string) (*StreamStore, error) {
	rowDir := filepath.Join(dir, streamRowDirName)
	if err := os.MkdirAll(rowDir, 0o700); err != nil {
		return nil, fmt.Errorf(
			"%w: the row directory %s could not be created: %v",
			ErrStreamStoreState,
			rowDir,
			err,
		)
	}
	store := &StreamStore{
		dir:         dir,
		rowDir:      rowDir,
		keySpaceTag: streamKeySpaceTagOf(streamKeyType()),
	}
	entries, err := os.ReadDir(rowDir)
	if err != nil {
		return nil, fmt.Errorf(
			"%w: the row directory %s could not be read: %v",
			ErrStreamStoreState,
			rowDir,
			err,
		)
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}
		if store.classifyStreamRowName(entry.Name()) != streamRowOfThisKeySpace {
			continue
		}
		if err := store.repairRow(entry.Name()); err != nil {
			return nil, err
		}
	}
	return store, nil
}

// repairRow truncates away a torn tail, once, and only when one is owed.
func (self *StreamStore) repairRow(rowName string) error {
	path := filepath.Join(self.rowDir, rowName)
	content, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("%w: row %s could not be read: %v", ErrStreamStoreState, rowName, err)
	}
	_, truncateTo, err := classifyStreamRow(rowName, content)
	if err != nil {
		// a corrupt body: not repairable, and the refusal is the reader's.
		return nil
	}
	if truncateTo == int64(len(content)) {
		return nil
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf(
			"%w: row %s could not be opened for repair: %v",
			ErrStreamStoreState,
			rowName,
			err,
		)
	}
	defer file.Close()
	self.countRowWrite()
	if err := file.Truncate(truncateTo); err != nil {
		return fmt.Errorf(
			"%w: row %s could not be truncated to %d: %v",
			ErrStreamStoreState,
			rowName,
			truncateTo,
			err,
		)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf(
			"%w: row %s could not be flushed after repair: %v",
			ErrStreamStoreState,
			rowName,
			err,
		)
	}
	return nil
}

// countRowWrite is called at the write site and nowhere else.
func (self *StreamStore) countRowWrite() {
	self.stateMutex.Lock()
	defer self.stateMutex.Unlock()
	self.rowWrites += 1
}

// rowWriteCount is the number of writes this store has performed against a row file. It is the
// observable that separates an open-time repair from a lazy one, because every ANSWER the two
// give is identical.
func (self *StreamStore) rowWriteCount() int {
	self.stateMutex.Lock()
	defer self.stateMutex.Unlock()
	return self.rowWrites
}

// Close releases the store. The next task's single-writer exclusion is released here; at this
// task the only thing Close owns is that the store stops answering, because a closed store that
// answered (0, nil) would be exactly the silent zero this file exists to make unreachable.
func (self *StreamStore) Close() error {
	self.stateMutex.Lock()
	defer self.stateMutex.Unlock()
	self.closed = true
	return nil
}

// streamHighWater is the highest index this store has ever allocated for the stream, or 0 for a
// stream it has never seen. The exported StreamHighWater of section 8.2 is the next task's, and
// it is this plus that task's sentinels.
//
// IT ENUMERATES THE ROW DIRECTORY RATHER THAN STATTING ONE PATH, and the cost of that -- one
// directory read per call -- is priced here rather than discovered. Statting one path cannot see
// a row this build cannot NAME, and a row this build cannot name is exactly ledger item 170: a
// pre-A1 row, indistinguishable from an absent one, answered (0, nil), restarting the ladder at
// index 1 under a class key that has not moved.
//
// THE REFUSAL IS DELIBERATELY COARSE. One foreign-tagged row refuses every key in the directory,
// not just the key whose identity that row might hold -- because the identity under a foreign
// derivation is opaque to this build, so a directory written by another build tells this build
// nothing about which of its keys that build had already spent. That is the "versioned and
// refused" half of the transition rule item 170 asks for, and it is the half this store takes.
// The other half -- migration, by taking the maximum over the classes of one (group_id,
// sender_handle) -- is vacuous here and saying so is load-bearing: this is the FIRST durable
// reserver in any tree, so a store that has never existed cannot hold a pre-A1 row, and a
// migration written for one is dead code on the day it ships. A version tag also closes the
// hazard's PROPERTY rather than its instance: a future ruling that changes row identity again,
// and a row left by a build nobody has, are refused identically.
func (self *StreamStore) streamHighWater(groupId []byte, senderHandle []byte) (uint64, error) {
	key, err := streamKeyFromOctets(groupId, senderHandle)
	if err != nil {
		return 0, err
	}
	self.stateMutex.Lock()
	closed := self.closed
	self.stateMutex.Unlock()
	if closed {
		return 0, fmt.Errorf("%w: the store at %s is closed", ErrStreamStoreState, self.dir)
	}

	rowName := streamRowName(key)
	entries, err := os.ReadDir(self.rowDir)
	if err != nil {
		return 0, fmt.Errorf(
			"%w: the row directory %s could not be read: %v",
			ErrStreamStoreState,
			self.rowDir,
			err,
		)
	}
	present := false
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			return 0, fmt.Errorf(
				"%w: %q in the row directory %s is not a regular file, and that directory holds rows and nothing else",
				ErrStreamStoreState,
				entry.Name(),
				self.rowDir,
			)
		}
		switch self.classifyStreamRowName(entry.Name()) {
		case streamRowOfAnotherKeySpace:
			return 0, fmt.Errorf(
				"%w: row %q in %s carries key-space tag %q and this build produces %q; answering this key with a silent zero would restart the stream index ladder at 1 under a class key that has not moved",
				ErrStreamKeySpace,
				entry.Name(),
				self.rowDir,
				entry.Name()[:streamKeySpaceTagLen],
				self.keySpaceTag,
			)
		case streamRowNotARow:
			return 0, fmt.Errorf(
				"%w: %q in the row directory %s is not a row under any key-space tag",
				ErrStreamStoreState,
				entry.Name(),
				self.rowDir,
			)
		}
		if entry.Name() == rowName {
			present = true
		}
	}
	if !present {
		// contract clause 4: a stream never seen is 0 with no error, so the first
		// allocation is 1.
		return 0, nil
	}
	content, err := os.ReadFile(filepath.Join(self.rowDir, rowName))
	if err != nil {
		return 0, fmt.Errorf(
			"%w: row %s is present and could not be read: %v",
			ErrStreamStoreState,
			rowName,
			err,
		)
	}
	highWater, _, err := classifyStreamRow(rowName, content)
	if err != nil {
		return 0, err
	}
	return highWater, nil
}
