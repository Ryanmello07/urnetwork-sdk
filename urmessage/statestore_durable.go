package urmessage

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/urnetwork/connect/mls"
)

// ── S2-14: the durable mls.StateStore ────────────────────────────────────────────────────────

// DurableStateStore is [mls.StateStore] on a directory, so that a device that is killed comes back
// into the groups it was in.
//
// WHAT PROTECTS THE PRIVATE KEYS IN IT, PLAINLY, BECAUSE THE HONEST ANSWER IS SHORT.
//
// FILE PERMISSIONS AND NOTHING ELSE. Every octet this store writes is written in the CLEAR: the
// MLS epoch state (which carries this member's leaf HPKE private key, its TreeKEM path-secret
// ladder and the epoch's restore secret), the init and encryption private keys of every key
// package this device published, this device's Ed25519 identity private key, and each group's
// `pq_secret` and `group_handle_key`. There is no passphrase, no key derivation, no OS keychain
// and no hardware. Anything that can read the directory can read every group this device is in,
// past and future, and can speak as this device.
//
// The directory is created 0o700 and every file 0o600, and on a POSIX filesystem that is a real
// bound: another user on the machine is refused. ON WINDOWS IT IS NOT A BOUND THIS CODE SETS.
// Go's mode argument is reduced to the read-only bit there, so a file inherits the ACL of the
// directory it is created in; what actually protects it is wherever the caller put the directory,
// and a caller that chose a world-readable path gets a world-readable key store with no complaint
// from here. Any process running as the same user reads it on every platform.
//
// WHAT WOULD CLOSE IT IS NOT INVENTED HERE. Encryption at rest needs a key, and a key needs
// either a passphrase the user types (with a KDF, a rekey story and a lost-passphrase story) or a
// platform keystore (DPAPI, the macOS Keychain, the Android Keystore, iOS's Secure Enclave) --
// each of which is a product decision with a different threat model, and none of which this
// package may take on its own. **FILED AS S2-24: what protects urmessage's private keys at rest.
// It is open, it has no owner, and until it is ruled the answer above is the whole answer.**
// Spec A §8.1's "sealed" columns are the server's obligation and say nothing about a client disk.
//
// WHAT IT DOES AND DOES NOT INHERIT FROM THE STREAM STORE NEXT DOOR. [sdk.StreamStore] solved
// crash safety for the stream-index reserver and this follows it rather than inventing a second
// discipline: a single-writer exclusion held by the operating system over the directory, acquired
// before anything is read or written; the guard entry BESIDE the data directory and never inside
// it, so "an entry in the data directory that is not a record is a finding" stays categorical; an
// fsync that must return before a value is observable; and no liveness heuristic anywhere -- the
// hold is released by Close and by the death of this process and by nothing else.
//
// WHERE IT DELIBERATELY DIFFERS, said at the line rather than here: the stream store's rows are
// fixed-width append-only records, so it repairs a torn tail in place; these values are
// variable-width and are REPLACED, so a half-written one can never become observable at all. See
// [DurableStateStore.writeRecord]. And the stream store has a key-space tag in every row name
// because messagegroup.StreamKey's field set can change under it; these keys are raw octets that
// mls hands over, so a format version inside each record is what stands in its place.
//
// It is safe for concurrent use. Every method takes the store's lock for the whole of its work,
// which is what makes the read-modify-erase of DeleteGroupStateBefore one step.
type DurableStateStore struct {
	dir     string
	dataDir string

	// exclusion is the SINGLE-WRITER guard, held by the operating system on an entry beside the
	// data directory. Two stores over one directory is two devices writing one device's MLS
	// state: the later writer's epoch overwrites the earlier's, and the earlier device then
	// restores a group whose ratchet position is another device's.
	exclusion io.Closer

	lock   sync.Mutex
	closed bool

	// unswept is every `.writing-*` [sweepStateTempFiles] found at open and could NOT remove.
	// It is a field and not a returned error because the sweep is not fatal; see that function
	// for why, and [DurableStateStore.UnsweptWrites] for what a caller is owed.
	unswept []string

	// flushes counts every write that passed through writeRecord, taken AFTER the Sync returns
	// rather than before it.
	//
	// WHAT IT MEASURES AND WHAT IT DOES NOT, AND THE SECOND HALF IS A CORRECTION OF WHAT USED
	// TO STAND HERE. This comment said "counted here, the flush cannot be deleted without this
	// number going to zero". THAT IS FALSE AND IT WAS FALSIFIED BY DELETING THE FLUSH: replace
	// `syncErr := temp.Sync()` with `var syncErr error`, leave `self.flushes += 1` exactly
	// where it is, and TestEveryValueTheDurableStoreNamesWasFlushedFirst still passes and so
	// does the whole of ./urmessage and ./cp3b. Re-measured at this commit, both directions.
	// The reason is structural rather than a slip of position: the increment is UNCONDITIONAL,
	// so it counts the same whether the call above it is there or not, and no rearrangement of
	// an unconditional statement turns it into a count of work performed.
	//
	// SO THE NUMBER IS ONE OF TWO CLAUSES AND IT IS THE WEAKER ONE. This counts that a value
	// went through the one write path -- one flush per value and not one per call, which is
	// what TestEveryValueTheDurableStoreNamesWasFlushedFirst actually drives, and it is worth
	// having. What holds the fsync ITSELF is TestEveryFsyncInThisPackageIsAtASiteThisSuiteNames
	// in sourcegate_test.go: it parses this package's own source and refuses any Sync call site
	// that is not writeRecord's or syncStateDir's, so deleting the flush is a RED gate rather
	// than an unchanged number. That gate is sdk/message_stream_store_test.go's, one package
	// over, and its absence here was the stream store's discipline copied one layer deep: the
	// counter came and the thing that made the counter mean something did not.
	//
	// It counts the VALUE flush and not the directory flush, because the directory flush is a
	// no-op on Windows by construction (see syncStateDir there) and a counter that read zero
	// on one platform and one on another would measure the platform rather than the code.
	flushes int

	// skipRemove is the injected failure point, set by tests in this package and by nothing
	// else. It is [sdk.StreamStore]'s `interrupt` field one package over, and it is here for
	// the same reason: the state it stands in for -- a remove that reported success and left
	// the entry readable -- is not one any filesystem this suite can run on will produce, and
	// a §5.12 clause that cannot be driven is a §5.12 clause nobody can tell is still there.
	//
	// It is a bool and not a path or a count, so it can only ever turn the erase off wholesale
	// in a test binary; there is no production path that sets it and no way to set it from
	// outside this package.
	skipRemove bool
}

var _ mls.StateStore = (*DurableStateStore)(nil)
var _ DeviceStore = (*DurableStateStore)(nil)

// DeviceStore is the durable surface a [Device] needs BEYOND [mls.StateStore], so that a restart
// is a restore rather than a new device.
//
// It is a separate interface and not extra methods on the config, because [DeviceConfig.StateStore]
// is an `mls.StateStore` and a store that cannot persist an identity must go on being legal there.
// [NewDevice] asks a store whether it satisfies this, and a store that does not gets exactly the
// behaviour it had before this interface existed: a fresh identity every process, no restore.
//
// EVERYTHING ON IT IS SECRET IN FULL. The identity private key speaks as this device in every
// group it is in; a [GroupRecord] carries two of the [Invite]'s four values, and whoever holds
// those plus the MLS state this store keeps beside them is in the group.
type DeviceStore interface {
	mls.StateStore

	// GetDeviceIdentity answers what PutDeviceIdentity last wrote, or a refusal wrapping
	// [ErrNoDeviceIdentity] when this store has never held one. It is never (nil, nil, nil, nil).
	GetDeviceIdentity() (signerPub []byte, signerPriv []byte, leafKeys []byte, err error)
	PutDeviceIdentity(signerPub []byte, signerPriv []byte, leafKeys []byte) error

	// PutGroupRecord writes the urmessage-side half of one group: the values that are this
	// package's rather than MLS's, and that a restore cannot be performed without.
	PutGroupRecord(record *GroupRecord) error

	// GroupRecords is every group this store holds a record for, in no particular order.
	GroupRecords() ([]*GroupRecord, error)

	// DeleteGroupRecord removes one group's record AND every MLS epoch state beside it AND every
	// copy of a record this device sent in it. It is how a device leaves a group without leaving
	// its keys, or what it said, on the disk.
	DeleteGroupRecord(groupId []byte) error

	// PutSentRecord writes the copy of one record this device sealed in one group, BEFORE that
	// record is submitted. SentRecords answers every copy one group holds, ascending by stream
	// index. See [SentRecord] for why the copy exists at all.
	PutSentRecord(groupId []byte, record *SentRecord) error
	SentRecords(groupId []byte) ([]*SentRecord, error)
}

// SentRecord is this device's copy of one application record it sealed: the only place its own
// half of a conversation can be read back from.
//
// WHY THERE IS A COPY. Since connect 4c030dc an application record's body is an MLS PrivateMessage,
// and a member cannot open its own -- Protect spends a generation of the leaf's own ratchet and MLS
// keeps no receiving ratchet for a leaf's own messages (connect messagegroup OPENITEMS MG-4). So a
// restarted device that re-fetches its history reads the other members' lines off the server and
// can read its OWN lines off nothing but this.
//
// IT IS PLAINTEXT ON THE DISK, AND THAT IS NOT A NEW EXPOSURE OF THIS DIRECTORY, said carefully
// because it would be easy to say too much. The epoch state beside it lets anything that can read
// this directory re-derive every OTHER member's record keys for this epoch and read their lines off
// the server; this is the same user's own lines, next to it. What it DOES change is what is readable
// with the server's rows gone: the directory alone now holds what this device said. [DurableStateStore]'s
// header is the answer on what protects any of it, and S2-24 is still what must rule that.
//
// IT GROWS WITHOUT BOUND, one file per line sent, until the group is left. Nothing prunes it, for
// the same reason nothing prunes the server's rows (7.2's sweep is not built): there is no retention
// decision yet for it to follow.
type SentRecord struct {
	// The §5.6 stream index the record was sealed at, and the name of this copy.
	StreamIndex uint64

	// The record's body_hash, which is how a record fetched back from the server is matched to the
	// copy without opening it.
	BodyHash [32]byte

	// The sender's clock reading the record's head carries, unix milliseconds.
	SentAtMs int64

	// What was sealed. Octets, never interpreted.
	Body []byte
}

// GroupRecord is the urmessage-side state of one group: the values that do not live in MLS and
// that [Device.Restore] cannot rebuild a session without.
//
// IT IS SECRET IN FULL. PqSecret and GroupHandleKey are two of the [Invite]'s four values; see
// [DurableStateStore] for what does and does not protect them on the disk.
type GroupRecord struct {
	// The 32 octet group id the server keys its rows by.
	GroupId []byte

	// §7's pq_secret, drawn by [messagegroup.NewPqSecret] at the founding and carried to the
	// joiner in the [Invite].
	PqSecret []byte

	// group_handle_key: the epoch ZERO storage root's expansion. It never moves, which is why it
	// is stored once rather than per epoch.
	GroupHandleKey []byte

	// The MLS epoch this device's session was at when the record was written. It is the epoch
	// [mls.LoadGroup] is asked for, because nothing on [mls.StateStore] enumerates epochs -- J1-8.
	Epoch uint64

	// Whether [Group.Open] has published this group on the server. A restored group that was
	// never opened would be refused by the server at its first send, with a REASON the caller
	// would have to decode; carrying the bit means [Group.Send] refuses it by name instead.
	Opened bool
}

// ── the record format ────────────────────────────────────────────────────────────────────────

// Every value this store writes is one record, and the record is self-describing so that a file
// which is not what the name says is a REFUSAL rather than a wrong answer.
//
// The name of a file is a hash of its key, so two keys that collided -- or a directory somebody
// copied from another device -- would otherwise be read as the value that was asked for. The key
// octets are therefore INSIDE the record and are compared against the key the caller supplied, on
// every read.
const (
	stateRecordMagic   = "URMSTATE"
	stateRecordVersion = byte(0x01)
)

// The kinds. A record read under the wrong kind is refused, so a private key file renamed over a
// group state cannot be handed to LoadGroup as an epoch.
const (
	stateKindGroupState     byte = 1
	stateKindPrivateKey     byte = 2
	stateKindKeyPackage     byte = 3
	stateKindDeviceIdentity byte = 4
	stateKindGroupRecord    byte = 5
	stateKindSentRecord     byte = 6
)

// encodeStateRecord frames one record: magic, version, kind, the parts each length-prefixed, and
// a SHA-256 over every octet before it.
//
// The checksum is NOT a security property and must not be read as one -- anything that can write
// this directory can recompute it. It is here for the reason the stream store's per-record
// checksum is: a file that a filesystem returned altered is refused instead of being decoded into
// a key schedule that then fails somewhere with nothing to point at.
func encodeStateRecord(kind byte, parts ...[]byte) ([]byte, error) {
	if len(parts) > 255 {
		return nil, fmt.Errorf("%w: a record of kind %d carries %d parts", ErrStateStoreFormat, kind, len(parts))
	}
	body := bytes.NewBuffer(nil)
	body.WriteString(stateRecordMagic)
	body.WriteByte(stateRecordVersion)
	body.WriteByte(kind)
	body.WriteByte(byte(len(parts)))
	for _, part := range parts {
		if len(part) > int(^uint32(0)>>1) {
			return nil, fmt.Errorf("%w: a part of %d octets does not fit its length prefix", ErrStateStoreFormat, len(part))
		}
		var prefix [4]byte
		binary.BigEndian.PutUint32(prefix[:], uint32(len(part)))
		body.Write(prefix[:])
		body.Write(part)
	}
	sum := sha256.Sum256(body.Bytes())
	body.Write(sum[:])
	return body.Bytes(), nil
}

// decodeStateRecord reads back what encodeStateRecord wrote and refuses everything else.
//
// EVERY REFUSAL NAMES WHAT IT SAW. A truncated record, a version this build does not write, the
// wrong kind and a checksum that does not match are four different sentences, because they have
// four different causes and a caller staring at one at 2am has to be able to tell them apart.
func decodeStateRecord(raw []byte, kind byte) ([][]byte, error) {
	header := len(stateRecordMagic) + 3
	if len(raw) < header+sha256.Size {
		return nil, fmt.Errorf("%w: %d octets is shorter than an empty record", ErrStateStoreFormat, len(raw))
	}
	if string(raw[:len(stateRecordMagic)]) != stateRecordMagic {
		return nil, fmt.Errorf("%w: the first %d octets are not this store's magic", ErrStateStoreFormat, len(stateRecordMagic))
	}
	if version := raw[len(stateRecordMagic)]; version != stateRecordVersion {
		return nil, fmt.Errorf("%w: the record is at version %#02x and this build writes %#02x",
			ErrStateStoreFormat, version, stateRecordVersion)
	}
	if got := raw[len(stateRecordMagic)+1]; got != kind {
		return nil, fmt.Errorf("%w: the record is of kind %d and kind %d was asked for",
			ErrStateStoreFormat, got, kind)
	}
	sum := sha256.Sum256(raw[:len(raw)-sha256.Size])
	if !bytes.Equal(sum[:], raw[len(raw)-sha256.Size:]) {
		return nil, fmt.Errorf("%w: the record's checksum is not the hash of the record", ErrStateStoreFormat)
	}
	count := int(raw[len(stateRecordMagic)+2])
	parts := make([][]byte, 0, count)
	at := header
	end := len(raw) - sha256.Size
	for index := 0; index < count; index += 1 {
		if end-at < 4 {
			return nil, fmt.Errorf("%w: part %d of %d has no length prefix", ErrStateStoreFormat, index, count)
		}
		width := int(binary.BigEndian.Uint32(raw[at : at+4]))
		at += 4
		if width < 0 || end-at < width {
			return nil, fmt.Errorf("%w: part %d of %d announces %d octets and %d are left",
				ErrStateStoreFormat, index, count, width, end-at)
		}
		parts = append(parts, append([]byte(nil), raw[at:at+width]...))
		at += width
	}
	if at != end {
		return nil, fmt.Errorf("%w: %d octets stand after the last part", ErrStateStoreFormat, end-at)
	}
	return parts, nil
}

// ── opening ──────────────────────────────────────────────────────────────────────────────────

// The data directory, and the guard entry BESIDE it. See [DurableStateStore] for why the guard is
// not inside the directory it excludes.
const (
	stateDataDirName = "state"
	stateGuardName   = "single-writer.lock"

	// The prefix every in-flight write wears. IT IS A CONSTANT BECAUSE THREE PLACES HAVE TO
	// AGREE ON IT: writeRecord makes them, OpenDurableStateStore sweeps them, and
	// deleteEpochsLocked has to remove them before it can say a directory is empty of state.
	// A second spelling of this string is a file nothing ever deletes, which is exactly the
	// defect the sweep exists for.
	stateTempPrefix = ".writing-"
)

// stateStoreGuardPath is the ONE place the guard's location is decided, so there is no second
// spelling of it to drift. This is [sdk.StreamStore]'s streamStoreGuardPath one package over and
// the reason is the same one.
func stateStoreGuardPath(dir string) string {
	return filepath.Join(dir, stateGuardName)
}

// OpenDurableStateStore opens the store at dir, creating it if it is not there.
//
// THE EXCLUSION IS ACQUIRED BEFORE ANYTHING IS READ AND BEFORE ANYTHING IS WRITTEN, which is the
// stream store's ordering and is here for the same reason: a second opener that had already read
// the directory has already made a decision on state it does not own.
//
// It is refused on a platform where this build can hold no exclusion, rather than opened with the
// property quietly deleted by a build constraint.
func OpenDurableStateStore(dir string) (*DurableStateStore, error) {
	if dir == "" {
		return nil, fmt.Errorf("%w: a durable state store needs a directory", ErrStateStoreState)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("%w: the store directory %s could not be created: %v", ErrStateStoreState, dir, err)
	}
	exclusion, err := acquireStateStoreExclusion(dir)
	if err != nil {
		return nil, err
	}
	released := false
	defer func() {
		if !released {
			exclusion.Close()
		}
	}()
	dataDir := filepath.Join(dir, stateDataDirName)
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return nil, fmt.Errorf("%w: the data directory %s could not be created: %v", ErrStateStoreState, dataDir, err)
	}
	unswept, err := sweepStateTempFiles(dataDir)
	if err != nil {
		return nil, err
	}
	released = true
	return &DurableStateStore{dir: dir, dataDir: dataDir, exclusion: exclusion, unswept: unswept}, nil
}

// UnsweptWrites is every leftover write [sweepStateTempFiles] found at open and could not remove,
// by path. Empty on the ordinary open, which is every open on a machine where nothing else is
// holding this directory's files.
//
// IT EXISTS SO THAT "THE SWEEP DID NOT REFUSE THE OPEN" IS NOT THE SAME SENTENCE AS "THERE WAS
// NOTHING TO SWEEP". A caller that wants to tell a user, or a probe that wants to assert the clean
// case, has one place to read it; nothing in this package makes a decision on it.
func (self *DurableStateStore) UnsweptWrites() []string {
	self.lock.Lock()
	defer self.lock.Unlock()
	return append([]string(nil), self.unswept...)
}

// sweepStateTempFiles removes every in-flight write left behind by a process that died.
//
// WHY THERE IS ANYTHING TO SWEEP. [DurableStateStore.writeRecord] is temp file, fsync, rename, and
// the `defer` that removes the temp on a failure only runs if the CALL RETURNS. A process killed
// between CreateTemp and Rename returns from nothing, and what it leaves in the epoch directory is
// a `.writing-XXXXXXXX` holding a COMPLETE epoch state -- this member's leaf HPKE private key and
// its whole TreeKEM path-secret ladder -- that decodes cleanly under decodeStateRecord. Measured
// with a real Process.Kill: it is not debris, it is a readable copy.
//
// AND NOTHING USED TO REMOVE IT, WHICH IS THE HALF THAT MATTERS. It is not epoch-named, so
// deleteEpochsLocked walked straight past it, and SO DID THE RE-READ that is sold as making
// "deleted" a measurement -- section 5.12's total erase reported success over a file holding the
// keys it had just promised to discard. The sweep here and the refusal in deleteEpochsLocked are
// the two halves of closing that, and they are deliberately in two places: this one bounds how
// long a leftover can live (one open), that one makes an erase that cannot see something REFUSE
// rather than report success.
//
// IT IS AN UNLINK AND NOT AN ERASE, which is this store's discipline everywhere and is stated
// rather than implied: the octets are still wherever the filesystem put them. See
// [DurableStateStore]'s header for what does and does not protect them.
//
// IT RUNS UNDER THE EXCLUSION AND BEFORE ANYTHING IS READ, so it can never race a live WRITER: the
// only process that may hold this directory for writing is this one, and it has not written yet.
// THAT SENTENCE USED TO SAY "a live writer: the only process that may hold this directory is this
// one", and it was reasoning about the wrong party -- the exclusion binds writers, and the party
// that breaks this is a third-party READER.
//
// A LEFTOVER THAT WILL NOT DELETE IS A WARNING AND NOT A REFUSAL, AND THAT IS THE DECISION.
// On Windows `os.Remove` of a file another handle holds without FILE_SHARE_DELETE answers
// ERROR_ACCESS_DENIED -- the same mechanism, from the same causes (a scanner, the search indexer, a
// backup agent), that `statestore_rename_windows_test.go` pins for MoveFileEx. Returning that error
// from here made the WHOLE STORE FAIL TO OPEN: a crash-recovery path turning a recoverable state
// into an unopenable one, and a transient third-party handle turning into "the app does not start".
// It was measured; it is not a hypothesis.
//
// WHY NON-FATAL IS RIGHT HERE AND FATAL IS STILL RIGHT IN deleteEpochsLocked, because the two look
// alike and are not. THE DIFFERENCE IS WHOSE PROMISE IT IS. §5.12's erase is a caller asking for
// octets to be gone, so an erase that cannot see a file MUST refuse rather than report success --
// that is the defect this store was carrying and it stays closed. Nobody asked this function for
// anything: it is opportunistic hygiene that bounds how long a leftover lives, and a leftover it
// cannot remove today is removed at the next open. Refusing the open makes the debris no smaller
// and costs the user their device.
//
// WHAT IS NOT SILENT. The paths are carried out to [DurableStateStore.UnsweptWrites], so a caller
// that wants to say something about them can, and the clean case is assertable rather than assumed.
// A WALK that fails is still fatal: a data directory this process cannot even enumerate is not a
// leftover problem, and the store is about to need that directory for every read it performs.
//
// NO RETRY BUDGET IS INVENTED HERE. S2-29's repair at writeRecord's rename is a bounded retry on
// ERROR_ACCESS_DENIED and ERROR_SHARING_VIOLATION, and 1141236's successor deliberately did not
// take it because the budget is somebody's to own; inventing one here, on a path where carrying on
// is free, would be taking that decision sideways. The day S2-29's retry lands, this site is the
// second caller of the same primitive.
func sweepStateTempFiles(dataDir string) ([]string, error) {
	unswept := []string{}
	err := filepath.WalkDir(dataDir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("%w: %s could not be walked for leftover writes: %v",
				ErrStateStoreState, dataDir, err)
		}
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), stateTempPrefix) {
			return nil
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			unswept = append(unswept, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return unswept, nil
}

// Close releases the store, and with it the single-writer exclusion, which is the only thing that
// releases it other than the death of this process.
//
// A closed store stops answering rather than answering an empty value, for [MemoryStateStore]'s
// reason and the stream store's: a store that answered "no group state" after it was closed would
// send a live device off to re-join a group it is already in.
func (self *DurableStateStore) Close() error {
	self.lock.Lock()
	defer self.lock.Unlock()
	if self.closed {
		return nil
	}
	self.closed = true
	return self.exclusion.Close()
}

// flushCount is how many value fsyncs this store has performed. It is unexported and read only
// by this package's own tests, for the reason the stream store gives: it is an OBSERVABLE of where
// the work happens, not part of the interface.
func (self *DurableStateStore) flushCount() int {
	self.lock.Lock()
	defer self.lock.Unlock()
	return self.flushes
}

func (self *DurableStateStore) refuseIfClosed() error {
	if self.closed {
		return fmt.Errorf("%w: this store is closed", ErrStateStoreState)
	}
	return nil
}

// ── the paths ────────────────────────────────────────────────────────────────────────────────

// stateNameOf is the file name one key gets: the SHA-256 of the key octets, hex.
//
// FIXED WIDTH RATHER THAN THE KEY ITSELF, and that is a decision about the FILESYSTEM and not
// about secrecy -- a key package ref and a group id are public-ish values and hex would carry
// them fine, but mls's interface admits a key of any width and a name is bounded at 255 octets on
// every filesystem that matters. The key octets are inside the record and are compared on read,
// so the hash is a name and never an identity: two keys that hashed alike are refused rather than
// confused.
func stateNameOf(key []byte) string {
	sum := sha256.Sum256(key)
	return hex.EncodeToString(sum[:])
}

func (self *DurableStateStore) privatePath(pub []byte) string {
	return filepath.Join(self.dataDir, "priv", stateNameOf(pub))
}

func (self *DurableStateStore) keyPackagePath(ref []byte) string {
	return filepath.Join(self.dataDir, "kp", stateNameOf(ref))
}

func (self *DurableStateStore) identityPath() string {
	return filepath.Join(self.dataDir, "device")
}

func (self *DurableStateStore) groupDir(groupId []byte) string {
	return filepath.Join(self.dataDir, "group", stateNameOf(groupId))
}

func (self *DurableStateStore) groupRecordPath(groupId []byte) string {
	return filepath.Join(self.groupDir(groupId), "meta")
}

func (self *DurableStateStore) epochDir(groupId []byte) string {
	return filepath.Join(self.groupDir(groupId), "epoch")
}

// sentDir is where one group's [SentRecord] copies live, each named by its stream index as sixteen
// hex digits -- stateEpochName's shape, and for its reason: the listing's lexical order is the
// numeric order.
func (self *DurableStateStore) sentDir(groupId []byte) string {
	return filepath.Join(self.groupDir(groupId), "sent")
}

// stateEpochName is one epoch's file name: the epoch as sixteen zero-padded hex digits, so that
// the lexical order of a directory listing IS the numeric order of the epochs and
// DeleteGroupStateBefore does not have to sort to be correct.
func stateEpochName(epoch uint64) string {
	return fmt.Sprintf("%016x", epoch)
}

func stateEpochOfName(name string) (uint64, bool) {
	if len(name) != 16 {
		return 0, false
	}
	epoch, err := strconv.ParseUint(name, 16, 64)
	if err != nil {
		return 0, false
	}
	return epoch, true
}

// ── the write, which is the whole of the crash safety ────────────────────────────────────────

// writeRecord makes one value observable, or makes nothing observable.
//
// TEMP FILE, FSYNC, RENAME -- AND THE FSYNC IS BEFORE THE RENAME, which is the whole property. A
// value written in place could be observed half-written by the next process to open this store,
// and half of an epoch state is a key schedule that rebuilds into a group agreeing with nobody;
// half of a key-package record is an init private key with no encryption private key beside it.
// After the fsync returns, the temp file holds the whole value on stable storage; the rename then
// puts that whole value under the name, and a reader sees the previous whole value or this one.
//
// THIS IS WHERE IT DIFFERS FROM THE STREAM STORE NEXT DOOR, and the difference is the shape of the
// data rather than a different opinion about durability. A stream row is fixed-width append-only
// records, so the store can and does repair a torn tail in place at open time; these values are
// variable width and every write REPLACES, so there is no tail to repair and no state in which a
// partially written value has a name -- the temp file that held it is not a record name and is
// removed.
//
// THE DIRECTORY FSYNC IS WHAT MAKES THE RENAME ITSELF DURABLE, and it is a no-op on Windows; see
// syncStateDir for exactly what that costs and why there is no second discipline hiding in it.
//
// WHAT THE `defer` BELOW DOES NOT COVER, said here because it used to be nowhere: it removes the
// temp file only if this CALL RETURNS. A process killed between CreateTemp and Rename leaves a
// `.writing-*` in the record's own directory holding a complete, decodable value -- for an epoch
// state, this member's leaf private key and its path-secret ladder. [sweepStateTempFiles] at open
// is what bounds how long that lives, and deleteEpochsLocked's re-read is what stops a discard
// reporting success over one.
func (self *DurableStateStore) writeRecord(path string, kind byte, parts ...[]byte) error {
	record, err := encodeStateRecord(kind, parts...)
	if err != nil {
		return err
	}
	// the assembled record is a SECOND copy of whatever secret it carries, and this function is
	// the only thing that can still reach it once the write has returned. Erasing it costs one
	// pass and takes the copy out of the heap for the collector to move around, which is
	// mls.(*Group).persist's own discipline one layer down.
	defer zeroizeState(record)

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("%w: %s could not be created: %v", ErrStateStoreState, dir, err)
	}
	temp, err := os.CreateTemp(dir, ".writing-*")
	if err != nil {
		return fmt.Errorf("%w: a temporary file in %s could not be created: %v", ErrStateStoreState, dir, err)
	}
	tempPath := temp.Name()
	committed := false
	defer func() {
		if !committed {
			temp.Close()
			os.Remove(tempPath)
		}
	}()
	// 0o600 explicitly and not CreateTemp's own mode, which is already 0o600 today -- said here
	// because "the file mode is the whole of what protects these octets" is this type's headline
	// and a value that important is not left to another package's default.
	if err := temp.Chmod(0o600); err != nil && !errors.Is(err, os.ErrInvalid) && !errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("%w: %s could not be given mode 0600: %v", ErrStateStoreState, tempPath, err)
	}
	if _, err := temp.Write(record); err != nil {
		return fmt.Errorf("%w: %s could not be written: %v", ErrStateStoreState, tempPath, err)
	}
	// NEVER SWALLOWED. A Put that returned after a failed flush has told a caller that a value is
	// durable when nothing recorded it, and for PutGroupState that caller is a seal that has
	// already consumed a ratchet generation.
	syncErr := temp.Sync()
	self.flushes += 1
	if syncErr != nil {
		return fmt.Errorf("%w: %s could not be flushed, so this value is not durable and must not be named: %v",
			ErrStateStoreState, tempPath, syncErr)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("%w: %s could not be closed: %v", ErrStateStoreState, tempPath, err)
	}
	if err := os.Rename(tempPath, path); err != nil {
		return fmt.Errorf("%w: %s could not be renamed onto %s: %v", ErrStateStoreState, tempPath, path, err)
	}
	committed = true
	return syncStateDir(dir)
}

// readRecord answers the parts of one record, or a refusal that says which of the two absences it
// is: no such value, or a value this build cannot read.
//
// THE NOT-FOUND CASE IS ITS OWN SENTINEL, which J1-4 says mls.StateStore does not give and which
// this package's callers need: [Device.Restore] has to tell "this device was never in that group"
// from "the disk is broken", and a bare error makes those one reading.
func (self *DurableStateStore) readRecord(path string, kind byte) ([][]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrStateNotFound, filepath.Base(path))
		}
		return nil, fmt.Errorf("%w: %s could not be read: %v", ErrStateStoreState, path, err)
	}
	return decodeStateRecord(raw, kind)
}

// zeroizeState overwrites one buffer this store assembled. It is this package's only erase and it
// erases what THIS process can still reach: it does not and cannot erase the file, the filesystem
// cache or whatever the allocator did with an earlier copy.
func zeroizeState(octets []byte) {
	for at := range octets {
		octets[at] = 0
	}
}

// ── mls.StateStore ───────────────────────────────────────────────────────────────────────────

// PutGroupState writes one epoch of one group.
//
// IT IS DURABLE BEFORE IT RETURNS, which is J1-11: mls persists inside the seal, before the
// ciphertext reaches its caller, precisely so that a restored member never re-draws a generation
// it has already spent. A store that buffered this would hand that guarantee back.
//
// The state is COPIED into the record this call writes, because mls erases the buffer it passed
// as soon as this returns -- the obligation on [mls.StateStore]'s own header. Nothing of the
// caller's is retained past the call: this store keeps no map.
func (self *DurableStateStore) PutGroupState(groupId []byte, epoch uint64, state []byte) error {
	self.lock.Lock()
	defer self.lock.Unlock()
	if err := self.refuseIfClosed(); err != nil {
		return err
	}
	var epochOctets [8]byte
	binary.BigEndian.PutUint64(epochOctets[:], epoch)
	return self.writeRecord(filepath.Join(self.epochDir(groupId), stateEpochName(epoch)),
		stateKindGroupState, groupId, epochOctets[:], state)
}

// GetGroupState answers the state PutGroupState wrote at this epoch.
//
// The group id and the epoch inside the record are compared against the ones asked for, so a file
// that is under this name for any reason other than this store having put it there is refused
// rather than decoded.
func (self *DurableStateStore) GetGroupState(groupId []byte, epoch uint64) ([]byte, error) {
	self.lock.Lock()
	defer self.lock.Unlock()
	if err := self.refuseIfClosed(); err != nil {
		return nil, err
	}
	parts, err := self.readRecord(filepath.Join(self.epochDir(groupId), stateEpochName(epoch)), stateKindGroupState)
	if err != nil {
		return nil, err
	}
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: a group state carries %d parts, want 3", ErrStateStoreFormat, len(parts))
	}
	if !bytes.Equal(parts[0], groupId) {
		return nil, fmt.Errorf("%w: the record under this name names group %x and group %x was asked for",
			ErrStateStoreFormat, parts[0], groupId)
	}
	if len(parts[1]) != 8 || binary.BigEndian.Uint64(parts[1]) != epoch {
		return nil, fmt.Errorf("%w: the record under this name does not name epoch %d", ErrStateStoreFormat, epoch)
	}
	return parts[2], nil
}

// DeleteGroupStateBefore ACTUALLY DELETES, and then reads the directory again to say so.
//
// §5.12 discards storage_root[n+1], write_key[n+1], eph_root[n+1] and every X-Wing wrap at once,
// and the hazard it names is the HALF erase: a surviving half looks exactly like a value somebody
// may still use, and nothing downstream reports it. So this does three things and not one.
//
//   - it removes by UNLINK and never by truncation or overwrite, so every epoch is removed whole:
//     a crash in the middle of the loop leaves some epochs and no half of one;
//   - it fsyncs the directory afterwards, so the unlinks are on stable storage rather than only
//     in the cache -- without which a crash could bring back a state this call reported gone;
//   - and it RE-READS the directory and refuses if any epoch below the cutoff survived. That is
//     the clause that makes "deleted" a measurement rather than an intention. A caller that was
//     told the discard happened, over a disk where it did not, is the exact shape §5.12 warns
//     about.
//
// Deleting NOTHING is success: mls calls this at every commit with a cutoff that is zero for the
// first thirty-two epochs of every group.
func (self *DurableStateStore) DeleteGroupStateBefore(groupId []byte, epoch uint64) error {
	self.lock.Lock()
	defer self.lock.Unlock()
	if err := self.refuseIfClosed(); err != nil {
		return err
	}
	return self.deleteEpochsLocked(groupId, epoch)
}

func (self *DurableStateStore) deleteEpochsLocked(groupId []byte, before uint64) error {
	dir := self.epochDir(groupId)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("%w: %s could not be read: %v", ErrStateStoreState, dir, err)
	}
	removed := 0
	for _, entry := range entries {
		at, named := stateEpochOfName(entry.Name())
		if !named {
			// AN IN-FLIGHT WRITE LEFT BY A PROCESS THAT DIED, and section 5.12's discard
			// has to remove it or it is not a discard. It carries a complete epoch state
			// of THIS group -- writeRecord makes it in this very directory -- so leaving
			// it is leaving the leaf private key and the path-secret ladder behind after
			// reporting the erase succeeded. Anything else that is not epoch-named is left
			// alone here and REFUSED by the re-read below.
			if !strings.HasPrefix(entry.Name(), stateTempPrefix) {
				continue
			}
			if !self.skipRemove {
				if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
					return fmt.Errorf("%w: %s is an unfinished write of group %x's epoch state and it could not be discarded: %v",
						ErrStateStoreState, entry.Name(), groupId, err)
				}
			}
			removed += 1
			continue
		}
		if before <= at {
			continue
		}
		if !self.skipRemove {
			if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("%w: epoch %d of group %x could not be discarded: %v",
					ErrStateStoreState, at, groupId, err)
			}
		}
		removed += 1
	}
	if removed == 0 {
		return nil
	}
	if err := syncStateDir(dir); err != nil {
		return err
	}
	// the measurement. It is a second ReadDir and it is the point of this method.
	entries, err = os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("%w: %s could not be re-read after the discard: %v", ErrStateStoreState, dir, err)
	}
	for _, entry := range entries {
		at, named := stateEpochOfName(entry.Name())
		if !named {
			// CATEGORICAL, AND THAT IS THE REPAIR. This loop used to consider only entries
			// that parse as sixteen hex digits, so the one thing the discard could not see
			// was the one thing it also could not delete: a `.writing-*` holding a complete
			// epoch state survived the erase AND survived the measurement that is sold as
			// proving the erase happened. This store's own header says "an entry in the
			// data directory that is not a record is a finding"; this is that sentence
			// enforced instead of asserted.
			//
			// WHAT IT COSTS, because a fail-closed rule with an unnamed cost is a trap.
			// Anything a third party drops in this directory -- a .DS_Store, a Thumbs.db,
			// an antivirus quarantine stub -- makes a discard REFUSE rather than report
			// success. That is the right way round: this store must not delete octets it
			// did not write, and a discard that walked past an entry it could not read
			// would be the exact half-erase §5.12 names. The exposure is also narrow by
			// construction -- the loop above returns early when it removed NOTHING, and
			// with PastEpochWindow at 32 the alpha calls this with cutoff 0 for every
			// epoch it has, so this re-read runs only when something actually went.
			return fmt.Errorf("%w: %s stands in group %x's epoch directory after a discard below %d, and it is not an epoch this store wrote",
				ErrStateStoreState, entry.Name(), groupId, before)
		}
		if at < before {
			return fmt.Errorf("%w: epoch %d of group %x is still readable after a discard below %d",
				ErrStateStoreState, at, groupId, before)
		}
	}
	return nil
}

// PutPrivateKey writes one MLS private key under its public half.
func (self *DurableStateStore) PutPrivateKey(pub []byte, priv []byte) error {
	self.lock.Lock()
	defer self.lock.Unlock()
	if err := self.refuseIfClosed(); err != nil {
		return err
	}
	return self.writeRecord(self.privatePath(pub), stateKindPrivateKey, pub, priv)
}

func (self *DurableStateStore) GetPrivateKey(pub []byte) ([]byte, error) {
	self.lock.Lock()
	defer self.lock.Unlock()
	if err := self.refuseIfClosed(); err != nil {
		return nil, err
	}
	parts, err := self.readRecord(self.privatePath(pub), stateKindPrivateKey)
	if err != nil {
		return nil, err
	}
	if len(parts) != 2 || !bytes.Equal(parts[0], pub) {
		return nil, fmt.Errorf("%w: the record under this name is not the private key of %x", ErrStateStoreFormat, pub)
	}
	return parts[1], nil
}

// DeletePrivateKey removes one key, durably.
//
// J1-12 IS NOT CLOSED BY THIS AND THE NUMBER IS THE POINT: nothing in the corpus calls it. The
// query, so it is checkable rather than quoted -- over this workspace at the commit that adds
// this file, `grep -rn "DeletePrivateKey(" --include=*.go connect sdk | grep -v _test.go` answers
// the declaration on mls.StateStore, this body and MemoryStateStore's, and no call. So
// `PutPrivateKey` on every ProposeUpdate grows this directory without bound, exactly as it grows
// the map next door. It is implemented because the interface declares it and because a store that
// could not perform the erase would make the eventual caller a store change as well.
func (self *DurableStateStore) DeletePrivateKey(pub []byte) error {
	self.lock.Lock()
	defer self.lock.Unlock()
	if err := self.refuseIfClosed(); err != nil {
		return err
	}
	return self.removeLocked(self.privatePath(pub))
}

func (self *DurableStateStore) removeLocked(path string) error {
	if err := os.Remove(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("%w: %s could not be removed: %v", ErrStateStoreState, path, err)
	}
	if err := syncStateDir(filepath.Dir(path)); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%w: %s is still readable after it was removed", ErrStateStoreState, path)
	}
	return nil
}

func (self *DurableStateStore) PutKeyPackage(ref []byte, kp []byte, initPriv []byte, encPriv []byte) error {
	self.lock.Lock()
	defer self.lock.Unlock()
	if err := self.refuseIfClosed(); err != nil {
		return err
	}
	return self.writeRecord(self.keyPackagePath(ref), stateKindKeyPackage, ref, kp, initPriv, encPriv)
}

// TakeKeyPackage is DESTRUCTIVE, which is mls.StateStore's contract and not this store's choice: a
// key package is single use, and a second join off one published package is a second device
// deriving the same init secret.
//
// THE ARRAYS IT ANSWERS ARE THIS CALL'S OWN AND ARE RETAINED NOWHERE, which is J1-5. The caller --
// `mls.JoinKeyMaterial.Zeroize`, through messagegroup's join -- ERASES exactly these three arrays
// when it is done with them, and a store that handed back storage it kept would have its own
// records wiped by a correct caller. A store that reads the file on every call cannot make that
// mistake; a store that cached would have to copy, and would have to remember to.
//
// THE REMOVE IS BEFORE THE RETURN AND ITS FAILURE IS THE CALL'S. A take that answered the material
// and could not delete it has published a single-use key package twice.
func (self *DurableStateStore) TakeKeyPackage(ref []byte) ([]byte, []byte, []byte, error) {
	self.lock.Lock()
	defer self.lock.Unlock()
	if err := self.refuseIfClosed(); err != nil {
		return nil, nil, nil, err
	}
	path := self.keyPackagePath(ref)
	parts, err := self.readRecord(path, stateKindKeyPackage)
	if err != nil {
		return nil, nil, nil, err
	}
	if len(parts) != 4 || !bytes.Equal(parts[0], ref) {
		return nil, nil, nil, fmt.Errorf("%w: the record under this name is not the key package of %x",
			ErrStateStoreFormat, ref)
	}
	if err := self.removeLocked(path); err != nil {
		return nil, nil, nil, err
	}
	return parts[1], parts[2], parts[3], nil
}

// ── DeviceStore ──────────────────────────────────────────────────────────────────────────────

func (self *DurableStateStore) PutDeviceIdentity(signerPub []byte, signerPriv []byte, leafKeys []byte) error {
	self.lock.Lock()
	defer self.lock.Unlock()
	if err := self.refuseIfClosed(); err != nil {
		return err
	}
	if len(signerPub) == 0 || len(signerPriv) == 0 || len(leafKeys) == 0 {
		return fmt.Errorf("%w: a device identity is a signature key pair and a leaf keys body, and one of the three is empty",
			ErrStateStoreFormat)
	}
	return self.writeRecord(self.identityPath(), stateKindDeviceIdentity, signerPub, signerPriv, leafKeys)
}

func (self *DurableStateStore) GetDeviceIdentity() ([]byte, []byte, []byte, error) {
	self.lock.Lock()
	defer self.lock.Unlock()
	if err := self.refuseIfClosed(); err != nil {
		return nil, nil, nil, err
	}
	parts, err := self.readRecord(self.identityPath(), stateKindDeviceIdentity)
	if err != nil {
		if errors.Is(err, ErrStateNotFound) {
			return nil, nil, nil, fmt.Errorf("%w: %s holds no device identity", ErrNoDeviceIdentity, self.dir)
		}
		return nil, nil, nil, err
	}
	if len(parts) != 3 {
		return nil, nil, nil, fmt.Errorf("%w: a device identity carries %d parts, want 3", ErrStateStoreFormat, len(parts))
	}
	return parts[0], parts[1], parts[2], nil
}

func (self *DurableStateStore) PutGroupRecord(record *GroupRecord) error {
	self.lock.Lock()
	defer self.lock.Unlock()
	if err := self.refuseIfClosed(); err != nil {
		return err
	}
	if record == nil {
		return fmt.Errorf("%w: no group record", ErrStateStoreFormat)
	}
	if len(record.GroupId) != GroupIdBytes {
		return fmt.Errorf("%w: a group id is %d octets and this one is %d",
			ErrStateStoreFormat, GroupIdBytes, len(record.GroupId))
	}
	if len(record.PqSecret) == 0 || len(record.GroupHandleKey) == 0 {
		return fmt.Errorf("%w: a group record with no pq_secret or no group_handle_key is a group no session can be rebuilt for",
			ErrStateStoreFormat)
	}
	var epochOctets [8]byte
	binary.BigEndian.PutUint64(epochOctets[:], record.Epoch)
	flags := []byte{0}
	if record.Opened {
		flags[0] = 1
	}
	return self.writeRecord(self.groupRecordPath(record.GroupId), stateKindGroupRecord,
		record.GroupId, record.PqSecret, record.GroupHandleKey, epochOctets[:], flags)
}

// GroupRecords walks the group directory and answers every record it holds.
//
// A DIRECTORY WITH NO meta IN IT IS SKIPPED AND NOT A REFUSAL, because that is a real state and
// not a corruption: mls writes an epoch state at NewGroup, before this package has a pq_secret to
// write beside it, so a crash between the two leaves exactly that. What it is NOT is a restorable
// group -- and a group with no record is one this device has to be re-invited to, which is what a
// missing pq_secret means whatever the MLS state says.
func (self *DurableStateStore) GroupRecords() ([]*GroupRecord, error) {
	self.lock.Lock()
	defer self.lock.Unlock()
	if err := self.refuseIfClosed(); err != nil {
		return nil, err
	}
	root := filepath.Join(self.dataDir, "group")
	entries, err := os.ReadDir(root)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("%w: %s could not be read: %v", ErrStateStoreState, root, err)
	}
	names := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	records := []*GroupRecord{}
	for _, name := range names {
		parts, err := self.readRecord(filepath.Join(root, name, "meta"), stateKindGroupRecord)
		if err != nil {
			if errors.Is(err, ErrStateNotFound) {
				continue
			}
			return nil, err
		}
		if len(parts) != 5 || len(parts[3]) != 8 || len(parts[4]) != 1 {
			return nil, fmt.Errorf("%w: the group record in %s is not one this build wrote", ErrStateStoreFormat, name)
		}
		records = append(records, &GroupRecord{
			GroupId:        parts[0],
			PqSecret:       parts[1],
			GroupHandleKey: parts[2],
			Epoch:          binary.BigEndian.Uint64(parts[3]),
			Opened:         parts[4][0] == 1,
		})
	}
	return records, nil
}

// DeleteGroupRecord removes one group's record AND every MLS epoch state beside it.
//
// BOTH HALVES, for DeleteGroupStateBefore's reason: a record with no epoch state is a restore that
// fails at LoadGroup, and an epoch state with no record is this device's leaf private key and its
// whole path-secret ladder left on the disk for a group it has left. The epoch discard runs FIRST
// and its failure is the call's, so there is no path on which the record is gone and the keys are
// not.
func (self *DurableStateStore) DeleteGroupRecord(groupId []byte) error {
	self.lock.Lock()
	defer self.lock.Unlock()
	if err := self.refuseIfClosed(); err != nil {
		return err
	}
	if err := self.deleteEpochsLocked(groupId, ^uint64(0)); err != nil {
		return err
	}
	// the copies of what this device said, SECOND and before the record for the same reason the
	// epochs go first: a failure leaves a group that can still be restored and left again, never a
	// directory of plaintext lines belonging to a group this device no longer knows it was in.
	if err := self.deleteSentLocked(groupId); err != nil {
		return err
	}
	if err := self.removeLocked(self.groupRecordPath(groupId)); err != nil {
		return err
	}
	// the now-empty epoch, sent and group directories, best effort: an empty directory is not a
	// value anybody can read, so a failure to remove one is not a failure of this call.
	os.Remove(self.epochDir(groupId))
	os.Remove(self.sentDir(groupId))
	os.Remove(self.groupDir(groupId))
	return nil
}

// PutSentRecord writes one [SentRecord], durably, before it returns.
//
// IT IS WRITE-ONCE BY INDEX AND A SECOND WRITE AT ONE INDEX IS REFUSED, because a reserver never
// hands one index out twice and this device seals once per index. A second copy at an index already
// held is therefore either a reserver that rewound -- the stream directory lost and the state
// directory kept, which [Group.Receive] refuses as [ErrIdentityInUse] -- or a caller bug, and in
// neither case may the copy of what the user said at that index be silently replaced with a
// different line.
func (self *DurableStateStore) PutSentRecord(groupId []byte, record *SentRecord) error {
	self.lock.Lock()
	defer self.lock.Unlock()
	if err := self.refuseIfClosed(); err != nil {
		return err
	}
	if record == nil {
		return fmt.Errorf("%w: no sent record", ErrStateStoreFormat)
	}
	if len(groupId) != GroupIdBytes {
		return fmt.Errorf("%w: a group id is %d octets and this one is %d", ErrStateStoreFormat, GroupIdBytes, len(groupId))
	}
	path := filepath.Join(self.sentDir(groupId), stateEpochName(record.StreamIndex))
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("%w: group %x already holds a copy of this device's record at stream index %d, and a reserver never hands an index out twice",
			ErrStateStoreState, groupId, record.StreamIndex)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("%w: %s could not be examined: %v", ErrStateStoreState, path, err)
	}
	var indexOctets [8]byte
	binary.BigEndian.PutUint64(indexOctets[:], record.StreamIndex)
	var sentAtOctets [8]byte
	binary.BigEndian.PutUint64(sentAtOctets[:], uint64(record.SentAtMs))
	return self.writeRecord(path, stateKindSentRecord,
		groupId, indexOctets[:], record.BodyHash[:], sentAtOctets[:], record.Body)
}

// SentRecords answers every [SentRecord] one group holds, ascending by stream index.
//
// AN ENTRY IN THE DIRECTORY THAT IS NOT A COPY IS A REFUSAL, which is this store's discipline
// everywhere: the one exception is an unfinished write a killed process left, which the sweep at
// open already tried to remove and which is not a record. A copy whose own group id or index is not
// the one its name says is refused rather than shown, because a copy moved under another index would
// be shown as the user's line at a position where they said something else.
func (self *DurableStateStore) SentRecords(groupId []byte) ([]*SentRecord, error) {
	self.lock.Lock()
	defer self.lock.Unlock()
	if err := self.refuseIfClosed(); err != nil {
		return nil, err
	}
	dir := self.sentDir(groupId)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []*SentRecord{}, nil
		}
		return nil, fmt.Errorf("%w: %s could not be read: %v", ErrStateStoreState, dir, err)
	}
	records := []*SentRecord{}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), stateTempPrefix) {
			continue
		}
		index, named := stateEpochOfName(entry.Name())
		if !named || entry.IsDir() {
			return nil, fmt.Errorf("%w: %s stands in group %x's sent directory and it is not a copy this store wrote",
				ErrStateStoreFormat, entry.Name(), groupId)
		}
		parts, err := self.readRecord(filepath.Join(dir, entry.Name()), stateKindSentRecord)
		if err != nil {
			return nil, err
		}
		if len(parts) != 5 || len(parts[1]) != 8 || len(parts[2]) != 32 || len(parts[3]) != 8 {
			return nil, fmt.Errorf("%w: the sent record %s is not one this build wrote", ErrStateStoreFormat, entry.Name())
		}
		if !bytes.Equal(parts[0], groupId) || binary.BigEndian.Uint64(parts[1]) != index {
			return nil, fmt.Errorf("%w: the sent record under %s names group %x index %d",
				ErrStateStoreFormat, entry.Name(), parts[0], binary.BigEndian.Uint64(parts[1]))
		}
		one := &SentRecord{
			StreamIndex: index,
			SentAtMs:    int64(binary.BigEndian.Uint64(parts[3])),
			Body:        parts[4],
		}
		copy(one.BodyHash[:], parts[2])
		records = append(records, one)
	}
	sort.Slice(records, func(a, b int) bool { return records[a].StreamIndex < records[b].StreamIndex })
	return records, nil
}

// deleteSentLocked removes every copy one group holds, and then reads the directory again to say
// so -- deleteEpochsLocked's discipline, and for §5.12's reason carried one step over: a copy that
// survived a discard reported as done is the user's own words left behind for a group they left.
func (self *DurableStateStore) deleteSentLocked(groupId []byte) error {
	dir := self.sentDir(groupId)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("%w: %s could not be read: %v", ErrStateStoreState, dir, err)
	}
	if len(entries) == 0 {
		return nil
	}
	for _, entry := range entries {
		_, named := stateEpochOfName(entry.Name())
		if !named && !strings.HasPrefix(entry.Name(), stateTempPrefix) {
			// not ours, and not removed: this store does not delete octets it did not write. The
			// re-read below refuses over it.
			continue
		}
		if !self.skipRemove {
			if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("%w: the sent copy %s of group %x could not be discarded: %v",
					ErrStateStoreState, entry.Name(), groupId, err)
			}
		}
	}
	if err := syncStateDir(dir); err != nil {
		return err
	}
	entries, err = os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("%w: %s could not be re-read after the discard: %v", ErrStateStoreState, dir, err)
	}
	if len(entries) != 0 {
		return fmt.Errorf("%w: %s still stands in group %x's sent directory after every copy was discarded",
			ErrStateStoreState, entries[0].Name(), groupId)
	}
	return nil
}
