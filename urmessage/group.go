package urmessage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/messagegroup"
	"github.com/urnetwork/connect/mls"
	"github.com/urnetwork/connect/protocol"
)

// GroupIdBytes is the width of the identifier the server keys its rows by, and the width a record
// header carries. It is the same 32 octets on both sides and a group id of any other width names
// nothing.
const GroupIdBytes = 32

// The alg id an EpochAttachment announces: 0x0031, HKDF-SHA-256, which is what derived write_key
// and read_key out of storage_root.
//
// connect/message holds the same number in an UNEXPORTED table (attachmentAlgIds), and refuses an
// attachment that announces any other, so this is a second site by construction of the visibility
// rules exactly as storageExporterLabel is. The change connect owes is to export it.
const epochAttachmentAlgId uint16 = 0x0031

// What an alpha wrap record carries, in the clear inside its own AEAD, so that a reader who finds
// one knows what it is and what it is not.
//
// 6.1 publishes an epoch by fanning a wrap out to every member and then closing the fan-out with a
// marker, and the server will not accept an ordinary record until the marker lands. In the full
// design a wrap is how a member is handed the epoch's secret. IN THE ALPHA IT IS NOT: the epoch's
// key schedule is derived from the MLS exporter on both sides, and the material a joiner needs
// travels in the MLS Welcome. So these records carry NO KEY MATERIAL, they are the ceremony the
// server's step (2) requires, and a device that cannot process a Welcome cannot join this build
// however many wraps it reads.
const alphaWrapBody = "urmessage/v1 alpha epoch wrap: no key material, the epoch secret travels in the mls welcome"

// The body of the marker that closes 6.1's fan-out.
const alphaEpochCompleteBody = "urmessage/v1 alpha epoch complete"

// How many 4.3.4 pages one [Group.Receive] will walk before it stops and SAYS it stopped.
//
// It is a bound and not a limit on history: at the advertised default of 512 records per fetch
// this is more records than the alpha can produce, and reaching it means either a group with an
// enormous backlog or a server that is paging a client in circles. Either way the answer is the
// same and it is the whole reason the constant exists: [Group.Receive] returns what it read AND
// [ErrFetchIncomplete], so "that is all there is" and "I stopped early" are two readings.
//
// A LOOP WITH NO BOUND WOULD BE THE WORSE FAILURE. A server that answered complete=false forever
// would hang the call rather than answer it, and a UI holding that call would look like a network
// problem instead of like a server problem.
const maxFetchPages = 1024

// Message is one line of text that crossed the group.
type Message struct {
	// The server's own id for the record: per group, gapless, and the cursor a later fetch
	// resumes from. Zero on a message this device has sent and the server has not yet numbered.
	RecordId uint64

	// 3.1's sender_handle, 16 octets. It is the routing identity of the member that sealed the
	// record and is not a name: the alpha has no identity system.
	SenderHandle []byte

	// True when this device sealed it.
	Mine bool

	// The text.
	Text string

	// The sender's own clock reading, unix milliseconds, out of the head the AEAD authenticated.
	SentAtMs int64

	// MASTER section 8.4.5's message_id for this record: 32 octets, derived by
	// [messagegroup.GroupSession.MessageIdOf] from this group's epoch-zero group_handle_key and
	// three fields of the record's own plaintext header.
	//
	// IT IS THE NAME EVERY LATER KIND QUOTES. A reply, a reaction, a tombstone and a read cursor
	// all have to say WHICH message they are about, and [Message.RecordId] cannot be that name:
	// it is the SERVER's per-group counter, so a sender does not know it until the submit is
	// answered, and a device whose submit response was lost holds a message whose RecordId is
	// zero. message_id is a function of the record alone and both sides compute it from the
	// header they already hold.
	//
	// IT IS A NAME AND NOT AN AUTHENTICATION, carried through verbatim from the derivation's own
	// document rather than softened here: group_handle_key is group-shared, so any member can
	// compute any member's id at any index, including indices nobody has written yet. What makes
	// a message's id trustworthy is that the record it names OPENED, and opening is what MASTER
	// section 8.4.3's R1 and R2 decide.
	//
	// Every [Message] this package produces carries one, because every one of them is built
	// beside the header it is derived from.
	MessageId []byte
}

// MaxTextOctets is the longest text [Group.Send] will seal, and it is a MEASURED number rather
// than a rung of the size ladder.
//
// WHERE IT COMES FROM. Since connect 4c030dc an application record's ct_body plaintext is an MLS
// PrivateMessage and the frame sits INSIDE the size rung, so the usable text per rung is the
// rung's own capacity less the frame's overhead. connect measures the whole column in
// messagegroup.TestTheSizeLadderCostOfTheInnerFrameIsMeasuredHere -- run on connect d368fea, it
// logs 59 / 826 / 3,898 / 16,186 / 65,334 usable, at 193 / 194 / 194 / 194 / 198 octets lost --
// and cp3b.TestEveryRecordTypeUrmessageSealsLandsOnTheRungItsBodyNeeds re-measures the same column
// through THIS package and a real server's own rows. This constant is the top of that column, and
// cp3b.TestTheTextCeilingRefusesBeforeItSpendsAnythingIrreversible is what holds it against a
// measurement rather than against this comment.
//
// THE OVERHEAD AS A FUNCTION OF LENGTH IS NOT RESTATED HERE, deliberately: connect's own
// mlsframe.go prose gives it as three steps -- 193 below 64, 194 below 16,384, 198 at or above --
// and that sentence is FALSE at P = 16,383, which connect's own applicationFrameOverhead table
// pins at 196 in the same file, in a case that passes. msgrepo ledger item 218 and MASTER §8.4.4's
// 2026-09-17 correction carry the four-band form. What this constant needs is the TOP of the
// capacity column and nothing else, so it takes the measured column and leaves the step function
// where it is measured.
//
// WHY THE REFUSAL IS HERE AND NOT LEFT TO THE SEALER, which is the whole reason the constant
// exists. messagegroup takes a CHEAP half of the ladder refusal before it reserves anything --
// bucketForBody over the CALLER's own length -- and that half passes for every body up to 65,532,
// because 65,532 is what the 64 KiB rung holds. The real bucket is chosen AFTER the frame exists,
// which is after the stream index has been reserved and after Protect has consumed an MLS
// generation. So a text of 65,335..65,532 octets -- connect's ledger open item 203, whose own
// TestABodyNoRungCouldHoldCostsNeitherAnIndexNorAGeneration measures the band by name -- used to
// pass through here, spend one DURABLE stream index and one MLS generation, and only then be
// answered [ErrTextTooLong]. Both are legal gaps and neither is recoverable, and a caller that
// retried a failed send spent another of each on every attempt.
//
// THE BAND IS 198 OCTETS WIDE AND IT IS NOT THE ONLY THING THIS REFUSES. Above 65,532 the sealer
// already refused for free. This makes the two answers one answer, taken in one place, before
// anything irreversible has happened -- so a send refused for length costs nothing however many
// times it is retried.
const MaxTextOctets = 65334

// Stats is what a group has seen, so that "nothing arrived" and "something arrived and this build
// would not open it" are two readings rather than one silence.
type Stats struct {
	// Records the server answered a fetch with.
	Fetched uint64

	// Records OPENED into a [Message]: decrypted, and their inner MLS frame authenticated to the
	// member whose sender_handle they carry. This device's own records are never among them; see
	// [Stats.OpenedOwn].
	Opened uint64

	// Records skipped because they are 6.1's ceremony rather than a message: the founding commit,
	// the epoch's wraps, the marker that closes them.
	SkippedCeremony uint64

	// Records skipped because this device sealed them AND ALREADY HOLDS THEM: their record id
	// is in this group's log, so they are the ordinary echo of a send this process made.
	//
	// IT USED TO COUNT EVERY OWN RECORD AND THAT IS THE DEFECT IT WAS PART OF. A restored
	// group's log starts empty, so "this device sealed it" and "this device still has it" came
	// apart at exactly the moment a user reopened the app -- and a counter that moves on both
	// readings cannot tell a UI which one happened. The two are now two numbers.
	SkippedOwn uint64

	// Records this device sealed that became a [Message] because this group does NOT already hold
	// them: the whole of a restarted device's own half of the conversation, and a record whose
	// submit response was lost after the server had stored it.
	//
	// THEY ARE RENDERED FROM THE COPY THIS DEVICE KEPT AND ARE NEVER DECRYPTED, and the name is
	// older than that. Since connect 4c030dc an application record's body is an MLS
	// PrivateMessage, and a member cannot open its own: Protect spends a generation of the leaf's
	// own ratchet and MLS keeps no receiving ratchet for it (connect messagegroup OPENITEMS MG-4).
	// So what moves this is a record whose stream index and body_hash are the ones [Group.Send]
	// sealed and kept -- see [Group.openOwnFromCopyLocked] -- and [Stats.Opened] does NOT move
	// with it, because nothing was opened.
	OpenedOwn uint64

	// Records under this device's own sender_handle that this group's keys AUTHENTICATED and that
	// it CANNOT SHOW, because it keeps no copy of what it sealed at that index.
	//
	// A NUMBER HERE IS A HOLE IN THIS DEVICE'S OWN HALF OF THE CONVERSATION. The ordinary ways
	// to reach it: a state directory written before this build kept copies, and a copy of the
	// app-data folder meeting a record the original sealed after the copy was taken (which
	// [Group.Receive] also refuses as [ErrIdentityInUse]). The record is not a failure -- it is
	// this device's own, and it moves [Stats.FailedOpen] never -- and it is resolved past, so it
	// costs one MLS peek per Receive that re-reads it and nothing else.
	OwnWithoutCopy uint64

	// Records skipped because this group's log already holds them under that record id. It
	// moves when a fetch is REWOUND -- which is what a record that failed to open now causes,
	// see [Group.Receive] -- and it is what keeps that rewind from delivering a message twice.
	SkippedSeen uint64

	// Records that did not open after [maxRecordAttempts] fetches and are no longer asked for.
	// [Group.UnopenedRecords] is which ones. A number here is a hole in the conversation that
	// this build has stopped trying to fill, and it is the number that must stay zero.
	Unopened uint64

	// Fetch pages the server called COMPLETE while naming a `high_water_record_id` above every
	// record it handed over -- §4.3.4's own statement that it is holding records back. See
	// [Group.Receive] for the one honest server that also moves this.
	Omitted uint64

	// Records skipped because they are not a class this build opens.
	SkippedClass uint64

	// ATTEMPTS to open a record from a member of this group that did not open -- one per
	// fetch, so a record retried [maxRecordAttempts] times moves this three times. It counts
	// attempts and not records because that is what it can honestly count: the retry is what
	// repairs a transient, and a counter that deduplicated would hide how hard this group is
	// working. [Stats.Unopened] is the one that counts RECORDS, and it counts the ones given
	// up on.
	//
	// This is the number that must stay zero, and [Group.Receive] returns an error naming the
	// first one whenever it does not.
	FailedOpen uint64

	// Records submitted, and records the server refused on the first attempt and accepted after
	// S2-2's single re-Hello and re-MAC. The second is the cost of Finding E and is readable
	// rather than invisible.
	Submitted uint64
	Rebound   uint64

	// Fetch PAGES the server answered, across every [Group.Receive]. It is here because one
	// Receive is not one page: 4.3.4 truncates a page by `limit` or by `max_response_bytes`
	// and calls both NORMAL, so a conversation longer than the server's page is several
	// requests. A number bigger than the Receive count is the ordinary reading of a backlog.
	Pages uint64

	// Fetch pages this build could NOT verify the 4.3.4 attestation of, which today is every
	// page the deployed server answers. It is a counter rather than a silence because the
	// thing it measures -- a server that OMITS records -- is the one thing the AEAD does not
	// catch. See [Group.Receive] for what is and is not checked, and what closing it needs.
	Unattested uint64
}

// trackedKey is one receiver ladder this group has installed. A second TrackSender over a live
// ladder would reset it to its head index and re-derive rungs it has already committed, so each
// one is installed exactly once.
type trackedKey struct {
	leaf          uint32
	retentionWire byte
	ephWindow     uint64
}

// ownSealed is what this group knows about one stream index of its own.
type ownSealed struct {
	// The body_hash of the record sealed at this index.
	bodyHash [32]byte

	// hasCopy is whether this device SEALED it and kept what it sealed. False for an index a
	// reconciling walk learned off a record the group's keys authenticated and this device holds
	// no copy of -- which is this lineage's own history, sealed before this build kept copies or
	// by a copy of the folder.
	hasCopy  bool
	body     []byte
	sentAtMs int64

	// recordId is the record id this copy has been shown under, zero until it has been. A second
	// record id carrying the same index and the same body_hash is one record shown twice, and a
	// server is the only party that numbers records.
	recordId uint64
}

// Group is one group on one device.
type Group struct {
	device         *Device
	id             []byte
	handle         messagegroup.GroupHandle
	groupHandleKey []byte
	pqSecret       []byte

	mutex sync.Mutex

	// The session at epoch zero, which exists on the FOUNDER only and only until the group is
	// open. It is what seals the founding commit: 4.3.2 self-certifies that record under
	// bootstrap_write_key, which is epoch zero's write key, and the session that holds epoch
	// zero's key schedule is the one constructed before the commit moved the handle.
	founding      *messagegroup.GroupSession
	foundingBound uint64

	// The session at the group's current epoch, and the one every message goes through.
	session      *messagegroup.GroupSession
	sessionBound uint64
	epoch        uint64

	// The MLS commit that opened the current epoch. It is the founding commit record's body, so
	// the record the server stores as is_commit actually carries a commit.
	commit []byte

	opened bool
	closed bool

	// cursor is the RESOLVED position: the highest record id below which every record has been
	// opened, skipped for a reason this build names, or given up on. It is deliberately NOT the
	// highest record id the server has handed over -- see [Group.Receive] and openPageLocked,
	// where a record that did not open holds this back so that the next fetch asks for it again.
	cursor  uint64
	log     []*Message
	tracked map[trackedKey]bool
	stats   Stats

	// delivered is the record ids that are in log. A fetch that is rewound over a record that
	// did not open re-reads everything after it, and this is what makes that free of duplicates.
	delivered map[uint64]bool

	// attempts is how many times one record id has been fetched and failed to open.
	attempts map[uint64]int

	// unopened is the record ids this group has given up on, ascending.
	unopened []uint64

	// ── one identity, two devices ────────────────────────────────────────────────────────
	//
	// ownIndices is every §5.6 stream index this group has accounted for as its own, AND THE
	// body_hash OF WHAT WAS SEALED AT IT -- and, for an index THIS DEVICE sealed, the copy of what
	// it sealed there.
	//
	// THE HASH IS WHY THIS IS NOT A SET, and it is what catches the hardest case. An index is
	// recorded at the SEAL and not at the submit, because a submit whose response was lost is
	// still a record this device sealed. So when two copies of one folder are EXACTLY level,
	// both seal at the same index, one submission wins and one is refused -- and the loser then
	// meets, on the server, a record under its own sender_handle at an index it DID seal, whose
	// body is not the body it sealed. An index alone cannot tell those apart. The hash can, and
	// 3.1's body_hash is authenticated by both AEADs, so a server cannot forge one that opens.
	//
	// THE COPY IS WHY IT CARRIES MORE THAN A HASH, and it is connect MG-4 read from this side. A
	// member cannot open its own application record any more, so this device's own half of a
	// conversation exists in exactly one place it can read: here, and in the durable store's copy
	// of it ([DeviceStore.PutSentRecord]), which [Device.Restore] reads back into this map.
	ownIndices map[uint64]*ownSealed

	// withoutCopy is every record id this group has authenticated as its own and cannot show. See
	// [Stats.OwnWithoutCopy].
	//
	// IT EXISTS BECAUSE A REWIND RE-READS THESE: without it a record re-fetched behind an earlier
	// failure is authenticated and counted again (cp3b.TestAnOwnRecordThisDeviceKeptNoCopyOf...).
	// IT KEEPS NO INDEX, and it used to: the skip re-noted the index it was authenticated at, and
	// deleting that re-note turned nothing red in urmessage or cp3b, because the index is already in
	// [Group.ownIndexSeen], which is the group's and not the walk's.
	withoutCopy map[uint64]bool

	// ownIndexSeen is the highest §5.6 stream index on a record of this device's own that this
	// group's keys AUTHENTICATED, across every walk since the group came up.
	//
	// IT IS THE GROUP'S AND NOT ONE WALK'S, and it used to be one walk's. The reconciliation holds
	// it against the reserver's high water on the first clean walk -- and a clean walk that comes
	// after a dirty one does not re-open the records the dirty one already resolved: a delivered
	// record is skipped by record id and contributes nothing. So a copy whose evidence arrived in
	// a walk that ALSO lost some other record reconciled on the next, clean walk with the evidence
	// forgotten, and sealed at an index the original had already used.
	// cp3b.TestACopyWhoseEvidenceArrivedInADirtyWalkIsStillCaught drives that.
	ownIndexSeen uint64

	// ownHeads is the head the receiver ladder over this device's OWN leaf was last tracked at, per
	// ladder. See [Group.advanceOwnLadderLocked].
	ownHeads map[trackedKey]uint64

	// reconciled is whether this group has compared its own stream position against the
	// server's rows since it came back. A group created or joined in THIS process is
	// reconciled by construction -- its identity was drawn here and nothing else holds it. A
	// RESTORED group is not, and [Group.Send] refuses until [Group.Receive] has run once.
	reconciled bool

	// identityInUse is sticky and is the whole of the clone refusal. Once set, every Send is
	// refused with it. See [Group.Receive].
	identityInUse error
}

// ── founding and joining ─────────────────────────────────────────────────────────────────────

// CreateGroup founds a group on this device. NOTHING REACHES THE SERVER HERE.
//
// The group is local and at MLS epoch zero, which is not an epoch any record can be written in:
// 6.1 opens a group at the epoch its first commit creates. [Group.AddMember] makes that commit and
// [Group.Open] publishes it. A caller that skips either is refused by name rather than by a
// REASON_REJECTED it has to decode.
//
// groupId is 32 octets and is the caller's to choose. It must be unpredictable -- the server keys
// its rows by it and anyone who can guess one can ask whether it exists -- so draw it from a
// CSPRNG.
func (self *Device) CreateGroup(ctx context.Context, groupId []byte) (*Group, error) {
	if len(groupId) != GroupIdBytes {
		return nil, fmt.Errorf("urmessage: a group id is %d octets and this one is %d", GroupIdBytes, len(groupId))
	}
	nonce, nonceEpoch, err := self.nonce()
	if err != nil {
		return nil, err
	}

	handle, err := self.createMlsGroup(groupId)
	if err != nil {
		return nil, err
	}
	if epoch := handle.Epoch(); epoch != 0 {
		handle.Close()
		return nil, fmt.Errorf("urmessage: a freshly created mls group is at epoch %d, want 0", epoch)
	}

	pqSecret, err := messagegroup.NewPqSecret(self.random)
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("urmessage: pq_secret: %w", err)
	}
	// AT EPOCH ZERO AND NOWHERE ELSE. group_handle_key is the epoch zero storage root's expansion
	// and it never moves; a value recomputed from a later root gives every epoch a different
	// sender_handle and ends every member's stream at every commit.
	mlsSecret, err := handle.Export(storageExporterLabel, nil, storageExporterBytes)
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("urmessage: the epoch zero exporter: %w", err)
	}
	groupHandleKey := messagegroup.GroupHandleKey(messagegroup.StorageRoot(mlsSecret, pqSecret))

	founding, err := messagegroup.NewGroupSession(handle, pqSecret, nil, self.reserver, self.nowMs, nonce)
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("urmessage: the session at epoch 0: %w", err)
	}
	group := &Group{
		device:         self,
		id:             append([]byte(nil), groupId...),
		handle:         handle,
		groupHandleKey: groupHandleKey,
		pqSecret:       pqSecret,
		founding:       founding,
		foundingBound:  nonceEpoch,
		// a group founded in THIS process holds an identity drawn in this process. There is
		// no earlier writer of its stream to reconcile against.
		reconciled: true,
	}
	group.initTables()
	self.hold(group)
	// NOTHING IS PERSISTED HERE AND THAT IS DELIBERATE. A group at epoch zero with no second
	// member cannot be restored into anything a caller can use -- [Group.AddMember] needs the
	// founding session, which is not persisted, and [Group.Open] needs the commit AddMember
	// makes -- so a record written here would describe a group that comes back dead. mls has
	// already written its own epoch-zero state by now; [DurableStateStore.GroupRecords] skips a
	// group directory with no record in it for exactly this state, and says so.
	return group, nil
}

// Join takes an [Invite] a founder handed over out of band and becomes a member.
//
// WHAT THIS DOES NOT CHECK, and it is MG-1 rather than an omission of this file: nothing here
// decides whether the device that built this Welcome is the device the user meant to talk to. The
// Welcome names a group and a membership, JoinFromWelcome joins it, and the identity a caller would
// read off the membership afterwards is whatever the Welcome's author put there. Deciding that is
// the contact card's job and contact cards are out of scope.
func (self *Device) Join(ctx context.Context, invite *Invite) (*Group, error) {
	if invite == nil {
		return nil, fmt.Errorf("urmessage: no invite")
	}
	if err := invite.check(); err != nil {
		return nil, err
	}
	nonce, nonceEpoch, err := self.nonce()
	if err != nil {
		return nil, err
	}
	handle, err := self.engine.JoinFromWelcome(invite.Welcome, invite.RatchetTree)
	if err != nil {
		return nil, fmt.Errorf("urmessage: JoinFromWelcome: %w", err)
	}
	if !bytes.Equal(handle.GroupId(), invite.GroupId) {
		handle.Close()
		return nil, fmt.Errorf("urmessage: the welcome joined group %x and the invite names %x",
			handle.GroupId(), invite.GroupId)
	}
	session, err := messagegroup.NewGroupSession(handle, invite.PqSecret, invite.GroupHandleKey,
		self.reserver, self.nowMs, nonce)
	if err != nil {
		handle.Close()
		return nil, fmt.Errorf("urmessage: the session at epoch %d: %w", handle.Epoch(), err)
	}
	group := &Group{
		device:         self,
		id:             append([]byte(nil), invite.GroupId...),
		handle:         handle,
		groupHandleKey: append([]byte(nil), invite.GroupHandleKey...),
		pqSecret:       append([]byte(nil), invite.PqSecret...),
		session:        session,
		sessionBound:   nonceEpoch,
		epoch:          handle.Epoch(),
		// The founder opened it. A joiner cannot observe that and does not pretend to: if it
		// has not, every send below is refused by the server and the refusal is returned.
		opened: true,
		// as for a founded group: this device's stream in this group starts here.
		reconciled: true,
	}
	group.initTables()
	if err := self.persistGroup(&GroupRecord{
		GroupId:        group.id,
		PqSecret:       group.pqSecret,
		GroupHandleKey: group.groupHandleKey,
		Epoch:          group.epoch,
		Opened:         true,
	}); err != nil {
		// the session first and the handle after it, which is [Group.Close]'s own order: the
		// session owns the loop that the handle is reached through.
		session.Close()
		handle.Close()
		return nil, fmt.Errorf(
			"urmessage: this group joined and its record could not be persisted, so a restart would not come back into it: %w", err)
	}
	self.hold(group)
	return group, nil
}

// AddMember adds one device to this group and answers the [Invite] it joins with.
//
// IT IS THE COMMIT THAT OPENS EPOCH ONE, which is why the alpha takes exactly one of them and
// takes it before [Group.Open]. A second add is a second epoch: every member's session has to
// advance, the server has to be handed the new epoch's keys in a new commit, and the wrap fan-out
// has to run again. None of that is built, so a second call is refused by name rather than half
// performed.
func (self *Group) AddMember(keyPackage []byte) (*Invite, error) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if self.closed {
		return nil, fmt.Errorf("urmessage: this group is closed")
	}
	if self.opened {
		return nil, ErrGroupOpen
	}
	if self.founding == nil {
		return nil, ErrAlphaOneAdd
	}
	if self.session != nil {
		return nil, ErrAlphaOneAdd
	}
	nonce, nonceEpoch, err := self.device.nonce()
	if err != nil {
		return nil, err
	}

	if _, err := self.handle.ProposeAdd(keyPackage); err != nil {
		return nil, fmt.Errorf("urmessage: ProposeAdd: %w", err)
	}
	commit, welcome, ratchetTree, err := self.handle.Commit(nil)
	if err != nil {
		self.handle.ClearPendingCommit()
		return nil, fmt.Errorf("urmessage: Commit: %w", err)
	}
	if err := self.handle.MergePendingCommit(); err != nil {
		return nil, fmt.Errorf("urmessage: MergePendingCommit: %w", err)
	}
	// THE HANDLE IS AT EPOCH ONE FROM HERE AND self.founding IS STILL AT EPOCH ZERO, which is the
	// one subtlety in this file and is load-bearing rather than incidental. A GroupSession
	// installs its epoch's whole key schedule at construction and reads NOTHING off the handle on
	// the seal path afterwards -- newRecordBuilderOnLoop takes the group id, the sender handle,
	// the epoch and the class keys out of its own fields -- so the founding session goes on
	// sealing epoch zero records after the handle has moved, which is exactly what 4.3.2's
	// self-certified founding commit needs. Delete that property in connect and this file starts
	// sealing the founding commit under epoch one's key, which the server refuses because it
	// verifies it under the bootstrap key the same request carries.
	session, err := messagegroup.NewGroupSession(self.handle, self.pqSecret, self.groupHandleKey,
		self.device.reserver, self.device.nowMs, nonce)
	if err != nil {
		return nil, fmt.Errorf("urmessage: the session at epoch %d: %w", self.handle.Epoch(), err)
	}
	self.session = session
	self.sessionBound = nonceEpoch
	self.epoch = self.handle.Epoch()
	self.commit = append([]byte(nil), commit...)
	// NOTHING IS PERSISTED HERE EITHER, for CreateGroup's reason carried one step further, and
	// it is written down because a record here LOOKS obviously right and is not.
	//
	// The handle is now at the epoch the commit opened and mls has persisted that epoch's state
	// inside MergePendingCommit above, so a restore could rebuild an MLS member. What it could
	// not rebuild is a group anybody can USE: [Group.Open] needs the epoch-zero founding session
	// to self-certify the founding commit, that session is not persisted, and a restored group
	// therefore answers ErrNoMemberAdded to Open and ErrGroupNotOpen to Send, for ever. A record
	// written here would make "a founder that died before Open" come back as a conversation the
	// user can see and cannot ever send in.
	//
	// MEASURED rather than reasoned: a record written here was deleted and the whole suite
	// stayed green, because [Group.Open] writes the founder's record and [Device.Join] writes
	// the joiner's, and those are the two moments a group becomes usable.
	return &Invite{
		GroupId:        append([]byte(nil), self.id...),
		Welcome:        append([]byte(nil), welcome...),
		RatchetTree:    append([]byte(nil), ratchetTree...),
		PqSecret:       append([]byte(nil), self.pqSecret...),
		GroupHandleKey: append([]byte(nil), self.groupHandleKey...),
	}, nil
}

// Open publishes this group on the message server: 6.1's founding commit, the epoch's wrap set,
// and the marker that closes the fan-out.
//
// ALL THREE, BECAUSE THE SERVER WILL NOT TAKE A MESSAGE UNTIL ALL THREE HAVE LANDED. CreateGroup
// leaves the group at epoch one with epoch_complete false, which step (2) makes
// readable-but-not-writable for everything except a wrap, a snapshot or the marker; an ordinary
// record before the marker is answered REASON_EPOCH_INCOMPLETE.
func (self *Group) Open(ctx context.Context) error {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if self.closed {
		return fmt.Errorf("urmessage: this group is closed")
	}
	if self.opened {
		return ErrGroupOpen
	}
	if self.session == nil || self.founding == nil {
		return ErrNoMemberAdded
	}
	if err := self.rebindLocked(); err != nil {
		return err
	}

	keys, err := self.session.EpochKeys()
	if err != nil {
		return fmt.Errorf("urmessage: this epoch's keys: %w", err)
	}
	defer keys.Destroy()
	writeKey, err := keys.WriteKey()
	if err != nil {
		return err
	}
	readKey, err := keys.ReadKey()
	if err != nil {
		return err
	}
	bootstrap, err := self.founding.EpochKeys()
	if err != nil {
		return fmt.Errorf("urmessage: epoch zero's keys: %w", err)
	}
	defer bootstrap.Destroy()
	bootstrapWriteKey, err := bootstrap.WriteKey()
	if err != nil {
		return err
	}

	groupContext, err := self.handle.GroupContextBytes()
	if err != nil {
		return fmt.Errorf("urmessage: the group context: %w", err)
	}
	contextHash := sha256.Sum256(groupContext)

	wrapTargets, err := self.wrapTargetsLocked()
	if err != nil {
		return err
	}
	if len(wrapTargets) == 0 {
		return ErrNoMemberAdded
	}

	// (1) the founding commit, sealed at epoch zero and carrying the epoch it opens.
	founding, err := self.founding.SealRecord(message.RetentionPermanent, 0, true,
		encodeHead(self.device.nowMs()), self.commit, 0, &message.ServerAttachment{
			Kind: message.AttachmentEpoch,
			Epoch: &message.EpochAttachment{
				Epoch:             self.epoch,
				AlgId:             epochAttachmentAlgId,
				WriteKey:          writeKey,
				ReadKey:           readKey,
				GroupContextHash:  contextHash[:],
				ExpectedWrapCount: uint32(len(wrapTargets)),
			},
		})
	if err != nil {
		return fmt.Errorf("urmessage: sealing the founding commit: %w", err)
	}
	created := append([]byte(nil), bootstrapWriteKey...)
	if _, err := self.sendSealedLocked(ctx, self.founding, founding, "the founding commit",
		func(record *protocol.Record) (protocol.Reason, uint64, error) {
			response, err := self.device.transport.Call(ctx, &protocol.CreateGroupRequest{
				GroupId:           self.id,
				InitialCommit:     record,
				BootstrapWriteKey: created,
			})
			if err != nil {
				return protocol.Reason_REASON_INTERNAL, 0, err
			}
			if response.GetReason() != protocol.Reason_REASON_OK {
				return response.GetReason(), 0, nil
			}
			body := response.GetCreateGroup()
			if body == nil {
				return protocol.Reason_REASON_INTERNAL, 0, fmt.Errorf("%w: the response carried no create_group arm", ErrCreateRefused)
			}
			if body.GetCurrentEpoch() != self.epoch {
				return protocol.Reason_REASON_INTERNAL, 0, fmt.Errorf(
					"%w: the group opened at epoch %d and this device is at %d",
					ErrCreateRefused, body.GetCurrentEpoch(), self.epoch)
			}
			return protocol.Reason_REASON_OK, body.GetRecordId(), nil
		}); err != nil {
		return err
	}

	// (2) the wrap set: one per member, carrying no key material. See [alphaWrapBody].
	for _, target := range wrapTargets {
		wrap, err := self.session.SealRecord(message.RetentionPermanent, 0, false,
			encodeHead(self.device.nowMs()), []byte(alphaWrapBody), 0, &message.ServerAttachment{
				Kind: message.AttachmentWrap,
				Wrap: &message.WrapTag{WrapTargetHandle: append([]byte(nil), target[:]...), Epoch: self.epoch},
			})
		if err != nil {
			return fmt.Errorf("urmessage: sealing an epoch wrap: %w", err)
		}
		if _, err := self.submitLocked(ctx, self.session, wrap, "an epoch wrap"); err != nil {
			return err
		}
	}

	// (3) the marker that closes the fan-out and makes the group writable.
	marker, err := self.session.SealRecord(message.RetentionDurable, 0, false,
		encodeHead(self.device.nowMs()), []byte(alphaEpochCompleteBody), 0, &message.ServerAttachment{
			Kind:     message.AttachmentComplete,
			Complete: &message.EpochComplete{Epoch: self.epoch, WrapCount: uint32(len(wrapTargets))},
		})
	if err != nil {
		return fmt.Errorf("urmessage: sealing the epoch complete marker: %w", err)
	}
	if _, err := self.submitLocked(ctx, self.session, marker, "the epoch complete marker"); err != nil {
		return err
	}

	self.opened = true
	// The opened bit, so that a restarted device knows the group is publishable rather than
	// finding out at its first send. The error says what actually happened: the group IS open
	// on the server, and it is the RECORD that did not land.
	if err := self.device.persistGroup(&GroupRecord{
		GroupId:        self.id,
		PqSecret:       self.pqSecret,
		GroupHandleKey: self.groupHandleKey,
		Epoch:          self.epoch,
		Opened:         true,
	}); err != nil {
		return fmt.Errorf("urmessage: this group is open on the server and its record could not be persisted, so a restart would refuse to send in it: %w", err)
	}
	return nil
}

// wrapTargetsLocked is one wrap_target_handle per member of the group at its current epoch.
func (self *Group) wrapTargetsLocked() ([][16]byte, error) {
	targets := [][16]byte{}
	for at := 0; at < self.handle.MemberCount(); at += 1 {
		leaf, _, _, err := self.handle.MemberAt(at)
		if err != nil {
			return nil, fmt.Errorf("urmessage: the group's member %d: %w", at, err)
		}
		targets = append(targets, messagegroup.WrapTargetHandle(self.groupHandleKey, self.epoch, leaf))
	}
	return targets, nil
}

// ── sending ──────────────────────────────────────────────────────────────────────────────────

// Send seals one line of text as a DURABLE record and submits it.
//
// The size bucket is whatever the text needs: [messagegroup.GroupSession.SealRecord] walks the
// ladder and takes the smallest rung the padded body fits, so a message leaks its rung rather than
// its length. THE RUNGS ARE NOT WHAT THEY WERE. Since connect 4c030dc the text is carried inside an
// MLS PrivateMessage that itself sits inside the rung, and the usable text per rung, measured through
// this method and a real server's rows by cp3b.TestEveryRecordTypeUrmessageSealsLandsOnTheRungItsBodyNeeds,
// is 59 / 826 / 3,898 / 16,186 / 65,334 octets where it was 252 / 1,020 / 4,092 / 16,380 / 65,532.
// So a text over 59 octets is stored at 1,040 octets where one up to 252 used to be stored at 272,
// and a text over [MaxTextOctets] -- including the 198 octets up to the old ceiling -- is refused
// with [ErrTextTooLong]; blob-backed bodies are out of scope.
//
// THE LENGTH REFUSAL IS TAKEN HERE AND COSTS NOTHING, which is a change from every build before
// this one: see [MaxTextOctets] for the 198 octet band that used to spend a durable stream index
// and an MLS generation on its way to the same error, and for why the sealer's own early refusal
// cannot cover it.
//
// IT NEVER RETURNS NIL ON A MESSAGE THAT DID NOT LAND. The record is accepted by the server, or
// this returns an error naming the refusal -- including after S2-2's single re-Hello and re-MAC.
func (self *Group) Send(ctx context.Context, text string) (*Message, error) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if self.closed {
		return nil, fmt.Errorf("urmessage: this group is closed")
	}
	if self.session == nil {
		return nil, ErrNoMemberAdded
	}
	if !self.opened {
		return nil, ErrGroupNotOpen
	}
	// BEFORE THE REBIND AND BEFORE THE SEAL, because the seal is the irreversible half: a
	// record sealed under a reused (key, nonce) exists whatever this method then returns.
	if self.identityInUse != nil {
		return nil, self.identityInUse
	}
	if !self.reconciled {
		return nil, fmt.Errorf("%w: group %x", ErrNotReconciled, self.id)
	}
	// AND BEFORE THE SEAL FOR THE SAME REASON, one clause further out than the sealer can take
	// it. See [MaxTextOctets]: the sealer's own early refusal is over the CALLER's length against
	// the rung, and the frame that decides the real rung does not exist until an index has been
	// reserved and a generation spent.
	//
	// IT IS AFTER THE TWO STICKY REFUSALS ABOVE AND THAT ORDER IS DELIBERATE. A group that has
	// seen a second writer, or a restored group that has not reconciled, must say THAT rather
	// than report a fact about the length of this particular line.
	if MaxTextOctets < len(text) {
		return nil, fmt.Errorf("%w: %d octets, and the largest inline rung carries %d",
			ErrTextTooLong, len(text), MaxTextOctets)
	}
	if err := self.rebindLocked(); err != nil {
		return nil, err
	}
	sentAtMs := self.device.nowMs()
	record, err := self.session.SealRecord(message.RetentionDurable, 0, false,
		encodeHead(sentAtMs), []byte(text), 0, nil)
	if err != nil {
		if errors.Is(err, messagegroup.ErrBodyTooLong) {
			return nil, fmt.Errorf("%w: %d octets: %w", ErrTextTooLong, len(text), err)
		}
		return nil, fmt.Errorf("urmessage: sealing this message: %w", err)
	}
	// THE ID IS TAKEN OFF THE RECORD AND BEFORE THE SUBMIT, which is what makes it a name the
	// sender can quote OPTIMISTICALLY: the three inputs are group_handle_key and three fields of
	// the header SealRecord just answered, so nothing about it waits on the server. A reply typed
	// before the submit is acknowledged can already name its parent.
	//
	// IT IS RAISED RATHER THAN LEFT NIL, and it is raised HERE rather than after the submit,
	// because the alternative to both is worse. A Message whose MessageId is nil is a message no
	// later kind can reference and nothing downstream would say so; and an error returned after
	// the submit succeeded would be this method reporting a failure for a record that LANDED,
	// which is the one thing its last paragraph promises it never does. At this point the seal
	// has happened and the submit has not, so this is the same class as the persistSent refusal
	// below: one stream index and one MLS generation spent, both legal gaps, and the send fails.
	messageId, err := self.session.MessageIdOf(&record.Header)
	if err != nil {
		return nil, fmt.Errorf("urmessage: this message was sealed and NOT sent, because its message_id could not be derived: %w", err)
	}
	// THE INDEX IS NOTED AT THE SEAL AND NOT AT THE SUBMIT, and the ordering is the whole of
	// why this is here rather than three lines down. A submit whose response never arrived is
	// still a record this device SEALED under this index -- the ciphertext exists and the
	// server may well hold it -- and a device that only recorded acknowledged indices would
	// meet its own lost record on a later fetch and read it as a second writer.
	//
	// AND THE COPY IS KEPT AT THE SAME MOMENT AND FOR THE SAME REASON, and since connect 4c030dc it
	// is the ONLY copy. The body is an MLS PrivateMessage and a member cannot open its own, so a
	// record whose answer was lost comes back on the next fetch as ciphertext this device will
	// never read again -- unless it kept what it sealed.
	//
	// IT IS DURABLE BEFORE THE SUBMIT, OR THE SUBMIT DOES NOT HAPPEN. A record that reached the
	// server with no copy on the disk is a line the user typed that a restart of this device can
	// never show them again, and nothing afterwards could repair it. Refusing here costs one
	// stream index and one MLS generation, both legal gaps, and the user sees the send fail and
	// types it again.
	sealed := &ownSealed{
		bodyHash: record.Header.BodyHash,
		hasCopy:  true,
		body:     []byte(text),
		sentAtMs: sentAtMs,
	}
	self.ownIndices[record.Header.StreamIndex] = sealed
	if err := self.device.persistSent(self.id, record.Header.StreamIndex, sealed); err != nil {
		return nil, fmt.Errorf("urmessage: this message was sealed and NOT sent, because the copy a restart would show it from could not be persisted: %w", err)
	}
	recordId, err := self.submitLocked(ctx, self.session, record, "a message")
	if err != nil {
		return nil, err
	}
	sealed.recordId = recordId
	handle := append([]byte(nil), record.Header.SenderHandle[:]...)
	sent := &Message{
		RecordId:     recordId,
		SenderHandle: handle,
		Mine:         true,
		Text:         text,
		SentAtMs:     sentAtMs,
		MessageId:    messageId[:],
	}
	self.log = append(self.log, sent)
	self.delivered[recordId] = true
	return sent, nil
}

// submitLocked is 4.3.5's submit of one record, with S2-2's recovery around it.
func (self *Group) submitLocked(ctx context.Context, session *messagegroup.GroupSession,
	record *message.Record, what string) (uint64, error) {

	return self.sendSealedLocked(ctx, session, record, what,
		func(projection *protocol.Record) (protocol.Reason, uint64, error) {
			response, err := self.device.transport.Call(ctx, &protocol.SubmitRequest{
				GroupId: self.id,
				Records: []*protocol.Record{projection},
			})
			if err != nil {
				return protocol.Reason_REASON_INTERNAL, 0, err
			}
			if response.GetReason() != protocol.Reason_REASON_OK {
				return response.GetReason(), 0, nil
			}
			body := response.GetSubmit()
			if body == nil || len(body.GetResults()) != 1 {
				return protocol.Reason_REASON_INTERNAL, 0, fmt.Errorf(
					"%w: one record was submitted and %d results came back", ErrSubmitRefused, len(body.GetResults()))
			}
			return body.GetResults()[0].GetReason(), body.GetResults()[0].GetRecordId(), nil
		})
}

// sendSealedLocked submits an already sealed record, and performs S2-2's ONE recovery when the
// server refuses it.
//
// THE RECOVERY IS FOR THE HALF OF A RECONNECT NOTHING IN sdk CAN SEE. NonceEpoch counts Hellos, so
// a connection replaced underneath this binding without a Hello through it leaves a superseded
// nonce readable at an unchanged number and rebindLocked finds nothing to repair. A refusal is
// then the only evidence there is, so one refusal buys one Hello, one rebind, one ReauthRecord --
// which re-MACs the record that is already sealed, consumes no stream index and re-encrypts
// nothing -- and one resubmission.
//
// IT IS ONE AND IT IS NOT A LOOP. A second refusal is a fact about the group, the epoch or the
// record rather than about the nonce, and a client that kept trying would turn a visible failure
// into a busy one. Both reasons are carried in the error.
//
// AND ONE REASON IS NOT A NONCE FACT AND IS NOT TREATED AS ONE: see [Group.cloneRefusalLocked].
func (self *Group) sendSealedLocked(ctx context.Context, session *messagegroup.GroupSession,
	record *message.Record, what string,
	send func(*protocol.Record) (protocol.Reason, uint64, error)) (uint64, error) {

	projection, err := projectionOf(record)
	if err != nil {
		return 0, fmt.Errorf("urmessage: the projection of %s: %w", what, err)
	}
	reason, recordId, err := send(projection)
	if err != nil {
		return 0, fmt.Errorf("urmessage: submitting %s: %w", what, err)
	}
	if reason == protocol.Reason_REASON_OK {
		self.stats.Submitted += 1
		return recordId, nil
	}
	if refusal := self.cloneRefusalLocked(reason, record, what); refusal != nil {
		return 0, refusal
	}

	// S2-2: one Hello, one rebind, one re-MAC, one resubmission.
	helloReason, hello, err := self.device.transport.Hello(ctx)
	if err != nil {
		return 0, fmt.Errorf("%w: %s was answered %v, and the Hello that would have repaired the nonce failed: %w",
			ErrSubmitRefused, what, reason, err)
	}
	if helloReason != protocol.Reason_REASON_OK || len(hello.GetServerNonce()) == 0 {
		return 0, fmt.Errorf("%w: %s was answered %v, and the Hello that would have repaired the nonce was answered %v",
			ErrSubmitRefused, what, reason, helloReason)
	}
	if err := self.rebindLocked(); err != nil {
		return 0, err
	}
	if err := session.ReauthRecord(record); err != nil {
		return 0, fmt.Errorf("%w: %s was answered %v and could not be re-MAC'd against the new connection's nonce: %w",
			ErrSubmitRefused, what, reason, err)
	}
	retryProjection, err := projectionOf(record)
	if err != nil {
		return 0, fmt.Errorf("urmessage: the re-MAC'd projection of %s: %w", what, err)
	}
	retryReason, retryRecordId, err := send(retryProjection)
	if err != nil {
		return 0, fmt.Errorf("urmessage: resubmitting %s: %w", what, err)
	}
	if refusal := self.cloneRefusalLocked(retryReason, record, what); refusal != nil {
		return 0, refusal
	}
	if retryReason != protocol.Reason_REASON_OK {
		return 0, fmt.Errorf("%w: %s was answered %v, and %v again after a fresh Hello and a re-MAC",
			ErrSubmitRefused, what, reason, retryReason)
	}
	self.stats.Submitted += 1
	self.stats.Rebound += 1
	return retryRecordId, nil
}

// cloneRefusalLocked is the clone check ON THE SEAL PATH: §4.5's REASON_STREAM_INDEX_REUSED, read
// as the finding it is rather than pasted into an error string.
//
// WHY IT HAD TO EXIST. Clause 2 of the clone check (see [Device.Restore]) lives only in
// [Group.Receive], and [Group.Send] consulted nothing but `identityInUse` and `reconciled`. So two
// level copies that kept SENDING collided on every index, not once: the refusal was returned
// non-sticky, and the next Send sealed at the next index and collided there too. The published
// bound -- "one record, not a stream of them" -- was FALSE by measurement, at four collisions from
// four typed messages, every one of them a two-time pad the ct_body XOR shows octet for octet.
//
// WHAT THE REASON MEANS, READ OUT OF THE SERVER'S SOURCE RATHER THAN ASSUMED. Both stores answer it
// from the same place: step (0)'s idempotency probe, BEFORE any gate, any allocation and the row
// lock, compares the submitted record's body_hash AND the hash of its ct_head against the
// `message_stream_claim` already standing at this (group_id, sender_handle, stream_index).
// Equal on both is `probeIdentical` and REASON_OK; different is `probeDiffers` and
// REASON_STREAM_INDEX_REUSED (msgrepo `store/memory.go:452`, `store/pgx.go:994`). So the reason is
// exactly one sentence: SOMETHING ELSE HAS ALREADY WRITTEN DIFFERENT CONTENT AT AN INDEX THIS
// DEVICE'S RESERVER HANDED OUT. A reserver never rewinds and this device seals once per index, so
// there is no second reading of that, and it is the same finding [ErrIdentityInUse] names.
//
// AND THE HONEST RETRY IS PRICED, WHICH IS THE THING THAT HAD TO BE CHECKED FIRST. The one way a
// healthy device resubmits at a consumed index is S2-2's recovery and a lost answer, and
// [messagegroup.GroupSession.ReauthRecord] writes EXACTLY ONE field -- `record.WriteAuth` -- which
// the probe does not read. So an honest resubmission is byte-identical where the probe looks and is
// answered REASON_OK, never REUSED. That is measured rather than reasoned:
// `cp3b.TestAnHonestResubmissionOfTheSameRecordIsAnsweredOkAndNotReadAsAClone`.
//
// IT IS TAKEN BEFORE S2-2'S RECOVERY AND NOT AFTER, and that ordering is the point. The recovery
// repairs a NONCE, and a reused index is not a nonce fact -- so running it here would buy nothing
// and would put the colliding ciphertext on the wire a SECOND time, which is exactly what was
// measured: "3 submissions, 2 distinct ciphertexts" at every collided index.
//
// THE COST, SAID PLAINLY. The reason is PLAINTEXT and unauthenticated, so a hostile or broken
// server can answer REUSED to a device that has no copy and stop that group sealing for the life of
// the process. That is accepted, for two reasons that are worth more than the risk: a server can
// already deny every submit outright, so this buys it only stickiness; and the failure direction is
// "this device will not send", never "this device sends under a reused key and nonce". A restart
// clears it and the next [Group.Receive] decides again on records that OPENED, which is evidence a
// server cannot forge.
func (self *Group) cloneRefusalLocked(reason protocol.Reason, record *message.Record, what string) error {
	if reason != protocol.Reason_REASON_STREAM_INDEX_REUSED {
		return nil
	}
	if self.identityInUse == nil {
		self.identityInUse = fmt.Errorf(
			"%w: group %x epoch %d: the server answered %v to %s at stream index %d, which is its statement that a record it already holds at that index under this device's own sender_handle carries different content -- two records under one (epoch, sender_handle, stream_index) are one record_key and one nonce",
			ErrIdentityInUse, self.id, self.epoch, reason, what, record.Header.StreamIndex)
	}
	return self.identityInUse
}

// ── receiving ────────────────────────────────────────────────────────────────────────────────

// Receive fetches everything the server has for this group since the last call, opens what is a
// message, and answers the messages in record order.
//
// IT PAGES UNTIL THE SERVER SAYS complete, AND WHEN IT CANNOT IT SAYS SO. 4.3.4's FetchResponse
// carries `complete` -- "false when truncated by limit OR by max_response_bytes; both are NORMAL"
// -- `next_record_id` and `high_water_record_id`, and an earlier build of this method read none of
// the three. One page then read as the whole history with a nil error, which is the worst failure
// an alpha can have, because a user cannot tell half a conversation from a quiet one. So:
//
//   - a truncated page is followed by the next one, resuming from `next_record_id`, until the
//     server answers complete;
//   - a server that answers incomplete and advances NO cursor is refused with
//     [ErrFetchNoProgress] rather than looped on forever;
//   - and reaching [maxFetchPages] returns the messages read so far TOGETHER WITH
//     [ErrFetchIncomplete], so a caller that ignores the error still sees messages and a caller
//     that reads it knows there are more.
//
// WHAT IT SKIPS IS COUNTED RATHER THAN DROPPED. 6.1's ceremony, records this group's log already
// holds, and classes this build does not open are each their own counter on [Group.Stats]; a
// record from a member that DID NOT OPEN is counted too AND returns an error, because that is the
// one case where a message was sent and this device cannot show it.
//
// THIS DEVICE'S OWN RECORDS ARE SHOWN AND NOT SKIPPED, and the sentence that stood here before
// that said the opposite. Every own record was skipped on the ground that this device "holds its
// own plaintext already" -- which is true of a device that has been running since it sent them, and
// FALSE of a restored one, whose log starts empty and whose cursor is not persisted. A user closed
// the app, reopened it, and got the other side's half of the conversation and none of their own,
// with a nil error and one counter that moves on the ordinary echo case too. Now an own record is
// shown unless its record id is already in this group's log, and the readings are counters:
// [Stats.SkippedOwn], [Stats.OpenedOwn] and [Stats.OwnWithoutCopy].
//
// SHOWN, AND SINCE connect 4c030dc NOT OPENED: a member cannot open its own application record
// (MG-4), so this device's own lines come from the copy [Group.Send] kept and the durable store
// holds. [Group.openPageLocked] carries the three roads an own record takes.
//
// A RECORD THAT DID NOT OPEN IS ASKED FOR AGAIN, up to [maxRecordAttempts] times, and then GIVEN
// UP ON BY NAME. The cursor this method resumes from is the RESOLVED position and not the paging
// one -- see [pageWalk] -- because an earlier build advanced one number over every row before the
// fail paths, so one transient cost the conversation that message for ever and the retry answered
// nothing with a nil error. At the bound the record is [ErrRecordAbandoned], [Stats.Unopened] and
// [Group.UnopenedRecords], which is a hole a caller can show.
//
// A SERVER HOLDING RECORDS BACK IS CAUGHT BY ITS OWN `high_water_record_id`, WITH NO KEY. See the
// complete-page branch in the body for the check, and for the one honest server that also trips
// it. This is the half of S2-27 below that is not blocked on key custody.
//
// AND A SECOND DEVICE SEALING UNDER THIS DEVICE'S IDENTITY -- a copied app-data folder -- IS
// REFUSED HERE, before this group seals again. [Device.Restore] carries the whole of that
// decision: what it covers, what it does not, and why the server's refusal of the duplicate is
// not a defence.
//
// ---------------------------------------------------------------------------------------------
// 4.3.4'S FETCH ATTESTATION: WHAT IS CHECKED, WHAT IS NOT, AND WHY NOT.
// ---------------------------------------------------------------------------------------------
//
// The attestation is the server's Ed25519 signature over what it returned -- since, until, the
// record ids, the high water, its own time and its own id. The AEAD catches a server that TAMPERS;
// nothing but this catches a server that OMITS, so a page with records missing from it is
// invisible to a client that ignores it.
//
// TWO OF THE THREE CHECKS ARE MADE HERE AND THEY NEED NO KEY.
//
//  1. THE DOWNGRADE. If the server ADVERTISED `capabilities.attestation_supported` and then
//     answered a page with no attestation, that is refused with [ErrFetchAttestation]. A server
//     that can sign and did not is not the same server as one that never could.
//  2. THE DESCRIPTION. If an attestation IS present, its group_id, its since, its record id
//     vector and its high water are compared against the page it arrived with. An attestation
//     that describes a DIFFERENT page -- one replayed from another fetch, or one that lists
//     records this page does not carry -- is refused. This is what turns the value from
//     decoration into a statement about these records.
//
// THE THIRD -- THE SIGNATURE ITSELF -- IS NOT VERIFIED, AND THAT IS STATED RATHER THAN PAPERED
// OVER. Verifying it needs the fleet's public key, and 4.3.1 says where that comes from:
// `HelloResponse.server_keys`, each certified by a FLEET ROOT key the client holds compiled in
// (Spec A section 7.6). MEASURED against the server this alpha is deployed from, at msgrepo's
// committed HEAD:
//
//	msgrepo/peer/peer.go:392  -- "HelloResponse.server_keys and HelloResponse.kt_gossip ... This
//	                             process holds no fleet key and observes no log" (declared NotBuilt)
//	msgrepo/api/api.go:497    -- "FetchAttestation: an Ed25519 signature by the fleet key over
//	                             nine response fields, and this process holds no fleet key"
//	msgrepo/api/fetch.go:112  -- "4.3.4's FetchAttestation is absent, not empty"
//
// So the deployed server signs nothing, advertises `attestation_supported` false, and publishes no
// key chain; and there is no compiled-in fleet root anywhere in this workspace to chain one to.
// VERIFYING AGAINST A KEY THE SERVER ITSELF HANDED OVER WOULD BE WORSE THAN NOT VERIFYING: it
// would read as verified and would authenticate the server to itself. So it is not done, it is
// COUNTED -- [Stats.Unattested] moves once per page whose signature this build could not verify,
// which today is every page -- and the gap is filed. **S2-27: a client cannot verify a fetch
// attestation until the fleet ships a key chain and this build ships a root to verify it against.
// Until it does, a message server that omits records from the MIDDLE of a page, or that lies about
// its own high water, is undetectable by this client.** (It used to say "omits records from a
// page", flat, and that was too strong; the paragraph below is the correction and the measurement.) It is not this package's to close: the key custody is Spec B section 9.1's, through
// `kt`, which is the owner msgrepo's own NotBuilt entry names.
//
// S2-27 IS NARROWED AND NOT CLOSED, AND THE NARROWING IS THE HALF THAT NEEDED NO KEY. The sentence
// above -- "a message server that silently omits records from a page is undetectable by this
// client" -- was too strong. `high_water_record_id` is the server's own statement of the highest
// record it holds for this group, it arrives on every page, and it needs no signature to read. A
// complete page that names a high water above everything it handed over is now counted in
// [Stats.Omitted] and returned as [ErrFetchOmitted]. What remains S2-27's, and genuinely does need
// the key: a server omitting records from the MIDDLE of a page, or one that lies about its own
// high water. Both are caught by a signature over the record id vector and by nothing else.
func (self *Group) Receive(ctx context.Context) ([]*Message, error) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if self.closed {
		return nil, fmt.Errorf("urmessage: this group is closed")
	}
	if self.session == nil {
		return nil, ErrNoMemberAdded
	}
	if err := self.rebindLocked(); err != nil {
		return nil, err
	}
	nonce, _, err := self.device.nonce()
	if err != nil {
		return nil, err
	}
	keys, err := self.session.EpochKeys()
	if err != nil {
		return nil, fmt.Errorf("urmessage: this epoch's keys: %w", err)
	}
	defer keys.Destroy()
	readKey, err := keys.ReadKey()
	if err != nil {
		return nil, err
	}
	own, err := self.session.SenderHandle()
	if err != nil {
		return nil, fmt.Errorf("urmessage: this device's sender handle: %w", err)
	}
	leaves, err := self.leavesLocked()
	if err != nil {
		return nil, err
	}

	walk := &pageWalk{
		own:        own,
		leaves:     leaves,
		opened:     []*Message{},
		from:       self.cursor,
		reached:    self.cursor,
		resolvedTo: self.cursor,
		reconciled: self.reconciled,
	}
	for page := 0; ; page += 1 {
		if maxFetchPages <= page {
			self.commitWalkLocked(walk)
			return walk.opened, fmt.Errorf("%w: %d pages, cursor at record %d", ErrFetchIncomplete, page, self.cursor)
		}
		since := walk.from
		request := &protocol.FetchRequest{
			GroupId:       self.id,
			SinceRecordId: since,
			ReadEpoch:     self.epoch,
		}
		if err := authorizeFetch(request, readKey, nonce); err != nil {
			self.commitWalkLocked(walk)
			return walk.opened, err
		}
		response, err := self.device.transport.Call(ctx, request)
		if err != nil {
			self.commitWalkLocked(walk)
			return walk.opened, fmt.Errorf("urmessage: Fetch: %w", err)
		}
		if response.GetReason() != protocol.Reason_REASON_OK {
			self.commitWalkLocked(walk)
			return walk.opened, fmt.Errorf("%w: %v", ErrFetchRefused, response.GetReason())
		}
		fetched := response.GetFetch()
		if fetched == nil {
			self.commitWalkLocked(walk)
			return walk.opened, fmt.Errorf("%w: the response carried no fetch arm", ErrFetchRefused)
		}
		self.stats.Pages += 1
		if err := self.checkAttestationLocked(since, fetched); err != nil {
			self.commitWalkLocked(walk)
			return walk.opened, err
		}
		self.openPageLocked(fetched, walk)
		if fetched.GetComplete() {
			// 4.3.4'S HIGH WATER, AND IT COSTS NOTHING. `high_water_record_id` is the
			// server's own statement of the highest record it holds for this group. On a
			// page it calls COMPLETE, a high water above everything it handed over is the
			// server saying it kept records back -- which is the one failure the AEAD
			// cannot see, and the half of it that needs no key, no fleet root and no
			// attestation. Before this clause the field was read in exactly one place,
			// inside checkAttestationLocked, which returns at its first branch when there
			// is no attestation -- which on the deployed server is every page.
			//
			// IT IS HELD AGAINST `reached` AND NOT AGAINST THE CURSOR. A record this device
			// could not open is still a record the server DID hand over, and naming the
			// server for this device's failure would be a true-sounding sentence about the
			// wrong party.
			//
			// THE ONE HONEST SERVER THAT WOULD ALSO MOVE IT, AND IT IS NOT BUILT YET.
			// high_water_record_id is `next_record_id - 1` off a monotone allocator on the
			// group row (msgrepo/store/pgx.go:501, store/memory.go:236), so it does NOT
			// come down when rows go. 7.2's retention sweep is what would take rows out
			// from under it, and a group whose oldest records had been pruned would answer
			// a complete page that stops short of its own high water with no dishonesty
			// anywhere.
			//
			// MEASURED rather than assumed, over msgrepo at ca8662d, because "there is a
			// legitimate cause" is the sentence that would quietly excuse every future
			// failure of this check:
			//
			//	grep -rn "DELETE FROM" --include=*.go --include=*.sql .
			//
			// answers TWO lines, both `DELETE FROM migration_audit` in a startup test.
			// NOTHING DELETES A message_record ROW. The `prune_after` column is written
			// and the sweep worklist index exists (store/migrations.go:155, :233) and the
			// sweep itself is NOT BUILT. So today this check has no known false positive
			// on the deployed server, and it acquires one the day 7.2 lands.
			//
			// It is a COUNTER and a returned error rather than a refusal anyway, and that
			// is the right way round for the same reason: the day the sweep lands, a
			// client that REFUSED the page would refuse an honest server doing its own
			// retention, and it would do it in a release nobody connected to this line.
			if walk.reached < fetched.GetHighWaterRecordId() {
				self.stats.Omitted += 1
				if walk.omitted == nil {
					walk.omitted = fmt.Errorf(
						"%w: group %x: it names high_water %d and handed over nothing above record %d",
						ErrFetchOmitted, self.id, fetched.GetHighWaterRecordId(), walk.reached)
				}
			}
			walk.complete = true
			break
		}
		// 4.3.4's resume cursor. It is taken as a MAXIMUM against what the rows moved the
		// paging position to rather than as an assignment: a server that answered a
		// next_record_id BEHIND the records it just sent would otherwise walk this client
		// backwards over records it has already opened, forever.
		if walk.from < fetched.GetNextRecordId() {
			walk.from = fetched.GetNextRecordId()
		}
		if walk.from <= since {
			self.commitWalkLocked(walk)
			return walk.opened, fmt.Errorf("%w: %d records, next_record_id %d, position still %d",
				ErrFetchNoProgress, len(fetched.GetRecords()), fetched.GetNextRecordId(), walk.from)
		}
	}
	return walk.opened, self.commitWalkLocked(walk)
}

// How many times one record is fetched and allowed to fail to open before this group gives up on
// it and says so.
//
// IT IS A BOUND ON A RETRY THAT DID NOT EXIST AT ALL. The cursor used to move past a record on the
// first sight of it, BEFORE the fail paths, so a transient -- a ciphertext bent in flight, a
// truncated body, a page a middlebox chewed -- cost the conversation that message for ever, and
// the next call answered no messages and a nil error while the record sat on the server.
//
// IT IS SMALL BECAUSE THE FAILURES A RETRY CAN REPAIR ARE TRANSIENT BY DEFINITION: a record that
// will not open three times will not open on the thousandth, and an unbounded retry is a group
// that re-reads its whole tail on every fetch for ever -- one bent record turned into a permanent
// cost, which is a shape an unfriendly peer would reach for.
//
// WHAT HAPPENS AT THE BOUND IS THE POINT: the record is named with [ErrRecordAbandoned], counted
// in [Stats.Unopened] and listed by [Group.UnopenedRecords]. A hole in a conversation this build
// has stopped trying to fill is a thing a user can be told about.
const maxRecordAttempts = 3

// pageWalk is one [Group.Receive]'s state across the pages it reads.
//
// IT IS A TYPE BECAUSE THE PAGING POSITION AND THE RESOLVED POSITION USED TO BE ONE NUMBER, and
// that is the whole of how a record that did not open was dropped for ever: `self.cursor` advanced
// over every row before the fail paths, so the next fetch asked from ABOVE the record that failed
// and no later call ever asked for it again. Two numbers cannot be confused for one another by an
// edit; one number could only be right for one of the two jobs.
type pageWalk struct {
	own    [16]byte
	leaves map[[16]byte]uint32

	opened       []*Message
	firstFailure error
	omitted      error

	// from is where the NEXT page is asked from. It moves over every row, always, so that one
	// record that will not open cannot loop this call.
	from uint64

	// reached is the highest record id the server has handed over in this call, and it is what
	// 4.3.4's high_water_record_id is held against.
	reached uint64

	// resolvedTo is the highest record id below which every row has been opened, skipped by a
	// name this build prints, or given up on. It becomes this group's cursor, so a row that did
	// not open is asked for again by the NEXT Receive.
	resolvedTo uint64
	blocked    bool

	complete bool

	// reconciled is [Group.reconciled] as it stood when this walk STARTED. A walk that is doing
	// the reconciling absorbs the own records it finds; one that is not treats an own record
	// this device never sealed as what it is.
	reconciled bool

	// THE HIGHEST OWN INDEX IS NOT HERE ANY MORE: it is [Group.ownIndexSeen], because one walk's
	// number forgot what an earlier, dirty walk had already authenticated. It is still read OFF
	// RECORDS THE GROUP'S KEYS AUTHENTICATED AND NEVER OFF A HEADER -- a record header is plaintext,
	// the server writes any sender_handle and stream_index it likes into one, and a number taken
	// off a header would let it wedge any client with one forged row. The three sources it IS
	// taken from: an own record that OPENED, which since MG-4 only a copy of this folder ahead of
	// this one can have sealed; an own record whose inner frame reached MLS's spent-generation
	// refusal (see ownFrameAlreadySpent); and an own record shown from this device's copy, whose
	// index is by construction one this device sealed at (see [Group.openOwnFromCopyLocked]).

	// the first own record that opened at a stream index this device did not seal THIS record
	// at. foreignBody distinguishes the two ways that happens, because they are two different
	// sentences to show a user.
	foreignIndex  uint64
	foreignRecord uint64
	foreignBody   bool
}

// commitWalkLocked folds one walk back into the group and answers what its caller must be told.
//
// THE CURSOR BECOMES THE RESOLVED POSITION AND NOT THE PAGING ONE. That is the repair: a record
// that did not open holds this back, so the next [Group.Receive] asks the server for it again.
//
// THE ORDER THE THREE ERRORS ARE RETURNED IN IS A DECISION. The identity refusal first, because it
// is the only one that stops this device sealing and because carrying on would carry on producing
// the collision; then the record that did not open, which is the existing contract and names a
// specific record; then the server that held records back, which moves [Stats.Omitted] whether or
// not it is the value returned.
func (self *Group) commitWalkLocked(walk *pageWalk) error {
	self.cursor = walk.resolvedTo
	if self.walkReconcilesLocked(walk) {
		// THE RECONCILIATION. It runs once per restored group, on the first walk of this
		// group's history that was COMPLETE AND CLEAN, and it is the half of the clone check
		// that happens BEFORE this device has sealed anything.
		//
		// THE INVARIANT IS ONE SENTENCE: every stream index on the server under this
		// device's sender_handle was allocated by this device's durable reserver, and a
		// reserver never rewinds. So a record of this device's own that the group's keys
		// AUTHENTICATE at an index the reserver has never handed out was sealed by something else
		// holding these keys, and there is no other reading of it. ("Authenticate" and not
		// "open" since MG-4: see ownFrameAlreadySpent, and [Group.ownIndexSeen] for why the
		// number compared is every walk's since the group came up and not this walk's.)
		//
		// WHAT THIS WALK CANNOT SEE: an own record that did NOT authenticate contributes no index,
		// because an index is only read off a record the aead authenticated -- so a server
		// bending one of this device's own records suppresses the evidence for that record.
		// THAT IS WHY THE GATE IS [Group.walkReconcilesLocked] AND NOT `walk.complete` ALONE.
		// The evidence this walk is missing is named by the walk itself, and a sentence as
		// strong as "this device is alone with its identity" is not written down over a walk
		// that is admittedly short of records.
		highWater, err := self.ownHighWaterLocked(walk.own)
		if err != nil {
			// NOT reconciled, so Send stays refused. A reserver that will not answer is
			// not evidence that this device is alone with its identity.
			return fmt.Errorf("urmessage: this device's own stream position could not be read, so this restored group cannot reconcile: %w", err)
		}
		if highWater < self.ownIndexSeen {
			self.identityInUse = fmt.Errorf(
				"%w: group %x epoch %d: the server holds a record this group's keys authenticated at stream index %d under this device's own sender_handle, and this device's durable reserver has never allocated past %d",
				ErrIdentityInUse, self.id, self.epoch, self.ownIndexSeen, highWater)
		}
		self.reconciled = true
	}
	if self.identityInUse == nil && walk.foreignIndex != 0 {
		if walk.foreignBody {
			// THE COLLISION ITSELF, AFTER THE FACT. Two records under one
			// (epoch, sender_handle, stream_index) is one record_key and one nonce, and
			// this device is holding the OTHER plaintext.
			self.identityInUse = fmt.Errorf(
				"%w: group %x epoch %d: record %d opened under this device's own sender_handle at stream index %d, and it is NOT the record this device sealed at that index -- two records under one (epoch, sender_handle, stream_index) are one record_key and one nonce",
				ErrIdentityInUse, self.id, self.epoch, walk.foreignRecord, walk.foreignIndex)
		} else {
			self.identityInUse = fmt.Errorf(
				"%w: group %x epoch %d: record %d opened under this device's own sender_handle at stream index %d, and this device never sealed at that index",
				ErrIdentityInUse, self.id, self.epoch, walk.foreignRecord, walk.foreignIndex)
		}
	}
	if self.identityInUse != nil {
		return self.identityInUse
	}
	if walk.firstFailure != nil {
		return walk.firstFailure
	}
	return walk.omitted
}

// walkReconcilesLocked is whether THIS walk is one the clone check may conclude anything from.
//
// IT IS A SEPARATE PREDICATE BECAUSE IT IS A SEPARATE QUESTION, and running the two together in an
// `if` was how the answer came out wrong. "Did the server finish handing over the page" and "did
// this walk see the group's history" are not the same sentence, and only the second one licenses
// [Group.reconciled].
//
// THE CHEAPEST WAY PAST A CHECK IS A FAILURE THE CHECKER ALREADY PRINTED. `walk.complete` means
// only that the server called one page COMPLETE. The same walk carries two fields that say it did
// not see the history, BOTH OF WHICH THIS CLIENT COMPUTED AND RETURNED TO ITS CALLER:
//
//   - `walk.omitted` -- §4.3.4's own `high_water_record_id`, above every record the server handed
//     over. The server's admission, in its own field, that a page it called complete is short.
//   - `walk.firstFailure` -- a record that did not open. An index is read only off a record the
//     aead authenticated, so a record that did not open contributes NO index, and the header is
//     plaintext so this build cannot even tell whether the lost record was its own. A walk with a
//     hole in it is a walk whose missing index could be the one the check exists to find.
//
// Reconciling over either of those is declaring "every index on the server under this handle is
// one my reserver allocated" on the strength of records that were never seen. Both were measured
// past the old gate: a copy two indices BEHIND the original -- the case [Device.Restore]'s header
// says is caught before it seals anything -- reconciled with [Stats.Omitted] at 1 and
// [ErrFetchOmitted] on its way back to the caller, and then sealed at an index the original had
// already used. One bent own record did the same.
//
// WHAT IT COSTS, BOUNDED RATHER THAN HAND-WAVED. A group that has not had a clean walk stays
// [ErrNotReconciled] and the caller calls [Group.Receive] again -- which is what the transport-error
// path above already does, so this is the shape the function already had rather than a new one. The
// cost is NOT unbounded: a record that will not open is retried [maxRecordAttempts] times and then
// ABANDONED, and an abandoned record is resolved past without calling `fail`, so it sets no
// `firstFailure` on any later walk. So one permanently bent record delays the reconciliation by at
// most maxRecordAttempts+1 Receives and then stops delaying it. A server that permanently omits is
// the case that stays refused, and that is the intended reading: this device cannot check itself
// against a server that will not show it its own history.
func (self *Group) walkReconcilesLocked(walk *pageWalk) bool {
	return walk.complete && walk.omitted == nil && walk.firstFailure == nil && !self.reconciled
}

// ownHighWaterLocked is the highest stream index this device's DURABLE reserver has ever allocated
// for this group's own stream. It is the reserver's number and never a recomputed one.
func (self *Group) ownHighWaterLocked(own [16]byte) (uint64, error) {
	key := messagegroup.StreamKey{SenderHandle: own}
	copy(key.GroupId[:], self.id)
	return self.device.reserver.HighWater(key)
}

// openPageLocked walks one page's records: it advances the two positions, counts what it skips,
// and opens what is a message.
//
// It is a method rather than the body of the loop above so that "one page" is a thing with a name
// -- and so that the paging decisions and the record decisions are not one forty-line block where
// a `continue` could mean either.
//
// THIS DEVICE'S OWN RECORDS ARE SHOWN HERE AND ARE NOT SKIPPED, which is the repair for the worst
// user-facing defect the durable store introduced. A restored group's log starts EMPTY and the
// cursor is not persisted, so a restarted device re-reads its whole history -- and while this
// method skipped every record whose sender_handle was its own, a user who closed the app and
// reopened it got the other side's half of the conversation and none of their own, with a nil
// error and one counter that moved on the ordinary echo case too.
//
// AND THEY ARE SHOWN FROM THE COPY THIS DEVICE KEPT, NOT OPENED, which is a change connect forced
// rather than one this method chose. Until connect 4c030dc an own record opened under a receiver
// ladder derived from the class key every member holds. Since it, the body is an MLS PrivateMessage
// and a member cannot open its own (MG-4), and at d368fea every own record here answered "mls:
// ratchet generation already consumed" -- which, while this method still asked for it, turned every
// restart, every clone case and the lost answer red in sdk/cp3b. So an own record now takes one of
// three roads, in this order, and each is its own counter:
//
//   - [Group.openOwnFromCopyLocked]: this device sealed at that index, kept what it sealed, and the
//     record carries that body_hash over that ct_body. Shown from the copy. [Stats.OpenedOwn].
//   - OpenRecord OPENS it: sealed by something else holding this leaf's signature key at a
//     generation this device never spent, which is a copy of this folder ahead of this one. Shown,
//     and read as the clone evidence it is. [Stats.OpenedOwn].
//   - OpenRecord refuses it at the spent generation: authenticated to this group's keys and not
//     showable. [Stats.OwnWithoutCopy], resolved past, and read as evidence the same way; see
//     ownFrameAlreadySpent for exactly how strong that evidence is.
//
// Every other refusal of an own record is an ordinary record that did not open. What keeps any of
// it from delivering a message twice is [Group.delivered] and, for the copy, the record id it was
// shown under.
func (self *Group) openPageLocked(fetched *protocol.FetchResponse, walk *pageWalk) {
	resolve := func(recordId uint64) {
		if !walk.blocked && walk.resolvedTo < recordId {
			walk.resolvedTo = recordId
		}
	}
	fail := func(recordId uint64, err error) {
		self.stats.FailedOpen += 1
		self.attempts[recordId] += 1
		if self.attempts[recordId] < maxRecordAttempts {
			if walk.firstFailure == nil {
				walk.firstFailure = err
			}
			// and the cursor stops here, so the NEXT Receive asks for this record again.
			walk.blocked = true
			return
		}
		// THE BOUND. The record is given up on, and an abandonment OUTRANKS whatever
		// retryable failure was already held: a hole that will not be filled is worse news
		// than one that might be, and the caller gets the worse of the two.
		self.unopened = append(self.unopened, recordId)
		self.stats.Unopened += 1
		walk.firstFailure = fmt.Errorf("%w: record %d, after %d attempts: %w",
			ErrRecordAbandoned, recordId, self.attempts[recordId], err)
		resolve(recordId)
	}
	for _, row := range fetched.GetRecords() {
		self.stats.Fetched += 1
		recordId := row.GetRecordId()
		if walk.from < recordId {
			walk.from = recordId
		}
		if walk.reached < recordId {
			walk.reached = recordId
		}
		if maxRecordAttempts <= self.attempts[recordId] {
			// already given up on. It is here only as a passenger of a rewind over some
			// earlier record, and it must not block the cursor a second time.
			resolve(recordId)
			continue
		}
		parsed, err := message.ParseRecord(row.GetRecordBytes())
		if err != nil {
			fail(recordId, fmt.Errorf("%w: record %d does not parse: %w", ErrRecordOpen, recordId, err))
			continue
		}
		header := &parsed.Header
		if header.IsCommit || len(header.ServerAttachment) != 0 {
			self.stats.SkippedCeremony += 1
			resolve(recordId)
			continue
		}
		mine := header.SenderHandle == walk.own
		if self.delivered[recordId] {
			// this group's log already holds it. The two readings are counted apart: the
			// ordinary echo of a send this process made, and a record re-read because a
			// rewind over an earlier failure passed back over it.
			if mine {
				self.stats.SkippedOwn += 1
			} else {
				self.stats.SkippedSeen += 1
			}
			resolve(recordId)
			continue
		}
		if header.RetentionClass != message.RetentionDurable {
			self.stats.SkippedClass += 1
			resolve(recordId)
			continue
		}
		if self.withoutCopy[recordId] {
			// authenticated as this device's own on an earlier walk, and still not showable. Its
			// evidence is already in [Group.ownIndexSeen] and, when it was a copy's, already in
			// identityInUse, so nothing is taken from the header re-fetched here.
			resolve(recordId)
			continue
		}
		if mine {
			shown, err := self.openOwnFromCopyLocked(walk, recordId, parsed)
			if err != nil {
				fail(recordId, err)
				continue
			}
			if shown {
				resolve(recordId)
				continue
			}
		}
		leaf, known := walk.leaves[header.SenderHandle]
		if !known {
			fail(recordId, fmt.Errorf("%w: record %d names sender_handle %x, which is no leaf of this group at epoch %d",
				ErrRecordOpen, recordId, header.SenderHandle, self.epoch))
			continue
		}
		if err := self.trackLocked(leaf, header); err != nil {
			fail(recordId, err)
			continue
		}
		if mine {
			if err := self.advanceOwnLadderLocked(leaf, header); err != nil {
				fail(recordId, err)
				continue
			}
		}
		headPlain, bodyPlain, err := self.session.OpenRecord(parsed)
		if err != nil {
			if mine && ownFrameAlreadySpent(err) {
				// connect MG-4, and the ONE refusal on this path that is not a failure. See
				// ownFrameAlreadySpent for exactly what it establishes and what it does not.
				//
				// ONE RECORD UNDER TWO RECORD IDS IS STILL ONE RECORD SHOWN TWICE, whether it is shown
				// from a copy or only counted: the same (index, body_hash) already accounted for under
				// another number is refused, as openOwnFromCopyLocked refuses it.
				if known, held := self.ownIndices[header.StreamIndex]; held && known.bodyHash == header.BodyHash &&
					known.recordId != 0 && known.recordId != recordId {
					fail(recordId, fmt.Errorf("%w: record %d carries this device's own record at stream index %d, which this group already holds as record %d",
						ErrRecordOpen, recordId, header.StreamIndex, known.recordId))
					continue
				}
				self.stats.OwnWithoutCopy += 1
				self.withoutCopy[recordId] = true
				self.noteOwnIndexLocked(walk, recordId, header.StreamIndex, header.BodyHash)
				if known, held := self.ownIndices[header.StreamIndex]; held && known.bodyHash == header.BodyHash && known.recordId == 0 {
					known.recordId = recordId
				}
				resolve(recordId)
				continue
			}
			fail(recordId, fmt.Errorf("%w: record %d from leaf %d: %w", ErrRecordOpen, recordId, leaf, err))
			continue
		}
		sentAtMs, err := decodeHead(headPlain)
		if err != nil {
			fail(recordId, fmt.Errorf("%w: record %d: %w", ErrRecordOpen, recordId, err))
			continue
		}
		messageId, err := self.session.MessageIdOf(header)
		if err != nil {
			// UNREACHABLE HERE AND CARRIED ANYWAY. MessageIdOf refuses a nil header, a closed
			// session and a record whose group_id is not this session's, and this record has
			// just been OPENED by this session -- both AEADs bound group_id. Measured: deleting
			// this branch leaves ./urmessage and ./cp3b green, so it defends nothing a test can
			// see. It is here because the alternative to a branch is a [Message] with a nil
			// MessageId delivered as though it had one.
			fail(recordId, fmt.Errorf("%w: record %d: its message_id could not be derived: %w", ErrRecordOpen, recordId, err))
			continue
		}
		self.stats.Opened += 1
		if mine {
			// A RECORD OF THIS DEVICE'S OWN THAT OPENED. This device cannot open what IT sealed
			// (MG-4), so what just opened was sealed by something else holding this leaf's
			// signature key at a generation this device has not spent: a copy of the folder,
			// ahead of this one. noteOwnIndexLocked reads it as exactly that. It is still shown,
			// because it is a message somebody in this group really wrote.
			self.stats.OpenedOwn += 1
			self.noteOwnIndexLocked(walk, recordId, header.StreamIndex, header.BodyHash)
		}
		received := &Message{
			RecordId:     recordId,
			SenderHandle: append([]byte(nil), header.SenderHandle[:]...),
			Mine:         mine,
			Text:         string(bodyPlain),
			SentAtMs:     sentAtMs,
			MessageId:    messageId[:],
		}
		walk.opened = append(walk.opened, received)
		self.log = append(self.log, received)
		self.delivered[recordId] = true
		resolve(recordId)
	}
}

// noteOwnIndexLocked accounts for one record that opened under this device's own sender_handle.
//
// THE FOUR READINGS, AND THEY ARE NOT THE SAME EVENT.
//
//   - THIS RECORD, AT AN INDEX THIS PROCESS SEALED IT AT. The ordinary case, and it includes a
//     record whose submit response never arrived: [Group.Send] notes index and body_hash at the
//     SEAL, so the record comes back as this device's own rather than as a stranger holding its
//     keys.
//   - AN INDEX FOUND DURING THE RECONCILING WALK of a restored group. This is this lineage's own
//     history and it is absorbed; commitWalkLocked holds the maximum of it against the reserver
//     afterwards, which is the check that needs the whole walk rather than one record.
//   - A DIFFERENT RECORD AT AN INDEX THIS DEVICE SEALED AT. This is the hard case and it is the
//     one an index-only check could not see: two copies of one folder that were EXACTLY level
//     both seal at this index, one submission wins, and the loser finds the winner's record here.
//     Conclusive: this device knows what it sealed at this index and this is not it.
//   - AN INDEX THIS DEVICE NEVER SEALED, after this group has reconciled. A copy that is ahead.
//
// WHY THE BODY HASH CAN BE TRUSTED HERE: this runs only after the record OPENED, and §3.1's
// body_hash is inside aad_head and is compared against the ciphertext before either AEAD runs. A
// party without this group's keys cannot produce a record that opens at all, let alone one whose
// body_hash it chose.
func (self *Group) noteOwnIndexLocked(walk *pageWalk, recordId uint64, index uint64, bodyHash [32]byte) {
	if self.ownIndexSeen < index {
		self.ownIndexSeen = index
	}
	sealed, mine := self.ownIndices[index]
	switch {
	case mine && sealed.bodyHash == bodyHash:
	case mine:
		if walk.foreignIndex == 0 {
			walk.foreignIndex, walk.foreignRecord = index, recordId
			walk.foreignBody = true
		}
	case !walk.reconciled:
		self.ownIndices[index] = &ownSealed{bodyHash: bodyHash}
	case walk.foreignIndex == 0:
		walk.foreignIndex, walk.foreignRecord = index, recordId
	}
}

// openOwnFromCopyLocked shows one record of this device's own from the copy [Group.Send] kept, and
// answers whether it did.
//
// WHY THERE IS A COPY TO SHOW IT FROM. Since connect 4c030dc an application record's body is an MLS
// PrivateMessage, and a member cannot open its own: Protect spends a generation of this leaf's own
// ratchet and MLS keeps no receiving ratchet for a leaf's own messages, so OpenRecord of a record
// this device sealed answers "mls: ratchet generation already consumed". That is connect's
// messagegroup OPENITEMS MG-4, and of the three answers it lists this is the first -- a sender
// renders its own message from the copy it kept -- because the second is a change to connect and
// the third, exempting self-attributed records from the inner open, re-opens the forgery 4c030dc
// closed and is written down there as refused.
//
// WHAT HAS TO HOLD BEFORE A COPY IS SHOWN, and why each clause is there:
//
//   - THIS DEVICE SEALED AT THIS INDEX AND KEPT WHAT IT SEALED. An index it only learned from the
//     server has no copy and is not shown from one.
//   - THE RECORD'S body_hash IS THE ONE SEALED THERE. Two copies of one folder both seal at an
//     index; the one whose record the server kept is not this device's, and it is not shown as
//     this device's text. It falls through to OpenRecord, which is what authenticates it and what
//     lets the clone check read it.
//   - THE HASH IS THE HASH OF THIS ct_body, and the group and epoch are this group's. A header is
//     plaintext; checking the hash against the ciphertext in hand is what ties the claim to
//     octets this device produced, because nobody can produce a second ct_body under one SHA-256.
//     What is NOT checked is ct_head, and nothing is lost by it: the head this device wrote is
//     the clock reading it kept, and it is shown from the copy.
//   - THE COPY HAS NOT ALREADY BEEN SHOWN UNDER ANOTHER RECORD ID. An honest server numbers one
//     record once -- an honest resubmission is answered with the record id it already holds -- so
//     a second number for the same (index, body_hash) is one record shown twice. It is refused as
//     a record that did not open rather than delivered again, which is what the receiver ladder
//     used to do for it when this device could still open its own records.
//
// A record that fails any of the first three is not an error here: it answers false, and the
// ordinary open path decides what it is.
func (self *Group) openOwnFromCopyLocked(walk *pageWalk, recordId uint64, parsed *message.Record) (bool, error) {
	header := &parsed.Header
	sealed, found := self.ownIndices[header.StreamIndex]
	if !found || !sealed.hasCopy || sealed.bodyHash != header.BodyHash {
		return false, nil
	}
	// THE GROUP AND EPOCH HALF OF THIS DEFENDS NOTHING A TEST CAN SEE, measured by deleting it over
	// urmessage and cp3b with nothing going red, and that is argued rather than hoped: a ct_body this
	// device sealed in another group or epoch hashes to a body_hash no copy in THIS group's table
	// holds, so the hash half already refuses it. It stays because it is free and says what a copy
	// is for.
	if sha256.Sum256(parsed.CtBody) != header.BodyHash || !bytes.Equal(header.GroupId[:], self.id) ||
		header.Epoch != self.epoch {
		return false, nil
	}
	if sealed.recordId != 0 && sealed.recordId != recordId {
		return false, fmt.Errorf("%w: record %d carries this device's own record at stream index %d, which this group already holds as record %d",
			ErrRecordOpen, recordId, header.StreamIndex, sealed.recordId)
	}
	// THE ID IS DERIVED FROM THE SERVER'S RECORD AND NOT FROM THE COPY, which is the only reason
	// this line is above the two counters rather than inside the literal below. The copy carries
	// the TEXT and the clock reading; the three inputs to message_id are header fields, and the
	// header in hand is the one whose body_hash has just been checked against the ciphertext. So
	// the id this device shows for its own message is computed from the same octets every other
	// member computes it from, and a restarted device that shows a line from its copy names it
	// the same way the group does.
	//
	// THE ERROR BRANCH DEFENDS NOTHING A TEST HERE CAN SEE, and it is the same unreachable clause
	// the ordinary open path carries, measured the same way: deleting it leaves ./urmessage and
	// ./cp3b green. MessageIdOf refuses a nil header, a closed session and a record whose group_id
	// is not this session's, and the clauses above have already compared this record's group and
	// epoch against this group's. It is kept because the alternative to a branch is a [Message]
	// delivered with a nil MessageId and nothing saying so.
	messageId, err := self.session.MessageIdOf(header)
	if err != nil {
		return false, fmt.Errorf("%w: record %d is this device's own at stream index %d and its message_id could not be derived: %w",
			ErrRecordOpen, recordId, header.StreamIndex, err)
	}
	sealed.recordId = recordId
	self.stats.OpenedOwn += 1
	self.noteOwnIndexLocked(walk, recordId, header.StreamIndex, header.BodyHash)
	received := &Message{
		RecordId:     recordId,
		SenderHandle: append([]byte(nil), header.SenderHandle[:]...),
		Mine:         true,
		Text:         string(sealed.body),
		SentAtMs:     sealed.sentAtMs,
		MessageId:    messageId[:],
	}
	walk.opened = append(walk.opened, received)
	self.log = append(self.log, received)
	self.delivered[recordId] = true
	return true, nil
}

// ownFrameAlreadySpent reports whether OpenRecord refused a record for exactly one reason: its inner
// MLS frame names a generation of this device's own leaf that this device has already spent. It is
// asked only of a record under this device's own sender_handle.
//
// WHAT THAT REFUSAL ESTABLISHES, READ OFF connect AT d368fea RATHER THAN ASSUMED, because the whole
// clone check leans on it. OpenRecord reaches the inner frame only after body_hash matched ct_body,
// the record key derived for this sender_handle at this stream_index, and BOTH record AEADs opened
// (messagegroup/seal.go, openRecordOnLoop) -- so a record that gets as far as ErrRecordInnerFrame
// was written by a holder of this group's class keys, at this position, with this body_hash. The
// frame's sender data then opened under the group's sender_data_secret, MASTER section 8.4.3's R1
// found the frame's leaf to be the one this sender_handle belongs to and R2 found its aad to be this
// record's own position (messagegroup/mlsframe.go, unframeBodyOnLoop, the PEEK half), and only then
// did mls refuse the generation (mls/secret_tree.go, classify, reached from MessageKey) -- BEFORE
// the content AEAD and BEFORE the signature.
//
// SO IT IS EXACTLY AS STRONG AS "IT OPENED" WAS BEFORE 4c030dc, AND NO STRONGER. The signature is
// never checked on this path and cannot be: the key it would need is the one this device erased
// when it sealed. Any MEMBER of the group can build a record that reaches this refusal at this
// device's handle -- which any member could also do, and have OPEN, before the ruling. The clone
// check therefore goes on resting on "a holder of this group's keys wrote this", which is what it
// rested on; what it does NOT get is "this device's own signature key wrote this", and a member that
// wants to wedge this device as a copy of itself can still do so for the price of one record. That
// is the residue connect's TestAnyMemberCanStillSquatAnotherLeafsStreamIndex already measures one
// layer down, reached from the clone check's side.
//
// cp3b.TestAnOwnRecordBentInFlightIsAFailureAndNotAnOwnRecord holds the half of this that a
// reordering inside connect would break: an own record whose ciphertext does not open never
// reaches this refusal and is a failure, not an own record.
//
// EACH HALF OF THE CONJUNCTION ALONE DEFENDS NOTHING A TEST HERE CAN SEE, measured by deleting each
// over urmessage and cp3b with nothing going red. Without the mls half, an own record whose inner
// frame fails for another reason -- a peek that does not parse, a generation too far ahead -- would
// be counted as this device's own; reaching those needs a record built at this device's handle with
// group keys and a bad frame, which nothing in sdk can build. Without the messagegroup half nothing
// changes at all, because no refusal on OpenRecord's path wraps the mls sentinel except through
// ErrRecordInnerFrame. The conjunction is kept because it names MG-4's one refusal exactly.
func ownFrameAlreadySpent(err error) bool {
	return errors.Is(err, messagegroup.ErrRecordInnerFrame) && errors.Is(err, mls.ErrRatchetGenerationConsumed)
}

// checkAttestationLocked performs the two halves of 4.3.4 that need no key, and counts the half
// that does. See [Group.Receive] for the whole of the decision and for S2-27.
func (self *Group) checkAttestationLocked(since uint64, fetched *protocol.FetchResponse) error {
	attestation := fetched.GetAttestation()
	if attestation == nil {
		// THE DOWNGRADE CHECK, and it reads the server's OWN advertisement rather than a
		// setting of ours: a server that says it signs and then does not is refused, and a
		// server that never claimed to is counted.
		if self.device.transport.Capabilities().GetAttestationSupported() {
			return fmt.Errorf("%w: this server advertises attestation_supported and answered a page with no attestation",
				ErrFetchAttestation)
		}
		self.stats.Unattested += 1
		return nil
	}
	if !bytes.Equal(attestation.GetGroupId(), self.id) {
		return fmt.Errorf("%w: it names group %x and this fetch was for %x",
			ErrFetchAttestation, attestation.GetGroupId(), self.id)
	}
	if attestation.GetSinceRecordId() != since {
		return fmt.Errorf("%w: it names since_record_id %d and this fetch asked from %d",
			ErrFetchAttestation, attestation.GetSinceRecordId(), since)
	}
	if attestation.GetHighWaterRecordId() != fetched.GetHighWaterRecordId() {
		return fmt.Errorf("%w: it names high_water %d and the response carries %d",
			ErrFetchAttestation, attestation.GetHighWaterRecordId(), fetched.GetHighWaterRecordId())
	}
	attested := attestation.GetRecordIds()
	records := fetched.GetRecords()
	if len(attested) != len(records) {
		return fmt.Errorf("%w: it lists %d record ids and the page carries %d records",
			ErrFetchAttestation, len(attested), len(records))
	}
	for at, record := range records {
		if attested[at] != record.GetRecordId() {
			return fmt.Errorf("%w: its record id %d at position %d is not the page's record %d",
				ErrFetchAttestation, attested[at], at, record.GetRecordId())
		}
		if attestation.GetHighWaterRecordId() < record.GetRecordId() {
			return fmt.Errorf("%w: it names high_water %d and the page carries record %d",
				ErrFetchAttestation, attestation.GetHighWaterRecordId(), record.GetRecordId())
		}
	}
	// AND THE SIGNATURE IS NOT CHECKED. Counted, never claimed. S2-27.
	self.stats.Unattested += 1
	return nil
}

// initTables allocates the per-group bookkeeping every constructor owes, IN ONE PLACE.
//
// THREE CONSTRUCTORS BUILD A [Group] -- [Device.CreateGroup], [Device.Join] and
// [Device.restoreOne] -- and each of them used to spell its own map literals. A fourth that
// forgot one would not fail to compile and would not fail a type check: it would panic on the
// first write to a nil map, inside [Group.Receive], on a device in somebody's hand. Four maps
// spelled in three places is the drift this removes.
//
// It is called AFTER the literal rather than replacing it, because the fields that differ between
// the three -- the founding session, the epoch, the opened bit, whether the group is reconciled --
// are the interesting ones and belong where a reader can see all of them at once.
func (self *Group) initTables() {
	self.tracked = map[trackedKey]bool{}
	self.delivered = map[uint64]bool{}
	self.attempts = map[uint64]int{}
	self.ownIndices = map[uint64]*ownSealed{}
	self.withoutCopy = map[uint64]bool{}
	self.ownHeads = map[trackedKey]uint64{}
}

// advanceOwnLadderLocked moves the receiver ladder over this device's OWN leaf up to the position
// this group has already authenticated, when the own record about to be opened lies past that
// ladder's window.
//
// WHY IT EXISTS, MEASURED AND NOT REASONED. Before MG-4 every own record was OPENED, in order, and
// each open committed a rung, so the ladder over this device's own leaf walked along behind them.
// Since MG-4 an own record shown from the copy, or authenticated at the spent generation, commits
// nothing -- so the own ladder stayed at its root, and the first own record that DID need opening
// past index 1,024 (messagegroup.DefaultRecordWindowSize) was ErrOutOfWindow. Measured over 1,030
// lines: a copy of the folder that was behind the original by one line reconciled cleanly and was
// NOT caught before it sealed -- the evidence record was retried three times, abandoned, and the
// next walk was clean -- and a restart with no copies left six abandoned holes.
//
// THE HEAD IS [Group.ownIndexSeen] + 1, WHICH IS CALLER STATE AND NOT A HEADER. TrackSender's
// head is walked from the root, so a number a server wrote would be a number of expansions a server
// chose; ownIndexSeen is read only off own records the group's keys authenticated or that this
// device sealed. The header's stream_index decides only WHETHER to move, never where to, and a
// move that would not raise the head is not made -- so a server that writes far-ahead indices buys
// nothing but a comparison. What moving costs is the indices below the new head: an own record
// there no longer opens. In a walk those are behind it already, because a server refuses a stream
// index that regresses.
func (self *Group) advanceOwnLadderLocked(leaf uint32, header *message.RecordHeader) error {
	retentionWire, err := message.RetentionClassWire(header.RetentionClass, header.EphBucket)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrRecordOpen, err)
	}
	key := trackedKey{leaf: leaf, retentionWire: retentionWire, ephWindow: header.EphWindow}
	head := self.ownHeads[key]
	if header.StreamIndex <= head+uint64(messagegroup.DefaultRecordWindowSize) {
		return nil
	}
	next := self.ownIndexSeen + 1
	if next <= head {
		return nil
	}
	if err := self.session.TrackSender(leaf, header.RetentionClass, header.EphBucket, header.EphWindow, next); err != nil {
		return fmt.Errorf("%w: moving this device's own ladder to index %d: %w", ErrRecordOpen, next, err)
	}
	self.ownHeads[key] = next
	self.tracked[key] = true
	return nil
}

// trackLocked installs this sender's receiver ladder once and only once.
func (self *Group) trackLocked(leaf uint32, header *message.RecordHeader) error {
	retentionWire, err := message.RetentionClassWire(header.RetentionClass, header.EphBucket)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrRecordOpen, err)
	}
	key := trackedKey{leaf: leaf, retentionWire: retentionWire, ephWindow: header.EphWindow}
	if self.tracked[key] {
		return nil
	}
	// headIndex zero: the ladder is followed from its root, which is the only honest answer for a
	// device that has been in this group since the epoch opened. It is the CALLER'S state and
	// never a number off the record, so a peer cannot choose how far this device walks.
	if err := self.session.TrackSender(leaf, header.RetentionClass, header.EphBucket, header.EphWindow, 0); err != nil {
		return fmt.Errorf("%w: tracking leaf %d: %w", ErrRecordOpen, leaf, err)
	}
	self.tracked[key] = true
	return nil
}

// leavesLocked is every member's sender_handle at this epoch, mapped to its leaf index.
//
// It is DERIVED and never read off a record: SenderHandle(group_handle_key, leaf) is the only
// thing that says which leaf a handle belongs to, and a table built from what arrived would let a
// sender name any leaf it liked.
func (self *Group) leavesLocked() (map[[16]byte]uint32, error) {
	leaves := map[[16]byte]uint32{}
	for at := 0; at < self.handle.MemberCount(); at += 1 {
		leaf, _, _, err := self.handle.MemberAt(at)
		if err != nil {
			return nil, fmt.Errorf("urmessage: the group's member %d: %w", at, err)
		}
		leaves[messagegroup.SenderHandle(self.groupHandleKey, leaf)] = leaf
	}
	return leaves, nil
}

// ── the rest of what a caller reads ──────────────────────────────────────────────────────────

// Id is this group's 32 octet identifier. A copy.
func (self *Group) Id() []byte {
	return append([]byte(nil), self.id...)
}

// Epoch is the epoch this group's session is at.
func (self *Group) Epoch() uint64 {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return self.epoch
}

// Open reports whether this device has published the group on the server.
func (self *Group) IsOpen() bool {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return self.opened
}

// Messages is every message this group has sent or received, in the order it learned them. A copy
// of the slice; the messages themselves are shared and are not written after they are appended.
func (self *Group) Messages() []*Message {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return append([]*Message(nil), self.log...)
}

// UnopenedRecords is the record ids this group has GIVEN UP on: fetched [maxRecordAttempts] times,
// refused by the AEAD or the parser every time, and no longer asked for. Ascending, a copy.
//
// IT EXISTS SO THAT A HOLE IN A CONVERSATION HAS A NAME. [Stats.Unopened] is how many; this is
// which. A caller that shows nothing here is showing a conversation with records silently missing
// from it, which is the reading this whole method set exists to prevent.
func (self *Group) UnopenedRecords() []uint64 {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return append([]uint64(nil), self.unopened...)
}

// IdentityInUse is the refusal this group is wedged on, or nil.
//
// NON-NIL MEANS ANOTHER DEVICE IS SEALING UNDER THIS DEVICE'S IDENTITY IN THIS GROUP -- a copy of
// the app-data folder. It is sticky, every [Group.Send] answers it, and a caller that shows it has
// the only sentence a user can act on: one of the two copies has to stop. See [Device.Restore] for
// what is detected and what is not.
func (self *Group) IdentityInUse() error {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return self.identityInUse
}

// Reconciled reports whether this group has compared its own stream position against the server's
// rows. A group created or joined in this process is reconciled from birth; a RESTORED one is not
// until [Group.Receive] has completed once, and [Group.Send] refuses until it has.
func (self *Group) Reconciled() bool {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return self.reconciled
}

// Stats is what this group has seen.
func (self *Group) Stats() Stats {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return self.stats
}

// Close closes both sessions and the MLS handle under them.
func (self *Group) Close() error {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if self.closed {
		return nil
	}
	self.closed = true
	var first error
	if self.session != nil {
		if err := self.session.Close(); err != nil && first == nil {
			first = err
		}
	}
	if self.founding != nil {
		if err := self.founding.Close(); err != nil && first == nil {
			first = err
		}
	}
	if err := self.handle.Close(); err != nil && first == nil {
		first = err
	}
	return first
}

// rebind is [Group.rebindLocked] for a caller that does not hold the lock.
func (self *Group) rebind() error {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if self.closed {
		return nil
	}
	return self.rebindLocked()
}

// rebindLocked moves this group's sessions onto the connection's current nonce, when and only when
// the Hello count has moved since they were last bound.
//
// A FAILED REBIND IS RETURNED AND IS NEVER SWALLOWED. A session still MAC'ing under a nonce the
// server has destroyed produces records that are refused on the wire, and a caller that was told
// its send succeeded would have a message that silently never arrives.
func (self *Group) rebindLocked() error {
	nonce, nonceEpoch, err := self.device.nonce()
	if err != nil {
		return err
	}
	if self.founding != nil && self.foundingBound != nonceEpoch {
		if err := self.founding.RebindServerNonce(nonce); err != nil {
			return fmt.Errorf("%w: the founding session at epoch 0: %w", ErrNonceRebind, err)
		}
		self.foundingBound = nonceEpoch
	}
	if self.session != nil && self.sessionBound != nonceEpoch {
		if err := self.session.RebindServerNonce(nonce); err != nil {
			return fmt.Errorf("%w: the session at epoch %d: %w", ErrNonceRebind, self.epoch, err)
		}
		self.sessionBound = nonceEpoch
	}
	return nil
}
