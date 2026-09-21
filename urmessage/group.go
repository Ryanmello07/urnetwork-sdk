package urmessage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
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

// Message is one entry of the conversation: what one record SAYS, after the content envelope has
// been read.
//
// IT IS NOT ONE RECORD. Three kinds of record produce no Message at all -- a REACTION, a TOMBSTONE
// and a COVER -- because a reaction is a change to another message and a cover is a change to
// nothing. Their effects arrive here as [Message.Reactions] and [Message.Deleted], on the message
// they name, whenever that message is present. See [Group.noteEffectLocked] for the ordering
// problem that makes "whenever" the right word.
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

	// ── what the content envelope said ───────────────────────────────────────────────────

	// The code at octet 0 of the application plaintext: what grammar [Text] and the fields
	// below were read under. See kind.go.
	//
	// A KIND THIS BUILD DOES NOT KNOW IS CARRIED HERE AS ITSELF, and that is the whole of the
	// unknown-kind rule's rendering obligation: the record kept its position and its
	// [Message.MessageId], [Message.Text] is empty, and a UI shows one closed placeholder
	// rather than a line of garbage attributed to a real sender. [ContentKind.String] names the
	// codes this registry has and prints the value of one it does not.
	//
	// ON A GAP IT IS THE CODE THE RECORD ARRIVED UNDER AND NOT WHAT THE RECORD IS. A malformed
	// REPLY carries [KindReply] here and is still a gap; what a reader branches on is
	// [Message.Gap], which is set on every gap and on nothing else. See [GapReason].
	Kind ContentKind

	// SET IFF THIS ENTRY IS A GAP: something is at this position in the conversation and this
	// build cannot show it. Empty on every message that is a message.
	//
	// IT IS THE FIELD A UI BRANCHES ON, and the reason it exists is that a gap and a blank line
	// were the same value before it. An unsupported record used to reach a caller as a [Message]
	// with an unknown [Message.Kind] and an EMPTY [Message.Text] -- indistinguishable, without
	// the registry in hand, from somebody sending nothing -- and a malformed one did not reach a
	// caller at all. Spec A section 7.4's `MessageEntry.GapReason` is this value; spec C section
	// 5.1's render table is the copy each one owes.
	Gap GapReason

	// REPLY only: the raw 32-octet message_id of the message being replied to. The quoted text
	// never travels -- the reply renders by looking its parent up -- and the parent may be
	// unavailable, deleted or not yet fetched.
	ReplyToId []byte

	// A TOMBSTONE from this message's OWN sender has been applied to it. The body is still in
	// [Message.Text]: this package refuses to decide what a UI does with a deleted line, and
	// the record itself is on the server either way.
	Deleted bool

	// The reactions standing on this message, rebuilt from every reaction record this group
	// holds for it whenever one arrives. Empty on a message nobody has reacted to.
	Reactions []Reaction
}

// GapReason is WHY a position in the conversation holds a gap rather than a message: spec A
// section 7.4's closed set, which this package renders into [Message.Gap].
//
// A GAP IS A FIRST-CLASS ENTRY AND NOT AN ERROR, which is the whole reason it is a field and not a
// refusal: something IS at this record id, this build cannot show it, and "a messenger that silently
// drops what it cannot read is a messenger that cannot be trusted to have shown you everything"
// (spec A section 7.4, verbatim). The position is kept, the message_id is kept, and the record after
// it arrives.
//
// THE SET IS CLOSED AT SEVEN AND THIS BUILD PRODUCES THREE. The three below are the three the
// receive walk can reach. THE OTHER FOUR ARE DELIBERATELY NOT DECLARED HERE -- a constant with no
// producer is a constant the next reader assumes is reachable, and each of these is waiting on
// something this package does not have:
//
//   - "expired"          a DESTROYED disappearing key. Needs the disappearing-message timer and
//     `DeleteGroupStateBefore`, and EPH(1..5) is not a class this walk opens.
//   - "not_a_member_yet" a record from before this device joined. A member added at a later epoch
//     holds no earlier epoch's schedule, so its earlier records refuse under THIS session's epoch
//     exactly as a pre-change record does -- and so they reach [GapOutOfWindow], not a value of
//     their own. Telling the two apart needs the multi-epoch open item 241 owes; until it exists
//     a record from an epoch this device cannot open is one gap however this device came to miss it.
//   - "withheld"         section 9.6's attestation refusal. The deployed server signs nothing;
//     see [Group.Receive] and S2-27.
//   - "no_wrap"          this device has no key wrap for the record's class yet. The wrap ceremony
//     is section 6.1's and no walk here reaches its absence as a gap.
//
// A further value for "the server erased the body" is OWED and does not exist in the closed set yet:
// that is ledger item 220, and a pruned DURABLE body refuses at the body-hash compare BEFORE either
// AEAD, so it is a pre-open refusal and is a fail() here today. It is deliberately not invented.
type GapReason string

const (
	// THE SENDER BROKE A RULE THAT IS ALREADY WRITTEN: [ContentMalformed]. It is NOT
	// [GapUnsupported], and the distinction is load-bearing in both directions -- a build that
	// called a future kind "malformed" would ACCUSE CORRECT SENDERS, and one that called a
	// genuinely malformed body "unsupported" would tell a user to upgrade out of a bug that no
	// upgrade fixes. Spec C section 5.1's copy for it carries NO upgrade affordance for exactly
	// that reason.
	GapMalformed GapReason = "malformed"

	// A CODE THIS BUILD DOES NOT KNOW, on a class its range allows: [ContentUnsupported]. The
	// record opened and its signature verified, so the sender did nothing wrong -- it is a newer
	// feature, and spec C section 5.1's copy for it is the one that offers the upgrade.
	GapUnsupported GapReason = "unsupported"

	// A RECORD SEALED AT AN EPOCH THIS DEVICE HAS LEFT. A [messagegroup.GroupSession] is
	// single-epoch, so a record from a past epoch refuses at §8.4.1's epoch check and no key on
	// THIS session opens it. The ordinary way to meet one is a restored device re-walking its
	// history at a later epoch -- the cursor is not persisted -- or an existing member re-reading
	// records it had not opened when a membership change moved the group on.
	//
	// IT IS A GAP AND NOT A fail(), and that is the decision A5 takes deliberately. Retrying it
	// three times spends three fetches on a disagreement no re-fetch repairs -- the epoch will not
	// come back -- and abandoning it names it [ErrRecordAbandoned], loudly, for a record that is a
	// known and expected consequence of a membership change rather than a fault. Item 241 rules
	// that history SURVIVES a membership change for existing members, through a per-epoch open
	// (an ExportAt / per-epoch LoadGroup door) this build does not have; until it lands, a
	// pre-change record is one visible, quiet gap the walk moves past. It sets no `firstFailure`,
	// so it does not hold the cursor and does not stop a restored group reconciling.
	GapOutOfWindow GapReason = "out_of_window"
)

// Reaction is one emoji standing on one message, from one member.
//
// THE REACTOR IS A sender_handle AND NOT A PERSON. The alpha has no identity system, so "the same
// reactor across one person's devices" is open item D7; until it is ruled a reactor is the leaf.
//
// THE EMOJI IS RAW AND IS NOT FOLDED TO A GROUPING KEY. Section 5.3 groups on (NFC, skin-tone
// modifiers and variation selectors removed), which needs normalisation tables this module does not
// carry -- see checkEmoji and open item M1-41 -- so two spellings of one emoji are two reactions
// here.
type Reaction struct {
	// The 16-octet sender_handle of the member who reacted.
	SenderHandle []byte

	// The emoji as that member's device sent it.
	Emoji string

	// True when this device sealed the reaction.
	Mine bool
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
//
// AND IT IS ONE OCTET SHORT OF THE MEASURED COLUMN SINCE THE CONTENT ENVELOPE LANDED. What connect
// measures is the APPLICATION PLAINTEXT's capacity, 65,334; under the 2026-09-17 ruling the
// plaintext is `kind ‖ body`, so the kind octet comes out of the same budget and the longest TEXT
// this package will seal is 65,333. That is the whole of what the envelope costs a stored record,
// and it costs nothing at all except on a body whose plaintext sat EXACTLY on a rung boundary.
const MaxTextOctets = 65333

// MaxReplyTextOctets is the same ceiling for a REPLY, which spends 32 more octets of the plaintext
// on the raw message_id its text is an answer to (rule R-c).
//
// IT IS DERIVED AND NOT MEASURED, deliberately: a second literal here would be a second column to
// keep level with connect's, and the subtraction is the layout itself.
const MaxReplyTextOctets = MaxTextOctets - MessageIdBytes

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

	// Records that OPENED and became a GAP rather than a message: the two values of [GapReason]
	// this build produces, counted apart because they are two different sentences about the
	// group and only one of them is anybody's fault.
	//
	// GapMalformed IS THE LOUD HALF OF LEDGER ITEM 224 AND IT IS WHY IT IS A COUNTER AT ALL.
	// Before it, a malformed body was a fail(): the cursor was held, the record was re-fetched
	// [maxRecordAttempts] times and then named by [ErrRecordAbandoned] -- three retries spent on
	// a disagreement about GRAMMAR, which no re-fetch can repair, and a loud error at the end of
	// them. The retries are gone and the record now resolves once, so this counter and
	// [Message.Gap] are the whole of what is left to be loud WITH: [Stats.FailedOpen] does not
	// move, [Stats.Unopened] does not move, and [Group.Receive] answers a nil error. A caller
	// that watches only the error no longer learns that a record could not be read, and that is
	// the cost of the repair, paid deliberately and written down here rather than discovered.
	//
	// GapUnsupported is not a fault in either direction: it is a member running a newer build.
	// A number here that keeps growing is this build getting old.
	GapMalformed   uint64
	GapUnsupported uint64

	// Records that became a [GapOutOfWindow] gap: sealed at an epoch this device has left, so no
	// key on this single-epoch session opens them. A restored device re-walking its history at a
	// later epoch produces one per pre-change record it holds; see [GapReason] and
	// [Group.noteEpochGapLocked]. It is the count "how much of this conversation's history a
	// membership change put out of this build's reach", which item 241 is what closes.
	GapOutOfWindow uint64

	// Commits INGESTED into this group: §6.1 membership-change records this device processed,
	// authorized, applied and followed into the next epoch. One per epoch this device did NOT
	// author but was carried into. See [Group.ingestCommitLocked].
	Ingested uint64

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

// ladderKey names one receiver ladder INDEPENDENT of the epoch its key schedule is derived at.
//
// IT IS THE EPOCH-INDEPENDENT HALF ON PURPOSE, and it is what [Group.peerHeads] is keyed by.
// §5.6's stream index is continuous across epochs -- a sender's counter does not rewind at a
// commit, because [messagegroup.SenderHandle] is derived from the epoch-zero group_handle_key and
// never moves -- so "the head this device has authenticated for this sender" is a fact about the
// whole stream and not about one epoch's schedule. A record layer key that carried the epoch would
// forget that head at every commit, which is the D3 starvation [Group.crossEpochLadderLocked]
// exists to prevent.
type ladderKey struct {
	leaf          uint32
	retentionWire byte
	ephWindow     uint64
}

// trackedKey is one receiver ladder this group has installed AT one epoch. A second TrackSender
// over a live ladder would reset it to its head index and re-derive rungs it has already
// committed, so each one is installed exactly once -- and [Group.tracked] is the memo that keeps
// it to once.
//
// THE EPOCH IS IN THE KEY AND IT IS LOAD-BEARING. [messagegroup.GroupSession.AdvanceEpoch] (and
// the constructor it shares an install with) ZEROIZES every receiver ratchet on an epoch change
// and nothing rebuilds them, so a memo that carried no epoch would still say "this ladder is
// tracked" after the change and the first open at the new epoch would fail with "no receiver
// ratchet is tracked for this sender and retention class." The epoch is what makes a new-epoch key
// miss the memo and re-track; [Group.crossEpochLadderLocked] clears the whole map in the same block
// as the install anyway, so the two are the one rule stated twice, and the AST-adjacent gate
// TestNoTrackedKeySurvivesAnEpochChangeWithoutItsEpoch holds it.
type trackedKey struct {
	epoch uint64
	ladderKey
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
	cursor uint64

	// log is every message this group holds, in the order it learned them, AND IT IS THE ONLY
	// PLACE A *Message IS HELD. Nothing else in this struct carries one -- [Group.logIndex] holds
	// a POSITION in this slice and not a pointer into it -- because the repair for msgrepo ledger
	// item 227 is that a [Message] is REPLACED rather than written through, and a second table
	// holding pointers would be a second table to leave stale. See [Group.reapplyLocked].
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

	// ── the kinds that change another message ────────────────────────────────────────────
	//
	// logIndex is where in [Group.log] every message this group holds sits, under its own
	// message_id. It is what a reaction, a tombstone or a reply resolves its target through, and
	// it is a map because the alternative is a scan of the log per effect record.
	//
	// IT HOLDS A POSITION AND NOT A POINTER, WHICH IS LEDGER ITEM 227's REPAIR IN ONE FIELD.
	// It used to be `map[...]*Message`, so a [Message] lived in two places at once and
	// [Group.reapplyLocked] kept them agreeing by writing THROUGH the pointer both of them held --
	// which is the write that reached callers holding a [Group.Messages] copy. Now the rebuild
	// REPLACES the message at its position, and a table of positions cannot go stale when it does:
	// there is exactly one holder of every *Message and it is [Group.log].
	//
	// ONE MESSAGE_ID IS ONE POSITION, which is what makes the position safe to hold. Both this map
	// and the log are written in [Group.deliverLocked] and nowhere else, together, and a record is
	// delivered at most once ([Group.delivered], keyed on the server's record id, and
	// [Group.openOwnFromCopyLocked]'s refusal of a second record id for one copy).
	logIndex map[[MessageIdBytes]byte]int

	// effects is every reaction and tombstone this group has read, under the EFFECT RECORD's
	// OWN message_id. The key is what makes a re-delivery idempotent: one record is one effect
	// however many times a rewind walks back over it, and a record's id is a function of the
	// record alone (MASTER §8.4.5).
	effects map[[MessageIdBytes]byte]*contentEffect

	// effectsOn is the same effects indexed by the message they NAME, which is the order they
	// have to be replayed in. See [Group.reapplyLocked] for why a replay rather than an
	// application.
	effectsOn map[[MessageIdBytes]byte][]*contentEffect

	// dirtyTargets is the messages whose effect set changed during the walk in progress and whose
	// rebuild has NOT happened yet. It is drained by [Group.rebuildDirtyLocked], once, where the
	// walk commits.
	//
	// IT EXISTS BECAUSE A REBUILD PER EFFECT IS A CUBE. Every arriving effect used to call
	// [Group.reapplyLocked] on its target, so n effects on ONE message cost n rebuilds of n
	// effects, and the ADD arm's dedupe scanned the reactions it had already appended -- n from the
	// walk, n from the rebuild, n from the scan. Measured on the real codec before this set
	// existed: 4,000 REACTION_ADD records on one message cost 8,087,950 mallocs and 41 seconds on
	// every OTHER member's client, growing as n^3 in time and n^2 in allocations (4x per doubling,
	// exactly), and the victim pays it ON EVERY LAUNCH because the cursor is not persisted. The
	// CONTROL that localises it: n effects over n DIFFERENT targets was already LINEAR, so the cost
	// was never the walk.
	//
	// WHAT IT DOES NOT CHANGE, AND THIS IS THE WHOLE OF WHY IT IS SAFE. The rebuild still happens,
	// still from the full sorted effect set, so [Group.reapplyLocked]'s rebuild-not-accumulate
	// property is untouched. The only new state is a target that is stale PART-WAY THROUGH A WALK,
	// and no caller outside this file can observe that: [Group.Receive] holds [Group.mutex] across
	// every page and across the commit, and [Group.Messages] takes the same mutex.
	//
	// THE TWO PLACES THAT NEED AN EFFECT'S ANSWER IMMEDIATELY DO NOT GO THROUGH THIS SET, and both
	// are outside a walk or are the walk's own repair: [Group.sendContentLocked] drains it before
	// it returns the message it just sealed, and [Group.deliverLocked] rebuilds a target directly
	// at the moment the target itself arrives.
	dirtyTargets map[[MessageIdBytes]byte]struct{}

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
	// ladder. See [Group.advanceOwnLadderLocked]. It is CLEARED at every epoch install, in the
	// same block, because the ratchet it describes is zeroized there; [Group.ownIndexSeen] is the
	// authenticated own head that survives the clear and re-seeds it.
	ownHeads map[trackedKey]uint64

	// peerHeads is the highest §5.6 stream index of a record from each PEER ladder that this group's
	// keys have AUTHENTICATED, keyed epoch-independent by [ladderKey].
	//
	// IT IS THE HEAD AN EPOCH CHANGE RE-TRACKS THAT PEER AT, AND NEVER 0. A ratchet re-tracked at 0
	// answers [messagegroup.DefaultRecordWindowSize] rungs and then ErrOutOfWindow, so a peer that
	// had sent more than 1024 records before a membership change would go silent on its very next
	// message -- the D3 starvation from the group-chat survey. Because the stream index is
	// continuous across epochs (see [ladderKey]), the head the previous epoch left off at is the
	// head the next epoch resumes from, so this is the ONE piece of ladder bookkeeping
	// [Group.crossEpochLadderLocked] does not clear. It is the peer analogue of
	// [Group.ownIndexSeen]. 0 for a ladder never seen -- a member just added, or a fresh group at
	// epoch one -- which is exactly the head [Group.trackLocked] used to pass unconditionally.
	peerHeads map[ladderKey]uint64

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

	// BY VALUE AND NOT BY REFERENCE, since 2026-09-18's CommitAdd (ledger item 239, step A2).
	// ProposeAdd-then-Commit names the add by a reference every receiver resolves against its
	// own proposal cache, so it only works while every member is handed the proposal before the
	// commit; the founding add has no other member to hand it to, and the second add -- the one
	// track A builds towards -- would have to fan a proposal record to every member first.
	// CommitAdd carries the Add inside the commit, attributed to the committer, and the SAME
	// call takes N key packages: one commit admits N members. Nothing is staged on its refusal,
	// and mls refuses the same things it refused through ProposeAdd, at the same call.
	commit, welcome, ratchetTree, err := self.handle.CommitAdd([][]byte{keyPackage})
	if err != nil {
		return nil, fmt.Errorf("urmessage: CommitAdd: %w", err)
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
	//
	// AND THE EPOCH STILL MOVES THROUGH THE ONE DOOR. enterEpochLocked is what writes the record
	// on every later epoch change; here it finds the group unopened and writes nothing, which is
	// the paragraph above stated as a rule rather than as a site that remembered.
	if err := self.enterEpochLocked(); err != nil {
		return nil, err
	}
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

// AddMemberAndPublish adds one device to an ALREADY-OPEN group and publishes the epoch it opens:
// the commit that admits the member, the wrap fan-out for the new epoch, and the marker that closes
// it -- and it answers the [Invite] the new member joins with.
//
// IT IS THE SECOND-EPOCH SIBLING OF [Group.AddMember] + [Group.Open], and the split is the alpha's
// two shapes of an add. AddMember/Open is the FOUNDING add: it runs before the group is open, needs
// the epoch-zero founding session to self-certify the founding commit, and reaches the server
// through CreateGroup. This one is every add AFTER: the group is open, there is no founding session,
// and the commit is an ordinary submit that opens the next epoch. Item 239 is what lifted the
// one-add limit that used to make this method [ErrAlphaOneAdd].
//
// THE COMMIT RECORD IS SEALED AT THE OLD EPOCH AND ANNOUNCES THE NEW ONE, which is the one subtlety.
// The server takes a commit iff its header names the current epoch and its attachment opens the
// next, so [Group.session] -- still at the old epoch after [messagegroup.GroupHandle.MergePendingCommit]
// moves the handle, for the reason [Group.AddMember]'s own comment gives -- seals the record, while a
// session freshly built at the NEW epoch supplies the write and read keys the attachment carries.
// That new session then becomes this group's, in the same block as A4's re-track and A3's persist.
//
// TWO WRITERS OF EPOCH STATE, IN ORDER. mls persists the new epoch's MLS state inside
// MergePendingCommit; [Group.enterEpochLocked] persists this package's record after the whole
// ceremony -- and nothing is a third writer. A restored group is refused ([ErrNotReconciled]) until
// it has received once, because a committer that has not checked its own stream against the server
// must not seal.
func (self *Group) AddMemberAndPublish(ctx context.Context, keyPackage []byte) (*Invite, error) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if self.closed {
		return nil, fmt.Errorf("urmessage: this group is closed")
	}
	if !self.opened {
		return nil, ErrGroupNotOpen
	}
	if self.session == nil {
		return nil, ErrNoMemberAdded
	}
	if self.identityInUse != nil {
		return nil, self.identityInUse
	}
	if !self.reconciled {
		return nil, fmt.Errorf("%w: group %x", ErrNotReconciled, self.id)
	}
	if err := self.rebindLocked(); err != nil {
		return nil, err
	}

	// (1) build the commit that admits the new member, BY VALUE, and merge it locally -- which is
	// where mls persists the new epoch's state. The handle moves to the new epoch; self.session
	// does NOT, and seals the commit record below at the epoch that is closing.
	commit, welcome, ratchetTree, err := self.handle.CommitAdd([][]byte{keyPackage})
	if err != nil {
		return nil, fmt.Errorf("urmessage: CommitAdd: %w", err)
	}
	if err := self.handle.MergePendingCommit(); err != nil {
		return nil, fmt.Errorf("urmessage: MergePendingCommit: %w", err)
	}
	newEpoch := self.handle.Epoch()

	// (2) the NEW epoch's write and read keys, which the commit's attachment announces so the
	// server can key the epoch it opens. They are derived STRAIGHT OFF the handle's new exporter --
	// the same three steps installEpochOnLoop takes inside a session -- rather than off a second
	// GroupSession, because a GroupSession's Close closes the handle it shares with this group, so
	// a transient session over this handle could not be closed without breaking the one that stays.
	// A [messagegroup.GroupSession.AdvanceEpoch] on this group's OWN session below is what actually
	// moves it, with no second goroutine to leak. write_key and read_key travel to the server in
	// the clear in the attachment, so nothing here is a new secret; the intermediates are erased.
	newMlsSecret, err := self.handle.Export(storageExporterLabel, nil, storageExporterBytes)
	if err != nil {
		return nil, fmt.Errorf("urmessage: the new epoch's exporter: %w", err)
	}
	newRoot := messagegroup.StorageRoot(newMlsSecret, self.pqSecret)
	writeKey := message.WriteKey(newRoot)
	readKey := message.ReadKey(newRoot)
	zeroizeState(newMlsSecret)
	zeroizeState(newRoot)
	groupContext, err := self.handle.GroupContextBytes()
	if err != nil {
		return nil, fmt.Errorf("urmessage: the group context: %w", err)
	}
	contextHash := sha256.Sum256(groupContext)
	memberCount := self.handle.MemberCount()

	// (3) the commit record, sealed at the OLD epoch by self.session, announcing the new epoch.
	commitRecord, err := self.session.SealRecord(message.RetentionPermanent, 0, true,
		encodeHead(self.device.nowMs()), commit, 0, &message.ServerAttachment{
			Kind: message.AttachmentEpoch,
			Epoch: &message.EpochAttachment{
				Epoch:             newEpoch,
				AlgId:             epochAttachmentAlgId,
				WriteKey:          writeKey,
				ReadKey:           readKey,
				GroupContextHash:  contextHash[:],
				ExpectedWrapCount: uint32(memberCount),
			},
		})
	if err != nil {
		return nil, fmt.Errorf("urmessage: sealing the epoch commit: %w", err)
	}
	if _, err := self.submitLocked(ctx, self.session, commitRecord, "an epoch commit"); err != nil {
		return nil, err
	}

	// (4) the epoch is open on the server. Advance this group's OWN session onto it -- reusing the
	// lifetime pq_secret (item 243), the same value AdvanceEpoch re-extracts the new root from --
	// then carry the ladder bookkeeping across (A4) and persist through the one door (A3). Session
	// and epoch move together, so a persist failure leaves the disk behind and never leaves the two
	// disagreeing. AdvanceEpoch is the committer's install, as ApplyCommit's AdvanceEpoch is the
	// receiver's; either way self.session is the one session, never a second one.
	if err := self.session.AdvanceEpoch(self.pqSecret); err != nil {
		return nil, fmt.Errorf("urmessage: advancing the session to epoch %d: %w", newEpoch, err)
	}
	self.commit = append([]byte(nil), commit...)
	if err := self.crossEpochLadderLocked(newEpoch); err != nil {
		return nil, err
	}
	if err := self.enterEpochLocked(); err != nil {
		return nil, err
	}

	// (5) the wrap fan-out and the marker that makes the new epoch writable.
	if err := self.publishEpochFanoutLocked(ctx); err != nil {
		return nil, err
	}

	return &Invite{
		GroupId:        append([]byte(nil), self.id...),
		Welcome:        append([]byte(nil), welcome...),
		RatchetTree:    append([]byte(nil), ratchetTree...),
		PqSecret:       append([]byte(nil), self.pqSecret...),
		GroupHandleKey: append([]byte(nil), self.groupHandleKey...),
	}, nil
}

// publishEpochFanoutLocked seals and submits §6.1 step (2)'s wrap set and the marker that closes
// it, at this group's CURRENT epoch. It is the half of [Group.Open] that is not the founding
// commit, and [Group.AddMemberAndPublish] runs it after the group has entered the new epoch.
func (self *Group) publishEpochFanoutLocked(ctx context.Context) error {
	wrapTargets, err := self.wrapTargetsLocked()
	if err != nil {
		return err
	}
	if len(wrapTargets) == 0 {
		return ErrNoMemberAdded
	}
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

// enterEpochLocked moves this group to the epoch its handle now stands at, AND WRITES THE RECORD IN
// THE SAME BLOCK. It is the one place [Group.epoch] is assigned, and epochpersist_test.go holds
// the package to that by reading the syntax tree rather than by trusting this sentence.
//
// WHY ONE DOOR. [GroupRecord.Epoch] is the epoch `messagegroup.GroupEngine.LoadGroup` is asked
// for at the next restart, and nothing below this package can answer "the latest" -- the mls
// store holds one blob per epoch and enumerates none of them. Until this door the record was
// written at exactly two moments, [Device.Join] and [Group.Open], both of which are epoch one.
// Every epoch change after them -- a commit this member ingests, an add it makes to a live group
// -- moved the handle and left the record naming the epoch before, and mls keeps 32 past epochs'
// state, so the next restart did not refuse: LoadGroup answered the OLD epoch, internally
// consistent in every way, and the restored device sealed under a schedule every peer had left.
// Nothing on that path says so. A record that moves with the epoch is what makes the restart
// come back at the epoch the group is at, and the only way a site can forget to write it is to
// not go through here, which the gate refuses.
//
// A GROUP WITH NO RECORD YET WRITES NONE. [Group.AddMember]'s paragraph is the rule: the
// founder's record is written by Open, because a founder that died before Open must NOT come
// back as a conversation it can see and never send in. `opened` is the field both record
// writers set, so it is the fact "a record exists" read off the group rather than a second flag
// to keep agreeing with the first.
//
// THE CALLER HAS ALREADY REBUILT THE SESSION, or is about to and holds no record of the epoch
// either way. This method does not touch [Group.session]: a session is an epoch's whole key
// schedule installed at construction, and which nonce, reserver and clock it is built over is
// the caller's business. What this method owes is that the number the next restart is handed is
// the number the handle answers now, and that the two are written in one place.
//
// ON A REFUSAL THE IN-MEMORY GROUP HAS MOVED AND THE DISK HAS NOT, and the error says so. The
// alternative -- move the field only after the write -- leaves a group whose session is at one
// epoch and whose epoch field names another, which every header this group seals would carry.
func (self *Group) enterEpochLocked() error {
	self.epoch = self.handle.Epoch()
	if !self.opened {
		return nil
	}
	if err := self.device.persistGroup(&GroupRecord{
		GroupId:        self.id,
		PqSecret:       self.pqSecret,
		GroupHandleKey: self.groupHandleKey,
		Epoch:          self.epoch,
		Opened:         true,
	}); err != nil {
		return fmt.Errorf(
			"urmessage: this group entered epoch %d and its record could not be persisted, so a restart would come back at the epoch before: %w",
			self.epoch, err)
	}
	return nil
}

// ── sending ──────────────────────────────────────────────────────────────────────────────────

// Send seals one line of text as a DURABLE record and submits it.
//
// WHAT IS SEALED IS `kind(TEXT) ‖ text` AND NOT THE TEXT, which is the 2026-09-17 ruling and is why
// [MaxTextOctets] is one octet short of connect's measured column. See kind.go.
//
// The size bucket is whatever the text needs: [messagegroup.GroupSession.SealRecord] walks the
// ladder and takes the smallest rung the padded body fits, so a message leaks its rung rather than
// its length. THE RUNGS ARE NOT WHAT THEY WERE. Since connect 4c030dc the text is carried inside an
// MLS PrivateMessage that itself sits inside the rung, and the usable PLAINTEXT per rung, measured
// through this method and a real server's rows by
// cp3b.TestEveryRecordTypeUrmessageSealsLandsOnTheRungItsBodyNeeds, is 59 / 826 / 3,898 / 16,186 /
// 65,334 octets where it was 252 / 1,020 / 4,092 / 16,380 / 65,532 -- one of which the kind now
// spends, so the text column is 58 / 825 / 3,897 / 16,185 / 65,333. A text over [MaxTextOctets] --
// including the 198 octets up to the old ceiling -- is refused with [ErrTextTooLong]; blob-backed
// bodies are out of scope.
//
// THE LENGTH REFUSAL IS TAKEN HERE AND COSTS NOTHING, which is a change from every build before
// this one: see [MaxTextOctets] for the 198 octet band that used to spend a durable stream index
// and an MLS generation on its way to the same error, and for why the sealer's own early refusal
// cannot cover it.
//
// AND AN EMPTY TEXT IS REFUSED, which is a PRODUCT change and not a size one: TEXT's body is a tail
// of at least one octet (rule R-d), so an empty line is a message the format has no encoding for
// and [ErrContentMalformed] is the answer. Before the content envelope it sealed a record with an
// empty body, which every receiver rendered as a blank line.
//
// IT NEVER RETURNS NIL ON A MESSAGE THAT DID NOT LAND. The record is accepted by the server, or
// this returns an error naming the refusal -- including after S2-2's single re-Hello and re-MAC.
func (self *Group) Send(ctx context.Context, text string) (*Message, error) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if err := self.sendableLocked(); err != nil {
		return nil, err
	}
	// THE ENCODE IS THE LENGTH REFUSAL AND IT IS BEFORE THE SEAL, one clause further out than the
	// sealer can take it. See [MaxTextOctets]: the sealer's own early refusal is over the CALLER's
	// length against the rung, and the frame that decides the real rung does not exist until an
	// index has been reserved and a generation spent.
	//
	// IT IS AFTER THE STICKY REFUSALS IN sendableLocked AND THAT ORDER IS DELIBERATE. A group that
	// has seen a second writer, or a restored group that has not reconciled, must say THAT rather
	// than report a fact about the length of this particular line.
	plaintext, err := encodeText(text)
	if err != nil {
		return nil, err
	}
	return self.sendContentLocked(ctx, plaintext, "a message")
}

// SendReply seals one line of text that names the message it answers, and submits it.
//
// replyTo is the parent's [Message.MessageId], raw, 32 octets. THE QUOTED TEXT NEVER TRAVELS: a
// reply carries its parent's NAME and renders by looking the parent up, which is what spec A §7.4's
// ephemeral-containment rule requires of a reply to an ephemeral message and what keeps a reply
// from being a second copy of a line the group already paid for.
//
// A reply is a new message and takes the conversation's own class, so its ceiling is
// [MaxReplyTextOctets] rather than [MaxTextOctets]: the 32 octets of the name come out of the same
// plaintext budget as the text.
func (self *Group) SendReply(ctx context.Context, replyTo []byte, text string) (*Message, error) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if err := self.sendableLocked(); err != nil {
		return nil, err
	}
	// THE PARENT IS NOT REQUIRED TO BE PRESENT, and that is the one place this differs from
	// [Group.React] and [Group.Delete]. A reply is a message in its own right: it renders whether
	// or not its parent is holdable, and the parent may legitimately be gone -- pruned, expired,
	// or not yet fetched by THIS device while the sender holds it. A reaction and a tombstone
	// have nothing to be but a change to something else, so those two refuse.
	plaintext, err := encodeReply(replyTo, text)
	if err != nil {
		return nil, err
	}
	return self.sendContentLocked(ctx, plaintext, "a reply")
}

// React seals one REACTION_ADD naming a message this group holds, and submits it.
//
// The emoji is sealed as the octets the caller passed. WHAT IS AND IS NOT VALIDATED is checkEmoji's
// comment and it is the honest half: valid UTF-8 of 1..[MaxEmojiOctets] octets, and NOT "exactly one
// extended grapheme cluster from the pinned Unicode version", which needs a UAX-29 dependency
// nobody has decided to take (open item M1-41).
//
// IT ANSWERS THE REACTION RECORD'S OWN [Message], WHICH IS NOT A LINE OF THE CONVERSATION. A
// reaction creates no entry: it changes the message it names, which this group applies locally at
// the same moment. The value is returned so that a caller has the record id and the message_id of
// what it just sent -- the two things a later Unreact and any log would need.
func (self *Group) React(ctx context.Context, target []byte, emoji string) (*Message, error) {
	return self.react(ctx, KindReactionAdd, target, emoji)
}

// Unreact seals one REACTION_REMOVE. It cancels an ADD with the same (reactor, target, emoji) --
// see [Reaction] for what "the same" means in a build with no identity system and no grouping key.
func (self *Group) Unreact(ctx context.Context, target []byte, emoji string) (*Message, error) {
	return self.react(ctx, KindReactionRemove, target, emoji)
}

func (self *Group) react(ctx context.Context, kind ContentKind, target []byte, emoji string) (*Message, error) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if err := self.sendableLocked(); err != nil {
		return nil, err
	}
	// K9/K5: a reaction may name a stored content message and nothing else, and a call naming an
	// id this device does not hold is a CALL ERROR that emits no record. It is not a courtesy
	// check: a reaction on an id nothing carries is a record every receiver holds for ever
	// waiting for a target that does not exist.
	if _, err := self.reactableLocked(target); err != nil {
		return nil, err
	}
	plaintext, err := encodeReaction(kind, target, emoji)
	if err != nil {
		return nil, err
	}
	return self.sendContentLocked(ctx, plaintext, "a reaction")
}

// Delete seals one TOMBSTONE naming a message of THIS DEVICE'S OWN, and submits it.
//
// THE SAME-SENDER RULE IS ENFORCED ON BOTH SIDES AND THIS IS THE SEND SIDE (T-b). A tombstone
// applies only if its sender_handle equals the target's, which is what MASTER §12.1's "a deletion
// cannot be forged" needs beyond R1: R1 proves who wrote the TOMBSTONE and nothing proves they
// wrote the target. So a tombstone naming somebody else's message is a record every honest receiver
// would ignore, and the honest thing is not to seal one.
//
// WHAT IT DOES NOT DO. It does not erase the record on the server -- spec B's B6 is "no
// client-initiated server-side erase in v1" -- and it does not decide what a UI shows: the target
// is marked [Message.Deleted] and keeps its text, because this package refuses to be the layer that
// throws away a user's data on a peer's say-so.
//
// THE 24-HOUR WINDOW IS NOT IMPLEMENTED AND IS NOT FORGOTTEN. MASTER §12.1:2564 bounds a tombstone
// to 24 hours and no document says WHICH CLOCK measures it; every clock reading in a record is its
// sender's claim, and the three candidate clocks are enumerated as owner choice 6 (msgrepo
// docs/reports/2026-09-16-content-kinds.md §5.4 T-d). Building one of them here would be this
// package taking an owner's decision.
func (self *Group) Delete(ctx context.Context, target []byte) (*Message, error) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	if err := self.sendableLocked(); err != nil {
		return nil, err
	}
	held, err := self.reactableLocked(target)
	if err != nil {
		return nil, err
	}
	if !held.Mine {
		return nil, fmt.Errorf("%w: message %x was sealed by %x and this device may only delete its own",
			ErrContentMalformed, target, held.SenderHandle)
	}
	plaintext, err := encodeTombstone(target)
	if err != nil {
		return nil, err
	}
	return self.sendContentLocked(ctx, plaintext, "a tombstone")
}

// sendableLocked is every refusal a send owes BEFORE it looks at what is being sent. It is one
// function because four entry points owe the same five, in the same order, and a fifth entry point
// that forgot one would seal under a reused identity.
func (self *Group) sendableLocked() error {
	if self.closed {
		return fmt.Errorf("urmessage: this group is closed")
	}
	if self.session == nil {
		return ErrNoMemberAdded
	}
	if !self.opened {
		return ErrGroupNotOpen
	}
	// BEFORE THE REBIND AND BEFORE THE SEAL, because the seal is the irreversible half: a
	// record sealed under a reused (key, nonce) exists whatever this method then returns.
	if self.identityInUse != nil {
		return self.identityInUse
	}
	if !self.reconciled {
		return fmt.Errorf("%w: group %x", ErrNotReconciled, self.id)
	}
	return nil
}

// reactableLocked answers the message a reaction or a tombstone may name, and refuses one it may
// not. T-a and K9 are the same rule read from two sides: the target must be a STORED CONTENT
// message -- TEXT or REPLY here, ATTACHMENT when the blob plane exists -- and a reaction, a
// tombstone and a COVER are not entries and cannot be named.
//
// THEY CANNOT BE NAMED BY CONSTRUCTION RATHER THAN BY A CLAUSE, which is worth knowing before
// somebody deletes the kind check below: this group's [Group.logIndex] holds only records that
// BECAME a [Message], and a reaction, a tombstone and a COVER become none. The clause is what makes
// the rule survive a later kind that does become a message and still may not be reacted to.
//
// AND A GAP IS REFUSED BEFORE THE KIND IS READ AT ALL, for the same reason [Group.deliverLocked]
// checks it first: a gap's [Message.Kind] is the code the record ARRIVED under, so a malformed REPLY
// body carries [KindReply] and would fall straight through the switch below into "yes, react to
// this" -- a reaction sealed against a record this device could not read, quoting an id whose
// content nobody in the group can agree on. T-a's own words are that a target must be a stored
// CONTENT message, and a gap is by definition the absence of one.
func (self *Group) reactableLocked(target []byte) (*Message, error) {
	if len(target) != MessageIdBytes {
		return nil, fmt.Errorf("%w: a message_id is %d octets and this one is %d",
			ErrContentMalformed, MessageIdBytes, len(target))
	}
	held, found := self.heldLocked(target)
	if !found {
		return nil, fmt.Errorf("%w: %x", ErrNoSuchMessage, target)
	}
	if held.Gap != "" {
		return nil, fmt.Errorf("%w: message %x is a %s gap, which is a record this build could not show",
			ErrNoSuchMessage, target, held.Gap)
	}
	switch held.Kind {
	case KindText, KindReply:
		return held, nil
	}
	return nil, fmt.Errorf("%w: message %x is a %s, which carries no reactions and no tombstone",
		ErrNoSuchMessage, target, held.Kind)
}

// sendContentLocked seals one already-encoded application plaintext as a DURABLE record, submits
// it, and folds what it says back into this group.
//
// IT PARSES WHAT IT IS ABOUT TO SEAL, BEFORE THE SEAL, and that is a gate rather than a
// belt-and-braces: the encoder and the parser are two sides of one grammar, and the day they
// disagree the sender ships a record every receiver refuses as malformed while its own screen shows
// it correctly. Taking the refusal here costs nothing -- no stream index, no MLS generation -- and
// what a sender then displays is built by the SAME code path the receiver's display is.
func (self *Group) sendContentLocked(ctx context.Context, plaintext []byte, what string) (*Message, error) {
	entry, verdict, why := ParseContent(plaintext, message.RetentionDurable, 0)
	if verdict != ContentParsed {
		return nil, fmt.Errorf("urmessage: this build would not read back the %s it was about to seal (%s): %w",
			what, verdict, why)
	}
	if err := self.rebindLocked(); err != nil {
		return nil, err
	}
	sentAtMs := self.device.nowMs()
	record, err := self.session.SealRecord(message.RetentionDurable, 0, false,
		encodeHead(sentAtMs), plaintext, 0, nil)
	if err != nil {
		if errors.Is(err, messagegroup.ErrBodyTooLong) {
			return nil, fmt.Errorf("%w: %d octets: %w", ErrTextTooLong, len(plaintext), err)
		}
		return nil, fmt.Errorf("urmessage: sealing %s: %w", what, err)
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
		return nil, fmt.Errorf("urmessage: %s was sealed and NOT sent, because its message_id could not be derived: %w", what, err)
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
	// WHAT IS KEPT IS THE PLAINTEXT AND NOT THE TEXT, which is [SentRecord.Body]'s own definition
	// -- "what was sealed, octets, never interpreted" -- and is what lets the own-copy path read a
	// restored device's own reply, reaction and tombstone back through the same codec every other
	// member reads them through.
	//
	// IT IS DURABLE BEFORE THE SUBMIT, OR THE SUBMIT DOES NOT HAPPEN. A record that reached the
	// server with no copy on the disk is a line the user typed that a restart of this device can
	// never show them again, and nothing afterwards could repair it. Refusing here costs one
	// stream index and one MLS generation, both legal gaps, and the user sees the send fail and
	// types it again.
	sealed := &ownSealed{
		bodyHash: record.Header.BodyHash,
		hasCopy:  true,
		body:     append([]byte(nil), plaintext...),
		sentAtMs: sentAtMs,
	}
	self.ownIndices[record.Header.StreamIndex] = sealed
	if err := self.device.persistSent(self.id, record.Header.StreamIndex, sealed); err != nil {
		return nil, fmt.Errorf("urmessage: %s was sealed and NOT sent, because the copy a restart would show it from could not be persisted: %w", what, err)
	}
	recordId, err := self.submitLocked(ctx, self.session, record, what)
	if err != nil {
		return nil, err
	}
	sealed.recordId = recordId
	// NO GAP IS REACHABLE HERE AND IT IS A PRECONDITION RATHER THAN A CHOICE: this method refuses
	// every verdict but [ContentParsed] at its first line, BEFORE the seal, so a record this device
	// sends is by construction one it can read back. A send path that could produce a gap would be a
	// device showing itself a placeholder for a message it had just written.
	sent := newMessage(entry, recordId, record.Header.SenderHandle[:], true, sentAtMs, messageId[:])
	line := self.deliverLocked(sent, entry)
	// THIS IS A SEND AND NOT A WALK, SO THE REBUILD CANNOT WAIT FOR ONE. A reaction or a tombstone
	// this device has just sealed is one the caller is about to read back off [Group.Messages], and
	// there is no [Group.commitWalkLocked] between here and that read.
	self.rebuildDirtyLocked()
	// AND THE ANSWER IS RE-READ FOR THE SAME REASON [Group.commitWalkLocked] re-reads walk.opened:
	// since ledger item 227 a rebuild REPLACES the message rather than writing through it, so the
	// value built above would be frozen the moment anything standing on it were applied. A message
	// this send added no line for -- a reaction, a tombstone, a COVER -- is not in the log at all
	// and is returned as itself, which is what it has always been: the record's own [Message], not
	// an entry in the conversation.
	//
	// THIS RE-READ DEFENDS NOTHING A TEST CAN SEE TODAY, MEASURED AND NOT ASSUMED: deleting it
	// leaves ./urmessage and ./cp3b green, because NOTHING CAN BE HELD FOR A MESSAGE THIS DEVICE
	// HAS ONLY JUST SEALED. An effect names its target by message_id, message_id is a function of
	// a header this call produced seconds ago, and no member can have named an id that did not
	// exist -- so [Group.effectsOn] for it is empty and [Group.reapplyLocked] returns without
	// replacing anything.
	//
	// IT IS KEPT BECAUSE IT IS THE OTHER END OF THAT ARGUMENT AND NOT BECAUSE IT IS FREE. What
	// makes the branch unreachable is reapplyLocked's empty-effect-set early return, which is a
	// COST decision -- it is what keeps a delivery of a message nobody has reacted to from
	// allocating a copy of it. Delete that early return, for a reason that will look entirely
	// local, and every send starts returning a [Message] this same call replaced in the log: the
	// caller's own line, correct in every field, and a different object from the one the
	// conversation holds. This clause is what keeps that from being a silent change.
	if line {
		if held, found := self.heldLocked(messageId[:]); found {
			sent = held
		}
	}
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
	// THE READ KEY IS RE-DERIVED WHEN THE EPOCH MOVES UNDER THIS WALK, and it used to be derived
	// once. A5's ingest can advance [Group.epoch] in the MIDDLE of a walk -- an is_commit record on
	// one page opens an epoch whose messages arrive on the next -- and §4.3.4's read authenticator
	// is a mac under the read key of the epoch the fetch NAMES. A page requested with ReadEpoch set
	// to the new epoch but MAC'd under the old epoch's read key is refused by the server, so the
	// read key follows the epoch. It is a closure over a captured epoch rather than a re-derivation
	// per page, so a walk that does not cross an epoch pays exactly the one derivation it did before.
	var epochKeys *messagegroup.EpochKeys
	var readKey []byte
	readKeyEpoch := ^uint64(0)
	defer func() {
		if epochKeys != nil {
			epochKeys.Destroy()
		}
	}()
	refreshReadKey := func() error {
		if epochKeys != nil && readKeyEpoch == self.epoch {
			return nil
		}
		next, err := self.session.EpochKeys()
		if err != nil {
			return fmt.Errorf("urmessage: this epoch's keys: %w", err)
		}
		key, err := next.ReadKey()
		if err != nil {
			next.Destroy()
			return err
		}
		if epochKeys != nil {
			epochKeys.Destroy()
		}
		epochKeys = next
		readKey = key
		readKeyEpoch = self.epoch
		return nil
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
		if err := refreshReadKey(); err != nil {
			self.commitWalkLocked(walk)
			return walk.opened, err
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
	// AND THE EFFECTS THIS WALK NOTED ARE REBUILT HERE, ONCE PER TARGET. Every [Group.Receive] exit
	// runs through this function, including the ones that return an error, so a walk that ended
	// badly still leaves the targets it touched consistent with the effects it recorded.
	self.rebuildDirtyLocked()
	// AND THEN THE WALK'S OWN ANSWER IS RE-READ, BECAUSE THE REBUILD REPLACES RATHER THAN WRITES.
	// walk.opened carries the [Message] values [Group.Receive] is about to hand its caller, taken
	// as each record was delivered and therefore BEFORE the line above. Since ledger item 227 a
	// rebuild leaves the message it rebuilt frozen and puts a new one in the log, so without this
	// a reaction that arrived in the SAME page as its target would be applied in the group and
	// missing from the slice Receive returns -- a caller that renders what Receive hands it,
	// rather than re-reading [Group.Messages], would never see it. Every entry is re-read from
	// the log, so what comes back is what this group holds at the moment the walk committed.
	for index, one := range walk.opened {
		if held, found := self.heldLocked(one.MessageId); found {
			walk.opened[index] = held
		}
	}
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
		if header.IsCommit {
			// A5: AN is_commit RECORD IS INGESTED, NOT SKIPPED -- but only the ONE that opens the
			// epoch this session is at, which is the commit whose header names this epoch (a
			// commit sealed at epoch E opens E+1, and this member at epoch E is the member that
			// must follow it). Every other is_commit record is ceremony this walk reads past: the
			// FOUNDING commit once this device is past epoch one (header epoch 0), and any commit
			// this device has already ingested and moved beyond on an earlier walk. Both would be
			// refused by OpenCeremonyRecord under this session's epoch check anyway (§8.4.1), so the
			// guard here and that check are the one rule; deciding it here keeps a stale commit off
			// the ingest path and out of a fail().
			if header.Epoch != self.epoch {
				self.stats.SkippedCeremony += 1
				resolve(recordId)
				continue
			}
			if err := self.ingestCommitLocked(walk, parsed); err != nil {
				fail(recordId, err)
				continue
			}
			self.stats.SkippedCeremony += 1
			resolve(recordId)
			continue
		}
		if len(header.ServerAttachment) != 0 {
			// THE CEREMONY RECORDS AROUND A COMMIT: the epoch's wrap fan-out and the epoch-complete
			// marker. They are STILL SKIPPED, deliberately. In the alpha a wrap carries no key
			// material ([alphaWrapBody]) and the marker is the server's own step-(2) fence, so
			// there is nothing in either for a receiving member to read: the epoch's key schedule
			// comes off the MLS exporter the COMMIT moved, not off these. A joiner gets its material
			// from the Welcome. So the ingest reads the commit and skips the fan-out around it.
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
		if header.Epoch < self.epoch {
			// A RECORD SEALED AT AN EPOCH THIS DEVICE HAS LEFT. A [messagegroup.GroupSession] is
			// single-epoch, so no key on this session opens it -- and this walk has already routed
			// past the commit that would have kept the two epochs' records together (the cursor is
			// not persisted, so a restored device re-walks its whole history at its later epoch).
			// It is a VISIBLE GAP and not a fail(): see [GapOutOfWindow]. Own and peer alike, because
			// the own-copy path refuses an epoch mismatch too and item 241's history-across-a-change
			// is a later step; what THIS build owes is that the record is not lost silently.
			self.noteEpochGapLocked(walk, recordId, header)
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
		// THE CONTENT ENVELOPE, read by the ONE codec both sides of this package use. What this
		// used to do was `Text: string(bodyPlain)` with no branch, which is what headVersion 0x02
		// exists to keep a pre-kinds record away from.
		//
		// THE THREE NON-PARSED ANSWERS ARE THREE DIFFERENT ACCOUNTINGS and that is the whole
		// reason the codec answers a verdict rather than an error:
		//
		//   - MALFORMED and UNSUPPORTED are both GAPS, and they are gaps with two different
		//     [GapReason]s. Neither is a fail(). Both are handled BELOW, with the parsed case,
		//     because a gap is a first-class ENTRY: it keeps its position and its message_id, it
		//     does not count toward [ErrRecordAbandoned], and it becomes one closed placeholder.
		//   - DROPPED is a transient on EPH(0): nothing was persisted, so there is nothing to
		//     render and nothing to be a hole. UNREACHABLE FROM THIS WALK TODAY -- the class skip
		//     above resolves every non-DURABLE record before this point -- and it is here because
		//     the codec can answer it and a reader of this switch should not have to prove that.
		//     IT IS THE ONE VERDICT THIS CHANGE DID NOT TOUCH.
		//
		// WHY MALFORMED IS NO LONGER A fail(), WHICH IS LEDGER ITEM 224 AND IS A BOUNDARY RATHER
		// THAN A PREFERENCE. Everything above this line is a refusal that a RE-FETCH CAN REPAIR:
		// a record that did not parse, a sender_handle that is no leaf of this epoch, a ladder
		// that would not install, an AEAD that would not open, a head this build did not write.
		// Every refusal raised from HERE DOWN is raised AFTER OpenRecord returned -- so the key
		// schedule and the ratchet are already satisfied AND COMMITTED, the signature verified,
		// and what is left in dispute is GRAMMAR. Asking the server for the same octets a second
		// time cannot change the answer, and the old path spent [maxRecordAttempts] fetches
		// finding that out before naming the record in [ErrRecordAbandoned].
		//
		// WHAT THAT COSTS AND WHAT IT BUYS, both stated because the trade is real. It buys the
		// record its POSITION: a malformed body used to hold the cursor for three Receives and
		// then become a hole this build had given up on, and it is now one visible gap the walk
		// moves past. It costs LOUDNESS: [Group.Receive] answered ErrContentMalformed through
		// ErrRecordOpen, and then ErrRecordAbandoned, and it now answers nil. What is left to be
		// loud with is [Stats.GapMalformed] and [Message.Gap], which is why both exist.
		//
		// AND WHY THE ERROR IS NOT KEPT AS WELL, which is the obvious third option and is WRONG:
		// [Group.walkReconcilesLocked] gates the clone check on `walk.firstFailure == nil`, and
		// the cursor is not persisted, so a restored group re-walks its whole history on every
		// launch. A malformed record that set firstFailure would set it on EVERY launch, for
		// ever, and that group would never reconcile -- so [Group.Send] would stay
		// [ErrNotReconciled] permanently. One malformed record from any member would take away
		// every restarted device's ability to send, which is a wedge handed to any member. The
		// bound that keeps the EXISTING fail() path from doing this is abandonment, and a record
		// that is no longer retried never reaches it. A record that opened also contributes its
		// own stream index as clone evidence, which is what firstFailure's presence in that gate
		// is protecting; so a gap is not evidence-poor and has no business in it.
		//
		// THE CODEC'S REFUSAL SENTENCE IS DISCARDED HERE AND THAT IS A NAMED LOSS. It used to
		// reach a caller wrapped in [ErrRecordOpen], and this package has no logger to put it
		// in; spec C §5.1's copy for a gap is one sentence with NO error code, deliberately, so
		// putting it on the [Message] would be an error code by another name. What survives is
		// which reason it was, in [Message.Gap] and in [Stats].
		entry, verdict, _ := ParseContent(bodyPlain, header.RetentionClass, header.EphBucket)
		if verdict == ContentDropped {
			self.stats.SkippedClass += 1
			resolve(recordId)
			continue
		}
		gap := GapReason("")
		switch verdict {
		case ContentMalformed:
			// THE CODEC ANSWERS NO ENTRY FOR A MALFORMED PLAINTEXT and the gap still owes a
			// reader the code the record arrived under, so one is built from octet 0 -- and
			// from NOTHING ELSE, because a body this build refused is a body it must not
			// quote.
			gap = GapMalformed
			self.stats.GapMalformed += 1
			entry = &Content{Kind: contentKindOf(bodyPlain)}
		case ContentUnsupported:
			gap = GapUnsupported
			self.stats.GapUnsupported += 1
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
		} else {
			// A PEER RECORD THAT OPENED, so its stream index is one this group's keys
			// authenticated: raise the head this peer's ladder will be re-tracked at after the
			// next epoch change. See [Group.notePeerHeadLocked] and [Group.crossEpochLadderLocked].
			self.notePeerHeadLocked(leaf, header)
		}
		var received *Message
		if gap == "" {
			received = newMessage(entry, recordId, header.SenderHandle[:], mine, sentAtMs, messageId[:])
		} else {
			received = newGap(gap, entry, recordId, header.SenderHandle[:], mine, sentAtMs, messageId[:])
		}
		// WHAT A RECORD BECOMES IS ONE DECISION AND IT IS TAKEN IN ONE PLACE. A reaction, a
		// tombstone and a COVER are records that add no line, and [Group.deliverLocked] is what
		// says so -- for this walk, for the own-copy path and for [Group.Send] alike, because
		// three sites that each decided it would be three sites to keep level.
		if self.deliverLocked(received, entry) {
			walk.opened = append(walk.opened, received)
		}
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
	// THE COPY IS AN APPLICATION PLAINTEXT AND IS READ BY THE SAME CODEC EVERY OTHER MEMBER READS
	// THIS RECORD WITH. [SentRecord.Body] is "what was sealed, octets, never interpreted", and what
	// [Group.Send] seals is `kind ‖ body` -- so this device's own reply, its own reaction and its
	// own tombstone come back through this path with the same meaning the group gives them, rather
	// than as a line of text that happens to start with an 0x02.
	//
	// A COPY THIS BUILD CANNOT READ IS NOT SHOWN AND IS NOT A SECOND KIND OF SILENCE. The one
	// population that reaches it is a state directory written by a PRE-KINDS build, whose copies
	// are raw text with no code, so the first octet of somebody's sentence is read as a kind.
	//
	// WHAT THAT COSTS, MEASURED OVER THE WHOLE FIRST-OCTET SPACE ON DURABLE AND NOT REASONED. Of
	// the 95 printable ASCII characters, 63 ARE MALFORMED and 32 render as a placeholder:
	//
	//	MALFORMED   0x40..0x7E -- '@', EVERY LETTER, and [ \ ] ^ _ ` { | } ~
	//	PLACEHOLDER 0x20..0x3F -- space, the punctuation of the first column, and the digits
	//
	// The 63 are malformed because 0x40..0x7F is the TRANSIENT range, which is legal on EPH(0) and
	// on no stored class, and a transient code on DURABLE is a rule the code alone decides. THAT IS
	// EVERY ENGLISH SENTENCE: a line beginning "h" is kind 0x68, which is 104, which is inside that
	// range -- not an unassigned code, and not a placeholder. This comment said the opposite and
	// said it for four reviews; the split is now a number that
	// TestTheMeasuredSplitOfAPrintableFirstOctetOnADurableCopy re-measures.
	//
	// SO THE COMMON CASE IS THE FALL-THROUGH, WHICH IS THE HONEST ONE. A copy that is malformed
	// under the codec is not shown here at all: it falls to the ordinary path, where it is
	// authenticated as this device's own and counted in [Stats.OwnWithoutCopy] -- a hole this device
	// NAMES, which is what "this build cannot read what it wrote" honestly is. The 32 that do render
	// render as one closed placeholder under the unknown-kind rule, which is the same answer every
	// other member's build gives an unknown code.
	//
	// AND NO OLD LINE IS EVER SILENTLY REINTERPRETED, which is the half of this that would have been
	// the real failure. The six codes this build has a grammar for are 0x01, 0x02, 0x04, 0x05, 0x06
	// and 0x07 -- all non-printable -- so NO printable-ASCII first character parses as a known kind
	// AT ANY LENGTH, swept and not argued. A pre-kinds line can be a named hole or a placeholder; it
	// cannot come back as a reply, a tombstone or a reaction.
	//
	// The local copy has no version byte of its own to refuse on, and buying one would cost the
	// state store's single version lever -- which every OTHER record in the directory, the device
	// identity included, is read under.
	entry, verdict, _ := ParseContent(sealed.body, header.RetentionClass, header.EphBucket)
	if verdict == ContentMalformed || verdict == ContentDropped {
		return false, nil
	}
	messageId, err := self.session.MessageIdOf(header)
	if err != nil {
		return false, fmt.Errorf("%w: record %d is this device's own at stream index %d and its message_id could not be derived: %w",
			ErrRecordOpen, recordId, header.StreamIndex, err)
	}
	sealed.recordId = recordId
	self.stats.OpenedOwn += 1
	self.noteOwnIndexLocked(walk, recordId, header.StreamIndex, header.BodyHash)
	// AND THE PLACEHOLDER HALF OF THE SPLIT ABOVE IS A GAP LIKE ANY OTHER. The 32 printable first
	// octets that answer [ContentUnsupported] reach a caller from HERE, not from the walk, and if
	// this site alone left [Message.Gap] empty then this device's own pre-kinds line would be the one
	// blank message in a build that has no others -- the exact failure this whole change is for,
	// surviving at the one call site nobody was looking at. The malformed 63 never reach this line:
	// they answered false above and are counted in [Stats.OwnWithoutCopy] by the ordinary path.
	received := newMessage(entry, recordId, header.SenderHandle[:], true, sealed.sentAtMs, messageId[:])
	if verdict == ContentUnsupported {
		self.stats.GapUnsupported += 1
		received = newGap(GapUnsupported, entry, recordId, header.SenderHandle[:], true, sealed.sentAtMs, messageId[:])
	}
	if self.deliverLocked(received, entry) {
		walk.opened = append(walk.opened, received)
	}
	self.delivered[recordId] = true
	return true, nil
}

// ── ingesting a commit: §6.1's membership change on the receiving side (A5) ───────────────────

// CommitMember is one member of a group as it stands at the moment a commit is authorized: the
// leaf a role is read at, and the sender_handle that names it on the wire.
type CommitMember struct {
	// Leaf is the member's leaf index in the ratchet tree.
	Leaf uint32

	// SenderHandle is [messagegroup.SenderHandle] for this leaf at this epoch: the 16 octets its
	// records carry. A copy.
	SenderHandle []byte
}

// CommitAuthorization is everything a receiving client's authorization decision is handed about one
// ingested commit, BEFORE it is applied.
//
// IT IS THE RECEIVING ARM OF MASTER §11, shaped now and filled later. §11 rules that a bad commit
// "is refused by the committing client, and is rejected by every receiving client on validation."
// The receiving-client arm is the commit-ingest path, and this is the value the check reads. The
// full role model (item 242) is not built; [CommitAuthorizer] returns nil today. What is built is
// the CALL, on the path, with the inputs a role check needs -- so the check fills the body without
// moving the call, which the plan says is strictly cheaper than retrofitting the path later.
type CommitAuthorization struct {
	// GroupId is the 32-octet group this commit is in. A copy.
	GroupId []byte

	// Epoch is the epoch this commit OPENS -- the current epoch plus one. The membership below and
	// the committer are as they stood at the epoch that is closing, which is where a role is read.
	Epoch uint64

	// CommitterLeaf is the AUTHENTICATED leaf that authored the commit: the commit's signature has
	// been verified against this leaf by [messagegroup.GroupHandle.Process] before this value is
	// built. A role check reads the committer's role at this leaf in [CommitAuthorization.Members].
	CommitterLeaf uint32

	// AddedLeaves, RemovedLeaves and UpdatedLeaves are where the commit's proposals landed, off the
	// staged commit rather than off any header. A role check reads them to decide whether the
	// committer's role permits what the commit does -- e.g. MASTER §11's ErrAdminRemovedByNonOwner.
	AddedLeaves   []uint32
	RemovedLeaves []uint32
	UpdatedLeaves []uint32

	// Members is the membership as it stands BEFORE the commit is applied. A role check reads the
	// committer's role and every affected member's role off this. It is the pre-commit tree because
	// the decision is taken before ApplyCommit, which is the only order under which a commit that
	// removes the owner can be refused by reading the owner's role.
	Members []CommitMember
}

// CommitAuthorizer is a device's receiving-client decision on an ingested commit. It returns nil to
// ALLOW, or an error to REFUSE -- which [Group.Receive] surfaces as [ErrCommitUnauthorized] with
// the returned cause carried, and which leaves this group at the epoch it was already at.
//
// A NIL AUTHORIZER ALLOWS EVERY COMMIT, which is the alpha's behaviour: the full role model (item
// 242) is not built, so there is no role to refuse on. It is a function value rather than a method
// on an interface so that the day the role model lands, the check is a body swap at one call site
// and not a new seam.
type CommitAuthorizer func(*CommitAuthorization) error

// ingestCommitLocked follows one received commit into the epoch it opens: the whole of A5, in the
// order A5's plan fixes and in one place.
//
//	OpenCeremonyRecord -> Process -> authorization hook -> ApplyCommit -> AdvanceEpoch ->
//	A4's re-track -> enterEpochLocked (A3's persist)
//
// THE ORDER IS NOT INTERCHANGEABLE. The hook is BEFORE ApplyCommit because a decision taken after
// the commit is applied cannot refuse a commit that removes the owner. ApplyCommit is BEFORE
// AdvanceEpoch because the session installs the epoch the HANDLE is at, so the handle must have
// moved first -- and mls persists the new epoch's MLS state inside ApplyCommit, which is the first
// of the two writers of epoch state. AdvanceEpoch reuses this group's LIFETIME pq_secret (item 243):
// the same value re-extracts the new epoch's storage root, which is why item 243 was a prerequisite.
// crossEpochLadderLocked (A4) runs in the same block as that install, and enterEpochLocked (A3) is
// LAST -- the second writer -- so a persist that named the new epoch never outruns the ladders that
// serve it.
//
// THE RECEIVER HOLDS THE GROUP MUTEX ACROSS THIS. Nothing here re-enters it: the handle and the
// session run their own loops, and the persist is the durable store's own lock. What it can block on
// is bounded -- one commit's worth of MLS work and one disk write -- so it does not stall the walk.
func (self *Group) ingestCommitLocked(walk *pageWalk, parsed *message.Record) error {
	header := &parsed.Header
	// (0) track the committer's ladder at the commit's own retention class, so the ceremony open
	// below has a receiver ratchet to peek. A commit is a PERMANENT record and this device may only
	// ever have tracked this sender's DURABLE ladder (its ordinary messages), so the class the
	// commit rides is one no ordinary record installed. The committer is a member of this group at
	// the epoch that is closing, so its sender_handle is a leaf of walk.leaves; a record whose
	// committer is not is refused rather than opened. The ceremony arm commits no ratchet, so this
	// peek costs nothing this device's own next record needs.
	committerLeaf, known := walk.leaves[header.SenderHandle]
	if !known {
		return fmt.Errorf("%w: the commit names sender_handle %x, which is no leaf of this group at epoch %d",
			ErrCommitIngest, header.SenderHandle, self.epoch)
	}
	if err := self.trackLocked(committerLeaf, header); err != nil {
		return fmt.Errorf("%w: %w", ErrCommitIngest, err)
	}
	// (1) open the ceremony record. It authenticates NOBODY -- the body is judged by mls below,
	// not by the sender_handle the record claims. The epoch check inside it has already been
	// satisfied by the caller's guard (header.Epoch == self.epoch).
	_, commitBytes, err := self.session.OpenCeremonyRecord(parsed)
	if err != nil {
		return fmt.Errorf("%w: opening the commit ceremony record: %w", ErrCommitIngest, err)
	}
	// (2) process the commit against this member's own tree, staging it. This is where the
	// commit's signature is verified against its committer and where its proposals are resolved.
	processed, err := self.handle.Process(commitBytes)
	if err != nil {
		return fmt.Errorf("%w: processing the commit: %w", ErrCommitIngest, err)
	}
	if processed.Kind != messagegroup.EngineProcessedCommit {
		return fmt.Errorf("%w: a record marked is_commit processed as kind %d rather than a commit",
			ErrCommitIngest, processed.Kind)
	}
	// (3) THE AUTHORIZATION HOOK, before anything is applied. Returns allow today; see the header.
	if err := self.authorizeCommitLocked(processed); err != nil {
		return err
	}
	// (4) apply it: the handle enters the epoch the commit opens, and mls persists that epoch's
	// state HERE -- the first of the two writers of epoch state.
	if err := self.handle.ApplyCommit(processed); err != nil {
		return fmt.Errorf("%w: applying the commit: %w", ErrCommitIngest, err)
	}
	newEpoch := self.handle.Epoch()
	// (5) advance the session onto the epoch the handle is now at, reusing the lifetime pq_secret.
	if err := self.session.AdvanceEpoch(self.pqSecret); err != nil {
		return fmt.Errorf("%w: advancing the session to epoch %d: %w", ErrCommitIngest, newEpoch, err)
	}
	// (6) A4: the ladder bookkeeping crosses the epoch here, in the same block as the install above.
	if err := self.crossEpochLadderLocked(newEpoch); err != nil {
		return err
	}
	// (7) A3: persist the new epoch through the one door -- the second writer, after mls.
	if err := self.enterEpochLocked(); err != nil {
		return err
	}
	// (8) THE MEMBERSHIP HAS CHANGED, AND THE WALK IS STILL RUNNING. walk.leaves was built at the
	// start of this Receive from the membership at the epoch that just closed, so a record from a
	// member this commit ADDED -- whose leaf did not exist then -- would fail "no leaf of this
	// group" if it arrives later in the same page. Rebuilt here off the handle at the new epoch, so
	// the rest of the walk resolves the new membership. walk.own does not change: this device's leaf
	// and the epoch-zero group_handle_key its handle is derived from both survive an epoch change.
	leaves, err := self.leavesLocked()
	if err != nil {
		return fmt.Errorf("%w: the membership at epoch %d: %w", ErrCommitIngest, newEpoch, err)
	}
	walk.leaves = leaves
	self.stats.Ingested += 1
	return nil
}

// authorizeCommitLocked takes the receiving-client decision on one processed commit. It is A5's
// hook, and it runs BEFORE ApplyCommit.
//
// A nil authorizer allows every commit and the membership is not even read, because building the
// [CommitAuthorization] a nil authorizer would ignore is work with no reader. When there IS an
// authorizer, it is handed the committer and what the commit does off [messagegroup.EngineProcessed]
// (authenticated by Process) and the PRE-commit membership off the handle. A refusal is surfaced as
// [ErrCommitUnauthorized] with the returned cause carried.
func (self *Group) authorizeCommitLocked(processed *messagegroup.EngineProcessed) error {
	authorizer := self.device.commitAuthorizer
	if authorizer == nil {
		return nil
	}
	members, err := self.membershipLocked()
	if err != nil {
		return fmt.Errorf("%w: the membership the authorization check reads: %w", ErrCommitIngest, err)
	}
	decision := &CommitAuthorization{
		GroupId:       append([]byte(nil), self.id...),
		Epoch:         self.epoch + 1,
		CommitterLeaf: processed.CommitterLeaf,
		AddedLeaves:   append([]uint32(nil), processed.AddedLeaves...),
		RemovedLeaves: append([]uint32(nil), processed.RemovedLeaves...),
		UpdatedLeaves: append([]uint32(nil), processed.UpdatedLeaves...),
		Members:       members,
	}
	if err := authorizer(decision); err != nil {
		return fmt.Errorf("%w: %w", ErrCommitUnauthorized, err)
	}
	return nil
}

// membershipLocked is this group's members as they stand right now, one [CommitMember] per member,
// with each sender_handle DERIVED from the group_handle_key and the leaf rather than read off any
// record. It is the pre-commit membership when the caller is [Group.authorizeCommitLocked].
func (self *Group) membershipLocked() ([]CommitMember, error) {
	members := make([]CommitMember, 0, self.handle.MemberCount())
	for at := 0; at < self.handle.MemberCount(); at += 1 {
		leaf, _, _, err := self.handle.MemberAt(at)
		if err != nil {
			return nil, fmt.Errorf("urmessage: the group's member %d: %w", at, err)
		}
		handle := messagegroup.SenderHandle(self.groupHandleKey, leaf)
		members = append(members, CommitMember{
			Leaf:         leaf,
			SenderHandle: append([]byte(nil), handle[:]...),
		})
	}
	return members, nil
}

// noteEpochGapLocked delivers one pre-change record as a [GapOutOfWindow] gap: something is at this
// record id, it was sealed at an epoch this device has left, and no key on this single-epoch session
// opens it. See [GapReason].
//
// IT READS NO BODY, because it cannot -- the body is under the old epoch's key -- so the gap carries
// no kind and no text, only its position and its message_id. message_id is a function of the header
// and the group_handle_key, both of which this session holds whatever epoch it is at, so the gap is
// still NAMED. A record whose id cannot be derived is counted and resolved past rather than retried:
// the epoch will not come back, so there is nothing a re-fetch repairs.
func (self *Group) noteEpochGapLocked(walk *pageWalk, recordId uint64, header *message.RecordHeader) {
	self.stats.GapOutOfWindow += 1
	messageId, err := self.session.MessageIdOf(header)
	if err != nil {
		return
	}
	mine := header.SenderHandle == walk.own
	entry := &Content{}
	received := newGap(GapOutOfWindow, entry, recordId, header.SenderHandle[:], mine, 0, messageId[:])
	if self.deliverLocked(received, entry) {
		walk.opened = append(walk.opened, received)
	}
	self.delivered[recordId] = true
}

// ── what a record becomes ────────────────────────────────────────────────────────────────────

// messageKeyOf is a message_id as a map key. It TRUNCATES NOTHING and pads nothing: an id of any
// other width is not a message_id, and every caller here has one off a [32]byte the derivation
// answered.
func messageKeyOf(messageId []byte) [MessageIdBytes]byte {
	key := [MessageIdBytes]byte{}
	copy(key[:], messageId)
	return key
}

// heldLocked is the [Message] this group holds under one message_id, READ OUT OF THE LOG rather
// than out of a table of its own.
//
// IT IS ONE FUNCTION BECAUSE THE POSITION MUST NEVER BE DEREFERENCED TWO WAYS. [Group.logIndex]
// answers where a message sits and [Group.log] holds it, and the whole of ledger item 227's repair
// is that the log slot is the only holder -- so a caller that resolved a target by indexing the log
// itself would be one more place to fix the day the pair grows a case. Every answer is the CURRENT
// message at that position, which after a rebuild is the replacement and not the message the
// rebuild froze.
func (self *Group) heldLocked(messageId []byte) (*Message, bool) {
	at, found := self.logIndex[messageKeyOf(messageId)]
	if !found {
		return nil, false
	}
	return self.log[at], true
}

// newMessage builds one [Message] from one parsed envelope. It is the only constructor, so the walk,
// the own-copy path and [Group.Send] cannot fill a [Message] three different ways.
//
// AN UNSUPPORTED ENTRY BECOMES A PLACEHOLDER HERE AND NOT SOMEWHERE ELSE: its Kind is the code that
// arrived, its Text is empty, and nothing else is set -- because a build that does not know a code
// must not guess at its layout, and a Text filled from a body it could not parse is exactly the
// failure headVersion 0x02 was bumped to prevent.
func newMessage(entry *Content, recordId uint64, senderHandle []byte, mine bool, sentAtMs int64,
	messageId []byte) *Message {

	received := &Message{
		RecordId:     recordId,
		SenderHandle: append([]byte(nil), senderHandle...),
		Mine:         mine,
		Text:         entry.Text,
		SentAtMs:     sentAtMs,
		MessageId:    append([]byte(nil), messageId...),
		Kind:         entry.Kind,
	}
	if entry.Kind == KindReply {
		received.ReplyToId = append([]byte(nil), entry.Target...)
	}
	return received
}

// newGap builds the [Message] one record that OPENED and cannot be SHOWN becomes: spec A section
// 7.4's gap entry, with the [GapReason] that says which of the two this build can produce it is.
//
// IT IS A SECOND CONSTRUCTOR AND NOT A SECOND WAY TO FILL A [Message]: it builds through
// [newMessage], so every field a gap shares with a message is still filled in exactly one place, and
// all it adds is the one field that makes it a gap. A gap built by assigning [Message.Gap] at a call
// site would be a gap somebody can forget to mark, and [Group.deliverLocked] and
// [Group.reactableLocked] both branch on that field -- an unmarked malformed REACTION_ADD would be
// read as an effect on a target of thirty-two zero octets and never shown at all.
//
// A GAP'S TEXT AND ReplyToId ARE EMPTY BY CONSTRUCTION AND ARE NOT CLEARED HERE. Both come off the
// entry, and the only two entries a gap is ever built from carry neither: [ContentUnsupported]
// answers the code and the raw body and nothing else, and a malformed gap's entry is synthesised in
// [Group.openPageLocked] from octet 0 alone. A line that cleared them would be a line no mutation
// could kill, so there is none.
func newGap(reason GapReason, entry *Content, recordId uint64, senderHandle []byte, mine bool,
	sentAtMs int64, messageId []byte) *Message {

	received := newMessage(entry, recordId, senderHandle, mine, sentAtMs, messageId)
	received.Gap = reason
	return received
}

// deliverLocked folds one opened record into this group and answers whether it became a LINE of the
// conversation.
//
// THREE KINDS OF RECORD ADD NO LINE and each answers false for a different reason:
//
//   - A REACTION and a TOMBSTONE are changes to another message. They are noted as effects and
//     applied to their target, now or whenever it arrives.
//   - A COVER is a change to nothing: "discarded, never receipted". It exists to be
//     indistinguishable from a real message on the wire, and a COVER that produced an entry would
//     be cover traffic the user can see.
//
// IT IS ONE FUNCTION BECAUSE THREE CALLERS ASK IT. [Group.openPageLocked], [Group.openOwnFromCopyLocked]
// and [Group.sendContentLocked] each hold a [Message] and an entry, and a rule about what a record
// becomes that lived in three places would be three rules the day one of them grew a case.
//
// A GAP IS ALWAYS A LINE, AND THAT CLAUSE IS LOAD-BEARING RATHER THAN TIDY. [Message.Kind] on a gap
// is the code the record ARRIVED under, not what the record is, and both rules below read that code:
// a malformed REACTION_ADD body -- a target shorter than thirty-two octets, say -- carries
// [KindReactionAdd], so without this clause effectOf would turn it into an effect standing on a
// target of thirty-two zero octets, deliverLocked would answer false, and THE GAP WOULD NEVER BE
// SHOWN. A malformed COVER would disappear the same way, and "discarded, never receipted" is a
// promise about a COVER this build could READ. A gap that is silent is the one thing a gap may not
// be, and the sender chooses the octets that decide which of these two rules it would have hit.
func (self *Group) deliverLocked(received *Message, entry *Content) bool {
	if received.Gap == "" {
		if effect, isEffect := effectOf(received, entry); isEffect {
			self.noteEffectLocked(effect)
			return false
		}
		if received.Kind == KindCover {
			return false
		}
	}
	key := messageKeyOf(received.MessageId)
	self.logIndex[key] = len(self.log)
	self.log = append(self.log, received)
	// AND THE EFFECTS THAT WERE WAITING FOR IT. A reaction or a tombstone that arrived before its
	// target has been held since, and this is the moment it applies.
	self.reapplyLocked(key)
	return true
}

// contentEffect is one record that changes ANOTHER message rather than adding one.
type contentEffect struct {
	kind ContentKind

	// The EFFECT RECORD's own message_id, which is the key it is held under. One record is one
	// effect however many times a rewind walks back over it.
	messageId [MessageIdBytes]byte

	// The server's number for it, and zero for a record this device has sealed and the server
	// has not answered yet. See [effectOrder] for what a zero sorts as and why.
	recordId uint64

	// Who sealed it, which is T-b's operand and a reaction's reactor.
	senderHandle []byte
	mine         bool

	// The message it names.
	target [MessageIdBytes]byte

	// A reaction's emoji, raw. Empty on a tombstone.
	emoji string
}

// effectOf reads one parsed envelope as an effect, and answers false for a kind that is a line of
// the conversation rather than a change to one.
func effectOf(received *Message, entry *Content) (*contentEffect, bool) {
	switch entry.Kind {
	case KindTombstone, KindReactionAdd, KindReactionRemove:
	default:
		return nil, false
	}
	return &contentEffect{
		kind:         entry.Kind,
		messageId:    messageKeyOf(received.MessageId),
		recordId:     received.RecordId,
		senderHandle: append([]byte(nil), received.SenderHandle...),
		mine:         received.Mine,
		target:       messageKeyOf(entry.Target),
		emoji:        entry.Emoji,
	}, true
}

// noteEffectLocked holds one reaction or tombstone and applies everything standing on its target.
//
// WHY IT IS HELD AND NOT APPLIED. A reaction, a tombstone and their target are three records and
// THE WALK'S ORDER IS NOT THE CONVERSATION'S ORDER: a record that fails to open holds the cursor
// back and is re-delivered on a LATER fetch, after record ids above it have already been shown, and
// after [maxRecordAttempts] it is abandoned and never delivered at all. So "the target is already
// here" is a thing this package may not assume, in either direction -- the target may arrive after
// the effect, and an effect may arrive after another effect that was written later.
//
// SO EVERY EFFECT IS KEPT AND THE TARGET'S STATE IS REBUILT, rather than each effect being applied
// once as it lands. The difference is not theoretical: an ADD at record 5 and a REMOVE at record 6
// that arrive in the order 6, 5 -- which is exactly what one failed open produces -- leave the
// reaction STANDING under apply-as-it-lands and REMOVED under a replay, and the second is what
// server order says. See [Group.reapplyLocked].
func (self *Group) noteEffectLocked(effect *contentEffect) {
	if held, seen := self.effects[effect.messageId]; seen {
		// ONE RECORD IS ONE EFFECT. The same record re-delivered behind an earlier failure is
		// the same effect with a record id the server may only now have given it, so the held
		// copy is updated in place rather than appended beside itself.
		*held = *effect
	} else {
		self.effects[effect.messageId] = effect
		self.effectsOn[effect.target] = append(self.effectsOn[effect.target], effect)
	}
	// AND THE TARGET IS MARKED, NOT REBUILT. A rebuild here is a rebuild PER EFFECT, which is the
	// outer factor of the cube [Group.dirtyTargets] exists to remove: n effects on one message
	// rebuild that message n times, and each rebuild reads all n effects. The rebuild happens once
	// per walk instead, in [Group.rebuildDirtyLocked], from the same full sorted effect set.
	self.dirtyTargets[effect.target] = struct{}{}
}

// rebuildDirtyLocked runs the rebuild every effect noted since the last drain is owed, once per
// target rather than once per effect, and empties the set.
//
// THE ORDER IT WALKS THE SET IN IS A MAP'S ORDER AND THAT IS NOT A HAZARD: one rebuild reads one
// message's own effects and writes that message's own fields, so no two of them can see each other.
// The order INSIDE a rebuild is server order and is decided by [effectOrder], which is the ordering
// that is load-bearing and is held by TestEffectsAreAppliedInServerOrderAndNotArrivalOrder.
//
// A DIRTY TARGET THIS GROUP DOES NOT HOLD IS DROPPED FROM THE SET AND NOTHING IS LOST.
// [Group.reapplyLocked] answers nothing for a target that has not arrived, and the effects stay
// held under [Group.effectsOn]; the rebuild that owes them is the one [Group.deliverLocked] runs at
// the moment the target is indexed.
func (self *Group) rebuildDirtyLocked() {
	for target := range self.dirtyTargets {
		self.reapplyLocked(target)
	}
	clear(self.dirtyTargets)
}

// reapplyLocked rebuilds one message's effects from every effect record this group holds for it, in
// SERVER ORDER.
//
// IT REBUILDS RATHER THAN ACCUMULATES, which is the whole of why [Message.Deleted] and
// [Message.Reactions] are cleared first: an effect that arrives out of order has to be able to
// change the answer that an effect already applied gave, and an accumulator cannot be walked
// backwards. The cost is one pass over one message's effects per effect record, and the effects on
// one message are a number a human produced.
//
// THE CLEARING ITSELF DEFENDS NOTHING A TEST CAN SEE, measured by deleting the two lines and
// running ./urmessage and ./cp3b with nothing going red, and it is kept for a reason rather than
// from habit. Every [contentEffect.applyTo] is idempotent TODAY -- an ADD dedupes on
// (reactor, emoji), a REMOVE filters, and a tombstone sets a bool nothing else clears -- so
// replaying onto the previous answer happens to reach the same state as replaying onto an empty
// one. The clearing is what makes that a PROPERTY of this function rather than a coincidence of
// those three, and the day one of them is not idempotent it is the line that keeps this a rebuild.
// The SORT beside it is not in the same position: deleting that turns
// TestEffectsAreAppliedInServerOrderAndNotArrivalOrder red.
//
// A TARGET THAT IS NOT HERE IS NOT AN ERROR AND NOT A DROP. The effects stay held; this is what
// runs again when [Group.deliverLocked] indexes the target.
//
// ── IT REPLACES THE MESSAGE AND NEVER WRITES THROUGH ONE (msgrepo ledger item 227) ───────────
//
// THE REBUILD USED TO WRITE `held.Deleted = false` AND `held.Reactions = nil` INTO THE MESSAGE
// ALREADY IN THE LOG, and [Group.Messages] hands that same *Message to every caller: it copies the
// SLICE under this group's mutex and shares the VALUES. So a caller rendering the conversation it
// had already been given shared those two fields with a rebuild running under a lock it has no way
// to take, and the promise in Messages's own doc comment -- "are not written after they are
// appended" -- was false. MEASURED, not inferred: a probe rendering Group.Messages on one goroutine
// while another called Group.Receive reported TWO data races under -race, both of them these two
// writes, reached through Receive -> commitWalkLocked -> rebuildDirtyLocked.
//
// SO THE REBUILD BUILDS A NEW [Message] AND PUTS IT AT THE OLD ONE'S POSITION. Every pointer this
// package has ever handed out is frozen at the instant it was handed out, for ever, WITHOUT a lock
// held across anybody's rendering -- which is the only shape that works for a UI, since a UI paints
// on its own schedule and cannot hold this group's mutex while it does.
//
// WHAT IT COSTS: one [Message] per REBUILT message per walk. Not per effect -- [Group.dirtyTargets]
// made the rebuild once-per-target-per-walk -- and not per message, since a target with no effect
// records at all returns below without copying anything, which is every message in a conversation
// nobody has reacted to.
//
// THE SHALLOW COPY IS SOUND AND THAT IS A CLAIM ABOUT [Message], NOT A HOPE. Of its fields only
// Deleted and Reactions are ever written after construction (this function and
// [contentEffect.applyTo] are the only writers of either); SenderHandle, MessageId and ReplyToId
// are []byte built by [newMessage] with append-onto-nil and never written again, so the copy and
// the frozen original share arrays that nothing mutates. Reactions is set to nil on the copy before
// a single effect is applied, so the two never share a reaction array either.
//
// WHERE THE REPLACEMENT HAS TO BE PICKED UP: [Group.commitWalkLocked], which re-reads the messages
// a walk is about to hand back, and [Group.sendContentLocked], which re-reads the one it just sent.
// A caller of either would otherwise be given the frozen copy of a message this same call had
// rebuilt.
func (self *Group) reapplyLocked(target [MessageIdBytes]byte) {
	at, found := self.logIndex[target]
	if !found {
		return
	}
	// A TARGET NOTHING HAS EVER NAMED IS NOT REBUILT AND IS NOT COPIED. effectsOn only ever
	// GROWS -- a cancelled reaction is a REMOVE record beside its ADD and not a deletion from
	// this table -- so an empty effect set means no effect has ever touched this message, its
	// Deleted is false and its Reactions are nil, and the rebuild below would replace it with an
	// identical copy. That is every message in a conversation nobody has reacted to, and
	// [Group.deliverLocked] rebuilds each of them once as it arrives.
	effectsOn := self.effectsOn[target]
	if len(effectsOn) == 0 {
		return
	}
	held := self.log[at]
	effects := append([]*contentEffect(nil), effectsOn...)
	slices.SortStableFunc(effects, effectOrder)
	rebuilt := *held
	rebuilt.Deleted = false
	rebuilt.Reactions = nil
	held = &rebuilt
	// THE DEDUPE SET IS THE REBUILD'S AND IS BUILT BESIDE THE SLICE IT MIRRORS. The ADD arm used to
	// answer "has this reactor already reacted with this emoji" by SCANNING [Message.Reactions],
	// which is a scan of everything the rebuild had appended so far: m reactions cost m^2 comparisons
	// inside one rebuild, and that is the inner factor of the cube [Group.dirtyTargets] removes the
	// outer one of. With the set, one rebuild costs the sort it already paid for and nothing more.
	//
	// THE KEY IS A CONCATENATED STRING AND NOT A STRUCT, DELIBERATELY: a struct with a []byte field
	// is not comparable and cannot be a map key at all, and a string of the handle with a separator
	// is the same equality the scan computed -- bytes.Equal on the handle AND equality on the emoji.
	// The separator is 0x00, which no emoji tail can carry and no sender_handle ends on ambiguously,
	// so (handle, emoji) pairs cannot collide across the join.
	//
	// IT IS HANDED DOWN RATHER THAN HELD ON THE GROUP because it is only ever true of ONE rebuild:
	// the slice it mirrors is cleared two lines above, so a set that outlived this call would be a
	// set describing reactions that no longer exist.
	seen := make(map[string]struct{}, len(effects))
	for _, effect := range effects {
		effect.applyTo(held, seen)
	}
	// AND IT IS PUBLISHED LAST, WHICH IS THE ONE LINE THAT MAKES THE COPY WORTH ANYTHING. Until
	// here the rebuilt message is reachable from this frame alone; after it, it is the message
	// [Group.log] holds and [Group.heldLocked] answers, and the one it replaced is frozen in
	// whatever [Group.Messages] copy already carries it.
	self.log[at] = held
}

// reactionKey is the (reactor, emoji) pair [Group.reapplyLocked]'s dedupe set is keyed on, and it is
// the SAME equality the scan it replaced computed: the raw sender_handle octets and the raw emoji
// octets, joined by a separator neither can contain.
func reactionKey(senderHandle []byte, emoji string) string {
	return string(senderHandle) + "\x00" + emoji
}

// effectOrder is server order: `record_id` ascending, which is what §5.3 says decides which of two
// reactions came last.
//
// A RECORD THE SERVER HAS NOT NUMBERED SORTS LAST, and that is a decision rather than a fallback.
// The only records with a zero id are ones THIS DEVICE has just sealed and not yet had answered, so
// "the newest thing that happened" is the true reading of one; sorting it first would let a
// half-submitted reaction be cancelled by a REMOVE the server numbered before it existed.
//
// THE TIE-BREAK IS THE EFFECT'S OWN message_id, so that two effects the server has not numbered
// have an order at all, and the SAME order on every device that holds them.
func effectOrder(first *contentEffect, second *contentEffect) int {
	if first.recordId != second.recordId {
		switch {
		case first.recordId == 0:
			return 1
		case second.recordId == 0:
			return -1
		case first.recordId < second.recordId:
			return -1
		}
		return 1
	}
	return bytes.Compare(first.messageId[:], second.messageId[:])
}

// applyTo is one effect, against the message it names.
//
// `seen` IS THE REBUILD'S DEDUPE SET AND BOTH REACTION ARMS OWE IT AN UPDATE. It mirrors
// [Message.Reactions] exactly -- a key is added where a reaction is appended and deleted where one
// is filtered out -- because the two are read against each other across a replay: an ADD replayed
// AFTER a REMOVE of the same (reactor, emoji) has to land, and it only lands if the REMOVE took the
// key out as well as the row. See [Group.reapplyLocked], which is the only caller and which owns
// the set's lifetime.
func (self *contentEffect) applyTo(target *Message, seen map[string]struct{}) {
	switch self.kind {
	case KindTombstone:
		// T-b, THE SAME-SENDER RULE, and it is what MASTER §12.1's "a deletion cannot be
		// forged" needs beyond R1: R1 proves who sealed the TOMBSTONE and nothing in it proves
		// they sealed the target. A tombstone from anybody else is ignored -- not refused,
		// because the record is a legal record and a receiver that failed the walk over one
		// would be handing any member a way to wedge the conversation.
		if !bytes.Equal(self.senderHandle, target.SenderHandle) {
			return
		}
		// T-a: only a stored CONTENT message can be deleted. A reaction, a tombstone and a
		// COVER are not entries and never reach here; a kind this build does not know is an
		// entry, and it is not one this build can say is deletable.
		switch target.Kind {
		case KindText, KindReply:
		default:
			return
		}
		target.Deleted = true
	case KindReactionAdd:
		key := reactionKey(self.senderHandle, self.emoji)
		if _, standing := seen[key]; standing {
			return
		}
		seen[key] = struct{}{}
		target.Reactions = append(target.Reactions, Reaction{
			SenderHandle: append([]byte(nil), self.senderHandle...),
			Emoji:        self.emoji,
			Mine:         self.mine,
		})
	case KindReactionRemove:
		// A REMOVE CANCELS AN ADD WITH THE SAME (reactor, target, emoji) AND NOBODY ELSE'S.
		// The reactor is the sender_handle: D7 is what would make it a person rather than a
		// leaf, and until it is ruled a second device of one person cannot take back the
		// first's reaction.
		//
		// AND IT CANCELS THE KEY AS WELL AS THE ROW. Without the delete, an ADD that sorts
		// after this REMOVE -- which is the ordinary shape of react, un-react, react again --
		// would find its key still standing and return without appending, and the reaction the
		// user made last would not be shown.
		delete(seen, reactionKey(self.senderHandle, self.emoji))
		kept := make([]Reaction, 0, len(target.Reactions))
		for _, standing := range target.Reactions {
			if standing.Emoji == self.emoji && bytes.Equal(standing.SenderHandle, self.senderHandle) {
				continue
			}
			kept = append(kept, standing)
		}
		target.Reactions = kept
	}
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
	self.peerHeads = map[ladderKey]uint64{}
	self.logIndex = map[[MessageIdBytes]byte]int{}
	self.effects = map[[MessageIdBytes]byte]*contentEffect{}
	self.effectsOn = map[[MessageIdBytes]byte][]*contentEffect{}
	self.dirtyTargets = map[[MessageIdBytes]byte]struct{}{}
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
	key := trackedKey{epoch: self.epoch, ladderKey: ladderKey{leaf: leaf, retentionWire: retentionWire, ephWindow: header.EphWindow}}
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

// crossEpochLadderLocked carries this group's receiver-ladder bookkeeping across an epoch change.
// It is A4, and its ONE caller is the commit-ingest path ([Group.ingestCommitLocked]), where it
// runs in the same statement block as the [messagegroup.GroupSession] install that zeroized the
// ratchets it describes -- not before it, because a peer record could still be opened against the
// epoch that is closing, and not after A3's persist, because a persist that named the new epoch
// with the ladders still describing the old one would come back from a restart tracked at nothing.
//
// TWO THINGS ARE CLEARED AND ONE IS KEPT. [Group.tracked] and [Group.ownHeads] both name receiver
// ratchets [messagegroup.GroupSession.AdvanceEpoch] has just zeroized, so they are cleared -- and
// [trackedKey] now carries the epoch, so a memo that survived would also be a memo at the epoch
// before, which is the same rule read the other way. [Group.peerHeads] is NOT cleared: it is the
// head this device authenticated for each peer, the stream index is continuous across epochs, and
// it is the whole of what stops a re-track at 0 from starving a busy peer.
//
// EACH PEER LADDER IS RE-TRACKED AT ITS AUTHENTICATED HEAD, keyed by the NEW epoch. A member just
// added has no head here and is tracked lazily at 0 by [Group.trackLocked] on first sight, which is
// correct: its stream starts at this epoch. The own ladder is not re-tracked here -- it is rebuilt
// lazily by [Group.advanceOwnLadderLocked] off [Group.ownIndexSeen], which survives the clear for
// peerHeads' reason.
//
// newEpoch is [Group.handle.Epoch], which [messagegroup.GroupHandle.ApplyCommit] has already
// advanced; [Group.epoch] does not move until [Group.enterEpochLocked] runs after this, so the key
// is built off the handle rather than the field. [Group.trackLocked]'s later keys use
// [Group.epoch], which enterEpochLocked then sets equal to this, so the two agree.
func (self *Group) crossEpochLadderLocked(newEpoch uint64) error {
	clear(self.tracked)
	clear(self.ownHeads)
	for ladder, head := range self.peerHeads {
		class, ephBucket, err := message.RetentionClassOf(ladder.retentionWire)
		if err != nil {
			return fmt.Errorf("%w: re-tracking leaf %d across the change to epoch %d: %w",
				ErrRecordOpen, ladder.leaf, newEpoch, err)
		}
		if err := self.session.TrackSender(ladder.leaf, class, ephBucket, ladder.ephWindow, head); err != nil {
			return fmt.Errorf("%w: re-tracking leaf %d at head %d across the change to epoch %d: %w",
				ErrRecordOpen, ladder.leaf, head, newEpoch, err)
		}
		self.tracked[trackedKey{epoch: newEpoch, ladderKey: ladder}] = true
	}
	return nil
}

// trackLocked installs this sender's receiver ladder once and only once, AT THIS GROUP'S EPOCH.
//
// THE HEAD IS THE ONE THIS DEVICE HAS AUTHENTICATED FOR THIS SENDER AND NEVER 0. It used to be a
// literal 0, which was the only honest answer WHILE a group had one epoch: a ladder followed from
// its root opens the sender's whole stream. It stops being honest at the first membership change.
// The receiver ratchets are zeroized at every epoch install and the stream index is continuous
// across epochs, so a peer that had reached index N by the epoch before is at N+1 now -- and a
// ladder re-tracked at 0 answers ErrOutOfWindow for it once N passes
// [messagegroup.DefaultRecordWindowSize]. [Group.peerHeads] holds that authenticated head, keyed
// epoch-independent, and is 0 for a ladder never seen -- a member just added, or a fresh group at
// epoch one -- so this collapses to the old literal in every case that used to reach it and only
// differs after an epoch change. It is CALLER STATE and never a number off the record: TrackSender
// walks one expansion per index below the head, and peerHeads is only ever raised off a record
// this group's keys AUTHENTICATED (see [Group.notePeerHeadLocked]), so a peer cannot choose how far
// this device walks.
func (self *Group) trackLocked(leaf uint32, header *message.RecordHeader) error {
	retentionWire, err := message.RetentionClassWire(header.RetentionClass, header.EphBucket)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrRecordOpen, err)
	}
	ladder := ladderKey{leaf: leaf, retentionWire: retentionWire, ephWindow: header.EphWindow}
	key := trackedKey{epoch: self.epoch, ladderKey: ladder}
	if self.tracked[key] {
		return nil
	}
	head := self.peerHeads[ladder]
	if err := self.session.TrackSender(leaf, header.RetentionClass, header.EphBucket, header.EphWindow, head); err != nil {
		return fmt.Errorf("%w: tracking leaf %d at head %d: %w", ErrRecordOpen, leaf, head, err)
	}
	self.tracked[key] = true
	return nil
}

// notePeerHeadLocked raises [Group.peerHeads] for one peer ladder to a stream index this group's
// keys have just AUTHENTICATED, which is the head a later epoch change re-tracks that ladder at.
//
// IT IS RAISED ONLY OFF AN OPENED RECORD, never off a header, for [Group.trackLocked]'s reason: the
// head decides how far TrackSender walks, so a number a server chose would be a number of
// expansions a server chose. §3.1's stream_index is inside both AEADs, so a record that opened is
// one whose index this device's own key schedule agreed to.
func (self *Group) notePeerHeadLocked(leaf uint32, header *message.RecordHeader) {
	retentionWire, err := message.RetentionClassWire(header.RetentionClass, header.EphBucket)
	if err != nil {
		// unreachable past an open: the class already went through the AEAD. Left as a nil-op
		// rather than a panic, because a head not raised is a re-track one index too low, which
		// the window absorbs, and a panic here would take down a Receive over a record that opened.
		return
	}
	ladder := ladderKey{leaf: leaf, retentionWire: retentionWire, ephWindow: header.EphWindow}
	if self.peerHeads[ladder] < header.StreamIndex {
		self.peerHeads[ladder] = header.StreamIndex
	}
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

// Messages is every message this group has sent or received, in the order it learned them.
//
// IT IS A SNAPSHOT AND THE WORD IS LOAD-BEARING (msgrepo ledger item 227). The slice is a copy, and
// so is every [Message] in it in the only sense that matters to a caller: NOTHING IN THIS PACKAGE
// EVER WRITES A [Message] AFTER HANDING IT OUT. A reaction or a tombstone arriving on a later
// [Group.Receive] builds a REPLACEMENT message and puts it in this group's log; what this call
// answered keeps saying what the conversation said at the instant it was asked.
//
// WHY THAT IS THE CONTRACT AND NOT "hold the lock while you render". This slice is what a UI
// paints, on its own thread and on its own schedule, while another thread polls [Group.Receive] --
// and a renderer cannot hold this group's mutex across a paint. Before the repair those two shared
// [Message.Deleted] and [Message.Reactions], which is a data race the detector reports and which
// every Go caller that rendered while it polled had.
//
// SO A CALLER THAT WANTS THE LATEST STATE ASKS AGAIN, which is what a render loop does anyway.
// Holding one of these messages and expecting a reaction to appear IN it is the one reading this
// method does not support.
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
