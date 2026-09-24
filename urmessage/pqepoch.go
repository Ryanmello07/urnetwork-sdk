// pq_secret ROTATES, ledger item 243's step 3, under item 251's rulings 36 to 40.
//
// WHAT THIS FILE IS. connect's [messagegroup.GroupSession] already holds a pq_secret TABLE keyed
// by epoch (ruling 40, connect 74abe029). This file is the other half: the thing that puts a
// DIFFERENT value in it every epoch, the carrier that delivers that value to the other members,
// and the three ways that delivery can fail said out loud rather than surfacing as a group that
// stopped working.
//
// THE connect COMMIT THIS PACKAGE REQUIRES, STATED BECAUSE A MERGE ORDER CAN BE GOT WRONG AND A
// WORKING TREE CANNOT SHOW IT. This file consumes [messagegroup.InstallPqSecret],
// [messagegroup.DeclarePqSecretRotated], [messagegroup.ErrPqSecretEpochConflict] and
// [messagegroup.ErrPqSecretUnknownEpoch], and NONE of them exists before connect 74abe029 --
// three commits past 39931315, which is where item 243's step 2 left that repository.
//
//	git show 39931315:messagegroup/pqsecret.go
//	  -> fatal: path '…' exists on disk, but not in '39931315'
//	git show 39931315:messagegroup/wrap.go              (the control, in the same query)
//	  -> present
//
// Per symbol, OCCURRENCES under messagegroup/ at 39931315 vs at 74abe029 -- re-measured here
// rather than quoted, with `git grep -o -h <sym> <rev> -- messagegroup/ | wc -l`:
// InstallPqSecret 0/58, DeclarePqSecretRotated 0/20, ErrPqSecretEpochConflict 0/10,
// ErrPqSecretUnknownEpoch 0/16; and the controls that are EQUAL at both revisions, which is what
// makes the zeros mean something rather than meaning the query was wrong: SealWrapBody 22/22,
// OpenWrapBody 47/47, ErrEphWrapWindowUnruled 6/6. SO THIS PACKAGE REQUIRES connect >= 74abe029
// AND DOES NOT COMPILE AGAINST 39931315. `git status --porcelain` being empty in both
// repositories is true of the WORKING TREES and says nothing whatever about this.
//
// WHY IT HAD TO BE BUILT WITH REMOVAL AND NOT AFTER IT (item 243, ruled 2026-09-18). pq_secret is
// the ONLY post-quantum material in this system -- item 251 measured connect/mls's HPKE hard-wired
// to X25519, so the MLS exporter carries no post-quantum contribution at all. A lifetime pq_secret
// therefore leaves a REMOVED member a permanent contribution to every future epoch's
// storage_root, and the residual is exact: an ex-member who keeps an independent archive of the
// group's ciphertext and later acquires a quantum computer reads every future epoch forever.
//
// THE CARRIER IS TASK 14's X-WING DEVICE WRAP AND RULING 36 REFUSED EVERY CHEAPER ONE, in one
// sentence: a post-quantum gate cannot be discharged by a carrier whose confidentiality rests on
// the MLS exporter. Ratcheting the next secret from the last one is worth naming twice, because it
// looks free -- the ex-member HOLDS pq_secret[n] by construction, so a quantum adversary supplying
// exporter[n+1] completes the derivation, and it buys literally nothing.
//
// RULING 37, AND IT IS THE ONE THE SHAPE OF THIS FILE FOLLOWS FROM. The wraps are submitted AT
// EPOCH n, STAGED AND PRE-MERGE. The fan-out used to publish after the merge, so wrap rows carried
// record epoch n+1 -- and item 246's F0 ceiling serves a reader standing at epoch n only rows with
// epoch <= n. Under rotation that is circular: read_key[n+1] needs pq_secret[n+1] needs the wrap
// needs read_key[n+1]. Submitting at epoch n breaks it with no server change and no re-opening of
// ruled item 246, and it has a second consequence this file depends on: the server's current_epoch
// is still n while the wraps are written, so they go on the wire BEFORE the commit record, not
// after it. A wrap submitted after the commit is accepted would be a write at a stale epoch.
//
// RULING 38 IS WHY THE DETECTORS ARE HERE AND NOT IN A LATER STEP. The day a wrap carries key
// material, a member that never opens a readable one goes dark in BOTH directions, permanently:
// read_key[n+1] and write_key[n+1] both hang off storage_root[n+1] and the server verifies
// req_auth before any AEAD is reached, so the answer is REASON_REJECTED with nothing to read. And
// the orphan case -- a lost CAS race leaving wraps addressed to an epoch that never opened -- MUST
// be a typed refusal separable from "I never got a readable wrap", or the two are
// indistinguishable in the field.
//
// ── THE DETECTOR, WHICH IS ITEM 132 ───────────────────────────────────────────────────────────
//
// Item 132's complaint is exact: the fan-out's only coverage check is `wrap_count` against
// `expected_wrap_count` -- TWO CLIENT-DECLARED NUMBERS COMPARED AGAINST EACH OTHER -- neither
// store ever counts a wrap record, and NOTHING TIES THE EPOCH-n WRAP ROWS TO THE EPOCH n+1 MARKER.
// A committer that omits one member's wrap while declaring the matching count produces a group
// that is writable, self-consistent to the server, and permanently unreadable for the omitted
// member.
//
// What this file binds them with is an authenticator that already exists and that no wrap can
// forge: H(epoch_keys). The commit that opens epoch n+1 carries a kind 0x0005
// [message.EpochDigestAttachment] whose EpochKeysDigest is SHA-256 over
// "URmessage/v1/epochkeys" | LP(group_id) | u64(opens_epoch) | LP(write_key) | LP(read_key), and
// those two keys descend from storage_root[n+1] = StorageRoot(mls_secret[n+1], pq_secret[n+1]).
// The digest sits inside server_attachment; LP(H(server_attachment)) is inside the write_auth
// preimage and inside AAD_head, so the digest is covered by a MAC under write_key[n] AND by the
// record AEAD. So a receiver that has applied the commit -- and therefore holds mls_secret[n+1] --
// can ASK OF ANY CANDIDATE SECRET whether it is the one this epoch was actually opened with, by
// recomputing the digest and comparing. That is [Group.matchesEpochDigestLocked].
//
// It is a real binding and not a second declared number, and the three states fall out of it
// rather than being guessed at:
//
//   - [ErrNoWrapForEpoch]     no wrap addressed to this device arrived for the epoch, and the
//     secret this device already holds does NOT open it. (If it does, the
//     committer did not rotate -- an older build -- and that is the
//     compatibility path, not a failure.)
//   - [ErrWrapUnreadable]     a wrap addressed to this device's own wrap_target_handle arrived and
//     did not open: the X-Wing decapsulation is implicit-rejection, so
//     this is always the Poly1305 tag and never a decapsulation error.
//   - [ErrOrphanWrap]         a wrap addressed to this device DID open, for an epoch that was then
//     opened by a commit whose digest names a different secret. That is
//     the lost-CAS-race fan-out, and under ruling 37's pre-merge submit it
//     is a state this build PRODUCES rather than a hypothetical: a
//     committer writes its wraps and then loses the race.
//
// Each has its own counter on [Stats] beside it, because a sentinel a caller has to be holding an
// error to see cannot answer "is this happening".
//
// ── WHAT AN OLD STORE DOES, WHICH IS THE QUESTION A ROTATION MUST ANSWER BEFORE IT SHIPS ──────
//
// Every group on the deployed alpha was written by a build that held ONE pq_secret scalar, and
// [GroupRecord] has one field for it. A restore that refused such a record would be a device that
// can never start again, so the read path takes a 5-part record as it always did and files that
// scalar as a ROW FOR EVERY EPOCH IN THE WINDOW AT OR BELOW THE ONE THE RECORD NAMES -- see
// [restoredPqSecrets] for why that is evidence rather than invention, and for the defect that
// filing one row cost a long-lived device at its first rotation. The group-lifetime PREMISE is
// left standing beside those rows, because they all carry one value and
// [pqSecretsShowRotation] decides on the octets; connect's own compatibility path
// ([messagegroup.GroupSession] answers every epoch out of the one secret it holds while no second
// value has been observed) then behaves exactly as it did before. A 6-part record carries the
// table and the premise's refutation with it and is NOT filled in: it was written by a build that
// can rotate, so a missing row is a missing row. [groupRecordOf] is where the arity switch lives
// and it is the same shape the x-wing seed's own 3-or-4 part switch already uses.
package urmessage

import (
	"bytes"
	"crypto/subtle"
	"fmt"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/messagegroup"
	"github.com/urnetwork/connect/mls"
)

// The three MASTER section 7 octets that have no code point in any document. connect's wrap.go
// says so in as many words and supplies no default for any of them: "which octet a device leaf
// takes, which a member's RECOVERY_PUB takes, which a pq_secret payload takes and which an
// eph_root payload takes are four wire decisions nobody has made" (connect open item MG-7).
//
// THIS PACKAGE ASSIGNS THEM AND SAYS SO. They are the caller's to choose, this is the caller, and
// a fan-out cannot be written without choosing. What matters for correctness today is only that
// the pq_secret payload's octet differs from the eph_root payload's -- that octet is the ONLY
// element of wrap_key's nine-element info separating two records sent to one target at one epoch,
// and [messagegroup.SealDeviceWraps] refuses a caller that passes one octet twice. The values
// below are provisional and the day MG-7 is ruled they move, which is a wire break for any group
// mid-rotation and is why they are three named constants in one place rather than literals.
const (
	wrapTargetTypeDeviceLeaf uint8 = 0x01
	wrapPayloadTypePqSecret  uint8 = 0x01
	wrapPayloadTypeEphRoot   uint8 = 0x02
)

// wrapTarget is one leaf a fan-out addresses: where it sits, the encapsulation key its leaf
// publishes, and the handle its records are filed under.
//
// THE KEY IS THE WIRE VALUE. It is read out of the ratchet tree through the seam's MemberAt, so it
// is the key that member's KeyPackage carried into this group and that every other member agrees
// on -- see [Group.MemberWrapKeys], whose header carries the argument. A fan-out addressed to a
// key this device holds locally would round-trip against itself and reach nobody.
type wrapTarget struct {
	leaf     uint32
	xwingPub []byte
	handle   [16]byte
}

// wrapCandidate is one opened wrap payload, waiting for the commit that says whether it is the
// epoch's own secret or an orphan.
//
// IT IS HELD BECAUSE THE TWO HALVES ARRIVE IN ONE PAGE AND IN THAT ORDER. Under ruling 37 the
// wraps are submitted before the commit, so they carry LOWER record ids and a walk in record-id
// order meets them first -- before the commit whose digest is the only thing that can judge them.
// So the payload is staged here and resolved at the commit, and never the other way round.
type wrapCandidate struct {
	recordId uint64
	secret   []byte
}

// ── the table ────────────────────────────────────────────────────────────────────────────────

// pqSecretAtLocked answers pq_secret[epoch] as this group holds it, or false.
//
// IT IS THE TABLE AND NOTHING ELSE -- no fallback to the current epoch's value, which is
// deliberately NOT repeated here. connect's [messagegroup.GroupSession] carries the
// group-lifetime premise and carries it in ONE place, with its own refutation rule; a second
// premise on this side would be a second thing to keep in agreement with it, and the two would
// disagree exactly when a rotation was half-observed.
func (self *Group) pqSecretAtLocked(epoch uint64) ([]byte, bool) {
	secret, held := self.pqSecrets[epoch]
	if !held {
		return nil, false
	}
	return secret, true
}

// pqSecretLocked is the secret this group's CURRENT epoch runs on.
//
// It is the value the storage root of every record this group seals descends from, the value an
// [Invite] hands a joiner, and -- until this file -- the only one there was.
func (self *Group) pqSecretLocked() []byte {
	secret, _ := self.pqSecretAtLocked(self.epoch)
	return secret
}

// filePqSecretLocked records pq_secret[epoch] and drops what the window has moved past.
//
// THE VALUE IS COPIED, for [installPqSecretOnLoop]'s reason read from this side: the caller's
// array is the caller's, and a table aliasing it would erase a caller's buffer when the window
// moved.
//
// THE BOUND IS [messagegroup.PastEpochWindow] AND IT IS THE SAME ONE CONNECT USES, spelled the
// same way round -- an entry satisfying `self.epoch - epoch > PastEpochWindow` can serve no open
// that connect's own pastEpochOnLoop would admit, so holding it is holding a retired epoch's post
// quantum half for nothing. The subtraction is guarded by `epoch < self.epoch` because these are
// uint64s and an entry at or above the current epoch would underflow into a number always past the
// window.
//
// AN EVICTED ENTRY IS ERASED AND NOT MERELY DELETED. These are the post-quantum half of a retired
// epoch's storage root; a map entry nobody blanked is a live secret with no owner.
func (self *Group) filePqSecretLocked(epoch uint64, pqSecret []byte) {
	if held, found := self.pqSecrets[epoch]; found {
		zeroizeState(held)
	}
	self.pqSecrets[epoch] = append([]byte(nil), pqSecret...)
	self.dropPqSecretsBelowWindowLocked()
}

// dropPqSecretsBelowWindowLocked erases and drops every entry the window has moved past.
func (self *Group) dropPqSecretsBelowWindowLocked() {
	for epoch, secret := range self.pqSecrets {
		if epoch < self.epoch && self.epoch-epoch > messagegroup.PastEpochWindow {
			zeroizeState(secret)
			delete(self.pqSecrets, epoch)
		}
	}
}

// zeroizePqSecretsLocked erases the whole table, entry by entry.
func (self *Group) zeroizePqSecretsLocked() {
	for epoch, secret := range self.pqSecrets {
		zeroizeState(secret)
		delete(self.pqSecrets, epoch)
	}
}

// pqSecretRecordsLocked is the table as [GroupRecord] persists it, in ascending epoch order.
//
// ORDER IS PART OF THE VALUE and not a tidiness: the record is written by appending each entry's
// octets to one frame, and a map's iteration order would make two writes of one unchanged table
// two different files -- which is a rewrite the store's own rename dance pays for on every persist
// and which makes a diff of two states unreadable.
func (self *Group) pqSecretRecordsLocked() []EpochPqSecret {
	records := make([]EpochPqSecret, 0, len(self.pqSecrets))
	for epoch, secret := range self.pqSecrets {
		records = append(records, EpochPqSecret{Epoch: epoch, PqSecret: append([]byte(nil), secret...)})
	}
	sortEpochPqSecrets(records)
	return records
}

// groupRecordLocked is this group as [GroupRecord] persists it, and it is the ONE place that value
// is built.
//
// IT IS ONE FUNCTION BECAUSE THERE ARE FOUR PERSIST SITES AND THE TABLE MUST REACH ALL OF THEM.
// Before rotation a [GroupRecord] carried one scalar that never changed, so four literals agreeing
// was free; a table that changes every epoch turns each literal into a site that can be the one
// that forgot. [Group.enterEpochLocked] is still the only door the EPOCH moves through and
// epochpersist_test.go still holds that; this is the same rule for the value beside it.
//
// PqSecret IS STILL WRITTEN AND IT IS THE CURRENT EPOCH'S. It is what a 5-part record holds and
// what [DurableStateStore.GroupRecords]'s old arm answers, so a store written by this build stays
// readable as the scalar it replaces -- the record describes itself twice, once in the old shape
// and once in the new, and the two cannot disagree because both come from here.
func (self *Group) groupRecordLocked(opened bool) *GroupRecord {
	return &GroupRecord{
		GroupId:        self.id,
		PqSecret:       self.pqSecretLocked(),
		PqSecrets:      self.pqSecretRecordsLocked(),
		GroupHandleKey: self.groupHandleKey,
		Epoch:          self.epoch,
		Opened:         opened,
	}
}

// restoredPqSecret is one row of a restored table, in the shape [Device.restoreOne] walks.
type restoredPqSecret struct {
	epoch  uint64
	secret []byte
}

// restoredPqSecrets turns a [GroupRecord] back into the table its group runs on, and answers the
// secret of the epoch the record names beside it.
//
// THIS IS WHERE AN OLD STORE IS ANSWERED, and the answer is one sentence: a record with no table
// (five parts, every group on the deployed alpha) becomes one row FOR EVERY EPOCH INSIDE THE
// WINDOW AT OR BELOW THE ONE IT NAMES, all carrying the scalar, because a five-part record is
// evidence for exactly that and nothing less.
//
// IT USED TO BE ONE ROW AND THAT WAS A DEFECT, reproduced before it was repaired by
// TestAFivePartRecordRestoredAboveABacklogKeepsItAcrossTheFirstRotation: a device restored at
// epoch 3 from a five-part record answered epochs 1 and 2 out of connect's group-lifetime premise,
// followed ONE ordinary rotation, and `installPqSecretOnLoop` refuted that premise on the octets
// -- after which epochs 1 and 2 had neither a row nor the premise and every record of theirs
// stopped opening at the AEAD tag. `trackSessionLadderLocked` passes ErrPqSecretUnknownEpoch
// through as a FAILURE rather than as a gap, so those records became walk.firstFailure, were
// retried maxRecordAttempts times and abandoned. [Group.cursor] is in-memory only, so every
// restart re-walks the group from record zero and meets them again. The device STARTS and fails
// later, which is the worse of the two outcomes.
//
// WHY THE WHOLE WINDOW IS EVIDENCE AND NOT AN INVENTION, which is the one sentence to argue with:
// a FIVE-PART record was written by a build that could not rotate, so pq_secret was ONE value for
// the whole of that group's life up to the epoch the record names. The rows this fills in are
// therefore exactly the answers connect's premise was already giving for exactly those epochs --
// written down as table rows, which survive the refutation, instead of resting on a premise, which
// does not. Nothing below the window is filled: an epoch more than [messagegroup.PastEpochWindow]
// behind can serve no open `pastEpochOnLoop` would admit, InstallPqSecret refuses it by name, and
// claiming it would tell a caller its history was recovered when it was not.
//
// AND THE ROWS ALL CARRY ONE VALUE, so [pqSecretsShowRotation] -- which compares OCTETS and never
// counts rows -- still answers false for them, the premise is left standing, and a restored device
// that meets no rotation behaves exactly as it did before this repair.
//
// A SIX-PART RECORD IS NOT FILLED IN, and the asymmetry is the point: it was written by a build
// that CAN rotate, so a missing row is a missing row and there is no premise behind it to write
// down.
//
// IT REFUSES A RECORD WHOSE TABLE DOES NOT COVER ITS OWN EPOCH, and that refusal is the reason
// this is a function rather than a loop at the call site. A group restored without pq_secret at
// the epoch its session is about to be built at would construct a session over SOME OTHER epoch's
// secret and seal every record under a storage root no peer reproduces -- which is silent, is
// item 251's ruling 40 defect exactly, and is a state no record written by this build can be in.
// A record that IS in it is corrupt or hand-edited, and refusing one group by name is what
// [Device.Restore] already does with every other unreadable row.
func restoredPqSecrets(record *GroupRecord) ([]restoredPqSecret, []byte, error) {
	if record.PqSecrets == nil {
		if len(record.PqSecret) == 0 {
			return nil, nil, fmt.Errorf("%w: this group record carries neither a pq_secret table nor a pq_secret", ErrStateStoreFormat)
		}
		// the arithmetic is the window's own, spelled the way connect spells it and guarded
		// against the underflow a uint64 subtraction has: a group below the window's width has
		// lived every epoch it has, starting at zero.
		lowest := uint64(0)
		if messagegroup.PastEpochWindow < record.Epoch {
			lowest = record.Epoch - messagegroup.PastEpochWindow
		}
		table := make([]restoredPqSecret, 0, record.Epoch-lowest+1)
		var current []byte
		for epoch := lowest; epoch <= record.Epoch; epoch += 1 {
			// EACH ROW IS ITS OWN ARRAY. They go into [Group.pqSecrets] and into connect's own
			// table, and both erase an entry in place when the window moves past it; rows sharing
			// one array would blank every other row the first time one of them was retired.
			secret := append([]byte(nil), record.PqSecret...)
			table = append(table, restoredPqSecret{epoch: epoch, secret: secret})
			if epoch == record.Epoch {
				current = secret
			}
		}
		return table, current, nil
	}
	table := make([]restoredPqSecret, 0, len(record.PqSecrets))
	var current []byte
	for _, row := range record.PqSecrets {
		secret := append([]byte(nil), row.PqSecret...)
		table = append(table, restoredPqSecret{epoch: row.Epoch, secret: secret})
		if row.Epoch == record.Epoch {
			current = secret
		}
	}
	if current == nil {
		return nil, nil, fmt.Errorf("%w: this group record stands at epoch %d and its pq_secret table holds %d row(s), none of them that epoch's",
			ErrStateStoreFormat, record.Epoch, len(record.PqSecrets))
	}
	return table, current, nil
}

// pqSecretsMapOf is a restored table as the map a [Group] holds.
func pqSecretsMapOf(table []restoredPqSecret) map[uint64][]byte {
	secrets := make(map[uint64][]byte, len(table))
	for _, row := range table {
		secrets[row.epoch] = row.secret
	}
	return secrets
}

// pqSecretsShowRotation is whether a restored table holds two different values, which is the only
// evidence a restarted device can have that its group rotates.
//
// IT IS THE OCTETS AND NEVER A ROW COUNT. A table with thirty-two rows all carrying one value is a
// group that never rotated and whose device simply stood at many epochs; a table with two rows
// carrying two values is a group that did. Counting rows would declare every long-lived alpha
// group rotated and take the compatibility path away from all of them, which is the same mistake
// connect's own header names on the other side ("a count of AdvanceEpoch calls would have made
// every group in the world rotated at its second commit").
func pqSecretsShowRotation(table []restoredPqSecret) bool {
	for at := 1; at < len(table); at += 1 {
		if subtle.ConstantTimeCompare(table[0].secret, table[at].secret) != 1 {
			return true
		}
	}
	return false
}

// ── the digest, which is the whole detector ──────────────────────────────────────────────────

// matchesEpochDigestLocked answers whether `candidate` is the secret the epoch this commit opens
// was ACTUALLY opened with, by recomputing H(epoch_keys) and comparing it against the one the
// commit carries.
//
// THIS IS THE BINDING ITEM 132 SAYS DOES NOT EXIST, and it needs no wire change and no server
// change because both of its inputs are already authenticated. mlsSecret is this member's own
// exporter output at the epoch the commit opened -- it cannot be supplied by anybody else -- and
// the digest reaches this member inside server_attachment, which LP(H(server_attachment)) binds
// into AAD_head and into the write_auth preimage. So a forged digest is a record that does not
// open, and a candidate secret that reproduces the digest is the epoch's own secret or a SHA-256
// collision.
//
// WHAT IT IS NOT: it is not an authorization. It says which secret this epoch runs on, and says
// nothing about whether the committer was entitled to open the epoch -- that is
// [Group.authorizeCommitLocked]'s, which runs before ApplyCommit and is untouched by any of this.
//
// The two keys are derived and dropped inside this call. They are the epoch's read and write keys
// and a caller holding them would be holding, for the length of a candidate loop, the pair item
// 244 spent a red team removing from the wire.
func (self *Group) matchesEpochDigestLocked(mlsSecret []byte, digest *message.EpochDigestAttachment,
	candidate []byte) (bool, error) {

	if digest == nil {
		return false, fmt.Errorf("%w: the commit that opens an epoch carries no epoch digest attachment", ErrCommitIngest)
	}
	if len(candidate) != messagegroup.PqSecretBytes {
		return false, nil
	}
	group, err := epochDigestGroupId(self.id)
	if err != nil {
		return false, err
	}
	root := messagegroup.StorageRoot(mlsSecret, candidate)
	writeKey := message.WriteKey(root)
	readKey := message.ReadKey(root)
	zeroizeState(root)
	computed, err := message.EpochKeysDigest(group, digest.Epoch, writeKey, readKey)
	zeroizeState(writeKey)
	zeroizeState(readKey)
	if err != nil {
		return false, err
	}
	// ConstantTimeCompare and not bytes.Equal: guardrail G8 sends every comparison over a value
	// derived from key material in this tree through it, and a length mismatch answers 0 here
	// rather than being a short comparison that happened to agree.
	return subtle.ConstantTimeCompare(computed, digest.EpochKeysDigest) == 1, nil
}

// resolvePqSecretLocked decides which secret the epoch this commit opens actually runs on, and
// names the failure when there is no answer.
//
// THE ORDER OF THE ARMS IS THE WHOLE OF THE RULE.
//
//  1. EVERY WRAP THIS DEVICE OPENED FOR THAT EPOCH, in arrival order. One of them is the epoch's
//     own secret and every other is an orphan -- a fan-out from a committer that lost the CAS
//     race. They are told apart by the digest and by nothing else, which is why more than one
//     candidate is an ordinary state here and not a refusal.
//  2. THE SECRET THIS GROUP ALREADY HOLDS. A committer built before this file rotates nothing, so
//     the epoch it opens runs on the value every member already has. That arm is the whole of the
//     compatibility path and it is decided by the SAME digest comparison, not by a version flag:
//     if the committer did rotate, this candidate simply fails to reproduce the digest.
//
// A MISS IS THREE DIFFERENT SENTENCES AND THAT IS RULING 38's REQUIREMENT. "I opened a wrap and it
// was for another epoch's fan-out", "a wrap arrived for me and did not open" and "no wrap arrived
// for me at all" are separable by [errors.Is] here, because in the field they have three different
// repairs and one of them -- the orphan -- is nobody's fault and resolves itself at the next
// commit.
func (self *Group) resolvePqSecretLocked(mlsSecret []byte, opensEpoch uint64,
	digest *message.EpochDigestAttachment) ([]byte, error) {

	held, isHeld := self.pqSecretAtLocked(self.epoch)
	if digest == nil {
		// A COMMIT WITH NO DIGEST CANNOT BE ASKED THE QUESTION, and that is a kind 0x0001 commit
		// inside Spec B section 5.4's open acceptance window rather than a malformed one. It
		// carries its epoch keys in the clear, it was built by a client that rotates nothing, and
		// the epoch it opens therefore runs on the secret this group already has. Named rather
		// than guessed at: if this group holds no secret at all it is refused by the same sentinel
		// a missing wrap gets, because the consequence is the same one.
		if isHeld {
			return held, nil
		}
		self.stats.WrapMissing += 1
		return nil, fmt.Errorf("%w: epoch %d was opened by a commit carrying no epoch digest and this device holds no pq_secret to follow it with",
			ErrNoWrapForEpoch, opensEpoch)
	}
	if digest.Epoch != opensEpoch {
		// The server refuses a commit whose attachment does not open current_epoch + 1, so this is
		// a record no server served -- but the two epochs are read from two places here (the
		// handle after the apply, and the attachment) and a check that costs one comparison is
		// cheaper than a candidate loop run against the wrong epoch's digest.
		return nil, fmt.Errorf("%w: the commit that moved this group to epoch %d carries a digest for epoch %d",
			ErrCommitIngest, opensEpoch, digest.Epoch)
	}
	candidates := self.wrapsFor[opensEpoch]
	orphans := 0
	for _, candidate := range candidates {
		matches, err := self.matchesEpochDigestLocked(mlsSecret, digest, candidate.secret)
		if err != nil {
			return nil, err
		}
		if matches {
			return candidate.secret, nil
		}
		orphans += 1
	}
	if isHeld {
		matches, err := self.matchesEpochDigestLocked(mlsSecret, digest, held)
		if err != nil {
			return nil, err
		}
		if matches {
			// THE COMPATIBILITY PATH, and it is reached by measurement rather than by assumption:
			// this epoch was opened with the secret the group already had, so the committer did
			// not rotate. Every group on the deployed alpha is here.
			return held, nil
		}
	}
	// no candidate reproduced the digest. Which of the three states this is depends on what
	// arrived, and all three are counted whatever the caller does with the error.
	if 0 < orphans {
		self.stats.WrapOrphaned += uint64(orphans)
		return nil, fmt.Errorf("%w: %d wrap(s) addressed to this device opened for epoch %d and none of them carries the secret that epoch was opened with, so they are the fan-out of a commit that lost its race",
			ErrOrphanWrap, orphans, opensEpoch)
	}
	if 0 < self.wrapsUnreadable[opensEpoch] {
		self.stats.WrapUnreadable += uint64(self.wrapsUnreadable[opensEpoch])
		return nil, fmt.Errorf("%w: %d wrap(s) at this device's own wrap_target_handle for epoch %d did not open",
			ErrWrapUnreadable, self.wrapsUnreadable[opensEpoch], opensEpoch)
	}
	self.stats.WrapMissing += 1
	return nil, fmt.Errorf("%w: epoch %d was opened with a pq_secret this device does not hold and no wrap addressed to it arrived, so every key of that epoch is unreachable in both directions",
		ErrNoWrapForEpoch, opensEpoch)
}

// epochDigestOf is the kind 0x0005 body a commit record carries, or nil when it carries the older
// kind that has none.
//
// A RECORD WITH NO ATTACHMENT AT ALL IS NOT A COMMIT THIS FUNCTION'S CALLER SHOULD HAVE REACHED,
// and it is answered as nil rather than refused here, because the caller's own guard
// (`header.IsCommit`) is what decides that and a second refusal spelled differently would be a
// second sentence about one condition.
func epochDigestOf(header *message.RecordHeader) (*message.EpochDigestAttachment, error) {
	if len(header.ServerAttachment) == 0 {
		return nil, nil
	}
	attachment, err := message.ParseServerAttachment(header.ServerAttachment)
	if err != nil {
		return nil, fmt.Errorf("the server attachment on this commit: %w", err)
	}
	if attachment.Kind != message.AttachmentEpochDigest {
		return nil, nil
	}
	return attachment.EpochDigest, nil
}

// parseLeafWrapKey is the X-Wing encapsulation key a leaf publishes in its urmessage_leaf_keys
// extension, read out of the body the seam answers.
//
// IT IS THE ONE PARSE AND BOTH READERS GO THROUGH IT. [Group.MemberWrapKeys] is the surface a
// caller measures the round trip with and [Group.wrapTargetsAtLocked] is the fan-out's own
// enumeration; two copies of this would be two answers to "what key is this member addressable
// at", which is the question a wrap cannot be wrong about and stay openable.
func parseLeafWrapKey(leafKeys []byte) ([]byte, error) {
	parsed, err := mls.ParseLeafKeysExtension(leafKeys)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), parsed.DeviceXwingPub...), nil
}

// ── the publishing leg ───────────────────────────────────────────────────────────────────────

// wrapTargetsAtLocked is every leaf the fan-out for `opensEpoch` addresses, read off the group at
// its CURRENT epoch and minus the leaves the staged commit removes.
//
// IT IS READ OFF THE GROUP AND NEVER OFF A LIST THE CALLER PASSES -- m1 Task 14 Property 1's scope
// rule, because a fan-out over a caller-supplied list is a fan-out that silently omits.
//
// AND IT IS THE PRE-COMMIT TREE, WHICH IS A LIMIT OF THE SEAM AND NOT A CHOICE. Ruling 37 submits
// these records before the merge, and the only staged-tree read the seam offers is
// [messagegroup.PendingEpoch] -- an epoch, a member COUNT and a context; [messagegroup.ProcessedMember]
// carries a HasLeafKeys bool and no key. So the staged tree's X-Wing keys are not reachable from
// here at all, and the enumeration is the live tree's. What that costs is exact and is why the
// two arms are safe:
//
//   - A REMOVE: the removed leaf is in the live tree and is excluded HERE, by leaf index, off the
//     same list the commit was built from. That exclusion is the whole of item 243 -- the removed
//     member gets no wrap, so it holds no pq_secret[n+1], so it derives no storage_root[n+1].
//   - AN ADD: the added leaf is not in the live tree and gets no wrap. It does not need one: a
//     joiner receives the epoch's secret in [Invite.PqSecret], out of band through the Welcome,
//     which MASTER section 7 has always been the founding delivery and which
//     [Group.AddMemberAndPublish] answers AFTER the rotation has filed the new epoch's value.
//
// So expected_wrap_count is the length of THIS list, and the marker's wrap_count is taken from the
// same call rather than recomputed after the merge -- two numbers built from one expression cannot
// disagree, which is the half of item 132 a client can fix by itself.
func (self *Group) wrapTargetsAtLocked(opensEpoch uint64, removing []uint32) ([]wrapTarget, error) {
	excluded := map[uint32]bool{}
	for _, leaf := range removing {
		excluded[leaf] = true
	}
	targets := []wrapTarget{}
	for at := 0; at < self.handle.MemberCount(); at += 1 {
		leaf, _, leafKeys, err := self.handle.MemberAt(at)
		if err != nil {
			return nil, fmt.Errorf("urmessage: the group's member %d: %w", at, err)
		}
		if excluded[leaf] {
			continue
		}
		parsed, err := parseLeafWrapKey(leafKeys)
		if err != nil {
			return nil, fmt.Errorf("urmessage: the group's member %d at leaf %d publishes a leaf keys body this build cannot read: %w",
				at, leaf, err)
		}
		targets = append(targets, wrapTarget{
			leaf:     leaf,
			xwingPub: parsed,
			handle:   messagegroup.WrapTargetHandle(self.groupHandleKey, opensEpoch, leaf),
		})
	}
	return targets, nil
}

// stagedRotation is one epoch's rotation before any of it has touched the wire: the secret the
// epoch will run on, the leaves it is delivered to, and the records that carry it.
type stagedRotation struct {
	pqSecret []byte
	targets  []wrapTarget
	wraps    []*message.Record
}

// stageEpochRotationLocked decides EVERYTHING about the epoch a staged commit opens that is not
// the wire: it draws that epoch's own pq_secret, enumerates the fan-out's targets, and seals one
// device wrap record per target.
//
// IT IS ONE FUNCTION BECAUSE THE THREE ARE ONE DECISION. The secret has to exist before the
// targets are enumerated (a wrap carries it), the targets have to be enumerated before the records
// are sealed (each is addressed to a leaf's own key), and expected_wrap_count has to be the length
// of that same list. Split across a caller, each step is a place a later edit can disagree with
// the other two.
//
// AND IT IS A FUNCTION RATHER THAN THIRTY LINES INSIDE [Group.publishCommitLocked] BECAUSE OF A
// MEASUREMENT, which is the part worth keeping. The first draft left all three inline; no test in
// this package can call publishCommitLocked, because it submits and a `*sdk.MessageTransport` is a
// concrete type with no stub -- so the property suite built its OWN fan-out beside production's
// and measured that. A mutant that replaced the draw with `self.pqSecretLocked()` -- no rotation
// at all, item 243's entire subject inverted -- then passed the whole suite, including the case
// whose headline is that a removed member cannot follow. The suite was measuring its own
// arithmetic. This is the seam that stops it: the harness calls this, production calls this, and
// what is left re-spelled in a test is only the submit.
//
// NOTHING IS FILED AND NOTHING IS SUBMITTED HERE. The table entry is written after the server has
// taken the commit ([Group.publishCommitLocked]'s step 4), because a row written before the CAS
// race is a row a LOST race leaves behind naming an epoch this device never entered -- which is
// the orphan state the receive side has to detect in other devices' fan-outs, and this device must
// not manufacture it in its own table.
func (self *Group) stageEpochRotationLocked(opensEpoch uint64, removing []uint32) (*stagedRotation, error) {
	// THE DRAW, ledger item 243's own sentence: a FRESH pq_secret for the epoch this commit
	// opens. Everything below descends from it -- the epoch's storage root, therefore its write
	// and read keys, therefore the digest the commit carries, therefore what every wrap has to
	// contain for that digest to be reproducible -- so it is first, and there is exactly one of
	// it. A second draw anywhere would be a second value to keep in step with this one.
	pqSecret, err := messagegroup.NewPqSecret(self.device.random)
	if err != nil {
		return nil, fmt.Errorf("urmessage: pq_secret for epoch %d: %w", opensEpoch, err)
	}
	// THE TARGETS, AND expected_wrap_count IS THE LENGTH OF THIS LIST. It used to be
	// `pending.MemberCount` at the commit and `len(wrapTargets)` at the marker: two numbers, two
	// reads, equal only because an Add's staged count and the post-merge live count agree. Under a
	// Remove they would not, and under the pre-merge fan-out they cannot -- the targets are the
	// LIVE tree minus the leaves this commit removes. Two numbers built from one expression cannot
	// disagree, which is the half of item 132 a client can close by itself.
	targets, err := self.wrapTargetsAtLocked(opensEpoch, removing)
	if err != nil {
		zeroizeState(pqSecret)
		return nil, err
	}
	if len(targets) == 0 {
		zeroizeState(pqSecret)
		return nil, ErrNoMemberAdded
	}
	staged := &stagedRotation{pqSecret: pqSecret, targets: targets}
	for _, target := range targets {
		record, err := self.sealEpochWrapLocked(opensEpoch, target, pqSecret)
		if err != nil {
			zeroizeState(pqSecret)
			return nil, err
		}
		staged.wraps = append(staged.wraps, record)
	}
	return staged, nil
}

// sealEpochWrapLocked builds one device wrap body for one target and seals it into a record at
// THIS group's current epoch.
//
// TWO EPOCHS ARE LIVE IN THIS CALL AND CONFUSING THEM IS THE DEFECT IT IS WRITTEN AGAINST. The
// record's header epoch is the epoch the group is standing at -- n, the one the server will accept
// a write at, because the commit has not been submitted yet. Everything the wrap is ABOUT is n+1:
// the envelope's content_epoch, the wrap_target_handle the target will look under, the WrapTag's
// own epoch, and the secret in the payload. So `opensEpoch` is a parameter and the header's epoch
// is never read here; a call that took one epoch would have to guess which.
//
// ONE RECORD PER TARGET AND NOT TWO, and the reason is a REFUSAL IN CONNECT rather than a
// simplification here. m1 Task 14 Property 1 is "exactly two" -- a PERMANENT record carrying
// pq_secret[k] and an EPH(5) one carrying eph_root[k] -- and connect's sealer refuses the second
// outright: seal.go's sealEphWindowOnLoop answers ErrEphWrapWindowUnruled for any EPH record
// carrying a wrap tag, because ledger open item 185 leaves that record's eph_window unstated while
// Spec A S19 and Spec B section 5.1 check 3 refuse an implausible one and a wrap head has no
// sent_at to divide. That refusal is MEASURED from this side rather than described --
// TestTheEphRootTwinOfThisWrapIsRefusedByConnectAndNotByThisPackage -- and it goes RED the day 185
// is ruled and the refusal lifts, which is when the second record is due and
// expected_wrap_count becomes MASTER section 8.2's 2 x device_leaves + 1.
func (self *Group) sealEpochWrapLocked(opensEpoch uint64, target wrapTarget, pqSecret []byte) (*message.Record, error) {
	publicKey, err := messagegroup.ParseXwingPublicKey(target.xwingPub)
	if err != nil {
		return nil, fmt.Errorf("urmessage: leaf %d's published x-wing key: %w", target.leaf, err)
	}
	body, err := messagegroup.SealWrapBody(self.device.random, publicKey, messagegroup.WrapEnvelope{
		FormatVersion: messagegroup.WrapFormatVersion,
		TargetType:    wrapTargetTypeDeviceLeaf,
		PayloadType:   wrapPayloadTypePqSecret,
		ContentEpoch:  opensEpoch,
	}, self.id, target.handle[:], pqSecret)
	if err != nil {
		return nil, fmt.Errorf("urmessage: sealing the device wrap for leaf %d at epoch %d: %w", target.leaf, opensEpoch, err)
	}
	record, err := self.session.SealRecord(message.RetentionPermanent, 0, false,
		encodeHead(self.device.nowMs()), body, 0, &message.ServerAttachment{
			Kind: message.AttachmentWrap,
			Wrap: &message.WrapTag{WrapTargetHandle: append([]byte(nil), target.handle[:]...), Epoch: opensEpoch},
		})
	if err != nil {
		return nil, fmt.Errorf("urmessage: sealing an epoch wrap: %w", err)
	}
	return record, nil
}

// ── the receiving leg ────────────────────────────────────────────────────────────────────────

// ingestWrapLocked reads one wrap record, and answers whether this device did anything with it.
//
// WHAT IT DOES NOT DO IS INSTALL. A wrap that opens is STAGED, under the epoch its envelope names,
// and nothing is filed until the commit that opens that epoch has been applied and its digest has
// said which candidate is the real one. That order is forced twice over: ruling 37 puts the wrap
// on the wire ahead of the commit, so at the moment it is read this device has no mls_secret[n+1]
// to judge it with; and m1 Task 14 Property 7 defines HONOURING a wrap as INSTALLING what it
// carries, so a wrap installed before it was judged is a wrap honoured on nobody's authority.
//
// EVERY ARM IS COUNTED AND THE MISS IS NOT AN ERROR HERE. A wrap addressed to some other member is
// the ordinary case -- a fan-out to N members puts N-1 of them in front of this device -- and it
// costs one handle derivation and no key material. A wrap addressed to THIS device that does not
// open is recorded against its epoch and resolved at the commit, not failed here, because the
// commit is what decides whether the epoch was even opened: a wrap that will not open for an epoch
// that never happens is a non-event and must not hold this group's cursor.
func (self *Group) ingestWrapLocked(walk *pageWalk, recordId uint64, parsed *message.Record,
	attachment *message.ServerAttachment) bool {

	tag := attachment.Wrap
	if tag == nil {
		return false
	}
	ownLeaf, known := walk.leaves[walk.own]
	if !known {
		return false
	}
	// THE MEMBER COMPUTES ITS OWN HANDLE AND THE SERVER CANNOT INVERT ONE -- m1 Task 14 Property
	// 2. The epoch in the derivation is the one the TAG names and never this group's, because the
	// wrap is filed under the epoch it delivers and is written while the group still stands at the
	// one below.
	own := messagegroup.WrapTargetHandle(self.groupHandleKey, tag.Epoch, ownLeaf)
	if !bytes.Equal(own[:], tag.WrapTargetHandle) {
		return false
	}
	// A wrap for an epoch this device has already entered carries a secret it either already holds
	// or can no longer act on: the founding fan-out's own records are the ordinary instance, since
	// epoch one's secret travels in the Welcome. Counted and dropped rather than opened, so a
	// re-walk over old rows cannot manufacture candidates for a decision that is already taken.
	if tag.Epoch <= self.epoch {
		return false
	}
	// THE SENDER'S LADDER AT THE WRAP'S OWN CLASS, FIRST, and it is the same obligation
	// [Group.ingestCommitLocked] has one record later and for the same reason: a device wrap is a
	// PERMANENT record, and this device may only ever have tracked this sender's DURABLE ladder
	// from its ordinary messages, so the class this record rides is one no message installed.
	// Without it the open fails at the ratchet rather than at anything about the wrap -- which is
	// indistinguishable, in the counter, from a wrap sealed to the wrong key. MEASURED: it is the
	// defect this line was added for, and every member's own wrap was reported unreadable.
	//
	// The ceremony arm commits no ratchet, so this peek spends nothing the sender's next ordinary
	// record needs.
	senderLeaf, senderKnown := walk.leaves[parsed.Header.SenderHandle]
	if !senderKnown {
		return false
	}
	if err := self.trackLocked(senderLeaf, &parsed.Header); err != nil {
		self.wrapsUnreadable[tag.Epoch] += 1
		return true
	}
	_, body, err := self.session.OpenCeremonyRecord(parsed)
	if err != nil {
		self.wrapsUnreadable[tag.Epoch] += 1
		return true
	}
	envelope, payload, err := self.device.openWrapToOwnLeaf(self.id, tag.Epoch,
		wrapTargetTypeDeviceLeaf, tag.WrapTargetHandle, wrapPayloadTypePqSecret, body)
	if err != nil {
		// THE DECAPSULATION NEVER SAYS NO. ML-KEM-768 uses implicit rejection, so a wrap sealed
		// for another leaf decapsulates SUCCESSFULLY to a pseudorandom secret and the only thing
		// that separates "mine" from "not mine" is the Poly1305 tag -- which is why this arm is
		// recorded as a wrap that did not open rather than diagnosed further. connect's
		// OpenWrapBody header carries the whole argument.
		self.wrapsUnreadable[tag.Epoch] += 1
		return true
	}
	if len(payload) != messagegroup.PqSecretBytes {
		zeroizeState(payload)
		self.wrapsUnreadable[tag.Epoch] += 1
		return true
	}
	_ = envelope
	self.wrapsFor[tag.Epoch] = append(self.wrapsFor[tag.Epoch], wrapCandidate{
		recordId: recordId,
		secret:   payload,
	})
	self.stats.WrapOpened += 1
	return true
}

// dropWrapCandidatesLocked erases and forgets every staged candidate for an epoch, and everything
// below it.
//
// IT RUNS AT EVERY RESOLUTION, INCLUDING THE FAILING ONES. A candidate that was not the epoch's
// secret is an orphan and will never become one -- the epoch is open and its digest has spoken --
// so a table that kept it would hold another group's post-quantum material until the process
// died, and would offer it again to the next epoch's resolution.
func (self *Group) dropWrapCandidatesLocked(throughEpoch uint64) {
	for epoch, candidates := range self.wrapsFor {
		if throughEpoch < epoch {
			continue
		}
		for _, candidate := range candidates {
			zeroizeState(candidate.secret)
		}
		delete(self.wrapsFor, epoch)
	}
	for epoch := range self.wrapsUnreadable {
		if epoch <= throughEpoch {
			delete(self.wrapsUnreadable, epoch)
		}
	}
}

// zeroizeWrapCandidatesLocked erases every staged candidate, whatever epoch it is for.
func (self *Group) zeroizeWrapCandidatesLocked() {
	for epoch, candidates := range self.wrapsFor {
		for _, candidate := range candidates {
			zeroizeState(candidate.secret)
		}
		delete(self.wrapsFor, epoch)
	}
}
