package urmessage

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/urnetwork/connect/mls"
)

// ══════════════════════════════════════════════════════════════════════════════════════════════
// LEDGER RULING 52: THE STATE A REMOVED MEMBER IS LEFT IN
// ══════════════════════════════════════════════════════════════════════════════════════════════
//
// WHAT THIS FILE IS ABOUT, AS MEASURED AT sdk ca89760 BEFORE ANY OF IT EXISTED. A device a commit
// removed was told once, generically, and then went quiet for ever:
//
//	1st Receive: ErrCommitIngest: applying the commit: mls: this client was removed by the commit
//	2nd Receive: ErrCommitIngest: processing the commit: mls: the group is closed and its epoch secrets have been zeroized
//	3rd Receive: ErrRecordAbandoned: record 7, after 3 attempts: <the 2nd sentence>
//	4th, 5th, 6th Receive: nil, with Stats.Omitted at 0 and a live composer.
//
// So there are four properties here and they are four different mechanisms: the sentinel has to be
// NAMED rather than generic; it has to survive the ONE walk mls can be asked on; the walk must not
// spend maxRecordAttempts on the record and resolve past it; and the whole thing has to survive a
// restart, which is what part TEN of [GroupRecord] is for. The Send half and the restart half are
// driven end to end over a real server by cp3b's
// TestARemovedDeviceIsToldSoByNameOnEveryWalkAndStillIsAfterARestart; what is here is the walk's
// own behaviour, the store's codec, and the compatibility question a new part always raises.

// A REMOVED DEVICE IS TOLD BY NAME ON EVERY WALK, AND THE RECORD IS NEVER ABANDONED.
//
// THE FOUR CLAUSES, each against a different one of the four defects above: the FIRST walk answers
// [ErrRemovedFromGroup] and NOT [ErrCommitIngest] (named, not generic) while still carrying mls's own
// sentinel so the cause is readable; the SECOND, THIRD and FOURTH walks answer the same sentinel,
// which is the state being sticky rather than re-derived -- mls cannot be asked twice, it closes the
// group as it answers; [Stats.Unopened], [Stats.FailedOpen] and [Group.UnopenedRecords] stay EMPTY
// across all four, which is the walk not treating a removal as a record that did not open; and the
// group stays at the epoch it was removed at, so nothing was half-applied.
//
// AND IT IS TOLD APART FROM THE OTHER THREE STATES BY NAME, in the same assertion block: not
// [ErrRemovalWithoutRotation] (ruling 41's halt, a commit this device REFUSED), not
// [ErrNoWrapForEpoch]/[ErrWrapUnreadable]/[ErrOrphanWrap] (ruling 38's dark states, a commit it
// FOLLOWED without keys), and not [ErrFetchRefused] or [ErrRecordAbandoned]. That list is the
// ruling's own text turned into a predicate.
//
// THE INLINE CONTROL IS THE SURVIVOR OF THE SAME COMMIT, in the same case and over the same page: bob
// walks the identical removal, follows it into the epoch it opens, and reads (0, nil) from
// [Group.Removal]. Without it every clause above is satisfied by a field set on every ingest.
//
// WHAT WOULD GO RED: drop the mls.ErrRemovedFromGroup arm in [Group.ingestCommitLocked] step (4)
// (the first walk answers ErrCommitIngest); drop the `self.removed != nil` clause in
// [Group.openPageLocked]'s is_commit arm (the second walk answers `the group is closed`, the third
// [ErrRecordAbandoned] with Unopened at 1, the fourth nil); set the state on any ApplyCommit failure
// (the control's survivor is removed too); set it for every ingest (the same).
func TestARemovedDeviceAnswersTheRemovalOnEveryWalkAndTheRecordIsNeverAbandoned(t *testing.T) {
	ctx := context.Background()
	world := newRotWorld(t, "alice", "bob", "carol")
	alice, bob, carol := world.member("alice"), world.member("bob"), world.member("carol")

	// NAME EVERY MEMBER IN THE POLICY, so the verb has an entry to drop and the commit it derives
	// is not an R0c phantom every receiver refuses before it can remove anybody.
	named := rotPolicyOf(t, alice)
	named.SetRole(bob.dev.identityPub, mls.RoleAdmin)
	named.SetRole(carol.dev.identityPub, mls.RoleMember)
	naming := world.rotate(alice, func() ([]byte, []byte, []byte, error) {
		return alice.handle.CommitPolicy(rotPolicyBody(t, named))
	})
	for _, who := range []*rotMember{bob, carol} {
		if err := world.deliver(who, naming.page()...); err != nil {
			t.Fatalf("%s's walk over the policy that names everybody: %v", who.name, err)
		}
	}

	// BEFORE THE REMOVAL BOTH RECEIVERS ARE MEMBERS AND SAY SO: the control that makes the two
	// different answers below two answers rather than one constant.
	for _, who := range []*rotMember{bob, carol} {
		if epoch, removal := who.group.Removal(); removal != nil || epoch != 0 {
			t.Fatalf("CONTROL FAILED: %s reads (%d, %v) from Removal while it is still a member",
				who.name, epoch, removal)
		}
	}
	removedAt := carol.group.Epoch()

	// THE VERB'S OWN DERIVATION, captured and refused so nothing is published, then committed
	// through the seam: the vector under test is the one [Group.RemoveMember] computed.
	capture := captureOutgoingOn(t, alice.group)
	if err := alice.group.RemoveMember(ctx, carol.dev.identityPub); !errors.Is(err, errRemoveCaptureStop) {
		t.Fatalf("alice's RemoveMember answered %v, want this case's authorizer refusal", err)
	}
	alice.group.device.commitAuthorizer = nil
	if capture.calls != 1 {
		t.Fatalf("the configured authorizer saw %d decision(s), want 1", capture.calls)
	}
	removal := world.rotate(alice, func() ([]byte, []byte, []byte, error) {
		return alice.handle.CommitRemoveWithExtensions(capture.decision.RemovedLeaves,
			capture.decision.ExtensionsAfter)
	})

	// ── THE SURVIVOR, FIRST, SO THE CONTROL IS TAKEN OVER THE SAME PAGE ─────────────────────────
	if err := world.deliver(bob, removal.page()...); err != nil {
		t.Fatalf("CONTROL FAILED: the survivor's walk over the removal answered %v; every clause "+
			"below would then be about a page nobody could follow", err)
	}
	if got := bob.group.Epoch(); got != removal.opens {
		t.Fatalf("CONTROL FAILED: the survivor is at epoch %d after the removal, want %d", got, removal.opens)
	}
	if epoch, state := bob.group.Removal(); state != nil || epoch != 0 {
		t.Errorf("the SURVIVOR of the removal reads (%d, %v) from Removal: the state is being set "+
			"for a member the commit left in the group", epoch, state)
	}

	// ── AND THE REMOVED DEVICE, FOUR WALKS OVER THE SAME PAGE ───────────────────────────────────
	for walk := 1; walk <= 4; walk += 1 {
		err := world.deliver(carol, removal.page()...)
		if !errors.Is(err, ErrRemovedFromGroup) {
			t.Fatalf("walk %d over the removal answered %v, want ErrRemovedFromGroup. Before ruling "+
				"52 walk 1 answered ErrCommitIngest, walk 2 `the group is closed and its epoch "+
				"secrets have been zeroized`, walk 3 ErrRecordAbandoned and walk 4 NIL", walk, err)
		}
		if !errors.Is(err, mls.ErrRemovedFromGroup) {
			t.Errorf("walk %d does not carry mls.ErrRemovedFromGroup, which is the cause and is a "+
				"value rather than state: %v", walk, err)
		}
		// NAMED AND NOT GENERIC, which is the ruling's second clause: ErrCommitIngest is what a
		// bent ciphertext and a commit whose exporter failed both answer, and a caller that saw it
		// here would read a membership that ended as a transient it should retry.
		if errors.Is(err, ErrCommitIngest) {
			t.Errorf("walk %d answers ErrCommitIngest as well, so a caller cannot tell a removal "+
				"from a commit that did not open: %v", walk, err)
		}
		for _, other := range []struct {
			name string
			err  error
		}{
			{"ErrRemovalWithoutRotation (ruling 41's halt: a commit this device REFUSED)", ErrRemovalWithoutRotation},
			{"ErrNoWrapForEpoch (ruling 38: a commit it FOLLOWED with no keys)", ErrNoWrapForEpoch},
			{"ErrWrapUnreadable", ErrWrapUnreadable},
			{"ErrOrphanWrap", ErrOrphanWrap},
			{"ErrRecordAbandoned (a record that did not open)", ErrRecordAbandoned},
			{"ErrFetchRefused (the transport)", ErrFetchRefused},
			{"ErrIdentityInUse", ErrIdentityInUse},
		} {
			if errors.Is(err, other.err) {
				t.Errorf("walk %d also answers %s; ruling 52's whole content is that this state is "+
					"distinguishable from that one", walk, other.name)
			}
		}
		// THE WALK DID NOT TREAT IT AS A RECORD THAT DID NOT OPEN: no attempt spent, nothing
		// abandoned, and the cursor still below the commit -- which is what makes walk 2 possible.
		stats := carol.group.Stats()
		if stats.FailedOpen != 0 || stats.Unopened != 0 || len(carol.group.UnopenedRecords()) != 0 {
			t.Errorf("after walk %d the removed device has FailedOpen %d, Unopened %d and unopened "+
				"records %v: three attempts and a cursor bump is the shape of a transient, and a "+
				"removal is the one record a device cannot open and must not retry",
				walk, stats.FailedOpen, stats.Unopened, carol.group.UnopenedRecords())
		}
		if epoch, state := carol.group.Removal(); state == nil || epoch != removedAt {
			t.Errorf("after walk %d Removal answers (%d, %v), want (%d, non-nil)",
				walk, epoch, state, removedAt)
		}
		if got := carol.group.Epoch(); got != removedAt {
			t.Errorf("after walk %d the removed device is at epoch %d, want %d", walk, got, removedAt)
		}
	}

	// AND THE SEND DOOR ANSWERS THE SAME STATE. It is the door and not [Group.Send] because this
	// package has no transport -- the real verb is driven in cp3b -- and it is the door every send
	// kind goes through.
	if _, err := carol.group.sendableLocked(KindText); !errors.Is(err, ErrRemovedFromGroup) {
		t.Errorf("the removed device's send door answered %v, want ErrRemovedFromGroup. Measured "+
			"before ruling 52: `sealing a message: messagegroup: an application record's inner MLS "+
			"frame did not open: mls: the group is closed and its epoch secrets have been zeroized`, "+
			"which carries no sentinel a composer could branch on", err)
	}
	if err := carol.group.committableLocked(); !errors.Is(err, ErrRemovedFromGroup) {
		t.Errorf("the removed device's commit door answered %v, want ErrRemovedFromGroup", err)
	}
	// the control beside them: the survivor's own doors are open
	if _, err := bob.group.sendableLocked(KindText); err != nil {
		t.Errorf("CONTROL FAILED: the SURVIVOR's send door answered %v, so the two refusals above "+
			"are satisfied by a door that is shut for everybody", err)
	}
	t.Logf("four walks over one removal: every one answers ErrRemovedFromGroup carrying mls's own "+
		"sentinel, nothing was abandoned, the group stands at epoch %d, and the survivor of the "+
		"same commit is at %d and unaffected", removedAt, removal.opens)
}

// RULING 52's STATE SURVIVES A RESTART, THROUGH PART TEN, AND THE ROUND TRIP IS THE STORE'S OWN.
//
// WHY THIS IS THE CASE THAT DECIDES THE CARRIER. The state is derivable from the wire exactly ONCE
// per MLS handle: mls closes the group and zeroizes its epoch secrets as it answers
// mls.ErrRemovedFromGroup, so the next Process answers `the group is closed`. A device that came back
// without the state would therefore be relying on a re-derivation that only works because the cursor
// is not persisted -- and would go quiet the moment anything above the removal was abandoned. So the
// state goes on the disk, and this asks the disk.
//
// WHAT IS ASSERTED: a removed group's record carries TEN parts with a non-empty tenth; the reader
// hands back the kind and the epoch it was written with; and [Device.restoreOne] rebuilds a group
// that answers [ErrRemovedFromGroup] from [Group.Removal] and from both doors, at the same epoch,
// with mls's own sentinel still in the chain -- which is [removedErrorOf] re-wrapping a VALUE rather
// than inventing a diagnosis.
//
// WHAT WOULD GO RED: drop RemovedKind/RemovedEpoch from [Group.groupRecordLocked]; stop writing part
// ten in [DurableStateStore.PutGroupRecord]; drop the two fields from [Device.restoreOne]'s literal;
// have [removedErrorOf] answer a bare sentence with no sentinel.
func TestTheRemovalStateIsOnTheDiskAndARestoredGroupComesBackKnowingIt(t *testing.T) {
	world := newRotWorld(t, "alice", "bob")
	removed := world.member("bob")
	removedAt := removed.group.Epoch()

	// the state, set through the one writer rather than by assigning the field: it persists itself.
	if err := removed.group.removedLocked(mls.ErrRemovedFromGroup); !errors.Is(err, ErrRemovedFromGroup) {
		t.Fatalf("removedLocked answered %v", err)
	}

	// ── THE DISK ────────────────────────────────────────────────────────────────────────────────
	store := removed.dev.store
	parts, err := store.readRecord(store.groupRecordPath(removed.group.id), stateKindGroupRecord)
	if err != nil {
		t.Fatalf("reading the group record back: %v", err)
	}
	if len(parts) != 10 {
		t.Fatalf("the group record carries %d parts, want 10: part ten is the removal", len(parts))
	}
	if len(parts[9]) != 1+8 {
		t.Fatalf("the removal part is %d octets, want %d (u8 kind, u64 epoch)", len(parts[9]), 1+8)
	}
	if parts[9][0] != removedByCommit {
		t.Errorf("the removal part names kind %d, want %d", parts[9][0], removedByCommit)
	}
	records, err := store.GroupRecords()
	if err != nil {
		t.Fatalf("GroupRecords: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("the store holds %d group record(s), want 1", len(records))
	}
	if records[0].RemovedKind != removedByCommit || records[0].RemovedEpoch != removedAt {
		t.Fatalf("the record decodes to kind %d at epoch %d, want %d at %d",
			records[0].RemovedKind, records[0].RemovedEpoch, removedByCommit, removedAt)
	}

	// ── THE RESTORE ─────────────────────────────────────────────────────────────────────────────
	revived := restoredRotDevice(t, removed)
	group, err := revived.device.restoreOne(revived.store, records[0], restoreTestNonce(), removedAt)
	if err != nil {
		t.Fatalf("the restore of a removed group: %v. A group whose device was removed is still a "+
			"group whose history this device may read, so a restore that refused it would take the "+
			"transcript away as well as the membership", err)
	}
	defer group.Close()

	epoch, state := group.Removal()
	if state == nil {
		t.Fatalf("the restored group reads (%d, nil) from Removal: the state did not survive the "+
			"process, and the device is back to reading as caught up and silent", epoch)
	}
	if epoch != removedAt {
		t.Errorf("the restored group was removed at epoch %d, want %d", epoch, removedAt)
	}
	if !errors.Is(state, ErrRemovedFromGroup) {
		t.Errorf("the restored state does not carry ErrRemovedFromGroup: %v", state)
	}
	if !errors.Is(state, mls.ErrRemovedFromGroup) {
		t.Errorf("the restored state does not carry mls.ErrRemovedFromGroup: %v. The cause is a "+
			"VALUE and not state a restart can invalidate, so a caller branching on that name must "+
			"not read true before a restart and false after it", state)
	}
	if _, err := group.sendableLocked(KindText); !errors.Is(err, ErrRemovedFromGroup) {
		t.Errorf("the restored group's send door answered %v, want ErrRemovedFromGroup", err)
	}
	if err := group.committableLocked(); !errors.Is(err, ErrRemovedFromGroup) {
		t.Errorf("the restored group's commit door answered %v, want ErrRemovedFromGroup", err)
	}
	t.Logf("the removal was written as part ten (kind %d, epoch %d) and came back as a group whose "+
		"every door answers by name", removedByCommit, removedAt)
}

// A STORE WRITTEN BEFORE PART TEN STILL STARTS, AND WHAT IT LOSES IS ONE WALK RATHER THAN ONE DEVICE.
//
// WHY THIS IS THE CASE THAT DECIDES THE SHAPE OF PART TEN. A restore that REFUSED a record written by
// an older build is a device that can never start again: the deployed alpha's disk is FIVE parts, the
// build before this one wrote NINE, and none of them carries a removal. So the reader takes every
// arity and a missing part means "this disk says nothing about a removal", which is exactly the state
// every build before this one was in.
//
// THE FIXTURE IS A REAL NINE-PART RECORD, written through the store's own framing with part ten
// dropped -- not a ten-part record with an empty part, which is what a device that is still a member
// writes and would prove nothing. The control is that the tenth part this build wrote is NOT empty,
// so stripping it changes something.
//
// AND THE SECOND CLAUSE IS THE PRICE, MEASURED RATHER THAN CLAIMED: such a device comes back reading
// as a MEMBER, and its next walk over the removing commit -- which is still the first record above a
// cursor that is not persisted, in a group whose MLS state on the disk still stands at the epoch
// before the removal -- re-derives the state and files part ten. So the loss is bounded to the window
// between the restore and the first Receive.
//
// WHAT WOULD GO RED: make [groupRecordOf] refuse a nine-part record (the restore fails and the device
// never starts); invent a removal at the read from anything other than part ten (the first clause);
// drop the mls.ErrRemovedFromGroup arm at ApplyCommit (the second clause cannot re-derive).
func TestAStoreWrittenBeforeTheRemovalPartStillStartsAndTheFirstWalkFilesTheRemoval(t *testing.T) {
	ctx := context.Background()
	world := newRotWorld(t, "alice", "bob")
	alice, bob := world.member("alice"), world.member("bob")

	named := rotPolicyOf(t, alice)
	named.SetRole(bob.dev.identityPub, mls.RoleMember)
	naming := world.rotate(alice, func() ([]byte, []byte, []byte, error) {
		return alice.handle.CommitPolicy(rotPolicyBody(t, named))
	})
	if err := world.deliver(bob, naming.page()...); err != nil {
		t.Fatalf("bob's walk over the policy that names him: %v", err)
	}
	removedAt := bob.group.Epoch()

	capture := captureOutgoingOn(t, alice.group)
	if err := alice.group.RemoveMember(ctx, bob.dev.identityPub); !errors.Is(err, errRemoveCaptureStop) {
		t.Fatalf("alice's RemoveMember answered %v, want this case's authorizer refusal", err)
	}
	alice.group.device.commitAuthorizer = nil
	removal := world.rotate(alice, func() ([]byte, []byte, []byte, error) {
		return alice.handle.CommitRemoveWithExtensions(capture.decision.RemovedLeaves,
			capture.decision.ExtensionsAfter)
	})
	if err := world.deliver(bob, removal.page()...); !errors.Is(err, ErrRemovedFromGroup) {
		t.Fatalf("bob's walk over his own removal answered %v", err)
	}

	// ── THE DISK, REWRITTEN AS A BUILD BEFORE PART TEN WROTE IT ─────────────────────────────────
	store := bob.dev.store
	path := store.groupRecordPath(bob.group.id)
	parts, err := store.readRecord(path, stateKindGroupRecord)
	if err != nil {
		t.Fatalf("reading the group record back: %v", err)
	}
	if len(parts) != 10 {
		t.Fatalf("this build wrote %d parts and this case strips the tenth; if the arity has moved, "+
			"the fixture is no longer an old store", len(parts))
	}
	if len(parts[9]) == 0 {
		t.Fatalf("CONTROL FAILED: the tenth part this build wrote is EMPTY over a group whose device " +
			"was removed, so stripping it changes nothing and this case would pass against a build " +
			"that never wrote one")
	}
	if err := store.writeRecord(path, stateKindGroupRecord, parts[:9]...); err != nil {
		t.Fatalf("rewriting the group record with nine parts: %v", err)
	}
	records, err := store.GroupRecords()
	if err != nil {
		t.Fatalf("GroupRecords over the nine-part disk: %v", err)
	}
	if len(records) != 1 || records[0].RemovedKind != removedNone || records[0].RemovedEpoch != 0 {
		t.Fatalf("the nine-part record decoded to kind %d at epoch %d; a record written before part "+
			"ten must come back as removedNone, which is a disk that says nothing rather than a "+
			"device that is certainly still a member",
			records[0].RemovedKind, records[0].RemovedEpoch)
	}

	// ── THE RESTORE: IT STARTS, AND IT READS AS A MEMBER ────────────────────────────────────────
	revived := restoredRotDevice(t, bob)
	group, err := revived.device.restoreOne(revived.store, records[0], restoreTestNonce(), removedAt)
	if err != nil {
		t.Fatalf("a device whose store predates part ten did not start: %v. A restore that refuses "+
			"an older record is a device that can never start again, which is the one outcome no "+
			"compatibility question may reach", err)
	}
	defer group.Close()
	if epoch, state := group.Removal(); state != nil || epoch != 0 {
		t.Fatalf("the nine-part restore came back with (%d, %v); part ten is the only place this "+
			"state is written, so a record without it must read as a member", epoch, state)
	}

	// ── AND THE FIRST WALK RE-DERIVES IT AND FILES IT, WHICH IS THE BOUND ON THE LOSS ───────────
	restoredMember := &rotMember{
		name: bob.name, root: bob.root,
		handle: group.handle, session: group.session, group: group,
		leaf: group.handle.OwnLeafIndex(),
	}
	group.ownFloorHeld, group.reconciled = true, true
	if err := world.deliver(restoredMember, removal.page()...); !errors.Is(err, ErrRemovedFromGroup) {
		t.Fatalf("the restored device's first walk over the commit that removed it answered %v, "+
			"want ErrRemovedFromGroup: the removing commit is still the first record above a cursor "+
			"nothing persists, so an old store's loss is one walk wide", err)
	}
	if epoch, state := group.Removal(); state == nil || epoch != removedAt {
		t.Fatalf("after the first walk the restored group reads (%d, %v), want (%d, non-nil)",
			epoch, state, removedAt)
	}
	after, err := revived.store.GroupRecords()
	if err != nil {
		t.Fatalf("GroupRecords after the walk: %v", err)
	}
	if len(after) != 1 || after[0].RemovedKind != removedByCommit || after[0].RemovedEpoch != removedAt {
		t.Errorf("after the re-derivation the disk holds kind %d at epoch %d, want %d at %d: the "+
			"walk that learned it did not write it down, so the NEXT restart loses it again",
			after[0].RemovedKind, after[0].RemovedEpoch, removedByCommit, removedAt)
	}
	t.Logf("a nine-part store started, read as a member, and its first walk over the removing "+
		"commit re-derived the state and wrote part ten (kind %d, epoch %d)", removedByCommit, removedAt)
}

// PART TEN's CODEC REFUSES EVERY SHAPE THIS BUILD DID NOT WRITE, AND THE ONE SHORT SHAPE IT ADMITS IS
// THE EMPTY ONE.
//
// IT IS [decodeWrapDark]'s DISCIPLINE ONE PART OVER, and the two are separate functions because they
// carry separate KIND SPACES -- but what this case MEASURED is that the codec cannot police that, and
// the finding is kept rather than dropped. A first draft asserted "a wrap_dark kind is refused by this
// part" with wrapDarkNoWrap as its instance, and it FAILED: wrapDarkNoWrap and removedByCommit are
// BOTH 1, so the one value a confused caller is most likely to hand the wrong encoder is the one value
// neither encoder can tell apart. The four wrap_dark kinds that do not collide (2, 3, 4, 5) ARE
// refused and that is asserted below; the collision at 1 is asserted as a FACT so the day either
// constant moves this case says so. What actually prevents the mix is structural and not checkable
// here: two parts, two encoders, two writers, and no call site that hands one field's kind to the
// other's function.
//
// AND EPOCH ZERO ROUND-TRIPS, which is why the kind octet is carried at all: this field holds the
// epoch a device was STANDING at, and a founder stands at epoch zero, so zero cannot be the "not
// removed" sentinel the way it is for [LeafOccupancy.DepartedEpoch].
//
// WHAT WOULD GO RED: accept a kind this build does not name; answer removedNone for a part of the
// wrong length; drop the kind octet and key "not removed" off a zero epoch; renumber either kind
// space so the collision at 1 stops being a collision (which is a disk format change and must be
// noticed).
func TestTheRemovalPartRefusesEveryShapeThisBuildDidNotWrite(t *testing.T) {
	if encoded, err := encodeRemoval(removedNone, 0); err != nil || encoded != nil {
		t.Errorf("encodeRemoval(removedNone) answered %v, %v; a member's part is EMPTY", encoded, err)
	}
	// AND removedNone WITH AN EPOCH IS STILL EMPTY, because the epoch is meaningless without a kind
	// and writing it would give two records of one member two shapes.
	if encoded, err := encodeRemoval(removedNone, 9); err != nil || encoded != nil {
		t.Errorf("encodeRemoval(removedNone, 9) answered %v, %v", encoded, err)
	}
	if _, err := encodeRemoval(removedUnnamed, 1); !errors.Is(err, ErrStateStoreFormat) {
		t.Errorf("encodeRemoval(removedUnnamed) answered %v, want ErrStateStoreFormat: a state this "+
			"build cannot name must fail the persist rather than be written as `still a member`", err)
	}
	// THE COLLISION, STATED AS THE FACT IT IS. This is the one wrap_dark kind part ten cannot refuse,
	// because the two constants are the same octet; every other one it can.
	if wrapDarkNoWrap != removedByCommit {
		t.Errorf("wrapDarkNoWrap is %d and removedByCommit is %d: they used to be the same octet, "+
			"which is why the loop below carves the first one out. If a kind space has been "+
			"renumbered, that is a disk format change and this case is the notice",
			wrapDarkNoWrap, removedByCommit)
	}
	for _, kind := range []uint8{wrapDarkUnreadable, wrapDarkOrphan, wrapDarkRemoval, wrapDarkUnfollowable} {
		if _, err := encodeRemoval(kind, 1); !errors.Is(err, ErrStateStoreFormat) {
			t.Errorf("encodeRemoval accepted wrap_dark kind %d, a kind of the part NEXT DOOR, and "+
				"answered %v", kind, err)
		}
		if _, _, err := decodeRemoval(append([]byte{kind}, bytes.Repeat([]byte{0x00}, 8)...)); !errors.Is(err, ErrStateStoreFormat) {
			t.Errorf("decodeRemoval read wrap_dark kind %d as a removal", kind)
		}
	}
	for _, epoch := range []uint64{0, 1, 7, ^uint64(0)} {
		encoded, err := encodeRemoval(removedByCommit, epoch)
		if err != nil {
			t.Fatalf("encodeRemoval at epoch %d: %v", epoch, err)
		}
		kind, got, err := decodeRemoval(encoded)
		if err != nil || kind != removedByCommit || got != epoch {
			t.Errorf("the removal part round-trips epoch %d as (%d, %d, %v)", epoch, kind, got, err)
		}
	}
	if kind, epoch, err := decodeRemoval(nil); err != nil || kind != removedNone || epoch != 0 {
		t.Errorf("decodeRemoval(nil) answered (%d, %d, %v), want removedNone", kind, epoch, err)
	}
	for _, part := range [][]byte{
		{removedByCommit},
		{removedByCommit, 0, 0, 0, 0, 0, 0, 0},
		{removedByCommit, 0, 0, 0, 0, 0, 0, 0, 0, 0},
		bytes.Repeat([]byte{0x00}, 9),
		append([]byte{removedUnnamed}, bytes.Repeat([]byte{0x00}, 8)...),
	} {
		if _, _, err := decodeRemoval(part); !errors.Is(err, ErrStateStoreFormat) {
			t.Errorf("decodeRemoval(% x) answered %v, want ErrStateStoreFormat: answering `still a "+
				"member` for a file that has been altered is answering the most comfortable thing",
				part, err)
		}
	}
	// AND THE PROJECTION OFF AN ERROR IS errors.Is AND NOT A STRING, held both ways.
	if got := removedKindOf(nil); got != removedNone {
		t.Errorf("removedKindOf(nil) is %d, want removedNone", got)
	}
	if got := removedKindOf(errors.New("some other refusal entirely")); got != removedUnnamed {
		t.Errorf("removedKindOf of an unrelated error is %d, want removedUnnamed: mapping it to "+
			"removedNone would persist the ABSENCE of a state that is present", got)
	}
	for _, wrapped := range []error{
		ErrRemovedFromGroup,
		errors.Join(ErrRemovedFromGroup, mls.ErrRemovedFromGroup),
		removedErrorOf(removedByCommit, 4),
	} {
		if got := removedKindOf(wrapped); got != removedByCommit {
			t.Errorf("removedKindOf(%v) is %d, want removedByCommit", wrapped, got)
		}
	}
	if removedErrorOf(removedNone, 4) != nil {
		t.Error("removedErrorOf(removedNone) answered a state")
	}
}
