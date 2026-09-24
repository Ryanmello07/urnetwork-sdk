// A NEWCOMER ON A REMOVED MEMBER'S LEAF INHERITS ITS sender_handle, AND WHAT THAT COSTS IS FOUR
// PIECES OF sdk STATE. LEDGER ITEM 245.
//
// ── THE DEFECT, IN ONE SENTENCE AND ONE DERIVATION ───────────────────────────────────────────
//
//	sender_handle = SenderHandle(group_handle_key, leaf)
//
// No epoch. No identity. And group_handle_key is the epoch-ZERO storage root's expansion, fixed for
// the life of the group and never rotated. RFC 9420 §7.7 refills the LEFTMOST BLANK leaf, so the
// first Add after a Remove puts a NEWCOMER on the removed member's leaf -- and therefore under the
// removed member's sixteen octets, byte for byte, for ever.
//
// Item 245 was RULED 2026-09-22: NO WIRE CHANGE. Both discriminator designs died on their own
// headline claims, and the consequence most cited for moving the wire -- "the newcomer can never
// send" -- is a special case of open item 205, which any current member can reach today in a group
// that has never removed anybody. What is left that is unique to this item is state, and it is
// what this file drives:
//
//  1. THE RESERVER SEED. The newcomer's durable reserver has never allocated for that stream, so
//     its first send seals at index 1 -- an index the server already holds a claim at -- is
//     answered REASON_STREAM_INDEX_REUSED, and [ErrIdentityInUse] latches for the life of the
//     process. [Group.seedOwnStreamLocked].
//  2. THE LADDER PRUNE. [Group.peerHeads] is kept across epochs by design and nothing pruned it,
//     so [Group.crossEpochLadderLocked] re-tracked the removed leaf's ladder at the removed
//     member's head -- and [ladderKey] is keyed on the LEAF, so that is the ladder the NEWCOMER's
//     first record meets. [Group.pruneRemovedLaddersLocked].
//  3. THE PER-RECORD-EPOCH HANDLE TABLE. [Group.leavesLocked] built the table at the CURRENT epoch
//     only, so every record the removed leaf sealed BELOW the commit resolved to no leaf and was
//     abandoned after [maxRecordAttempts]. [Group.leavesAtLocked].
//  4. ATTRIBUTION OFF THE SIGNED LEAF. `mine := header.SenderHandle == walk.own` was true of every
//     record the previous occupant of this device's leaf ever wrote. [Group.recordIsOwnLocked] and
//     [Message.SenderIdentity].
//
// ── THE CLAIM THIS FILE WAS SENT TO VERIFY RATHER THAN REPEAT ────────────────────────────────
//
// Item 245 says the reserver seed closes the message_id collision "for free, because message_id is
// computed from the record's own header, so disjoint index ranges give disjoint ids with no
// preimage change" -- and the ruling that no wire change is needed RESTS on that being true. It is
// measured here in both directions, from production's own derivation, in
// [TestANewcomerOnAReusedLeafCanSendAndItsMessageIdsAreDisjoint]:
//
//	MessageId = HKDF-Expand(group_handle_key, "mid/v1" ‖ LP(group_id) ‖ LP(sender_handle) ‖ u64(index), 32)
//
// group_id and sender_handle are EQUAL by construction for two occupants of one leaf, so the id is
// a function of the stream index alone across them. The collision at an EQUAL index is driven as
// the control -- two different members' records under ONE message_id -- and the disjointness above
// the seed is driven as the property. Neither is asserted from the formula: both are computed by
// [messagegroup.GroupSession.MessageIdOf], the door production uses.
//
// ── WHAT THIS FILE DOES NOT MEASURE, AND WHICH MUTANT SAYS SO ────────────────────────────────
//
// ONE OF THE FOUR PIECES IS UNMEASURED AND IT IS A THEOREM RATHER THAN A GAP. Replacing
// [Group.recordIsOwnLocked]'s whole body with `return maybeMine` -- the pre-repair line, the fourth
// piece's own mutant -- leaves every case here and all 176 cases of this package GREEN. The two
// facts that make that difference unproducible are written where the function is; the short of it
// is that a device can only open records at epochs it holds state for, and at every one of those it
// stands at its own leaf, so the two answers can differ only for a device whose HANDLE HAS MOVED --
// a removal and a re-Add of this device, which the sdk exposes no product method for.
//
// THE MUTANT THAT DOES DIE IS THE FAITHFUL SPELLING OF "ATTRIBUTION BACK TO THE HANDLE":
// [Message.SenderIdentity] filled from `header.SenderHandle` instead of from the signed leaf turns
// three cases here RED, because that is the value a reader attributes by and it is the one the two
// occupants of a leaf share.
package urmessage

import (
	"bytes"
	"fmt"
	"testing"
	"time"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/messagegroup"
)

// ── the world's remaining missing door ───────────────────────────────────────────────────────

// reuseWorld is one cohort at the moment a leaf changes hands: alice the founder and committer,
// bob at the leaf that is about to be taken away, carol the SURVIVOR that watches it happen, and
// eve the newcomer that lands on bob's leaf.
//
// EVERY MEMBER IS A REAL DEVICE over a real durable store with a real reserver -- [rotWorld] and
// [crossProcessDevice] -- so "the reserver starts at 1" and "the floor moved" are facts about a
// row on a disk and not about a field.
type reuseWorld struct {
	*rotWorld
	alice, bob, carol, eve *rotMember
	leaf                   uint32
	handle                 [16]byte
	bobRecords             []*sealed
	bobIds                 [][]byte
	aliceRecord            *sealed
	published              *rotation
}

// sealDurable seals one application record as `who` and gives it the next record id, exactly as
// [Group.Send] would below its own content codec: the class is DURABLE, the head is a clock
// reading, and the index comes off THIS DEVICE'S DURABLE RESERVER. The index is what this file is
// about, so it is never chosen here.
func (self *rotWorld) sealDurable(who *rotMember, body string) *sealed {
	self.t.Helper()
	record, err := who.group.session.SealRecord(message.RetentionDurable, 0, false,
		encodeHead(time.Now().UnixMilli()), []byte{byte(KindText), 'x'}, 0, nil)
	if err != nil {
		self.t.Fatalf("%s sealing %q: %v", who.name, body, err)
	}
	id, err := who.group.session.MessageIdOf(&record.Header)
	if err != nil {
		self.t.Fatalf("%s's message_id for %q: %v", who.name, body, err)
	}
	one := self.number(record)
	one.messageId = id[:]
	return one
}

// newReuseWorld builds the cohort and takes the leaf away, with the DEFECT ITSELF asserted as the
// precondition rather than assumed: the newcomer's handle must be byte-identical to the removed
// member's, or every case below is measuring an ordinary add.
//
// THE REMOVAL AND THE ADD ARE ONE COMMIT, which is the shape RFC 9420 §7.7 decides -- removes are
// applied before adds, so the Add takes the leaf the Remove has just blanked. It is built by
// [rotWorld.bundleAddAndRemove] (by REFERENCE, because the seam's by-value arms carry one kind of
// proposal each) and published as an HONEST rotation by [rotWorld.rotate], so the commit carries a
// real epoch digest over a real fresh pq_secret and ruling 41's refusal is not what this file
// measures.
func newReuseWorld(t *testing.T, bobLines int) *reuseWorld {
	t.Helper()
	world := newRotWorld(t, "alice", "bob", "carol")
	alice, bob, carol := world.member("alice"), world.member("bob"), world.member("carol")

	// (1) BOB WRITES, AT EPOCH 1, UNDER THE HANDLE THAT IS ABOUT TO CHANGE HANDS. These are the
	// records every later clause is about: the newcomer's stream collides with their indices, the
	// survivor's ladder stands at their head, and their handle stops resolving the moment bob's
	// leaf leaves the membership.
	records := []*sealed{}
	ids := [][]byte{}
	for at := 0; at < bobLines; at += 1 {
		one := world.sealDurable(bob, fmt.Sprintf("bob's line %d", at+1))
		records = append(records, one)
		ids = append(ids, one.messageId)
	}
	for at, one := range records {
		if one.record.Header.StreamIndex != uint64(at+1) {
			t.Fatalf("bob's line %d is at stream index %d, want %d: this file's whole subject is "+
				"which indices that stream has spent", at+1, one.record.Header.StreamIndex, at+1)
		}
	}
	// AND ALICE WRITES ONE LINE TOO, which is the fixture for the prune's own control rather
	// than decoration: [Group.peerHeads] holds a row only for a ladder that has AUTHENTICATED a
	// record, so a cohort in which only bob ever wrote gives the prune nothing it could wrongly
	// take away and "alice's row survived" would pass over an absence.
	aliceLine := world.sealDurable(alice, "alice's line, the ladder the prune must not take")
	// carol reads them, which is what puts her receiver ladders for both leaves at their heads.
	if err := world.deliver(carol, append(append([]*sealed{}, records...), aliceLine)...); err != nil {
		t.Fatalf("carol's walk over bob's and alice's lines: %v", err)
	}

	// (2) ONE COMMIT: BOB OUT, EVE IN.
	arm, joiner := world.bundleAddAndRemove(alice, bob.leaf, "eve", carol)
	var welcome, ratchetTree []byte
	published := world.rotate(alice, []uint32{bob.leaf}, func() ([]byte, []byte, []byte, error) {
		commit, admission, tree, err := arm()
		welcome, ratchetTree = admission, tree
		return commit, admission, tree, err
	})
	if err := world.deliver(carol, published.page()...); err != nil {
		t.Fatalf("carol's walk over the commit that removes bob and adds eve: %v", err)
	}
	handle, err := joiner.engine.JoinFromWelcome(welcome, ratchetTree)
	if err != nil {
		t.Fatalf("eve's JoinFromWelcome: %v", err)
	}
	t.Cleanup(func() { handle.Close() })
	eve := world.enrollAt("eve", joiner, handle, published.pqSecret)

	// (3) THE DEFECT, REPRODUCED, AS THIS FILE'S PRECONDITION. Two different members, one leaf,
	// one sender_handle.
	if eve.leaf != bob.leaf {
		t.Fatalf("eve landed at leaf %d and bob stood at leaf %d. RFC 9420 §7.7 refills the "+
			"leftmost blank, so this build's tree is not putting the newcomer where item 245 "+
			"measured it and every case in this file is measuring an ordinary add", eve.leaf, bob.leaf)
	}
	bobHandle, err := bob.group.session.SenderHandle()
	if err != nil {
		t.Fatalf("bob's sender handle: %v", err)
	}
	eveHandle, err := eve.group.session.SenderHandle()
	if err != nil {
		t.Fatalf("eve's sender handle: %v", err)
	}
	if bobHandle != eveHandle {
		t.Fatalf("eve's sender_handle %x is not bob's %x. Item 245's whole subject is that the "+
			"derivation takes no epoch and no identity, so if these differ the defect is gone and "+
			"this file is measuring nothing", eveHandle, bobHandle)
	}
	// AND THE CONTROL IN THE SAME QUERY, so that "two handles are equal" cannot be satisfied by a
	// build in which every handle is equal: carol stands at a different leaf and derives different
	// octets.
	carolHandle, err := carol.group.session.SenderHandle()
	if err != nil {
		t.Fatalf("carol's sender handle: %v", err)
	}
	if carolHandle == eveHandle {
		t.Fatalf("CONTROL FAILED: carol's sender_handle equals eve's, so this build derives one " +
			"handle for every leaf and the equality above says nothing about a reused leaf")
	}
	t.Logf("the defect: bob stood at leaf %d under sender_handle %x, eve was added onto leaf %d "+
		"and derives %x -- byte identical, with carol at leaf %d on %x as the control",
		bob.leaf, bobHandle, eve.leaf, eveHandle, carol.leaf, carolHandle)

	return &reuseWorld{
		rotWorld: world, alice: alice, bob: bob, carol: carol, eve: eve,
		leaf: bob.leaf, handle: eveHandle,
		bobRecords: records, bobIds: ids, aliceRecord: aliceLine, published: published,
	}
}

// ownStreamKey is the durable reserver's row for one member's own stream in this group: exactly
// the key [Group.ownHighWaterLocked] and [Group.seedOwnStreamLocked] build.
func (self *reuseWorld) ownStreamKey(handle [16]byte) messagegroup.StreamKey {
	key := messagegroup.StreamKey{SenderHandle: handle}
	copy(key.GroupId[:], self.groupId)
	return key
}

func (self *reuseWorld) highWater(who *rotMember) uint64 {
	self.t.Helper()
	high, err := who.dev.reserver.HighWater(self.ownStreamKey(self.handle))
	if err != nil {
		self.t.Fatalf("%s's own stream high water: %v", who.name, err)
	}
	return high
}

// ── 1. THE NEWCOMER CAN SEND, AND THE message_id COLLISION IS CLOSED BY THE SAME EDIT ────────

// A NEWCOMER ON A REUSED LEAF CAN SEND, AND THE PRE-FIX BRICK IS THE INLINE CONTROL.
//
// THE BRICK, DRIVEN AND NOT DESCRIBED. Before the walk, eve's reserver is a row that has never
// been allocated for -- the durable store answers contract clause 4's error-free zero -- so eve's
// first seal takes index 1. That record is sealed here, and TWO things about it are measured:
// its stream index is 1, an index bob's first line already spent; and its message_id, computed by
// [messagegroup.GroupSession.MessageIdOf], is BYTE-IDENTICAL to bob's first line's. On a server
// that is REASON_STREAM_INDEX_REUSED -- the claim map is keyed on (group_id, sender_handle,
// stream_index) with no epoch -- which [Group.cloneRefusalLocked] latches as [ErrIdentityInUse]
// for the life of the process. A member that has just joined can never send in the group it just
// joined.
//
// THE REPAIR. One walk over the page that is already on the server, and the floor has moved past
// every index claimed under those octets. The next seal is at 4 -- and 4 rather than 2 is exactly
// the seed's effect, because eve has already spent 1 herself.
//
// THE CLAIM VERIFIED RATHER THAN REPEATED, which is what this case was sent for. Item 245 says the
// seed closes the message_id collision "for free" and the no-wire-change ruling rests on it. Both
// directions are measured from production's own door: equal index under equal (group, handle)
// gives ONE id (the brick above), and disjoint indices give ids disjoint from bob's whole set.
// THE PREIMAGE IS UNCHANGED and that is held too -- the id is recomputed with the free function
// [messagegroup.MessageId] over (group_handle_key, group_id, sender_handle, stream_index) and must
// equal the session's answer, so "disjoint" is a property of the INDEX RANGE and not of some field
// this repair quietly added.
//
// WHAT WOULD GO RED: delete the seed in [Group.seedOwnStreamLocked]; gate it on
// [Group.walkReconcilesLocked] (a joined group is `reconciled` by construction, so the seed would
// never run for the one device that needs it); take the floor from records that OPENED rather than
// from the headers of records under this handle (eve can open none of bob's -- they are at an
// epoch she holds no state for).
func TestANewcomerOnAReusedLeafCanSendAndItsMessageIdsAreDisjoint(t *testing.T) {
	world := newReuseWorld(t, 3)
	eve := world.eve

	// ── THE BRICK, AS THE CONTROL, BEFORE ANY WALK ──────────────────────────────────────────
	if high := world.highWater(eve); high != 0 {
		t.Fatalf("CONTROL FAILED: eve's reserver already stands at %d before any walk, so an "+
			"index above bob's below would not be evidence that anything seeded it", high)
	}
	brick := world.sealDurable(eve, "eve's first line, on a fresh reserver")
	if brick.record.Header.StreamIndex != 1 {
		t.Fatalf("CONTROL FAILED: eve's first seal took index %d and a fresh reserver hands out 1; "+
			"the collision below is about index 1", brick.record.Header.StreamIndex)
	}
	if !bytes.Equal(brick.messageId, world.bobIds[0]) {
		t.Fatalf("CONTROL FAILED: eve's record at index 1 has message_id %x and bob's has %x. "+
			"They must be EQUAL: MASTER §8.4.5 expands an id from (group_id, sender_handle, "+
			"stream_index) and the first two are equal by construction here, so a difference "+
			"means the id takes an input item 245's ruling does not know about and the "+
			"no-wire-change premise has to be re-examined", brick.messageId, world.bobIds[0])
	}
	t.Logf("THE BRICK, DRIVEN: eve's first record and bob's first record are both at "+
		"(group %x, sender_handle %x, stream_index 1) and carry ONE message_id %x. On the server "+
		"that is REASON_STREAM_INDEX_REUSED and ErrIdentityInUse for the life of the process",
		world.groupId[:4], world.handle, brick.messageId)

	// ── THE WALK, AND THE FLOOR IT MOVES ────────────────────────────────────────────────────
	page := append([]*sealed{}, world.bobRecords...)
	page = append(page, world.published.page()...)
	if err := world.deliver(eve, page...); err != nil {
		t.Fatalf("eve's first walk answered %v. It must not: bob's lines are at an epoch eve "+
			"holds no state for, which is a GAP and not a failure, and the commit is one eve has "+
			"already applied through its Welcome", err)
	}
	if high := world.highWater(eve); high != 3 {
		t.Fatalf("eve's own stream floor stands at %d after the walk, want 3 -- the highest index "+
			"the page claimed under her own sender_handle. A floor below that is a device whose "+
			"next send collides with a record the server already holds", high)
	}
	if seeded := eve.group.Stats().StreamFloorSeeded; seeded != 1 {
		t.Fatalf("Stats.StreamFloorSeeded is %d, want 1: the one number that says a leaf changed "+
			"hands under this device", seeded)
	}

	// ── THE PROPERTY: THE NEXT SEAL IS ABOVE EVERYTHING BOB SPENT ───────────────────────────
	next := world.sealDurable(eve, "eve's line after the walk")
	if next.record.Header.StreamIndex != 4 {
		t.Fatalf("eve's next seal took index %d, want 4. Three is what bob spent and one is what "+
			"eve spent on the brick above, so 2 is the answer a device with NO seed gives and 4 "+
			"is the answer a seeded one gives -- the two are what this case tells apart",
			next.record.Header.StreamIndex)
	}
	for at, id := range world.bobIds {
		if bytes.Equal(next.messageId, id) {
			t.Fatalf("eve's record at index %d carries bob's line %d's message_id %x",
				next.record.Header.StreamIndex, at+1, id)
		}
	}
	if bytes.Equal(next.messageId, brick.messageId) {
		t.Fatalf("eve's two records carry one message_id")
	}

	// ── AND THE PREIMAGE IS UNCHANGED, which is the half of the claim a count could hide ────
	rebuilt := messagegroup.MessageId([]byte(world.groupHandleKey), [32]byte(world.groupId),
		world.handle, next.record.Header.StreamIndex)
	if !bytes.Equal(rebuilt[:], next.messageId) {
		t.Fatalf("the id the session answered (%x) is not HKDF-Expand(group_handle_key, "+
			"\"mid/v1\" ‖ LP(group_id) ‖ LP(sender_handle) ‖ u64(%d)) (%x). Item 245's ruling "+
			"rests on the id being a function of exactly those three inputs, so a difference here "+
			"means the preimage moved and the lead must be told",
			next.messageId, next.record.Header.StreamIndex, rebuilt)
	}
	t.Logf("ITEM 245's message_id CLAIM, VERIFIED IN BOTH DIRECTIONS: at an EQUAL index two " +
		"occupants of one leaf carry one id (the brick), and above the seed eve's indices {4} are " +
		"disjoint from bob's {1,2,3} so their ids are too -- with the id recomputed from the " +
		"published preimage to show nothing was added to it")
}

// ── 2. THE SURVIVOR DOES NOT RE-TRACK THE REUSED LEAF AT THE REMOVED MEMBER'S HEAD ───────────

// A SURVIVOR PRUNES THE REMOVED LEAF'S LADDER, AND THE NEWCOMER'S FIRST RECORD OPENS.
//
// WHY THE HARM IS NOT A WASTED LADDER. [Group.peerHeads] is the head each peer's receiver ratchet
// is re-tracked at after an epoch change, and it is kept across epochs BY DESIGN -- a ladder
// re-tracked at 0 answers [messagegroup.DefaultRecordWindowSize] rungs and then ErrOutOfWindow, so
// a busy peer would go silent at every commit. Nothing pruned it by RemovedLeaves. [ladderKey] is
// keyed on the LEAF, and §7.7 puts the newcomer on the removed member's leaf: so the survivor met
// the newcomer's very first record -- stream index 1 of a stream that starts here -- against a
// ratchet standing at the head somebody ELSE left behind, and a receiver ratchet does not rewind.
//
// THE CONTROL FIRES FOR ITS OWN REASON: alice's ladder, in the same table, at the same moment, is
// KEPT. Without it "the removed leaf's head is gone" would be satisfied by a prune that emptied
// the whole table -- which is the D3 starvation [Group.peerHeads] exists to prevent, arriving as
// the repair for this one.
//
// WHAT WOULD GO RED: delete [Group.pruneRemovedLaddersLocked]; call it AFTER
// [Group.crossEpochLadderLocked] instead of before it (the re-track has already installed the
// stale ladder by then); prune [Group.peerHeads] and not [Group.peerHeadsAt] and
// [Group.persistedHeads] (the table is written back as the UNION of the disk's and this process's,
// so a row left in either comes back at the next restart).
func TestASurvivorDoesNotReTrackAReusedLeafAtTheRemovedMembersHead(t *testing.T) {
	world := newReuseWorld(t, 3)
	carol, eve := world.carol, world.eve

	wire, err := message.RetentionClassWire(message.RetentionDurable, 0)
	if err != nil {
		t.Fatalf("the durable retention wire byte: %v", err)
	}
	removed := ladderKey{leaf: world.leaf, retentionWire: wire, ephWindow: 0}
	kept := ladderKey{leaf: world.alice.leaf, retentionWire: wire, ephWindow: 0}

	// ── THE CONTROL FOR THE FIXTURE ITSELF: carol really did authenticate bob's head ────────
	// It is taken from a SECOND world, walked to exactly the same point but with the commit not
	// yet delivered, because the assertion below is that the head is GONE and a head that was
	// never there would satisfy it.
	before := newRotWorld(t, "alice", "bob", "carol")
	beforeBob, beforeCarol := before.member("bob"), before.member("carol")
	beforeRecords := []*sealed{}
	for at := 0; at < 3; at += 1 {
		beforeRecords = append(beforeRecords, before.sealDurable(beforeBob, fmt.Sprintf("line %d", at+1)))
	}
	if err := before.deliver(beforeCarol, beforeRecords...); err != nil {
		t.Fatalf("CONTROL FAILED: carol's walk over bob's lines answered %v", err)
	}
	beforeLadder := ladderKey{leaf: beforeBob.leaf, retentionWire: wire, ephWindow: 0}
	if head := beforeCarol.group.peerHeads[beforeLadder]; head != 3 {
		t.Fatalf("CONTROL FAILED: with no removal at all, carol's head for bob's ladder is %d and "+
			"want 3. If it is 0 here then nothing in this world ever tracked that ladder and the "+
			"prune below would pass over an empty table", head)
	}
	t.Logf("CONTROL: with no removal, carol's ladder for leaf %d stands at head 3", beforeBob.leaf)

	// ── THE PROPERTY: after the commit, the removed leaf's rows are gone and alice's are not ─
	if head, held := carol.group.peerHeads[removed]; held {
		t.Fatalf("carol still holds a peer head of %d for leaf %d after the commit that removed "+
			"its occupant. [Group.crossEpochLadderLocked] re-tracks every entry of this table at "+
			"the new epoch, so this row is a ladder installed at the REMOVED member's head for a "+
			"leaf the NEWCOMER now stands at", head, removed.leaf)
	}
	for key := range carol.group.peerHeadsAt {
		if key.leaf == world.leaf {
			t.Fatalf("carol still holds a per-epoch head for the removed leaf %d at epoch %d; it "+
				"is what [Group.persistPeerHeadsLocked] writes back to the disk, so a restart "+
				"would restore the stale ladder this prune exists to remove", key.leaf, key.epoch)
		}
	}
	// AND NO MEMO SURVIVES FOR IT EITHER -- which is [Group.crossEpochLadderLocked]'s wholesale
	// clear and NOT the prune's doing, measured: a fourth loop over [Group.tracked] inside
	// [Group.pruneRemovedLaddersLocked] was deleted because removing it turned nothing red. It is
	// asserted here anyway, because what this case owes is the STATE the newcomer meets and not a
	// list of which function produced it.
	for key := range carol.group.tracked {
		if key.leaf == world.leaf {
			t.Fatalf("carol still memos leaf %d as tracked at epoch %d, so [Group.trackLocked] "+
				"would install nothing for the newcomer at all", key.leaf, key.epoch)
		}
	}
	if _, held := carol.group.peerHeads[kept]; !held {
		t.Fatalf("CONTROL FAILED: carol's head for alice's ladder (leaf %d) went with the removed "+
			"leaf's. The prune must take the leaves the commit REMOVED and no others -- emptying "+
			"the table is the D3 starvation this table exists to prevent", kept.leaf)
	}

	// ── AND THE NEWCOMER'S FIRST RECORD OPENS AT THE SURVIVOR ───────────────────────────────
	// This is the harm itself, driven end to end: eve seals at stream index 1 of a stream that
	// starts at this epoch, and carol opens it. Against an unpruned table the ladder would be
	// standing at 3 and a receiver ratchet does not rewind.
	first := world.sealDurable(eve, "eve's first line to the survivor")
	if first.record.Header.StreamIndex != 1 {
		t.Fatalf("eve's first record is at index %d; this clause is about index 1",
			first.record.Header.StreamIndex)
	}
	opened, err := carol.group.receiveForTest(world.rotWorld, carol, first)
	if err != nil {
		t.Fatalf("carol's walk over the newcomer's first record answered %v. It is stream index 1 "+
			"of a stream that starts at this epoch, and a ladder left standing at the removed "+
			"member's head refuses every index below it", err)
	}
	if len(opened) != 1 {
		t.Fatalf("carol opened %d message(s) from the newcomer's first record, want 1", len(opened))
	}
	if !bytes.Equal(opened[0].SenderIdentity, eve.dev.identityPub) {
		t.Fatalf("carol attributed the newcomer's record to identity %x, want eve's %x",
			opened[0].SenderIdentity, eve.dev.identityPub)
	}
	t.Logf("the newcomer's first record, at stream index 1 of the reused leaf, opened at the " +
		"survivor and was attributed to eve")
}

// receiveForTest is [rotWorld.deliver] with the opened messages handed back, which `deliver`
// answers only an error for. It is a method on [Group] so that a case can read what a walk
// DELIVERED and not only whether it refused.
func (self *Group) receiveForTest(world *rotWorld, who *rotMember, page ...*sealed) ([]*Message, error) {
	world.t.Helper()
	at := len(self.log)
	err := world.deliver(who, page...)
	delivered := []*Message{}
	for _, one := range self.log[min(at, len(self.log)):] {
		delivered = append(delivered, one)
	}
	return delivered, err
}

// ── 3. A REMOVED LEAF'S RECORD STILL RESOLVES, AND IS ATTRIBUTED TO THE REMOVED MEMBER ───────

// A RECORD FROM A REMOVED LEAF, AT ITS OWN EPOCH, MET BY A SURVIVOR STANDING AT THE EPOCH ABOVE.
//
// IT IS THE ORDINARY FIRST DAY OF REMOVE AND NOT A CORNER. The commit that removes a member is the
// LAST record of that member's history, so its whole conversation sits below it in record order --
// and the cursor is not persisted, so every restart re-walks all of it. With the handle table
// built at the CURRENT epoch the removed leaf is simply not in it: every one of those records
// answered "which is no leaf of this group", was retried [maxRecordAttempts] times and abandoned.
//
// THE TWO HALVES, AND THE SECOND IS THE ONE THE HANDLE CANNOT DO. It RESOLVES (the per-record-epoch
// table), and it is attributed to BOB (the signed leaf). The newcomer's record under the SAME
// sixteen octets is attributed to EVE, in the same case and at the same survivor, which is the
// control: two occupants, one handle, two identities. A build that attributed by sender_handle
// answers one value for both and cannot tell them apart at all -- and this case asserts the handles
// ARE equal, so that the identities differing is a statement about the repair and not about the
// fixture.
//
// AND IT DRIVES THE RESTART HALF OF THE LADDER PRUNE, which is the order
// [TestASurvivorDoesNotReTrackAReusedLeafAtTheRemovedMembersHead] cannot reach: the removed
// member's records are re-opened by a survivor ALREADY STANDING at the epoch above, which is
// exactly what a restart does (the cursor is not persisted, and the commit is met again at an
// epoch this device has left and skipped as ceremony, so it does not prune a second time).
// [Group.notePeerHeadLocked] refuses to raise the CURRENT head off a previous occupant's record,
// and without that clause the newcomer's line below is refused "index 1 is below this receiver's
// head 3" -- the very starvation the prune exists to stop, arriving through the re-walk.
//
// WHAT WOULD GO RED: put [Group.leavesAtLocked] back to the current epoch (the record is abandoned);
// take [Message.SenderIdentity] off the header's sender_handle instead of the signed leaf (bob's
// line and eve's line come back under one identity); delete the previous-occupant clause in
// [Group.notePeerHeadLocked] (the newcomer's line is starved).
func TestARecordFromARemovedLeafResolvesAtItsOwnEpochAndIsAttributedToTheRemovedMember(t *testing.T) {
	world := newReuseWorld(t, 3)
	carol, eve := world.carol, world.eve

	// carol stands at the epoch the commit opened; bob's records are at the one below it.
	if carol.group.epoch != world.published.opens {
		t.Fatalf("carol stands at epoch %d and the commit opened %d", carol.group.epoch, world.published.opens)
	}
	for _, one := range world.bobRecords {
		if one.record.Header.Epoch != world.published.opens-1 {
			t.Fatalf("bob's record is at epoch %d and the commit opened %d; this case is about a "+
				"record sealed one epoch BELOW the removal", one.record.Header.Epoch, world.published.opens)
		}
	}

	// THE RE-WALK. carol's log is emptied first, so what comes back is what THIS walk delivered
	// and not what she read before the commit -- the state a restart leaves, with no cursor.
	carol.group.mutex.Lock()
	carol.group.log = nil
	carol.group.logIndex = map[[MessageIdBytes]byte]int{}
	carol.group.delivered = map[uint64]bool{}
	carol.group.mutex.Unlock()

	delivered, err := carol.group.receiveForTest(world.rotWorld, carol, world.bobRecords...)
	if err != nil {
		t.Fatalf("carol's walk over the removed member's own records answered %v. They are at an "+
			"epoch she holds state for and under a handle her table must still resolve; a refusal "+
			"here is the abandonment item 245's third piece exists to stop", err)
	}
	if len(delivered) != len(world.bobRecords) {
		t.Fatalf("carol delivered %d of the removed member's %d records", len(delivered), len(world.bobRecords))
	}
	for at, one := range delivered {
		if one.Gap != "" {
			t.Fatalf("the removed member's line %d came back as a %q gap rather than as a message", at+1, one.Gap)
		}
		if one.Mine {
			t.Fatalf("carol reads the removed member's line %d as her own", at+1)
		}
		if !bytes.Equal(one.SenderIdentity, world.bob.dev.identityPub) {
			t.Fatalf("the removed member's line %d is attributed to identity %x, want bob's %x",
				at+1, one.SenderIdentity, world.bob.dev.identityPub)
		}
	}

	// AND THE RE-WALK RAISED NO CURRENT HEAD FOR THE REUSED LEAF. Three records of the previous
	// occupant just opened at their own epoch; if each had raised [Group.peerHeads] the newcomer's
	// ladder would now stand at 3 and its first record would be starved.
	wire, err := message.RetentionClassWire(message.RetentionDurable, 0)
	if err != nil {
		t.Fatalf("the durable retention wire byte: %v", err)
	}
	reused := ladderKey{leaf: world.leaf, retentionWire: wire, ephWindow: 0}
	if head := carol.group.peerHeads[reused]; head != 0 {
		t.Fatalf("after re-opening the removed member's %d records, carol's CURRENT head for leaf "+
			"%d stands at %d. A previous occupant's indices are not the newcomer's stream: the "+
			"newcomer starts at 1 and a ladder positioned at %d refuses every record it writes "+
			"until it has caught up with a history it had no part in",
			len(delivered), reused.leaf, head, head)
	}
	// AND THE CONTROL IN THE SAME QUERY: the PER-EPOCH head for that leaf at the epoch the
	// records were sealed at DID rise. Without it "the head is 0" would be satisfied by a build
	// that stopped recording heads at all, which is the D3 starvation arriving as the repair.
	rose := false
	for key, head := range carol.group.peerHeadsAt {
		if key.leaf == world.leaf && key.epoch == world.published.opens-1 && head == uint64(len(delivered)) {
			rose = true
		}
	}
	if !rose {
		t.Fatalf("CONTROL FAILED: carol recorded no per-epoch head of %d for leaf %d at epoch %d. "+
			"The clause above must suppress the CURRENT head only; a build that recorded no head "+
			"anywhere would pass it and would starve every peer at every epoch change",
			len(delivered), world.leaf, world.published.opens-1)
	}

	// ── THE CONTROL, AT THE SAME SURVIVOR AND UNDER THE SAME SIXTEEN OCTETS ─────────────────
	eveLine := world.sealDurable(eve, "eve's line, same handle, different person")
	if eveLine.record.Header.SenderHandle != world.bobRecords[0].record.Header.SenderHandle {
		t.Fatalf("CONTROL FAILED: eve's record and bob's carry different sender_handles, so " +
			"attributing them to two identities says nothing about a reused leaf")
	}
	fromEve, err := carol.group.receiveForTest(world.rotWorld, carol, eveLine)
	if err != nil {
		t.Fatalf("carol's walk over the newcomer's line answered %v", err)
	}
	if len(fromEve) != 1 {
		t.Fatalf("carol delivered %d message(s) for the newcomer's line, want 1", len(fromEve))
	}
	if !bytes.Equal(fromEve[0].SenderIdentity, eve.dev.identityPub) {
		t.Fatalf("the newcomer's line is attributed to identity %x, want eve's %x",
			fromEve[0].SenderIdentity, eve.dev.identityPub)
	}
	if bytes.Equal(world.bob.dev.identityPub, eve.dev.identityPub) {
		t.Fatalf("CONTROL FAILED: bob and eve are one identity, so the two assertions above are " +
			"one assertion")
	}
	t.Logf("ONE sender_handle %x, TWO members: %d record(s) attributed to bob %x and 1 to eve %x, "+
		"at one survivor, out of one table. The handle cannot tell them apart and the signed leaf can",
		world.handle, len(delivered), world.bob.dev.identityPub[:4], eve.dev.identityPub[:4])
}

// ── 4. A STORE WRITTEN BEFORE PART NINE STILL STARTS ─────────────────────────────────────────

// A DEVICE BUILT ON AN OLD STORE KEEPS WORKING, AND WHAT IT LOSES IS MEASURED RATHER THAN CLAIMED.
//
// WHY THIS IS THE CASE THAT DECIDES THE SHAPE OF PART NINE. A restore that REFUSED a record written
// by an older build is a device that can never start again -- the deployed alpha's disk is FIVE
// parts, the build before this one wrote EIGHT, and none of them carries a leaf ledger. So the
// reader takes both arities and [Device.restoreOne] seeds the handle set with the one leaf the tree
// says, which is exactly what every build before this one held.
//
// THE FIXTURE IS A REAL EIGHT-PART RECORD, written through the store's own framing with part nine
// dropped, and not a nine-part record with an empty ledger: those two decode to NIL and to an EMPTY
// SLICE and the distinction is the one [GroupRecord.Leaves] is read by.
//
// WHAT IS ASSERTED, and the second clause is the honest half: the device STARTS, opens its backlog
// and recognises its own handle; and the departed table comes back EMPTY, which is the loss named
// at [GroupRecord.Leaves] -- such a device resolves a departed leaf's records only while the leaf
// has been refilled.
//
// WHAT WOULD GO RED: make [groupRecordOf] refuse an eight-part record; stop seeding the handle set
// in [Group.initTables] (the restored device would recognise none of its own records); invent a
// departed table out of the current membership at the read (this case's second clause).
func TestADeviceRestoredFromAStoreWithNoLeafLedgerStillStarts(t *testing.T) {
	world := newRotWorld(t, "alice", "bob")
	alice := world.member("alice")
	line := world.sealDurable(alice, "a line written before the restart")

	// ── THE DISK, REWRITTEN AS A BUILD BEFORE PART NINE WROTE IT ────────────────────────────
	store := alice.dev.store
	path := store.groupRecordPath(alice.group.id)
	parts, err := store.readRecord(path, stateKindGroupRecord)
	if err != nil {
		t.Fatalf("reading the group record back: %v", err)
	}
	if len(parts) != 9 {
		t.Fatalf("this build wrote %d parts and this case strips the ninth; if the arity has "+
			"moved, the fixture is no longer an old store", len(parts))
	}
	if len(parts[8]) == 0 {
		t.Fatalf("CONTROL FAILED: the ninth part this build wrote is EMPTY, so stripping it " +
			"changes nothing and this case would pass against a build that never wrote one")
	}
	if err := store.writeRecord(path, stateKindGroupRecord, parts[:8]...); err != nil {
		t.Fatalf("rewriting the group record with eight parts: %v", err)
	}
	// AND THE FIXTURE IS CHECKED THROUGH THE READER ITSELF, so "an eight-part record" is what is
	// on the disk and not what this case meant to put there.
	records, err := store.GroupRecords()
	if err != nil {
		t.Fatalf("GroupRecords over the eight-part disk: %v", err)
	}
	if len(records) != 1 || records[0].Leaves != nil {
		t.Fatalf("the eight-part record decoded with %d leaf ledger row(s); a record written "+
			"before part nine must come back with NIL, which is the signal [Device.restoreOne] "+
			"acts on", len(records[0].Leaves))
	}

	// ── THE RESTORE ─────────────────────────────────────────────────────────────────────────
	revived := restoredRotDevice(t, alice)
	group, err := revived.device.restoreOne(revived.store, records[0], restoreTestNonce(), 1)
	if err != nil {
		t.Fatalf("a device whose store predates part nine did not start: %v. A restore that "+
			"refuses an older record is a device that can never start again, which is the one "+
			"outcome no compatibility question may reach", err)
	}
	defer group.Close()

	// it recognises its own handle -- the set seeded from the one leaf the tree says
	own, err := group.session.SenderHandle()
	if err != nil {
		t.Fatalf("the restored group's sender handle: %v", err)
	}
	if !group.ownHandles[own] {
		t.Fatalf("the restored group does not hold its own sender_handle %x in its handle set, "+
			"so every record it ever wrote comes back as a stranger's", own)
	}
	if len(group.ownHandles) != 1 {
		t.Fatalf("the restored group holds %d handle(s) and an old store can say exactly one",
			len(group.ownHandles))
	}
	// AND THE LOSS, ASSERTED AND NOT ONLY WRITTEN DOWN.
	if len(group.departedAt) != 0 {
		t.Fatalf("the restored group came back with %d departed leaf/leaves out of a record that "+
			"carries none; inventing one is this build deciding, from the current membership, a "+
			"question the disk does not answer", len(group.departedAt))
	}

	// AND IT STILL RECOGNISES THE RECORD IT WROTE BEFORE THE RESTART AS ITS OWN, which is the
	// clause that makes "it starts" mean something: the handle set is what both graceful
	// own-record roads are gated on, so a restored device whose set were EMPTY would come back
	// showing its own half of the conversation as a stranger's -- with no error anywhere.
	if line.record.Header.SenderHandle != own {
		t.Fatalf("the line written before the restart carries sender_handle %x and the restored "+
			"device derives %x", line.record.Header.SenderHandle, own)
	}
	if !group.ownHandles[line.record.Header.SenderHandle] {
		t.Fatalf("the restored device does not read the record it wrote before the restart as its own")
	}
	t.Logf("a device whose disk carries EIGHT parts restored, recognises its one handle %x, and "+
		"comes back with an EMPTY departed table -- which is the state every build before this "+
		"one was in", own)
}

// ── 5. A REMOVAL WITH NO REFILL, WHICH IS THE ONE THE DEPARTED TABLE IS THE ONLY ANSWER FOR ──

// THE REMOVED LEAF STAYS BLANK, AND THE SURVIVOR STILL RESOLVES THE RECORDS IT SEALED.
//
// WHY THIS CASE EXISTS AND IT IS A MUTANT'S DOING. The reuse cohort above removes and refills a
// leaf in ONE commit, so the leaf is back in the CURRENT membership and
// SenderHandle(group_handle_key, leaf) -- which takes the leaf alone -- resolves the removed
// member's records through the NEWCOMER's row. Measured: disabling the departed-leaf half of
// [Group.leavesAtLocked] entirely (`if false && epoch < departed`) left every case above GREEN.
// The table's whole subject is a leaf that is GONE, and a refilled leaf is not gone.
//
// SO THIS IS THE ORDINARY FIRST DAY OF REMOVE, in the ledger's own words: one member removed,
// nobody added, and every record that member ever sealed sitting BELOW the commit in record order
// -- which every restart re-walks, because the cursor is not persisted. With the handle table
// built at the current epoch those records answer "which is no leaf of this group", are retried
// [maxRecordAttempts] times and are ABANDONED: the removed member's half of the conversation
// disappears from every survivor, permanently, with [ErrRecordAbandoned] as the only sign.
//
// THE CONTROL FIRES FOR ITS OWN REASON: the leaf really is out of the CURRENT membership. It is
// checked by deriving the handle table at the epoch the commit opened and finding the removed
// member's handle absent from it, which is the state the old code handed to every record.
//
// WHAT WOULD GO RED: delete the departed-leaf half of [Group.leavesAtLocked]; file the departure
// epoch at the epoch the commit CLOSED instead of the one it opened (the removed member's records
// at the closing epoch would stop resolving, which is most of them).
func TestARemovedLeafThatIsNeverRefilledStillResolvesItsOwnRecords(t *testing.T) {
	world := newRotWorld(t, "alice", "bob", "carol")
	alice, bob, carol := world.member("alice"), world.member("bob"), world.member("carol")

	lines := []*sealed{}
	for at := 0; at < 3; at += 1 {
		lines = append(lines, world.sealDurable(bob, fmt.Sprintf("bob's line %d", at+1)))
	}
	if err := world.deliver(carol, lines...); err != nil {
		t.Fatalf("carol's walk over bob's lines: %v", err)
	}
	published := world.rotate(alice, []uint32{bob.leaf}, func() ([]byte, []byte, []byte, error) {
		return alice.handle.CommitRemove([]uint32{bob.leaf})
	})
	if err := world.deliver(carol, published.page()...); err != nil {
		t.Fatalf("carol's walk over the commit that removes bob: %v", err)
	}

	// ── THE CONTROL: the leaf really is out of the current membership ───────────────────────
	bobHandle, err := bob.group.session.SenderHandle()
	if err != nil {
		t.Fatalf("bob's sender handle: %v", err)
	}
	carol.group.mutex.Lock()
	current := map[[16]byte]uint32{}
	for at := 0; at < carol.group.handle.MemberCount(); at += 1 {
		leaf, _, _, memberErr := carol.group.handle.MemberAt(at)
		if memberErr != nil {
			carol.group.mutex.Unlock()
			t.Fatalf("carol's member %d: %v", at, memberErr)
		}
		current[messagegroup.SenderHandle(carol.group.groupHandleKey, leaf)] = leaf
	}
	carol.group.mutex.Unlock()
	if _, standing := current[bobHandle]; standing {
		t.Fatalf("CONTROL FAILED: bob's sender_handle %x is still in carol's CURRENT membership "+
			"after the commit that removed him, so the table built at the current epoch would "+
			"resolve his records anyway and this case measures nothing", bobHandle)
	}
	t.Logf("CONTROL: bob's sender_handle %x is not in the membership at epoch %d (%d member(s)), "+
		"which is the table every record used to be resolved through",
		bobHandle, carol.group.epoch, len(current))

	// ── THE PROPERTY: the re-walk still resolves them, opens them, and names bob ────────────
	carol.group.mutex.Lock()
	carol.group.log = nil
	carol.group.logIndex = map[[MessageIdBytes]byte]int{}
	carol.group.delivered = map[uint64]bool{}
	carol.group.mutex.Unlock()

	delivered, err := carol.group.receiveForTest(world, carol, lines...)
	if err != nil {
		t.Fatalf("carol's re-walk over the removed member's records answered %v. That is the "+
			"abandonment ledger item 245's third piece exists to stop: the removed member's whole "+
			"half of the conversation, gone from every survivor at the first restart", err)
	}
	if len(delivered) != len(lines) {
		t.Fatalf("carol delivered %d of the removed member's %d records", len(delivered), len(lines))
	}
	for at, one := range delivered {
		if one.Gap != "" {
			t.Fatalf("the removed member's line %d came back as a %q gap", at+1, one.Gap)
		}
		if !bytes.Equal(one.SenderIdentity, bob.dev.identityPub) {
			t.Fatalf("the removed member's line %d is attributed to %x, want bob's %x",
				at+1, one.SenderIdentity, bob.dev.identityPub)
		}
	}
	if len(carol.group.unopened) != 0 {
		t.Fatalf("carol gave up on %d record(s) of the removed member's", len(carol.group.unopened))
	}
	t.Logf("a leaf removed at epoch %d and never refilled: all %d records it sealed at epoch %d "+
		"still resolve at the survivor and are attributed to the member that wrote them",
		published.opens, len(delivered), published.opens-1)
}

// ── 6. THE SEED MUST NOT LAUNDER THE CLONE CHECK'S OWN EVIDENCE ──────────────────────────────

// A RESTORED GROUP DOES NOT MOVE ITS OWN FLOOR UNTIL THE CLONE CHECK HAS CONCLUDED.
//
// WHY THIS CASE EXISTS AND IT IS A REGRESSION THIS PASS CAUSED AND THEN CLOSED. The seed and the
// clone check read ONE fact -- "an index on the server under my own sender_handle that my reserver
// never allocated" -- and draw opposite conclusions from it: the check says ANOTHER COPY OF THIS
// FOLDER, the seed says A PREVIOUS OCCUPANT OF THIS LEAF. The handle cannot tell them apart; that
// is item 245's linkability residual seen from the inside. What tells them apart is the AEAD: a
// clone's record was sealed by this device's own leaf key at an epoch this device stands in, so it
// authenticates and raises [Group.ownIndexSeen]; a previous occupant's is below this device's
// admission and raises nothing. The check compares the reserver against that authenticated number,
// so a seed taken BEFORE the comparison raises the high water past the evidence.
//
// MEASURED, on the first run of the full battery: without the [Group.reconciled] gate,
// cp3b.TestACopyWhoseEvidenceArrivedInADirtyWalkIsStillCaught went RED -- "the copy's clean Receive
// answered <nil>, want ErrIdentityInUse" -- because a copy's FIRST walk is dirty, the check does not
// run on a dirty walk, and an ungated seed fires on it anyway.
//
// THIS CASE IS THE MECHANISM WITHOUT THE SERVER, so the property is held in the package that owns
// the code and not only in the module that has a message server. The two halves are driven in one
// case, which is what makes the second half a control rather than a claim: on the DIRTY walk the
// floor must not move, and on the CLEAN walk that follows it must.
//
// WHAT WOULD GO RED: drop `!self.reconciled` from [Group.seedOwnStreamLocked] (the dirty walk
// seeds); move the seed ABOVE the reconciliation block in [Group.commitWalkLocked] (the clean walk
// seeds before the check reads the high water).
func TestARestoredGroupDoesNotSeedItsFloorOverADirtyWalk(t *testing.T) {
	world := newReuseWorld(t, 3)
	eve, carol := world.eve, world.carol

	// A LINE THE RESTORED DEVICE CAN OPEN, BENT, so the walk has a record that FAILS rather than
	// one that is a gap. Bob's lines are at an epoch eve holds no state for: those are
	// [GapOutOfWindow] and do not make a walk dirty.
	clean := world.sealDurable(carol, "carol's line at the current epoch")
	bent := &sealed{recordId: clean.recordId, messageId: clean.messageId, record: &message.Record{
		Header: clean.record.Header,
		CtHead: append([]byte(nil), clean.record.CtHead...),
		CtBody: append([]byte(nil), clean.record.CtBody...),
	}}
	bent.record.CtBody[0] ^= 0xFF

	// ── THE RESTORE, which is the ONLY way a group comes back NOT reconciled ────────────────
	revived := restoredRotDevice(t, eve)
	records, err := revived.store.GroupRecords()
	if err != nil {
		t.Fatalf("GroupRecords: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("eve's disk holds %d group record(s), want 1", len(records))
	}
	restored, err := revived.device.restoreOne(revived.store, records[0], restoreTestNonce(), 1)
	if err != nil {
		t.Fatalf("restoring eve: %v", err)
	}
	defer restored.Close()
	if restored.Reconciled() {
		t.Fatalf("CONTROL FAILED: the restored group came back RECONCILED, so the gate this case " +
			"measures is not even reached and the dirty walk below would seed for the right reason " +
			"by accident")
	}
	if high, err := restored.ownHighWaterLocked(world.handle); err != nil || high != 0 {
		t.Fatalf("CONTROL FAILED: eve's floor already stands at %d (%v) before any walk, so a "+
			"floor that has not moved below would say nothing", high, err)
	}
	at := &rotMember{name: "eve-restored", dev: eve.dev, group: restored, leaf: eve.leaf}

	// ── THE DIRTY WALK: the claims are there, the floor does not move ───────────────────────
	page := append([]*sealed{}, world.bobRecords...)
	page = append(page, bent)
	err = world.deliver(at, page...)
	if err == nil {
		t.Fatalf("CONTROL FAILED: the walk carrying a bent record answered nil, so it is not dirty " +
			"and this case measures a clean walk twice")
	}
	if restored.Reconciled() {
		t.Fatalf("the restored group reconciled over a dirty walk, which is a different defect")
	}
	if high, err := restored.ownHighWaterLocked(world.handle); err != nil || high != 0 {
		t.Fatalf("the dirty walk moved eve's floor to %d (%v). The clone check has not run yet -- "+
			"a dirty walk is exactly the walk it refuses to conclude from -- so a floor raised here "+
			"is the evidence of a second copy of this folder erased before anything read it", high, err)
	}
	if seeded := restored.Stats().StreamFloorSeeded; seeded != 0 {
		t.Fatalf("Stats.StreamFloorSeeded is %d after a dirty walk, want 0", seeded)
	}

	// ── THE CLEAN WALK: the check concludes, and THEN the floor moves ───────────────────────
	if err := world.deliver(at, world.bobRecords...); err != nil {
		t.Fatalf("the clean walk answered %v", err)
	}
	if !restored.Reconciled() {
		t.Fatalf("CONTROL FAILED: the clean walk did not reconcile, so the floor below is held " +
			"back by the gate rather than released by it and the two halves are one")
	}
	high, err := restored.ownHighWaterLocked(world.handle)
	if err != nil {
		t.Fatalf("eve's floor after the clean walk: %v", err)
	}
	if high != 3 {
		t.Fatalf("eve's floor stands at %d after the clean walk, want 3. The gate delays the seed "+
			"by one walk; it must not cancel it, or the newcomer is bricked exactly as before", high)
	}
	t.Logf("the dirty walk left eve's floor at 0 with the clone check unconcluded, and the clean " +
		"walk that followed reconciled first and then moved it to 3")
}
