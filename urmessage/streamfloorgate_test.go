// THE GATE THAT SAYS THIS DEVICE'S OWN STREAM FLOOR HAS BEEN HELD, DRIVEN AGAINST THE TWO WALKS
// THAT RAISED IT WHILE THE FLOOR STOOD EXACTLY WHERE IT STARTED. LEDGER ITEM 245's FIRST PIECE.
//
// [Group.ownFloorHeld] was raised by [Group.walkSawTheWholeHistoryLocked] alone -- complete page, no
// omission, no record that failed -- which is a statement about whether the SERVER finished handing
// something over. The thing it was read as saying is that this device's durable reserver now stands
// above every stream index the server holds a claim at under this device's sixteen octets, and
// [Group.seedOwnStreamLocked], the only code that moves that floor, returned early on three roads
// the gate could not see. This file is the walks that get through, each with the floor printed beside
// the flag so that "the gate is up" and "the floor moved" cannot be confused for each other: a clean
// walk over an empty page (1), a row given up on before its header could be read (2), a reserver
// that cannot move a floor at all (3), and a claim read by a walk that was not allowed to act on it
// (4).
//
// BOTH CASES ARE THE SAME COHORT AS THE REST OF THE REMOVAL SUITE -- bob spends indices under leaf
// 1, the leaf is removed, eve is added onto it and derives bob's handle byte for byte, carol at
// leaf 2 is the control that this build does not derive one handle for every leaf
// ([newReuseWorld]).
//
// WHAT WOULD GO RED: M-gate-empty -- put the gate back to `if self.walkSawTheWholeHistoryLocked(walk)`
// (cases 1, 2 and 3); M-gate-abandoned -- drop the [Group.ownFloorBlind] clause from
// [Group.ownFloorHeldByLocked] (case 2); M-gate-cursor -- drop its cursor clause (case 1);
// M-gate-noseed -- make [Group.seedOwnStreamLocked] answer true when the [StreamIndexSeeder]
// assertion fails (case 3); M-claim-perwalk -- clear [Group.ownClaimSeen] at the end of
// [Group.commitWalkLocked], which is what a claim number that lives on the walk does (case 4).
//
// AND ONE CLAUSE THAT IS DELIBERATELY NOT DRIVEN, because a case for it would be a case for nothing:
// the seed's `!self.reconciled` early return. [Group.commitWalkLocked] sets `reconciled` ABOVE the
// seed on the first clean walk, so the only walks that reach the seed unreconciled are DIRTY ones --
// which clause 2 of [Group.ownFloorHeldByLocked] refuses for its own reason. The clause is kept
// because it is the honest answer to "did this call establish the floor", and a mutant that makes it
// answer true survives this file. That is recorded here rather than left to be discovered.

package urmessage

import (
	"errors"
	"strings"
	"testing"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/messagegroup"
	"github.com/urnetwork/connect/protocol"
)

// walkRaw is [rotWorld.deliver] with the page handed over as RAW ROWS rather than as records this
// build encoded, which is the only way to put a row a receiver CANNOT PARSE on the wire. Everything
// else is the same three lines [Group.Receive] writes.
func (self *rotWorld) walkRaw(receiver *rotMember, rows []*protocol.Record) error {
	self.t.Helper()
	return self.walkRawAt(receiver, rows, true)
}

// walkRawAt is [rotWorld.walkRaw] with the server's own COMPLETE flag in the caller's hands, which is
// the difference between a page the server finished handing over and one a transport cut short.
func (self *rotWorld) walkRawAt(receiver *rotMember, rows []*protocol.Record, complete bool) error {
	self.t.Helper()
	group := receiver.group
	own, err := group.session.SenderHandle()
	if err != nil {
		self.t.Fatalf("%s's sender handle: %v", receiver.name, err)
	}
	group.ownHandles[own] = true
	walk := &pageWalk{
		own:          group.ownHandles,
		ownNow:       own,
		leaves:       map[uint64]map[[16]byte]uint32{},
		opened:       []*Message{},
		from:         group.cursor,
		reached:      group.cursor,
		resolvedTo:   group.cursor,
		reconciled:   group.reconciled,
		complete:     complete,
		unobtainable: map[uint64]bool{},
	}
	group.openPageLocked(&protocol.FetchResponse{Records: rows}, walk)
	return group.commitWalkLocked(walk, nil)
}

// rawRows encodes a page the way the server serves it, and hands back the octets so a case can bend
// one row before the receiver sees it.
func (self *rotWorld) rawRows(page ...*sealed) []*protocol.Record {
	self.t.Helper()
	rows := []*protocol.Record{}
	for _, one := range page {
		encoded, err := message.EncodeRecord(one.record)
		if err != nil {
			self.t.Fatalf("encoding record %d: %v", one.recordId, err)
		}
		rows = append(rows, &protocol.Record{RecordId: one.recordId, RecordBytes: encoded})
	}
	return rows
}

// floorOf is one member's own durable stream floor for the reused leaf's stream, read off THE
// RESERVER ITS GROUP HOLDS -- which is the one [Group.seedOwnStreamLocked] writes through, and the
// one a restarted member has. [reuseWorld.highWater] reads the member's pre-restart device, whose
// store a restart has closed.
func (self *reuseWorld) floorOf(who *rotMember) uint64 {
	self.t.Helper()
	high, err := who.group.device.reserver.HighWater(self.ownStreamKey(self.handle))
	if err != nil {
		self.t.Fatalf("%s's own stream high water: %v", who.name, err)
	}
	return high
}

// ── 1. A WALK THAT COVERED NOTHING HAS BEEN TOLD NOTHING ─────────────────────────────────────

// ONE CLEAN WALK OVER AN EMPTY PAGE RAISED THE GATE WHILE THE SERVER HELD THREE CLAIMS.
//
// The newcomer's cursor is at zero, the server hands back no rows and calls the page complete, and
// every clause of [Group.walkSawTheWholeHistoryLocked] is satisfied -- `complete`, no omission, no
// failure -- because each of them is a statement about a page that was served rather than about the
// history. The reserver stays where a joiner's reserver starts, which is nowhere, and the first
// Send then seals at index 1 of a stream the previous occupant of this leaf has already spent.
//
// A GROUP ABOVE EPOCH ZERO CANNOT HAVE AN EMPTY HISTORY, which is what makes this checkable at all
// rather than a server's word against nothing: the commit that opened this device's own epoch is
// sealed at the epoch BELOW it, so it passes item 246's `epoch <= read_epoch` ceiling, and a joiner
// asks from record zero. A page of nothing is therefore a server that showed this device nothing.
//
// THE POSITIVE CONTROL IS IN THE SAME RUN AND ON THE SAME GROUP: the identical walk over the rows
// that DO exist raises the gate, moves the floor to bob's top index, and lets the send through. So
// this case cannot pass by the gate having been nailed shut.
func TestAWalkThatCoveredNoRecordDoesNotRaiseTheOwnStreamFloorGate(t *testing.T) {
	world := newReuseWorld(t, 3)
	eve := world.eve

	if eve.group.ownFloorHeld {
		t.Fatalf("CONTROL FAILED: the newcomer's floor is already held at the Join, so this case " +
			"cannot say anything about what raises it")
	}
	topClaim := world.bobRecords[len(world.bobRecords)-1].record.Header.StreamIndex
	if world.highWater(eve) != 0 {
		t.Fatalf("CONTROL FAILED: the newcomer's reserver starts at %d and a joiner's starts at 0",
			world.highWater(eve))
	}

	if err := world.walkRaw(eve, nil); err != nil {
		t.Fatalf("the newcomer's walk over an empty page answered %v; an empty page is not a "+
			"failure and this case is about what a CLEAN walk concludes", err)
	}
	if eve.group.ownFloorHeld {
		t.Fatalf("one clean walk over an EMPTY page raised the stream floor gate. The reserver is "+
			"at %d and the server holds claims up to %d under this device's own sender_handle %x, "+
			"so the first Send would seal at index 1 of a stream that is already spent and latch "+
			"ErrIdentityInUse for the life of the process",
			world.highWater(eve), topClaim, world.handle)
	}
	if world.highWater(eve) != 0 {
		t.Fatalf("the empty walk moved the newcomer's floor to %d off no record at all",
			world.highWater(eve))
	}
	if _, err := eve.group.sendableLocked(KindText); !errors.Is(err, ErrStreamFloorUnheld) {
		t.Fatalf("the newcomer's Send after the empty walk is refused with %v, want "+
			"ErrStreamFloorUnheld", err)
	}
	t.Logf("after one clean walk over an empty page: ownFloorHeld=%v, reserver high water %d, "+
		"while the previous occupant spent indices 1..%d under the same sender_handle %x",
		eve.group.ownFloorHeld, world.highWater(eve), topClaim, world.handle[:4])

	// ── THE CONTROL: THE SAME WALK OVER THE ROWS THAT EXIST ─────────────────────────────────
	if err := world.walkRaw(eve, world.rawRows(world.bobRecords...)); err != nil {
		t.Fatalf("the newcomer's walk over the previous occupant's records answered %v", err)
	}
	if !eve.group.ownFloorHeld {
		t.Fatalf("CONTROL FAILED: a clean walk that covered the whole history did NOT raise the " +
			"gate, so the property above is a build that refuses everything")
	}
	if world.highWater(eve) != topClaim {
		t.Fatalf("CONTROL FAILED: the floor stands at %d after that walk and the previous "+
			"occupant's top claim is %d", world.highWater(eve), topClaim)
	}
	if _, err := eve.group.sendableLocked(KindText); err != nil {
		t.Fatalf("CONTROL FAILED: the newcomer's Send after the whole history answered %v", err)
	}
	t.Logf("CONTROL: the same walk over the %d rows that exist raised the gate and moved the "+
		"floor 0 -> %d", len(world.bobRecords), world.highWater(eve))
}

// ── 2. A RECORD GIVEN UP ON BEFORE ITS HEADER WAS READ IS A CLAIM AT AN UNKNOWN INDEX ────────

// THE REACHABLE ONE, AND THERE IS NO ADVERSARY IN IT. One row under the joiner's own sixteen octets
// is served in a wire shape this build's codec cannot parse -- which is what a record_format_version
// this build does not know looks like from here, and what msgrepo item 253's rollout window exists
// to bound.
//
// THE MECHANISM IS THE RETRY BOUND, NOT THE PARSE. Walks 1 and 2 answer `record N does not parse`
// and are dirty, so the gate stays down for the right reason. Walk 3 spends the last of
// [maxRecordAttempts], ABANDONS the row and resolves the cursor PAST it. Walk 4 asks from above it,
// meets an empty page, is clean by every clause of [Group.walkSawTheWholeHistoryLocked] -- and used
// to raise the gate with the floor standing exactly where walk 1 left it, one index below the claim
// the row carried. The first seal then lands on that index, with a message_id byte for byte the
// previous occupant's, which is the collision the whole gate exists to prevent.
//
// SO THE ABANDONMENT IS A FACT ABOUT THE GROUP AND NOT ABOUT ONE WALK. Every other failure in the
// page loop happens BELOW the header read, so the index the row claims is already folded into
// [Group.ownClaimSeen] whatever becomes of the record; this one loses it for ever, and the refusal
// says so by naming the record rather than inviting a caller to Receive again.
//
// THE CONTROL IS THE SAME FOUR WALKS WITH THE ROW INTACT: the gate goes up, the floor lands on the
// top claim, and the send is allowed.
func TestARecordGivenUpOnBeforeItsHeaderWasReadKeepsTheStreamFloorGateDown(t *testing.T) {
	world := newReuseWorld(t, 3)
	eve := world.eve
	top := world.bobRecords[len(world.bobRecords)-1]
	topClaim := top.record.Header.StreamIndex

	rows := world.rawRows(world.bobRecords...)
	intact := rows[len(rows)-1].RecordBytes
	if _, err := message.ParseRecord(intact); err != nil {
		t.Fatalf("CONTROL FAILED: the previous occupant's top row does not parse intact: %v", err)
	}
	bent := append([]byte(nil), intact[:len(intact)-8]...)
	if _, err := message.ParseRecord(bent); err == nil {
		t.Fatalf("CONTROL FAILED: the bent row still parses, so this case is not about a record " +
			"this build cannot read")
	}
	rows[len(rows)-1].RecordBytes = bent

	for at := 1; at <= maxRecordAttempts+1; at += 1 {
		err := world.walkRaw(eve, rows)
		t.Logf("walk %d: ownFloorHeld=%v, cursor=%d, floor=%d, err=%v",
			at, eve.group.ownFloorHeld, eve.group.cursor, world.highWater(eve), err)
	}

	if eve.group.ownFloorHeld {
		t.Fatalf("the gate is up after the row at stream index %d was given up on unread. The "+
			"floor stands at %d, the row claimed %d, and the next seal would take the index the "+
			"previous occupant's line %d is already on",
			topClaim, world.highWater(eve), topClaim, len(world.bobRecords))
	}
	if world.highWater(eve) != topClaim-1 {
		t.Fatalf("the newcomer's floor stands at %d, want %d: this case is only about the row the "+
			"walk could not read, so every row it COULD read must still have moved the floor",
			world.highWater(eve), topClaim-1)
	}
	if eve.group.cursor < top.recordId {
		t.Fatalf("the cursor is at %d and the abandoned row is record %d; this case is about the "+
			"walk that comes AFTER the record is out of reach", eve.group.cursor, top.recordId)
	}
	_, err := eve.group.sendableLocked(KindText)
	if !errors.Is(err, ErrStreamFloorUnheld) {
		t.Fatalf("the newcomer's Send answered %v, want ErrStreamFloorUnheld", err)
	}
	if !strings.Contains(err.Error(), "header") {
		t.Fatalf("the refusal reads %q and does not say that a record was given up on before its "+
			"header could be read -- a caller told only `Receive once before Send` would retry for "+
			"ever, because that record is never fetched again", err)
	}
	t.Logf("the gate stayed down after %d walks, the refusal names the record: %v",
		maxRecordAttempts+1, err)

	// ── THE CONTROL: THE SAME FOUR WALKS, ROW INTACT ────────────────────────────────────────
	fresh := newReuseWorld(t, 3)
	for at := 1; at <= maxRecordAttempts+1; at += 1 {
		if err := fresh.walkRaw(fresh.eve, fresh.rawRows(fresh.bobRecords...)); err != nil {
			t.Fatalf("CONTROL FAILED: walk %d over the intact page answered %v", at, err)
		}
	}
	if !fresh.eve.group.ownFloorHeld {
		t.Fatalf("CONTROL FAILED: the same four walks over an INTACT page did not raise the gate")
	}
	if fresh.highWater(fresh.eve) != topClaim {
		t.Fatalf("CONTROL FAILED: the floor stands at %d over the intact page, want %d",
			fresh.highWater(fresh.eve), topClaim)
	}
	if _, err := fresh.eve.group.sendableLocked(KindText); err != nil {
		t.Fatalf("CONTROL FAILED: the newcomer's Send over the intact page answered %v", err)
	}
	t.Logf("CONTROL: the same four walks with the row intact raised the gate and put the floor at %d",
		fresh.highWater(fresh.eve))
}

// ── 3. A RESERVER THAT CANNOT MOVE A FLOOR NEVER HOLDS ONE ───────────────────────────────────

// noSeedReserver is [messagegroup.StreamIndexReserver] and NOTHING ELSE: the two methods a sender
// ratchet allocates through, with no [StreamIndexSeeder] on it. It is what a caller that built its
// own reserver over some other store hands this package.
type noSeedReserver struct {
	inner messagegroup.StreamIndexReserver
}

func (self *noSeedReserver) Reserve(stream messagegroup.StreamKey) (uint64, error) {
	return self.inner.Reserve(stream)
}

func (self *noSeedReserver) HighWater(stream messagegroup.StreamKey) (uint64, error) {
	return self.inner.HighWater(stream)
}

// A DEVICE THAT CANNOT SEED IS REFUSED RATHER THAN GIVEN THE BENEFIT OF THE DOUBT, AND THAT IS A
// CHANGE OF BEHAVIOUR THIS CASE EXISTS TO PIN.
//
// [StreamIndexSeeder] is an OPTIONAL interface and a reserver without it still works -- deliberately,
// because Reserve and HighWater are a sender ratchet's surface and a ratchet has no business moving a
// floor. What such a device could NOT do is hold its floor against a previous occupant's claims, and
// the gate used to raise anyway: [Group.seedOwnStreamLocked] returned nil for "there was nothing I
// could do", the walk was tidy, and the flag went up. So the one device that certainly WILL collide
// was the one the gate certified.
//
// It is refused now, by name, and the refusal is the good half of the trade: a sticky
// [ErrIdentityInUse] after the seal against a sentence before it. The CONTROL is the same cohort on
// the shipping reserver, which raises the gate over the same page.
//
// WHAT WOULD GO RED: make [Group.seedOwnStreamLocked] answer true when the type assertion fails.
func TestAReserverThatCannotSeedNeverRaisesTheStreamFloorGate(t *testing.T) {
	world := newReuseWorld(t, 3)
	eve := world.eve

	shipping := eve.group.device.reserver
	eve.group.device.reserver = &noSeedReserver{inner: shipping}
	if _, canSeed := eve.group.device.reserver.(StreamIndexSeeder); canSeed {
		t.Fatalf("CONTROL FAILED: the wrapper still answers StreamIndexSeeder, so this case is not " +
			"about a reserver that cannot move a floor")
	}
	if _, canSeed := shipping.(StreamIndexSeeder); !canSeed {
		t.Fatalf("CONTROL FAILED: the shipping reserver does not answer StreamIndexSeeder either, " +
			"so the refusal below would say nothing about the wrapper")
	}

	if err := world.walkRaw(eve, world.rawRows(world.bobRecords...)); err != nil {
		t.Fatalf("the walk over the previous occupant's records answered %v", err)
	}
	if eve.group.ownFloorHeld {
		t.Fatalf("the gate is up on a device whose reserver cannot move a floor. Its next seal " +
			"takes index 1 of a stream the previous occupant has spent, which is the collision " +
			"this gate exists to prevent")
	}
	if _, err := eve.group.sendableLocked(KindText); !errors.Is(err, ErrStreamFloorUnheld) {
		t.Fatalf("that device's Send answered %v, want ErrStreamFloorUnheld", err)
	}
	t.Logf("a reserver with no SeedTo left the gate down over %d rows and the send is refused by name",
		len(world.bobRecords))

	// ── THE CONTROL: THE SHIPPING RESERVER, SAME COHORT, SAME PAGE ──────────────────────────
	control := newReuseWorld(t, 3)
	if err := control.walkRaw(control.eve, control.rawRows(control.bobRecords...)); err != nil {
		t.Fatalf("CONTROL FAILED: the same walk on the shipping reserver answered %v", err)
	}
	if !control.eve.group.ownFloorHeld {
		t.Fatalf("CONTROL FAILED: the shipping reserver did not raise the gate over the same page")
	}
	if _, err := control.eve.group.sendableLocked(KindText); err != nil {
		t.Fatalf("CONTROL FAILED: the shipping reserver's Send answered %v", err)
	}
	t.Logf("CONTROL: the shipping reserver raised the gate over the same page and moved the floor to %d",
		control.highWater(control.eve))
}

// ── 4. THE CLAIM A CUT-SHORT WALK READ IS STILL THERE ON THE WALK THAT MAY ACT ON IT ─────────

// A RESTORED GROUP READS THE CLAIMS ON A WALK THAT MAY NOT SEED, AND SEEDS ON A WALK THAT NO LONGER
// SEES THEM. That gap is why the claimed index lives on the group ([Group.ownClaimSeen]) and not on
// the walk, and it is the same defect one field along from the one that moved [Group.ownIndexSeen]
// there.
//
// THE TWO WALKS, AND BOTH ARE ORDINARY. Walk 1 is a restored group's first: a page the transport cut
// short, so `complete` is false, the group does not reconcile -- and [Group.seedOwnStreamLocked]
// returns early, because a seed taken before the clone check LAUNDERS that check's own evidence. The
// cursor still moves over every row it resolved. Walk 2 asks from ABOVE those rows, gets a clean
// empty page, reconciles, and is the first walk allowed to move the floor -- with nothing under this
// device's handle in front of it.
//
// SO THE ASSERTION IS THE FLOOR AND NOT THE FLAG. A per-walk number leaves the gate up with the
// reserver exactly where the restore found it, which is the state that seals into a spent index; the
// cumulative number puts the floor on the previous occupant's top claim before the gate rises.
//
// WHAT WOULD GO RED: M-claim-perwalk -- clear [Group.ownClaimSeen] at the end of
// [Group.commitWalkLocked], which is what a number that lives on the walk does.
func TestAClaimReadByACutShortWalkStillRaisesTheFloorOnTheWalkThatSeeds(t *testing.T) {
	world := newReuseWorld(t, 3)
	topClaim := world.bobRecords[len(world.bobRecords)-1].record.Header.StreamIndex
	top := world.bobRecords[len(world.bobRecords)-1]

	eve := world.restart(world.eve)
	if eve.group.reconciled {
		t.Fatalf("CONTROL FAILED: the restored group came back reconciled, so walk 1 below would " +
			"seed and this case would not be about the walk that cannot")
	}
	if eve.group.ownFloorHeld {
		t.Fatalf("CONTROL FAILED: the restored group came back with its floor held")
	}

	// WALK 1: the page the transport cut short. It reads the claims and may not act on them.
	if err := world.walkRawAt(eve, world.rawRows(world.bobRecords...), false); err != nil {
		t.Fatalf("the cut-short walk answered %v", err)
	}
	if eve.group.reconciled {
		t.Fatalf("CONTROL FAILED: the cut-short walk reconciled the group, so the seed was allowed " +
			"to run on it after all")
	}
	if world.floorOf(eve) != 0 {
		t.Fatalf("CONTROL FAILED: the cut-short walk moved the floor to %d; the seed is gated on "+
			"the clone check and must not have run", world.floorOf(eve))
	}
	if eve.group.cursor < top.recordId {
		t.Fatalf("the cut-short walk left the cursor at %d and the rows it read end at %d; this "+
			"case needs the next walk to ask from ABOVE them", eve.group.cursor, top.recordId)
	}

	// WALK 2: clean, and there is nothing under this device's handle left to see.
	if err := world.walkRawAt(eve, nil, true); err != nil {
		t.Fatalf("the clean walk above the rows answered %v", err)
	}
	if !eve.group.reconciled {
		t.Fatalf("CONTROL FAILED: the clean walk did not reconcile the restored group")
	}
	if world.floorOf(eve) != topClaim {
		t.Fatalf("the floor stands at %d after the walk that was allowed to seed, and the previous "+
			"occupant's top claim is %d. The claim was read by walk 1 and forgotten, so the gate "+
			"below certifies a floor nobody holds", world.floorOf(eve), topClaim)
	}
	if !eve.group.ownFloorHeld {
		t.Fatalf("CONTROL FAILED: the gate is still down after a clean walk that established the " +
			"floor, so the floor assertion above says nothing about what a caller may do")
	}
	if _, err := eve.group.sendableLocked(KindText); err != nil {
		t.Fatalf("CONTROL FAILED: the restored group's Send after both walks answered %v", err)
	}
	t.Logf("the claim at index %d was read by a cut-short walk and the floor moved 0 -> %d on the "+
		"clean walk that saw none of those rows", topClaim, world.floorOf(eve))
}
