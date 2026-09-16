package urmessage

import (
	"bytes"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/messagegroup"
	"github.com/urnetwork/connect/protocol"
)

// ── the walk, over records that carry a content envelope ─────────────────────────────────────
//
// WHY THESE DRIVE THE REAL WALK AND NOT A PARSER. The unknown-kind rule is an ACCOUNTING rule --
// "keeps its position, is NOT a fail(), does not count toward ErrRecordAbandoned" -- and none of
// those words are about the codec. They are about [Group.openPageLocked], which is the only place
// fail(), resolve() and the cursor exist. A case over ParseContent alone cannot see any of it.
//
// The records are sealed by a REAL second member through a real GroupSession and opened by a real
// one, so what is measured is a record crossing the same seal/open path a server would carry it
// over. What is NOT here is the server: that is the cp3b module, and cp3b's own kinds case drives
// the same properties end to end.

// kindWalk is two members of one group, with the far side's [Group] available to drive a page
// through.
type kindWalk struct {
	t *testing.T

	groupId []byte
	alice   *messagegroup.GroupSession
	bob     *Group

	// the server's numbering, which is this harness's to assign because no server is here.
	nextRecordId uint64
}

// newKindWalk founds a group, adds a second member, and answers the pair.
func newKindWalk(t *testing.T) *kindWalk {
	t.Helper()
	root := t.TempDir()
	alice := openCrossProcessDevice(t, filepath.Join(root, "alice"))
	t.Cleanup(alice.close)
	bob := openCrossProcessDevice(t, filepath.Join(root, "bob"))
	t.Cleanup(bob.close)

	groupId := make([]byte, GroupIdBytes)
	if _, err := rand.Read(groupId); err != nil {
		t.Fatalf("drawing a group id: %v", err)
	}
	aliceHandle := alice.createGroup(t, groupId)
	t.Cleanup(func() { aliceHandle.Close() })

	mlsSecret, err := aliceHandle.Export(storageExporterLabel, nil, storageExporterBytes)
	if err != nil {
		t.Fatalf("the epoch zero exporter: %v", err)
	}
	pqSecret, err := messagegroup.NewPqSecret(rand.Reader)
	if err != nil {
		t.Fatalf("pq_secret: %v", err)
	}
	groupHandleKey := messagegroup.GroupHandleKey(messagegroup.StorageRoot(mlsSecret, pqSecret))

	keyPackage, err := bob.engine.NewKeyPackage()
	if err != nil {
		t.Fatalf("bob's key package: %v", err)
	}
	if _, err := aliceHandle.ProposeAdd(keyPackage); err != nil {
		t.Fatalf("ProposeAdd: %v", err)
	}
	_, welcome, ratchetTree, err := aliceHandle.Commit(nil)
	if err != nil {
		aliceHandle.ClearPendingCommit()
		t.Fatalf("Commit: %v", err)
	}
	if err := aliceHandle.MergePendingCommit(); err != nil {
		t.Fatalf("MergePendingCommit: %v", err)
	}
	bobHandle, err := bob.engine.JoinFromWelcome(welcome, ratchetTree)
	if err != nil {
		t.Fatalf("bob's JoinFromWelcome: %v", err)
	}
	t.Cleanup(func() { bobHandle.Close() })

	aliceSession := newCrossProcessSession(t, aliceHandle, pqSecret, groupHandleKey, alice.reserver, "alice's nonce")
	t.Cleanup(func() { aliceSession.Close() })
	bobSession := newCrossProcessSession(t, bobHandle, pqSecret, groupHandleKey, bob.reserver, "bob's nonce")
	t.Cleanup(func() { bobSession.Close() })

	// BOB'S GROUP IS BUILT FIELD BY FIELD AND NOT THROUGH [Device.Join], because Join needs a
	// transport and a server nonce and this case needs neither: everything below the fetch is
	// what is under test. `reconciled` is true for the reason a joined group's is -- this
	// device's stream in this group starts here -- and it also keeps commitWalkLocked off the
	// reserver, which a group with no device could not reach.
	bobGroup := &Group{
		id:             append([]byte(nil), groupId...),
		handle:         bobHandle,
		groupHandleKey: groupHandleKey,
		pqSecret:       pqSecret,
		session:        bobSession,
		epoch:          bobHandle.Epoch(),
		opened:         true,
		reconciled:     true,
	}
	bobGroup.initTables()
	return &kindWalk{t: t, groupId: groupId, alice: aliceSession, bob: bobGroup, nextRecordId: 1}
}

// sealed is one of alice's records and the message_id every member derives for it.
type sealed struct {
	recordId  uint64
	record    *message.Record
	messageId []byte
}

// seal seals one application plaintext as alice, DURABLE, and gives it the next record id.
func (self *kindWalk) seal(plaintext []byte) *sealed {
	self.t.Helper()
	record, err := self.alice.SealRecord(message.RetentionDurable, 0, false,
		encodeHead(time.Now().UnixMilli()), plaintext, 0, nil)
	if err != nil {
		self.t.Fatalf("alice's SealRecord: %v", err)
	}
	messageId, err := self.alice.MessageIdOf(&record.Header)
	if err != nil {
		self.t.Fatalf("alice's MessageIdOf: %v", err)
	}
	one := &sealed{recordId: self.nextRecordId, record: record, messageId: messageId[:]}
	self.nextRecordId += 1
	return one
}

// deliver walks one page of already sealed records through bob's group, in the order given, the way
// [Group.Receive] walks one: a fresh [pageWalk] from the group's cursor, [Group.openPageLocked] over
// the page, then [Group.commitWalkLocked] to fold it back in. It answers what the caller would see.
func (self *kindWalk) deliver(page ...*sealed) ([]*Message, error) {
	self.t.Helper()
	own, err := self.bob.session.SenderHandle()
	if err != nil {
		self.t.Fatalf("bob's sender handle: %v", err)
	}
	leaves, err := self.bob.leavesLocked()
	if err != nil {
		self.t.Fatalf("bob's leaves: %v", err)
	}
	walk := &pageWalk{
		own:        own,
		leaves:     leaves,
		opened:     []*Message{},
		from:       self.bob.cursor,
		reached:    self.bob.cursor,
		resolvedTo: self.bob.cursor,
		reconciled: self.bob.reconciled,
		complete:   true,
	}
	rows := []*protocol.Record{}
	for _, one := range page {
		encoded, err := message.EncodeRecord(one.record)
		if err != nil {
			self.t.Fatalf("encoding record %d: %v", one.recordId, err)
		}
		rows = append(rows, &protocol.Record{RecordId: one.recordId, RecordBytes: encoded})
	}
	self.bob.openPageLocked(&protocol.FetchResponse{Records: rows}, walk)
	return walk.opened, self.bob.commitWalkLocked(walk)
}

// held answers the [Message] bob's group holds under one message_id.
func (self *kindWalk) held(messageId []byte) *Message {
	self.t.Helper()
	return self.bob.byMessage[messageKeyOf(messageId)]
}

// A KIND THIS BUILD DOES NOT KNOW KEEPS ITS POSITION AND IS NOT A FAILURE.
//
// This is the half of the unknown-kind rule that is about the WALK rather than about the codec, and
// every clause of it is a separate thing that could be got wrong:
//
//   - it is NOT a fail(): [Stats.FailedOpen] does not move, so the cursor is not held back and the
//     next fetch does not ask for the record again;
//   - it does not count toward [ErrRecordAbandoned]: [Stats.Unopened] stays zero and Receive
//     answers a nil error;
//   - it keeps its POSITION: the cursor resolves past it, and the records after it are delivered;
//   - it keeps its message_id, which is what a later kind naming it would quote;
//   - it renders as one closed PLACEHOLDER: a [Message] with the code and no text;
//   - AND IT IS NEVER PARSED AS A KNOWN KIND, which is why the body below would be a perfectly
//     good REPLY if anything guessed.
//
// WHAT WOULD GO RED IF THE RULE WERE AN ORDINARY REFUSAL: every clause but the last.
func TestAnUnknownKindKeepsItsPositionAndIsNotAFailure(t *testing.T) {
	world := newKindWalk(t)
	target := aTarget(0x99)

	before := world.seal(mustEncodeText(t, "a line before"))
	unknown := world.seal(append(append([]byte{byte(KindEdit)}, target...), "a body a later build reads"...))
	after := world.seal(mustEncodeText(t, "a line after"))

	opened, err := world.deliver(before, unknown, after)
	if err != nil {
		t.Fatalf("the walk answered %v, and an unknown kind is not a failure", err)
	}
	if len(opened) != 3 {
		t.Fatalf("the walk delivered %d message(s) over three records", len(opened))
	}
	stats := world.bob.stats
	if stats.FailedOpen != 0 || stats.Unopened != 0 {
		t.Errorf("an unknown kind moved FailedOpen to %d and Unopened to %d, and it is neither",
			stats.FailedOpen, stats.Unopened)
	}
	if world.bob.cursor != after.recordId {
		t.Errorf("the cursor resolved to %d and the page ended at record %d, so the unknown kind held it back",
			world.bob.cursor, after.recordId)
	}

	placeholder := opened[1]
	if placeholder.Kind != KindEdit {
		t.Errorf("the placeholder carries kind %s, want the code that arrived", placeholder.Kind)
	}
	if placeholder.Text != "" {
		t.Errorf("an unknown kind was rendered as text %q", placeholder.Text)
	}
	if placeholder.ReplyToId != nil {
		t.Errorf("an unknown kind's body was read as a reply_to: %x", placeholder.ReplyToId)
	}
	if !bytes.Equal(placeholder.MessageId, unknown.messageId) {
		t.Errorf("the placeholder's message_id is %x and the record's is %x",
			placeholder.MessageId, unknown.messageId)
	}
	if placeholder.RecordId != unknown.recordId {
		t.Errorf("the placeholder is record %d and the record is %d", placeholder.RecordId, unknown.recordId)
	}
	// and the records either side of it arrived as themselves
	if opened[0].Text != "a line before" || opened[2].Text != "a line after" {
		t.Errorf("the lines around the unknown kind came back as %q and %q", opened[0].Text, opened[2].Text)
	}
}

// A MALFORMED BODY IS A REFUSAL, AND THE REFUSAL IS THE WALK'S EXISTING ONE.
//
// It is a fail(): it moves [Stats.FailedOpen], it holds the cursor back so the next fetch asks for
// the record again, and it names [ErrContentMalformed] through [ErrRecordOpen] rather than being
// resolved past in silence. That is NOT the answer this owes forever -- spec A §7.4's closed
// GapReason set has a "malformed" value and sdk has no gap entry to render it into -- and it is
// the answer that cannot lose a record while somebody designs one.
func TestAMalformedBodyIsARefusalThatHoldsTheCursor(t *testing.T) {
	world := newKindWalk(t)

	good := world.seal(mustEncodeText(t, "a line"))
	// a TEXT whose required tail is empty: one octet of plaintext, and R-d's third clause
	malformed := world.seal([]byte{byte(KindText)})

	opened, err := world.deliver(good, malformed)
	if !errors.Is(err, ErrContentMalformed) {
		t.Errorf("the walk answered %v, want a refusal carrying ErrContentMalformed", err)
	}
	if !errors.Is(err, ErrRecordOpen) {
		t.Errorf("the walk answered %v, want it carried through the walk's own ErrRecordOpen", err)
	}
	if len(opened) != 1 {
		t.Fatalf("the walk delivered %d message(s), want only the good one", len(opened))
	}
	if world.bob.stats.FailedOpen != 1 {
		t.Errorf("FailedOpen is %d, want 1", world.bob.stats.FailedOpen)
	}
	if world.bob.cursor != good.recordId {
		t.Errorf("the cursor resolved to %d and the malformed record is %d; a record the next fetch will not ask for again is a record lost in silence",
			world.bob.cursor, malformed.recordId)
	}
	// AND IT IS GIVEN UP ON AFTER THE BOUND, which is the existing contract and is what keeps a
	// body no retry can repair from being re-fetched for ever.
	for attempt := 2; attempt <= maxRecordAttempts; attempt += 1 {
		_, err = world.deliver(malformed)
		if err == nil {
			t.Fatalf("attempt %d of the malformed record answered a nil error", attempt)
		}
	}
	if !errors.Is(err, ErrRecordAbandoned) {
		t.Errorf("after %d attempts the malformed record answered %v, want ErrRecordAbandoned", maxRecordAttempts, err)
	}
	if world.bob.stats.Unopened != 1 {
		t.Errorf("Unopened is %d after the bound, want 1", world.bob.stats.Unopened)
	}
	if world.bob.cursor != malformed.recordId {
		t.Errorf("the abandoned record left the cursor at %d, and a record given up on must not block it for ever",
			world.bob.cursor)
	}
}

// A RECORD THAT CHANGES ANOTHER MESSAGE IS NOT A LINE OF THE CONVERSATION.
//
// A reaction, a tombstone and a COVER each open, each resolve the cursor, and each add NO entry.
// The reaction and the tombstone land on the message they name; the COVER lands nowhere, which is
// the whole of what it is for -- a COVER that produced an entry would be cover traffic the user can
// see.
func TestAReactionATombstoneAndACoverAddNoLineOfTheirOwn(t *testing.T) {
	world := newKindWalk(t)

	line := world.seal(mustEncodeText(t, "a line worth reacting to"))
	opened, err := world.deliver(line)
	if err != nil || len(opened) != 1 {
		t.Fatalf("the line: %d message(s), %v", len(opened), err)
	}

	add := world.seal(mustEncodeReaction(t, KindReactionAdd, line.messageId, "👍"))
	tombstone := world.seal(mustEncodeTombstone(t, line.messageId))
	cover := world.seal(encodeCover())

	opened, err = world.deliver(add, tombstone, cover)
	if err != nil {
		t.Fatalf("the walk answered %v", err)
	}
	if len(opened) != 0 {
		kinds := []ContentKind{}
		for _, one := range opened {
			kinds = append(kinds, one.Kind)
		}
		t.Fatalf("three records that add no line delivered %d message(s): %v", len(opened), kinds)
	}
	if world.bob.cursor != cover.recordId {
		t.Errorf("the cursor resolved to %d and the page ended at record %d", world.bob.cursor, cover.recordId)
	}
	if world.bob.stats.FailedOpen != 0 {
		t.Errorf("FailedOpen is %d and none of the three is a failure", world.bob.stats.FailedOpen)
	}

	held := world.held(line.messageId)
	if held == nil {
		t.Fatal("the line is not in this group's index")
	}
	if len(held.Reactions) != 1 || held.Reactions[0].Emoji != "👍" {
		t.Errorf("the line carries %v, want one 👍", held.Reactions)
	}
	if !held.Deleted {
		t.Error("the tombstone was sealed by the line's own sender and the line is not marked deleted")
	}
	// AND THE TEXT IS STILL THERE. A tombstone is a mark, not an erase: this package refuses to
	// decide what a UI does with a deleted line, and the record is on the server either way.
	if held.Text != "a line worth reacting to" {
		t.Errorf("the deleted line's text came back as %q", held.Text)
	}
}

// AN EFFECT WHOSE TARGET HAS NOT ARRIVED IS HELD, NOT DROPPED.
//
// The survey measured that the walk's order is not the conversation's order: a record that fails to
// open holds the cursor back and is re-delivered AFTER record ids above it, and after
// [maxRecordAttempts] it is abandoned and never delivered at all. So a reaction can arrive before
// the message it names, and a receiver that dropped it would lose a reaction permanently for a
// transient this build is designed to recover from.
func TestAnEffectThatArrivesBeforeItsTargetIsHeldAndApplied(t *testing.T) {
	world := newKindWalk(t)

	line := world.seal(mustEncodeText(t, "a line that arrives second"))
	add := world.seal(mustEncodeReaction(t, KindReactionAdd, line.messageId, "🎯"))

	// the reaction alone, naming a message this group has never seen
	opened, err := world.deliver(add)
	if err != nil {
		t.Fatalf("a reaction for a target that has not arrived answered %v", err)
	}
	if len(opened) != 0 {
		t.Fatalf("the reaction delivered %d message(s)", len(opened))
	}
	if world.bob.cursor != add.recordId {
		t.Errorf("the cursor resolved to %d and the reaction is record %d", world.bob.cursor, add.recordId)
	}

	// and now the target
	opened, err = world.deliver(line)
	if err != nil {
		t.Fatalf("the target answered %v", err)
	}
	if len(opened) != 1 {
		t.Fatalf("the target delivered %d message(s)", len(opened))
	}
	if len(opened[0].Reactions) != 1 || opened[0].Reactions[0].Emoji != "🎯" {
		t.Errorf("the target arrived carrying %v, and a reaction sealed before it was held for it",
			opened[0].Reactions)
	}
}

// EFFECTS ARE APPLIED IN SERVER ORDER AND NOT IN ARRIVAL ORDER.
//
// THIS IS THE CASE THE SURVEY'S MEASUREMENT IS FOR. An ADD at record 2 and a REMOVE at record 3 that
// arrive in the order 3, 2 -- which is exactly what one failed open produces, because the failure
// holds the cursor and the record is re-delivered behind ids above it -- leave the reaction STANDING
// under apply-as-it-lands and REMOVED under a replay in record_id order. §5.3 says records are
// ordered by server order, so the second is the answer.
//
// WHAT WOULD GO RED: apply each effect once as it lands ([Group.reapplyLocked] deleted, its body
// inlined into noteEffectLocked) and this case sees a 👍 that the group's own records say was taken
// back.
func TestEffectsAreAppliedInServerOrderAndNotArrivalOrder(t *testing.T) {
	world := newKindWalk(t)

	line := world.seal(mustEncodeText(t, "a line reacted to and un-reacted to"))
	add := world.seal(mustEncodeReaction(t, KindReactionAdd, line.messageId, "👍"))
	remove := world.seal(mustEncodeReaction(t, KindReactionRemove, line.messageId, "👍"))
	if !(add.recordId < remove.recordId) {
		t.Fatalf("this case needs the ADD to be numbered before the REMOVE, and they are %d and %d",
			add.recordId, remove.recordId)
	}

	// the line and the REMOVE arrive; the ADD is the record that did not open the first time
	if _, err := world.deliver(line, remove); err != nil {
		t.Fatalf("the first page answered %v", err)
	}
	if held := world.held(line.messageId); len(held.Reactions) != 0 {
		t.Fatalf("a REMOVE with no ADD before it left %v standing", held.Reactions)
	}

	// and now the ADD, with a LOWER record id, after them
	if _, err := world.deliver(add); err != nil {
		t.Fatalf("the re-delivered ADD answered %v", err)
	}
	held := world.held(line.messageId)
	if len(held.Reactions) != 0 {
		t.Errorf("the ADD (record %d) arrived after the REMOVE (record %d) and left %v standing; in server order the REMOVE is last",
			add.recordId, remove.recordId, held.Reactions)
	}

	// THE CONTROL, which is what keeps the assertion above from passing for a build that drops
	// every reaction: the same two records in the other order leave the reaction standing.
	second := newKindWalk(t)
	secondLine := second.seal(mustEncodeText(t, "a line reacted to"))
	secondRemove := second.seal(mustEncodeReaction(t, KindReactionRemove, secondLine.messageId, "👍"))
	secondAdd := second.seal(mustEncodeReaction(t, KindReactionAdd, secondLine.messageId, "👍"))
	if _, err := second.deliver(secondLine, secondAdd); err != nil {
		t.Fatalf("the control's first page answered %v", err)
	}
	if _, err := second.deliver(secondRemove); err != nil {
		t.Fatalf("the control's second page answered %v", err)
	}
	if held := second.held(secondLine.messageId); len(held.Reactions) != 1 {
		t.Errorf("the control: the REMOVE is record %d and the ADD is record %d, so in server order the ADD is last and the reaction stands; it carries %v",
			secondRemove.recordId, secondAdd.recordId, held.Reactions)
	}
}

// ONE RECORD IS ONE EFFECT, however many times a rewind walks back over it, AND THERE ARE TWO
// LINES OF DEFENCE RATHER THAN ONE.
//
// A record that did not open holds the cursor back, so the NEXT fetch re-reads every record after
// it -- which is the ordinary shape of this build's retry. A reaction counted twice would show one
// member reacting twice, and a REMOVE counted twice would be harmless only by accident.
//
// THE FIRST DEFENCE IS THE WALK'S [Group.delivered] MAP, which skips a record id this group has
// already shown, and it is what the first half below measures. THE SECOND IS [Group.effects],
// keyed by the effect record's own message_id, and the second half reaches it directly because the
// first makes it unreachable through the walk. MEASURED: with the effects map's dedupe deleted and
// only the append left, the walk half of this case stays GREEN -- so it is the second half, and
// nothing else in either suite, that holds the codec-level half of the rule.
func TestAReDeliveredEffectIsStillOneEffect(t *testing.T) {
	world := newKindWalk(t)
	line := world.seal(mustEncodeText(t, "a line"))
	add := world.seal(mustEncodeReaction(t, KindReactionAdd, line.messageId, "👍"))

	if _, err := world.deliver(line, add); err != nil {
		t.Fatalf("the first page answered %v", err)
	}
	// the same record again, which is what a rewind over an earlier failure delivers
	if _, err := world.deliver(add); err != nil {
		t.Fatalf("the rewind answered %v", err)
	}
	held := world.held(line.messageId)
	if len(held.Reactions) != 1 {
		t.Errorf("one reaction record delivered twice left %d reactions: %v", len(held.Reactions), held.Reactions)
	}
	if count := len(world.bob.effectsOn[messageKeyOf(line.messageId)]); count != 1 {
		t.Errorf("one reaction record is held %d times", count)
	}
	if world.bob.stats.SkippedSeen == 0 {
		t.Error("the re-delivered record was not skipped as one this group already holds, so the first defence is not the one that fired")
	}

	// ── and the second defence, reached past the first ──────────────────────────────────────
	group := &Group{}
	group.initTables()
	sender := bytes.Repeat([]byte{0x01}, 16)
	lineId := aTarget(0xE1)
	effectId := aTarget(0xE2)
	text := &Content{Kind: KindText, Text: "a line"}
	target := newMessage(text, 10, sender, false, 0, lineId)
	deliverOneThroughAWalk(group, target, text)

	reaction := &Content{Kind: KindReactionAdd, Target: lineId, Emoji: "👍"}
	deliverOneThroughAWalk(group, newMessage(reaction, 11, sender, false, 0, effectId), reaction)
	deliverOneThroughAWalk(group, newMessage(reaction, 11, sender, false, 0, effectId), reaction)
	if count := len(group.effectsOn[messageKeyOf(lineId)]); count != 1 {
		t.Errorf("one effect record delivered twice is held %d times", count)
	}
	if len(target.Reactions) != 1 {
		t.Errorf("one effect record delivered twice left %d reactions: %v", len(target.Reactions), target.Reactions)
	}
}

// ── the effect rules, at the unit the walk cannot reach ──────────────────────────────────────

// deliverOneThroughAWalk is one record through a ONE-RECORD WALK: [Group.deliverLocked] to fold the
// record in, then [Group.rebuildDirtyLocked] to run the rebuild the effects it noted are owed. It
// answers what deliverLocked answers.
//
// IT IS TWO CALLS BECAUSE THE PRODUCTION PATH IS TWO, and it was one until the replay was measured
// at n^3. An effect MARKS its target dirty as it lands and the rebuild happens ONCE per walk, at
// [Group.commitWalkLocked] -- see [Group.dirtyTargets] for what a rebuild per effect cost. The cases
// below drive deliverLocked BELOW the walk, because each needs something no session in this suite
// can produce -- a third party's sender_handle, a record id of zero, a kind this build cannot send
// -- so each owes itself the commit step a walk would have run for it. Nothing they assert is about
// WHEN the rebuild happens.
//
// WHAT IT STILL CATCHES: delete the dirty mark in [Group.noteEffectLocked] and this helper drains an
// empty set, so every case below goes red. Delete the drain from [Group.commitWalkLocked] instead
// and these stay green while every walk-driven case above goes red -- which is the split that says
// these cases are under the walk and those are through it.
func deliverOneThroughAWalk(group *Group, received *Message, entry *Content) bool {
	line := group.deliverLocked(received, entry)
	group.rebuildDirtyLocked()
	return line
}

// A TOMBSTONE FROM ANYBODY BUT THE TARGET'S OWN SENDER IS IGNORED (T-b), AND IT IS IGNORED RATHER
// THAN REFUSED.
//
// R1 proves who sealed the TOMBSTONE and nothing in it proves they sealed the target, so without
// this rule MASTER §12.1's "a deletion cannot be forged" is false: any member could delete any
// message. It is IGNORED and not a walk failure because the record is a legal record -- failing the
// walk over one would hand any member a way to wedge the conversation.
//
// This is at the unit rather than through the walk because the walk has two members and this needs
// a third party's handle, which no session in this suite can produce.
func TestATombstoneFromAnotherSenderIsIgnored(t *testing.T) {
	group := &Group{}
	group.initTables()

	mine := bytes.Repeat([]byte{0x01}, 16)
	theirs := bytes.Repeat([]byte{0x02}, 16)
	lineId := aTarget(0xA1)

	line := newMessage(&Content{Kind: KindText, Text: "a line"}, 10, mine, false, 0, lineId)
	if !deliverOneThroughAWalk(group, line, &Content{Kind: KindText, Text: "a line"}) {
		t.Fatal("a TEXT did not become a line of the conversation")
	}

	stranger := &Content{Kind: KindTombstone, Target: lineId}
	deliverOneThroughAWalk(group, newMessage(stranger, 11, theirs, false, 0, aTarget(0xA2)), stranger)
	if line.Deleted {
		t.Errorf("a tombstone sealed by %x deleted a message sealed by %x", theirs, mine)
	}

	owner := &Content{Kind: KindTombstone, Target: lineId}
	deliverOneThroughAWalk(group, newMessage(owner, 12, mine, false, 0, aTarget(0xA3)), owner)
	if !line.Deleted {
		t.Error("a tombstone sealed by the line's own sender did not delete it")
	}
}

// A REMOVE CANCELS THE SAME REACTOR'S ADD AND NOBODY ELSE'S.
//
// Two members reacting with one emoji are two reactions, and one of them taking theirs back leaves
// the other's standing. A remove written as "drop every reaction with this emoji" passes every
// single-member case and fails this one.
func TestAReactionIsPerReactorAndARemoveTakesBackOnlyItsOwn(t *testing.T) {
	group := &Group{}
	group.initTables()

	alice := bytes.Repeat([]byte{0x01}, 16)
	bob := bytes.Repeat([]byte{0x02}, 16)
	lineId := aTarget(0xB1)

	line := &Content{Kind: KindText, Text: "a line"}
	held := newMessage(line, 10, alice, false, 0, lineId)
	deliverOneThroughAWalk(group, held, line)

	react := func(kind ContentKind, who []byte, emoji string, recordId uint64, id byte) {
		entry := &Content{Kind: kind, Target: lineId, Emoji: emoji}
		deliverOneThroughAWalk(group, newMessage(entry, recordId, who, false, 0, aTarget(id)), entry)
	}
	react(KindReactionAdd, alice, "👍", 11, 0xB2)
	react(KindReactionAdd, bob, "👍", 12, 0xB3)
	react(KindReactionAdd, bob, "🎯", 13, 0xB4)
	if len(held.Reactions) != 3 {
		t.Fatalf("three reactions from two members left %d: %v", len(held.Reactions), held.Reactions)
	}
	// the same member's same emoji twice is one reaction
	react(KindReactionAdd, bob, "👍", 14, 0xB5)
	if len(held.Reactions) != 3 {
		t.Errorf("one member's same emoji twice left %d reactions: %v", len(held.Reactions), held.Reactions)
	}

	react(KindReactionRemove, bob, "👍", 15, 0xB6)
	if len(held.Reactions) != 2 {
		t.Fatalf("a REMOVE left %d reactions: %v", len(held.Reactions), held.Reactions)
	}
	for _, standing := range held.Reactions {
		if standing.Emoji == "👍" && bytes.Equal(standing.SenderHandle, bob) {
			t.Error("bob's 👍 survived bob's own REMOVE")
		}
	}
	kept := 0
	for _, standing := range held.Reactions {
		if standing.Emoji == "👍" && bytes.Equal(standing.SenderHandle, alice) {
			kept += 1
		}
	}
	if kept != 1 {
		t.Errorf("bob's REMOVE took back alice's 👍 as well: %v", held.Reactions)
	}
}

// A KIND THIS BUILD CANNOT READ IS AN ENTRY AND IS NOT A THING TO REACT TO OR DELETE.
//
// T-a is the rule: a tombstone applies to a stored CONTENT message -- TEXT, REPLY, and ATTACHMENT
// when the blob plane exists -- and to nothing else. A placeholder is the case that makes it a
// clause rather than a property of the index: it IS a [Message], it IS in this group's view, and
// this build does not know what it is, so it can neither say that deleting it is meaningful nor
// hand a UI a reaction attached to something it cannot render.
//
// The send side of the same rule is reactableLocked, driven here directly: it needs no server, and
// the API cannot reach it otherwise because nothing in this package can SEND an unknown kind.
func TestAKindThisBuildCannotReadIsNotReactableAndIsNotDeletable(t *testing.T) {
	group := &Group{}
	group.initTables()

	sender := bytes.Repeat([]byte{0x01}, 16)
	placeholderId := aTarget(0xC1)
	lineId := aTarget(0xC2)

	placeholder := &Content{Kind: KindEdit}
	held := newMessage(placeholder, 10, sender, true, 0, placeholderId)
	if !deliverOneThroughAWalk(group, held, placeholder) {
		t.Fatal("a placeholder is an entry of the conversation and this build dropped it")
	}
	line := &Content{Kind: KindText, Text: "a line"}
	heldLine := newMessage(line, 11, sender, true, 0, lineId)
	deliverOneThroughAWalk(group, heldLine, line)

	// the send side
	if _, err := group.reactableLocked(placeholderId); !errors.Is(err, ErrNoSuchMessage) {
		t.Errorf("a placeholder answered %v to reactableLocked, want a refusal", err)
	}
	if _, err := group.reactableLocked(lineId); err != nil {
		t.Errorf("the control: a TEXT this device holds answered %v", err)
	}

	// and the receipt side: a tombstone from the placeholder's OWN sender, which passes T-b
	tombstone := &Content{Kind: KindTombstone, Target: placeholderId}
	deliverOneThroughAWalk(group, newMessage(tombstone, 12, sender, true, 0, aTarget(0xC3)), tombstone)
	if held.Deleted {
		t.Error("a tombstone deleted a record whose kind this build cannot read")
	}
	// the control, which is what says the clause above is about the KIND and not about the
	// tombstone being ignored altogether
	onTheLine := &Content{Kind: KindTombstone, Target: lineId}
	deliverOneThroughAWalk(group, newMessage(onTheLine, 13, sender, true, 0, aTarget(0xC4)), onTheLine)
	if !heldLine.Deleted {
		t.Error("the control: a tombstone on this sender's own TEXT did not delete it")
	}
}

// AN EFFECT THE SERVER HAS NOT NUMBERED YET IS THE NEWEST THING THIS DEVICE DID.
//
// The only records with a zero record id are ones THIS DEVICE has just sealed and whose submit has
// not been answered. Sorting one FIRST would let a half-submitted reaction be cancelled by a REMOVE
// the server numbered before it existed, which is a reaction a user made and watched disappear.
func TestAnEffectWithNoRecordIdYetSortsAfterEveryNumberedOne(t *testing.T) {
	group := &Group{}
	group.initTables()

	sender := bytes.Repeat([]byte{0x01}, 16)
	lineId := aTarget(0xD1)
	line := &Content{Kind: KindText, Text: "a line"}
	held := newMessage(line, 10, sender, true, 0, lineId)
	deliverOneThroughAWalk(group, held, line)

	remove := &Content{Kind: KindReactionRemove, Target: lineId, Emoji: "👍"}
	deliverOneThroughAWalk(group, newMessage(remove, 15, sender, true, 0, aTarget(0xD2)), remove)
	add := &Content{Kind: KindReactionAdd, Target: lineId, Emoji: "👍"}
	deliverOneThroughAWalk(group, newMessage(add, 0, sender, true, 0, aTarget(0xD3)), add)

	if len(held.Reactions) != 1 {
		t.Errorf("a reaction this device has just sealed was cancelled by a REMOVE the server numbered before it: %v",
			held.Reactions)
	}
	// and the control: the same two with the ADD numbered BELOW the remove leave nothing standing
	second := &Group{}
	second.initTables()
	secondHeld := newMessage(line, 10, sender, true, 0, lineId)
	deliverOneThroughAWalk(second, secondHeld, line)
	numbered := &Content{Kind: KindReactionAdd, Target: lineId, Emoji: "👍"}
	deliverOneThroughAWalk(second, newMessage(numbered, 14, sender, true, 0, aTarget(0xD3)), numbered)
	deliverOneThroughAWalk(second, newMessage(remove, 15, sender, true, 0, aTarget(0xD2)), remove)
	if len(secondHeld.Reactions) != 0 {
		t.Errorf("the control: an ADD at record 14 and a REMOVE at 15 left %v standing", secondHeld.Reactions)
	}
}

// ── small helpers, so a case reads as what it is measuring ───────────────────────────────────

func mustEncodeText(t *testing.T, text string) []byte {
	t.Helper()
	plaintext, err := encodeText(text)
	if err != nil {
		t.Fatalf("encodeText(%q): %v", text, err)
	}
	return plaintext
}

func mustEncodeReaction(t *testing.T, kind ContentKind, target []byte, emoji string) []byte {
	t.Helper()
	plaintext, err := encodeReaction(kind, target, emoji)
	if err != nil {
		t.Fatalf("encodeReaction: %v", err)
	}
	return plaintext
}

func mustEncodeTombstone(t *testing.T, target []byte) []byte {
	t.Helper()
	plaintext, err := encodeTombstone(target)
	if err != nil {
		t.Fatalf("encodeTombstone: %v", err)
	}
	return plaintext
}
