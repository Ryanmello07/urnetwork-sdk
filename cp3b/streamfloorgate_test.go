package cp3b

import (
	"context"
	"errors"
	"testing"

	"github.com/urnetwork/sdk/urmessage"
)

// A JOINER ADMITTED ABOVE EPOCH ONE MAY NOT SEND UNTIL IT HAS HELD ITS OWN STREAM FLOOR, AND ONE
// ADMITTED AT EPOCH ONE MAY. LEDGER ITEM 245's FIRST PIECE, AS A GATE.
//
// WHY THE GATE EXISTS. A joiner lands on the leftmost BLANK leaf (RFC 9420 section 7.7), which may
// be a leaf a removed member stood at, and `sender_handle = SenderHandle(group_handle_key, leaf)`
// takes no epoch and no identity -- so it inherits that member's sixteen octets byte for byte and
// the server already holds a stream claim at every index that member spent. A first Send with no
// walk behind it seals at index 1 of a stream that is already spent, is answered
// REASON_STREAM_INDEX_REUSED, and latches urmessage.ErrIdentityInUse FOR THE LIFE OF THE PROCESS:
// a member that has just joined can never send in the group it just joined. Group.seedOwnStreamLocked
// moves the floor past those claims on the first walk; this is what stops a Send from happening
// before that walk, because the seal is the irreversible half.
//
// AND WHY IT STOPS AT EPOCH ONE, WHICH IS THE NARROWING AND IS DRIVEN HERE RATHER THAN ASSERTED.
// The commit that OPENS epoch one is committed against epoch zero, and Device.CreateGroup makes
// epoch zero with exactly ONE member -- so the only leaf that commit could remove is the
// committer's own, which RFC 9420 section 12.4 forbids. There is no blank for section 7.7 to
// refill, so a device admitted at epoch one is on a leaf nobody has ever stood at. Above epoch one
// that argument is gone and this device cannot tell from a tree snapshot which leaves have changed
// hands. BOTH DIRECTIONS ARE IN THIS ONE RUN: the epoch-one joiner sends with no Receive behind it
// and the epoch-two joiner is refused by name, so neither half can pass by the gate being absent
// or by it refusing everything.
//
// WHAT WOULD GO RED: drop the ownFloorHeld clause from urmessage.Group.sendableLocked (the
// epoch-two Send is answered nil); set ownFloorHeld false at every Join (the epoch-one control is
// refused); set it true at every Join (the property is).
func TestAJoinerAboveEpochOneHoldsItsStreamFloorBeforeItSends(t *testing.T) {
	world := newWorld(t)
	ctx := context.Background()

	alice := world.newPersona(t, "alice")
	bob := world.newPersona(t, "bob")
	carol := world.newPersona(t, "carol")
	for _, who := range []*persona{alice, bob, carol} {
		if err := who.device.Connect(ctx); err != nil {
			t.Fatalf("%s's Connect: %v", who.name, err)
		}
	}

	aliceGroup, bobGroup := openPair(t, ctx, alice, bob, newGroupId(t))

	// ── THE CONTROL: THE EPOCH-ONE JOINER SENDS WITH NO WALK BEHIND IT ──────────────────────
	if bobGroup.Epoch() != 1 {
		t.Fatalf("the first joiner was admitted at epoch %d, want 1", bobGroup.Epoch())
	}
	if _, err := bobGroup.Send(ctx, "the epoch-one joiner's first line, with no Receive behind it"); err != nil {
		t.Fatalf("CONTROL FAILED: the epoch-one joiner's first Send answered %v. Its leaf is fresh "+
			"by construction -- there is no blank leaf at epoch zero for section 7.7 to refill -- "+
			"so a gate that refuses it is refusing every group this build makes", err)
	}

	// ── THE PROPERTY: THE EPOCH-TWO JOINER IS REFUSED BY NAME ───────────────────────────────
	keyPackage, err := carol.device.KeyPackage()
	if err != nil {
		t.Fatalf("carol's KeyPackage: %v", err)
	}
	invite, err := aliceGroup.AddMemberAndPublish(ctx, keyPackage)
	if err != nil {
		t.Fatalf("alice's AddMemberAndPublish: %v", err)
	}
	carolGroup, err := carol.device.Join(ctx, gcReencodeInvite(t, invite))
	if err != nil {
		t.Fatalf("carol's Join: %v", err)
	}
	if carolGroup.Epoch() != 2 {
		t.Fatalf("the second joiner was admitted at epoch %d, want 2", carolGroup.Epoch())
	}
	sent, err := carolGroup.Send(ctx, "a line from a joiner that has not looked at its own stream")
	if !errors.Is(err, urmessage.ErrStreamFloorUnheld) {
		t.Fatalf("the epoch-two joiner's first Send answered %v (message %v), want "+
			"ErrStreamFloorUnheld. A joiner above epoch one may be standing on a removed member's "+
			"leaf, and the refusal a collision there produces is sticky for the life of the process",
			err, sent)
	}

	// ── AND A COMMIT DOOR IS REFUSED BY THE SAME NAME, because a commit is a record too ─────
	// It is sealed through the same sealer and spends a stream index under this device's own
	// sender_handle exactly as a message does, so a committer whose floor has not been held
	// collides in the same way -- and the group it was trying to change is then the one it can
	// never write to.
	bobId := rolesIdentityOf(t, bobGroup)
	if err := carolGroup.SetRole(ctx, bobId, "admin"); !errors.Is(err, urmessage.ErrStreamFloorUnheld) {
		t.Fatalf("the epoch-two joiner's SetRole before any walk answered %v, want "+
			"ErrStreamFloorUnheld: the commit door owes the same refusal as the send door", err)
	}

	// ── AND ONE Receive CLEARS IT, so the gate is a delay and not a brick ───────────────────
	if _, err := carolGroup.Receive(ctx); err != nil {
		t.Fatalf("the epoch-two joiner's first Receive: %v", err)
	}
	// THE CONTROL FOR THE CLAUSE ABOVE: the same call, after the walk, is refused for the
	// CALLER'S ROLE and not for the floor -- so what refused it above was this gate rather than
	// the rule behind it, and one Receive really does clear the gate.
	if err := carolGroup.SetRole(ctx, bobId, "admin"); err == nil ||
		errors.Is(err, urmessage.ErrStreamFloorUnheld) {
		t.Fatalf("CONTROL FAILED: the same SetRole after one clean walk answered %v. A MEMBER may "+
			"not set a role, so it must be refused for THAT and not for the floor", err)
	}
	line := "the epoch-two joiner's line, after one walk"
	if _, err := carolGroup.Send(ctx, line); err != nil {
		t.Fatalf("the epoch-two joiner's Send after one clean walk answered %v. The gate delays "+
			"the first send by one Receive; it must not cancel it", err)
	}
	gcReceiveText(t, ctx, "alice", aliceGroup, line)
	t.Logf("the epoch-one joiner sent with no walk behind it, the epoch-two joiner was refused by " +
		"name until one Receive, and its line then opened at the founder")
}
