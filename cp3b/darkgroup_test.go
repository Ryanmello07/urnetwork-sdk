package cp3b

import (
	"context"
	"errors"
	"testing"

	"github.com/urnetwork/message-server/store"
	"github.com/urnetwork/sdk/urmessage"
)

// A DARK GROUP NAMES ITS WRAP ON **EVERY LATER** Receive, AND NOT THE SERVER'S REFUSAL.
//
// THE FINDING THIS CASE EXISTS FOR, reproduced against this server before it was repaired. Ruling
// 38 requires that a member which never opens a readable wrap is told WHY rather than being handed
// an undiagnosable refusal. The build that introduced the sticky diagnosis got the FIRST Receive
// right and lost it on every one after:
//
//	1st Receive: urmessage: a device wrap addressed to this device did not open … 1 wrap(s) at
//	             this device's own wrap_target_handle for epoch 2 did not open  -- ErrWrapUnreadable
//	2nd Receive: urmessage: the message server refused this fetch: REASON_REJECTED -- ErrFetchRefused,
//	             and errors.Is(ErrWrapUnreadable) FALSE
//	3rd Receive: the same.
//
// Five arms of [urmessage.Group.Receive] called [Group.commitWalkLocked] as a statement and
// returned their own transport error, and [Group.wrapDark] is only consulted inside that function.
//
// AND THE REFUSAL ARM IS NOT INCIDENTAL -- IT IS THE ARM A DARK GROUP IS GUARANTEED TO TAKE. Both
// keys of an epoch hang off storage_root[n+1]: a member with the wrong pq_secret has the wrong
// read_key, §4.3.4's req_auth is a mac under it, and the server verifies that BEFORE it reaches
// any AEAD. So from its second fetch onwards a dark group is refused at the door, for ever.
//
// WHY THIS CASE CANNOT LIVE IN `urmessage`, which is the other half of the finding. That package
// has no transport: its harness hands a page straight to openPageLocked, so the arm that answers a
// REFUSAL does not exist there at all. The previous commit's mutation row M9 deleted the sticky
// field and watched three urmessage cases go red -- a gate whose CLASS did not match the defect's
// SHAPE, because the defect was in an arm only a server can reach.
//
// THE INLINE CONTROL IS THE PAGE COUNTER AND IT FIRES FOR ITS OWN REASON. [Stats.Pages] is
// incremented AFTER the REASON_OK check, so a Receive that did not move it was refused rather than
// served. Without that clause this case would also pass against a build whose second Receive
// quietly succeeded and answered a stale sticky error -- which would prove nothing about the arm.
func TestADarkGroupNamesItsWrapOnEveryLaterReceiveAndNotTheServersRefusal(t *testing.T) {
	world := newWorldWith(t, worldOptions{fetchShape: fetchBendsOneRecord})
	ctx := context.Background()

	alice := world.newPersona(t, "alice")
	bob := world.newPersona(t, "bob")
	for _, who := range []*persona{alice, bob} {
		if err := who.device.Connect(ctx); err != nil {
			t.Fatalf("%s's Connect: %v", who.name, err)
		}
	}
	groupId := newGroupId(t)
	aliceGroup, bobGroup := openPair(t, ctx, alice, bob, groupId)

	beforeTheCommit := uint64(0)
	for _, row := range world.allRows(t, groupId) {
		if beforeTheCommit < row.RecordId {
			beforeTheCommit = row.RecordId
		}
	}

	// ── THE EPOCH BOB MUST FOLLOW, AND THE FAN-OUT THAT CARRIES ITS SECRET ──────────────────
	hsAddAndJoin(t, ctx, aliceGroup, world.newPersona(t, "carol"))
	if aliceGroup.Epoch() != 2 {
		t.Fatalf("alice is at epoch %d after the add, want 2", aliceGroup.Epoch())
	}
	wrapIds := []uint64{}
	for _, row := range world.allRows(t, groupId) {
		if row.RecordId <= beforeTheCommit || row.Attachment == nil {
			continue
		}
		if row.Attachment.Kind == store.AttachmentWrap {
			wrapIds = append(wrapIds, row.RecordId)
		}
	}
	if len(wrapIds) == 0 {
		t.Fatal("the second epoch published no wrap row, so there is nothing to make unreadable " +
			"and this case would be measuring an ordinary group")
	}

	// EVERY WRAP ROW OF THE EPOCH, because a wrap_target_handle cannot be inverted from the
	// server side and a test holding only what the store holds cannot tell bob's from alice's.
	// See [shapedStore.bendAll].
	world.shaped.bendAll(wrapIds, 1000)

	// ── THE FIRST Receive: THE DIAGNOSIS, WHICH THE BUILD BEFORE THE REPAIR ALSO GOT RIGHT ──
	if _, err := bobGroup.Receive(ctx); !errors.Is(err, urmessage.ErrWrapUnreadable) {
		t.Fatalf("bob's FIRST Receive over a bent fan-out answered %v, want ErrWrapUnreadable", err)
	}
	if bobGroup.Epoch() != 2 {
		t.Fatalf("bob is at epoch %d, want 2: the epoch moves whatever the wrap did, because a "+
			"member with no secret for it is dark there either way", bobGroup.Epoch())
	}
	if unreadable := bobGroup.Stats().WrapUnreadable; unreadable == 0 {
		t.Fatal("Stats.WrapUnreadable did not move, so bob did not reach the state this case is about")
	}

	// ── THE SECOND AND THIRD, WHICH IS THE FINDING ──────────────────────────────────────────
	for attempt := 2; attempt <= 3; attempt += 1 {
		pagesBefore := bobGroup.Stats().Pages
		_, err := bobGroup.Receive(ctx)
		pagesAfter := bobGroup.Stats().Pages

		// THE CONTROL, FIRST, BECAUSE THE CLAUSE AFTER IT IS WORTHLESS WITHOUT IT: the fetch was
		// REFUSED and not served, which is what puts this Receive on the arm the finding is about.
		if pagesBefore != pagesAfter {
			t.Fatalf("CONTROL FAILED: bob's Receive number %d was SERVED a page (Stats.Pages %d "+
				"-> %d), so it never reached the refusal arm and the assertion below is measuring "+
				"something else. A dark group's read_key is wrong and §4.3.4's req_auth is a mac "+
				"under it, so this Receive is supposed to be refused at the door",
				attempt, pagesBefore, pagesAfter)
		}
		if !errors.Is(err, urmessage.ErrWrapUnreadable) {
			t.Fatalf("bob's Receive number %d answered %v. The sticky diagnosis is gone and the "+
				"caller is told the SYMPTOM -- a refused fetch -- instead of the cause. That is "+
				"the undiagnosable REASON_REJECTED ruling 38 exists to prevent, and after this "+
				"point no Receive can ever say it again", attempt, err)
		}
		if errors.Is(err, urmessage.ErrFetchRefused) {
			t.Fatalf("bob's Receive number %d still matches ErrFetchRefused, so a caller that "+
				"reads a refusal as a transport problem will retry a group that cannot recover "+
				"by being retried", attempt)
		}
	}

	// ── AND Send SAYS THE SAME THING, which is the second control: it shows the sticky field IS
	//    set, so the clause above is about the READ path losing it rather than about the field.
	if _, err := bobGroup.Send(ctx, "a line from a group that has gone dark"); !errors.Is(err, urmessage.ErrWrapUnreadable) {
		t.Fatalf("a dark group's Send answered %v, want ErrWrapUnreadable", err)
	}

	// ── AND THE THIRD CONTROL, IN THE SAME RUN: THE SERVER IS STILL SERVING. alice is not dark,
	//    her keys are right, and her Receive is taken. Without this the case above is satisfiable
	//    by a server that refuses everybody.
	if _, err := aliceGroup.Receive(ctx); err != nil {
		t.Fatalf("CONTROL FAILED: alice's Receive answered %v, so the refusals above are not "+
			"about bob's keys", err)
	}
}
