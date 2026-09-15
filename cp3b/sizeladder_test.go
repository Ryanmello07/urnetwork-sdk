package cp3b

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/message-server/store"
	"github.com/urnetwork/sdk/urmessage"
)

// WHAT urmessage SEALS AT EVERY RECORD TYPE, AND WHICH RUNG EACH ONE LANDS ON, READ OFF THE
// SERVER'S OWN ROWS.
//
// WHY THIS CASE EXISTS. connect 4c030dc made an APPLICATION record's ct_body plaintext an MLS
// PrivateMessage, and the frame sits INSIDE the size rung: connect's own
// TestTheSizeLadderCostOfTheInnerFrameIsMeasuredHere measures usable body falling 252 to 59,
// 1,020 to 826, 4,092 to 3,898, 16,380 to 16,186 and 65,532 to 65,334. That measurement is over
// messagegroup.GroupSession directly. THIS one is over what a user types, through
// urmessage.Group.Send, a real server, and the row the server stored -- so a text length that used
// to cost 272 stored octets and now costs 1,040 is a fact about THIS client rather than a column
// transcribed from the layer below.
//
// AND IT HOLDS THE THREE CEREMONY TYPES APART FROM THE TEXT, because MASTER section 8.4.1's table
// frames only one arm: a founding commit (is_commit), a wrap and an epoch-complete marker (each
// carrying a server attachment) have NO inner frame, so the ruling should not have moved any of
// them. If a later change framed them, the rung each lands on is where it shows.
//
// EVERY TEXT IS READ BACK ON THE FAR SIDE AND COMPARED WHOLE, so a boundary that sealed but did not
// open is red here rather than a rung number that looks right.
func TestEveryRecordTypeUrmessageSealsLandsOnTheRungItsBodyNeeds(t *testing.T) {
	world := newWorld(t)
	ctx := context.Background()

	alice := world.newPersona(t, "alice")
	bob := world.newPersona(t, "bob")
	if err := alice.device.Connect(ctx); err != nil {
		t.Fatalf("alice's Connect: %v", err)
	}
	if err := bob.device.Connect(ctx); err != nil {
		t.Fatalf("bob's Connect: %v", err)
	}
	groupId := newGroupId(t)
	aliceGroup, bobGroup := openPair(t, ctx, alice, bob, groupId)

	rows := func() map[uint64]*store.Record {
		t.Helper()
		result, err := world.store.Fetch(context.Background(), &store.FetchRequest{GroupId: groupId})
		if err != nil {
			t.Fatalf("reading the server's own rows: %v", err)
		}
		byId := map[uint64]*store.Record{}
		for _, row := range result.Records {
			byId[row.RecordId] = row
		}
		return byId
	}

	// ── the ceremony: founding commit, one wrap per member, the marker ──────────────────────
	ceremony := rows()
	commits, wraps, markers := 0, 0, 0
	for _, row := range ceremony {
		kind := "text"
		want := message.SizeBucket(0xFF)
		switch {
		case row.IsCommit:
			// the founding commit's body is the MLS commit that added bob, measured at 272 octets
			// of ct_body at this commit. Pinned for the same reason as the other two, and if it
			// moves the cause may equally be a bigger commit rather than a frame.
			kind, commits = "founding commit", commits+1
			want = message.SizeBucket256
		case row.Attachment != nil && row.Attachment.Kind == store.AttachmentWrap:
			kind, wraps = "epoch wrap", wraps+1
			want = message.SizeBucket256
		case row.Attachment != nil && row.Attachment.Kind == store.AttachmentEpochComplete:
			kind, markers = "epoch complete marker", markers+1
			want = message.SizeBucket256
		}
		t.Logf("record %d: %s, size_bucket %d (%d octets rung), ct_body %d octets",
			row.RecordId, kind, row.SizeBucket, message.SizeBucketBytes(message.SizeBucket(row.SizeBucket)), len(row.CtBody))
		// a wrap's body is 91 octets of prose and a marker's 33, and neither carries a frame: both
		// fit the 256 rung with the old 252 usable octets and must still.
		if want != 0xFF && message.SizeBucket(row.SizeBucket) != want {
			t.Errorf("record %d, a %s, landed on rung %d and carries no inner frame, so it should be on rung %d",
				row.RecordId, kind, row.SizeBucket, want)
		}
	}
	if commits != 1 || wraps != 2 || markers != 1 {
		t.Fatalf("the founding left %d commit(s), %d wrap(s) and %d marker(s), want 1, 2 and 1", commits, wraps, markers)
	}

	// ── the text ladder, at every edge the ruling moved and at the edges it used to be ───────
	type edge struct {
		octets int
		rung   message.SizeBucket
	}
	edges := []edge{
		{0, message.SizeBucket256},
		{1, message.SizeBucket256},
		{59, message.SizeBucket256},
		{60, message.SizeBucket1K},
		{252, message.SizeBucket1K}, // fitted the 256 rung before 4c030dc
		{826, message.SizeBucket1K},
		{827, message.SizeBucket4K},
		{1020, message.SizeBucket4K}, // fitted the 1K rung before
		{3898, message.SizeBucket4K},
		{3899, message.SizeBucket16K},
		{16186, message.SizeBucket16K},
		{16187, message.SizeBucket64K},
		{65334, message.SizeBucket64K},
	}
	for _, one := range edges {
		text := strings.Repeat("u", one.octets)
		sent, err := aliceGroup.Send(ctx, text)
		if err != nil {
			t.Fatalf("a %d octet text: %v", one.octets, err)
		}
		row := rows()[sent.RecordId]
		if row == nil {
			t.Fatalf("a %d octet text was answered record %d and the server holds no such row", one.octets, sent.RecordId)
		}
		if message.SizeBucket(row.SizeBucket) != one.rung {
			t.Errorf("a %d octet text landed on rung %d and the measured ladder puts it on %d",
				one.octets, row.SizeBucket, one.rung)
		}
		got, err := bobGroup.Receive(ctx)
		if err != nil {
			t.Fatalf("bob's Receive of the %d octet text: %v", one.octets, err)
		}
		if len(got) != 1 || got[0].Text != text {
			lengths := []int{}
			for _, message := range got {
				lengths = append(lengths, len(message.Text))
			}
			t.Fatalf("bob read %d message(s) of lengths %v for one %d octet text", len(got), lengths, one.octets)
		}
		t.Logf("a %5d octet text: rung %d, ct_body %5d octets, read back whole", one.octets, row.SizeBucket, len(row.CtBody))
	}

	// ── and the ceiling: 65,335 is one past the largest inline rung and is refused by name ───
	//
	// It used to fit: 65,532 octets were usable before 4c030dc. The 198 octet band between is the
	// one connect's ledger open item 203 names, and a blob rung is its only destination.
	for _, octets := range []int{65335, 65532} {
		if _, err := aliceGroup.Send(ctx, strings.Repeat("u", octets)); !errors.Is(err, urmessage.ErrTextTooLong) {
			t.Errorf("a %d octet text answered %v, want ErrTextTooLong", octets, err)
		}
	}
	assertNothingFailedToOpen(t, "bob", bobGroup)
}
