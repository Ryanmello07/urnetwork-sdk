package cp3b

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/urnetwork/message-server/store"
	"github.com/urnetwork/sdk/urmessage"
)

// A CONVERSATION LONGER THAN ONE FETCH PAGE COMES BACK WHOLE, AND ONE Receive IS WHAT DOES IT.
//
// §4.3.4's FetchResponse carries `complete` -- "false when truncated by limit OR by
// max_response_bytes; both are NORMAL" -- and an earlier build of [urmessage.Group.Receive] read
// none of it: one page came back as the whole history, with a NIL ERROR. A UI that called Receive
// once and rendered the slice showed half a conversation and believed it had all of it, which is
// the worst failure an alpha can have because a user cannot tell it from a quiet room.
//
// THE SERVER'S PAGE IS SET THE WAY AN OPERATOR WOULD SET IT and not through a test seam:
// `api.Config.MaxRecordsPerFetch` is §4.3.1's advertised `max_records_per_fetch`, it is a
// configured number in the deployed binary, and three is a legal value for it. The alternative
// would be to send 513 messages to cross the default, which measures the same thing more slowly.
//
// HOW IT FAILS IF THE PAGING IS DELETED: the group's own ceremony -- the founding commit, two
// wraps and the epoch-complete marker -- is four records ahead of the first message, so a single
// page of three answers ZERO messages. The count below is the assertion; the log line prints the
// page count beside it so a reader can see it really did take several.
func TestAConversationLongerThanOneFetchPageComesBackWhole(t *testing.T) {
	const pageLimit = 3
	const lines = 11

	world := newWorldWith(t, worldOptions{maxRecordsPerFetch: pageLimit})
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

	typed := []string{}
	for at := 0; at < lines; at += 1 {
		text := fmt.Sprintf("line %d of %d, and every one of them has to come back", at+1, lines)
		if _, err := aliceGroup.Send(ctx, text); err != nil {
			t.Fatalf("alice's Send %d: %v", at+1, err)
		}
		typed = append(typed, text)
	}

	// ONE Receive.
	got, err := bobGroup.Receive(ctx)
	if err != nil {
		t.Fatalf("bob's Receive: %v", err)
	}
	if len(got) != lines {
		t.Fatalf("alice sent %d lines and ONE Receive answered %d over a %d-record page: %v",
			lines, len(got), pageLimit, textsOf(got))
	}
	for at, one := range got {
		if one.Text != typed[at] {
			t.Errorf("message %d came back as %q and was typed as %q", at, one.Text, typed[at])
		}
		if 0 < at && one.RecordId <= got[at-1].RecordId {
			t.Errorf("message %d is record %d and message %d is record %d, so the order is not the server's",
				at, one.RecordId, at-1, got[at-1].RecordId)
		}
	}
	stats := bobGroup.Stats()
	if stats.Pages < 2 {
		t.Fatalf("a %d-record page over %d records took %d page(s), so this case never reached the truncation path",
			pageLimit, stats.Fetched, stats.Pages)
	}
	t.Logf("%d lines over a %d-record page: %d pages, %d records fetched, %d opened, %d ceremony, %d own",
		lines, pageLimit, stats.Pages, stats.Fetched, stats.Opened, stats.SkippedCeremony, stats.SkippedOwn)

	// AND THE CURSOR LANDED AT THE END. A second Receive over a group nobody has written to
	// answers nothing and no error -- which is what says the loop terminated because the server
	// said complete, and not because it ran out of something.
	again, err := bobGroup.Receive(ctx)
	if err != nil {
		t.Fatalf("bob's second Receive: %v", err)
	}
	if len(again) != 0 {
		t.Errorf("a second Receive over an unchanged group answered %d message(s): %v", len(again), textsOf(again))
	}
	assertNothingFailedToOpen(t, "bob", bobGroup)
}

// A SERVER THAT ADVERTISES §4.3.4 AND SENDS NO ATTESTATION IS REFUSED.
//
// This is the half of the attestation a client can check WITHOUT a key, and it is a real
// downgrade: `capabilities.attestation_supported` is the server's own claim, made in its Hello,
// and a page that arrives unsigned afterwards is either a server that lied or something between
// the two that stripped the field. The signature itself is NOT verified and
// [urmessage.Group.Receive] says at length why -- there is no fleet key chain and no compiled-in
// root to verify one against (S2-27) -- so this clause is the whole of what is enforced today.
//
// THE SERVER HERE IS THE REAL ONE AND THE ADVERTISEMENT IS THE ONLY THING CHANGED. msgrepo signs
// nothing whatever its Capabilities say (`api/fetch.go:112`: "§4.3.4's FetchAttestation is absent,
// not empty"), so turning the bit on is exactly "a server that claims to sign and does not".
func TestAServerThatAdvertisesAnAttestationAndSendsNoneIsRefused(t *testing.T) {
	world := newWorldWith(t, worldOptions{attestationSupported: true})
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
	if _, err := aliceGroup.Send(ctx, "a line from a server that says it signs its fetches"); err != nil {
		t.Fatalf("alice's Send: %v", err)
	}

	got, err := bobGroup.Receive(ctx)
	if !errors.Is(err, urmessage.ErrFetchAttestation) {
		t.Fatalf("a fetch from a server advertising attestation support and sending none answered %v, want ErrFetchAttestation",
			err)
	}
	if len(got) != 0 {
		t.Errorf("%d message(s) came back from a page that was refused: %v", len(got), textsOf(got))
	}
	t.Logf("the downgrade is refused by name: %v", err)

	// THE CONTROL. The same server, the same records, with the advertisement OFF: the page is
	// taken, the message opens, and the page is COUNTED as unattested rather than silently
	// treated as verified. Without this clause the case above would also pass on a build that
	// refused every fetch.
	honest := newWorldWith(t, worldOptions{})
	honestAlice := honest.newPersona(t, "alice")
	honestBob := honest.newPersona(t, "bob")
	if err := honestAlice.device.Connect(ctx); err != nil {
		t.Fatalf("the control alice's Connect: %v", err)
	}
	if err := honestBob.device.Connect(ctx); err != nil {
		t.Fatalf("the control bob's Connect: %v", err)
	}
	honestGroupId := newGroupId(t)
	honestAliceGroup, honestBobGroup := openPair(t, ctx, honestAlice, honestBob, honestGroupId)
	if _, err := honestAliceGroup.Send(ctx, "a line from a server that never claimed to sign"); err != nil {
		t.Fatalf("the control alice's Send: %v", err)
	}
	control, err := honestBobGroup.Receive(ctx)
	if err != nil {
		t.Fatalf("the control Receive: %v", err)
	}
	if len(control) != 1 {
		t.Fatalf("the control read %d message(s), want 1: %v", len(control), textsOf(control))
	}
	if unattested := honestBobGroup.Stats().Unattested; unattested == 0 {
		t.Error("a page with no attestation was taken and counted as attested; Stats.Unattested did not move")
	}
}

// A SERVER THAT PAGES IN CIRCLES IS REFUSED RATHER THAN LOOPED ON.
//
// The decorator below is a real `store.Store` behind the real `api.Handler`: every check §5.1 runs
// still runs, and the only thing changed is the shape of the fetch RESULT -- no records,
// `complete` false, and a `next_record_id` that does not move. That is a server a client must not
// spin on, and an unbounded "page until complete" would hang the call forever with no error and
// no messages.
func TestAServerThatAnswersIncompleteAndAdvancesNoCursorIsRefused(t *testing.T) {
	world := newWorldWith(t, worldOptions{fetchShape: fetchStandsStill})
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
	if _, err := aliceGroup.Send(ctx, "a line no fetch will ever page past"); err != nil {
		t.Fatalf("alice's Send: %v", err)
	}
	got, err := bobGroup.Receive(ctx)
	if !errors.Is(err, urmessage.ErrFetchNoProgress) {
		t.Fatalf("a fetch that advanced no cursor answered %v, want ErrFetchNoProgress", err)
	}
	if len(got) != 0 {
		t.Errorf("%d message(s) came back from a fetch that never advanced: %v", len(got), textsOf(got))
	}
	t.Logf("a server paging in circles is refused by name: %v", err)
}

// A SERVER THAT NEVER SAYS complete IS BOUNDED, AND WHAT COMES BACK CARRIES THE REFUSAL WITH IT.
//
// The decorator here advances the cursor by one per page and never answers complete, so the loop
// makes progress forever. [urmessage.maxFetchPages] is what stops it, and the contract is that the
// messages read so far come back TOGETHER WITH [urmessage.ErrFetchIncomplete] -- a caller that
// ignores the error still renders what arrived, and a caller that reads it knows there is more.
func TestAFetchThatNeverCompletesStopsAtItsPageBoundAndSaysSo(t *testing.T) {
	world := newWorldWith(t, worldOptions{fetchShape: fetchNeverCompletes})
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
	const typed = "the one line this server will hand over before it starts padding"
	if _, err := aliceGroup.Send(ctx, typed); err != nil {
		t.Fatalf("alice's Send: %v", err)
	}
	got, err := bobGroup.Receive(ctx)
	if !errors.Is(err, urmessage.ErrFetchIncomplete) {
		t.Fatalf("a fetch that never completes answered %v, want ErrFetchIncomplete", err)
	}
	// AND THE MESSAGES ARE STILL THERE. This is the clause that separates "stopped early and
	// said so" from "refused the whole page": the first page carried a real message and it comes
	// back beside the refusal.
	if len(got) != 1 || got[0].Text != typed {
		t.Fatalf("the bounded fetch answered %v beside its refusal, want the one line alice sent", textsOf(got))
	}
	t.Logf("bounded, and what arrived came with it: %v", err)
}

// ── the two fetch shapes a real server must not be believed about ────────────────────────────

type fetchShape int

const (
	fetchNormal fetchShape = iota

	// no records, complete false, next_record_id unmoved: a server paging in circles.
	fetchStandsStill

	// no records, complete false, next_record_id one past where it was asked: a server that
	// makes progress and never finishes.
	fetchNeverCompletes
)

// shapedStore is `store.Store` with ONE method overridden.
//
// It is an embedding and not a reimplementation on purpose: every other call -- CreateGroup,
// Submit, the epoch keys, the group state -- is the real memory store's, so the group is founded,
// opened and written through the real §6.1 transaction, and only the fetch RESULT is bent. A
// hand-written double would have been a second server, and a case against a second server says
// nothing about this one.
type shapedStore struct {
	store.Store
	shape fetchShape
}

func (self *shapedStore) Fetch(ctx context.Context, request *store.FetchRequest) (*store.FetchResult, error) {
	result, err := self.Store.Fetch(ctx, request)
	if err != nil || self.shape == fetchNormal {
		return result, err
	}
	// the first page is the honest one, so a case can hold what came back BEFORE the bending
	// started. After it, nothing but the shape.
	if request.SinceRecordId == 0 && self.shape == fetchNeverCompletes {
		result.Complete = false
		return result, nil
	}
	result.Records = nil
	result.Complete = false
	switch self.shape {
	case fetchStandsStill:
		result.NextRecordId = request.SinceRecordId
	case fetchNeverCompletes:
		result.NextRecordId = request.SinceRecordId + 1
	}
	return result, nil
}
