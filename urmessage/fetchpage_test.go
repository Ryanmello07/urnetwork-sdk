package urmessage

import (
	"bytes"
	"errors"
	"testing"

	"github.com/urnetwork/connect/protocol"
)

// §4.3.4'S ATTESTATION, HELD AGAINST THE PAGE IT ARRIVED WITH.
//
// WHY THIS CASE IS HERE AND NOT IN cp3b, said plainly because it is a limit on what has been
// measured: the deployed server SIGNS NOTHING (`msgrepo/api/fetch.go:112` -- "§4.3.4's
// FetchAttestation is absent, not empty"), and there is no way to make it produce one through
// `store.Store`, which is the only seam `cp3b` can bend. So the four description clauses below
// are UNREACHABLE against a real server today, and against a fake one they would be a test of the
// fake. They are driven here, directly, against the function that holds them.
//
// WHAT IS STILL NOT CHECKED ANYWHERE, and it is the one that matters: the SIGNATURE. Verifying it
// needs a fleet key chain the server does not publish and a compiled-in fleet root this workspace
// does not have. See [Group.Receive] and S2-27. Everything below is what a client can hold
// WITHOUT a key -- which is "this attestation describes this page" and never "this page is what
// the server has".
func TestAnAttestationThatDoesNotDescribeItsOwnPageIsRefused(t *testing.T) {
	groupId := bytes.Repeat([]byte{0x71}, GroupIdBytes)
	page := func() *protocol.FetchResponse {
		return &protocol.FetchResponse{
			Records: []*protocol.Record{
				{RecordId: 5},
				{RecordId: 6},
			},
			HighWaterRecordId: 9,
			Complete:          true,
			Attestation: &protocol.FetchAttestation{
				GroupId:           append([]byte(nil), groupId...),
				SinceRecordId:     4,
				RecordIds:         []uint64{5, 6},
				HighWaterRecordId: 9,
			},
		}
	}
	group := &Group{id: groupId}

	// THE CONTROL: the whole, agreeing page is taken, and it is COUNTED as unattested because
	// its signature was not verified. Without this clause every refusal below would also pass on
	// a build that refused everything.
	if err := group.checkAttestationLocked(4, page()); err != nil {
		t.Fatalf("an attestation that describes its own page was refused: %v", err)
	}
	if group.stats.Unattested != 1 {
		t.Fatalf("a page whose signature was not verified moved Stats.Unattested to %d, want 1",
			group.stats.Unattested)
	}

	for _, one := range []struct {
		name string
		bend func(*protocol.FetchResponse)
	}{
		{"it names another group", func(p *protocol.FetchResponse) {
			p.Attestation.GroupId = bytes.Repeat([]byte{0x27}, GroupIdBytes)
		}},
		{"it names another since_record_id", func(p *protocol.FetchResponse) {
			p.Attestation.SinceRecordId = 3
		}},
		{"its high_water is not the response's", func(p *protocol.FetchResponse) {
			p.Attestation.HighWaterRecordId = 8
		}},
		{"it lists fewer records than the page carries", func(p *protocol.FetchResponse) {
			p.Attestation.RecordIds = []uint64{5}
		}},
		{"it lists more records than the page carries", func(p *protocol.FetchResponse) {
			p.Attestation.RecordIds = []uint64{5, 6, 7}
		}},
		{"one of its record ids is not the page's", func(p *protocol.FetchResponse) {
			p.Attestation.RecordIds = []uint64{5, 7}
		}},
		{"its high_water is below a record the page carries", func(p *protocol.FetchResponse) {
			p.Records = append(p.Records, &protocol.Record{RecordId: 11})
			p.Attestation.RecordIds = []uint64{5, 6, 11}
		}},
	} {
		t.Run(one.name, func(t *testing.T) {
			bent := page()
			one.bend(bent)
			if err := group.checkAttestationLocked(4, bent); !errors.Is(err, ErrFetchAttestation) {
				t.Fatalf("an attestation where %s answered %v, want ErrFetchAttestation", one.name, err)
			}
		})
	}
}

// EVERY VALUE THIS STORE NAMES WAS FLUSHED BEFORE IT WAS NAMED.
//
// The count is taken AFTER the Sync returns and at no other site, which is
// sdk/message_stream_store.go's measured discipline: a counter incremented ABOVE the flush
// survives the mutation "return before the flush", because the number still moves. This case is
// what makes the fsync in [DurableStateStore.writeRecord] undeletable -- remove that line and this
// number is zero on every write below.
//
// ONE FLUSH PER VALUE AND NOT ONE PER CALL, which is the other half: a store that flushed twice
// per value would be paying twice for the same guarantee, and one that batched would be reporting
// a value durable before it is.
func TestEveryValueTheDurableStoreNamesWasFlushedFirst(t *testing.T) {
	store := openTestStore(t, t.TempDir())
	if store.flushCount() != 0 {
		t.Fatalf("a freshly opened store has already flushed %d time(s)", store.flushCount())
	}
	for at, one := range []struct {
		name string
		call func() error
	}{
		{"PutGroupState", func() error { return store.PutGroupState(testGroupId, 0, testState) }},
		{"PutPrivateKey", func() error { return store.PutPrivateKey(testPub, testPriv) }},
		{"PutKeyPackage", func() error { return store.PutKeyPackage(testRef, testKp, testInit, testEnc) }},
		{"PutDeviceIdentity", func() error { return store.PutDeviceIdentity(testPub, testPriv, testKp) }},
		{"PutGroupRecord", func() error {
			return store.PutGroupRecord(&GroupRecord{
				GroupId: testGroupId, PqSecret: testPriv, GroupHandleKey: testPub, Epoch: 0,
			})
		}},
	} {
		if err := one.call(); err != nil {
			t.Fatalf("%s: %v", one.name, err)
		}
		if flushes := store.flushCount(); flushes != at+1 {
			t.Fatalf("after %d writes ending in %s the store has performed %d value flush(es)",
				at+1, one.name, flushes)
		}
	}
	// and a READ flushes nothing, which is what says the number counts writes rather than calls
	before := store.flushCount()
	if _, err := store.GetGroupState(testGroupId, 0); err != nil {
		t.Fatalf("GetGroupState: %v", err)
	}
	if _, err := store.GroupRecords(); err != nil {
		t.Fatalf("GroupRecords: %v", err)
	}
	if after := store.flushCount(); after != before {
		t.Errorf("two reads performed %d value flush(es)", after-before)
	}
}
