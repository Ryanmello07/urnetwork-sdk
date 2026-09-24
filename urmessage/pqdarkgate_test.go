// A GROUP THAT GOES DARK IS DARK FOR EVER, AND THE CODE IS NOW HELD TO SAYING SO.
//
// WHAT THIS FILE IS. Three production sentences claimed that a dark group repairs itself -- the
// resolution's own header ("nobody's fault and resolves itself at the next commit"), errors.go's
// ErrOrphanWrap ("IT IS NOT A FAULT AND IT REPAIRS ITSELF"), and cgo's wrap_orphaned doc ("which
// repairs itself"). All three were FALSE rather than merely unmeasured, and the third is in a
// different package from the first two, which is why the prose gate below does not read a file by
// name: a gate scoped to a bug's current address is one this project has already been bitten by.
//
// AND THE DIAGNOSIS IS NOW DURABLE, which is ruling 38 surviving a restart: a device that went
// dark used to come back with a pq_secret no peer agrees with, no sentence anywhere, and a
// pq_secret table that reads as healthy -- pqSecretsShowRotation compares OCTETS and the fallback
// wrote the same octets as the epoch below, so nothing in the table says anything is wrong.
//
// AND A REMOVAL MAY NOT BE FOLLOWED ON A SECRET THIS GROUP ALREADY HOLDS, which is item 243's own
// property arriving inverted. It was written here as a rule about the two arms that return the
// identifier `held`, and the arm that returns a WRAP CANDIDATE reaches the same value off the wire
// and had no guard: a committer that removed a leaf and fanned out the secret the group already
// had was followed by every survivor with a nil error and no dark state. The gate below was scoped
// to the identifier, printed `candidate.secret` in its own complement, and passed. Both halves are
// repaired here -- the rule is on the VALUE at one exit, and the gate is on the SHAPE of every
// return that can carry one, asserted rather than printed.
//
// AND ITEM 251's RULING 41: an unrotated removal is an INVALID COMMIT, refused the way an
// unauthorized one is -- the receiver stays at epoch n and does NOT go dark. Refused-and-halted
// and valid-and-dark are two outcomes, separately reachable, separately named and separately
// tested below.
package urmessage

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/urnetwork/connect/messagegroup"
)

// ── 1. PERMANENCE, DRIVEN RATHER THAN ASSERTED ───────────────────────────────────────────────

// A SECOND, CLEAN, COMPLETE ROTATION DOES NOT REPAIR A DARK GROUP, AND THIS IS THE CLAIM'S OWN
// COUNTEREXAMPLE FAILING TO EXIST.
//
// The deleted sentence said the orphan "resolves itself at the next commit". This case builds
// exactly that: bob's wrap for epoch 2 is bent to a payload the epoch was not opened with, so bob
// takes ErrOrphanWrap and follows on the stale secret; then alice publishes a SECOND rotation with
// nothing wrong with it, including bob's own wrap, and bob is served the whole page.
//
// THE CONTROL IS IN THE SAME LOOP AND IT FIRES FOR ITS OWN REASON: carol, who was never bent,
// takes the same two pages and follows both, so what the case measures is bob's state and not a
// harness that stopped delivering. Without it "bob is still dark" would also be satisfied by a
// world in which nothing was delivered to anybody.
func TestADarkGroupIsStillDarkAfterTheNextCleanRotation(t *testing.T) {
	world := newRotWorld(t, "alice", "bob", "carol")
	alice, bob, carol := world.member("alice"), world.member("bob"), world.member("carol")

	first := world.rotate(alice, nil, func() ([]byte, []byte, []byte, error) {
		return alice.handle.Commit(nil)
	}, rotBend{leaf: bob.leaf, payload: make([]byte, messagegroup.PqSecretBytes)})

	darkErr := world.deliver(bob, first.page()...)
	if !errors.Is(darkErr, ErrOrphanWrap) {
		t.Fatalf("bob's walk over the bent fan-out answered %v, want ErrOrphanWrap", darkErr)
	}
	if bob.group.wrapDark == nil {
		t.Fatalf("bob took ErrOrphanWrap and was not marked dark")
	}
	if bob.group.epoch != first.opens {
		t.Fatalf("bob stands at epoch %d after the bent rotation, want %d", bob.group.epoch, first.opens)
	}
	if err := world.deliver(carol, first.page()...); err != nil {
		t.Fatalf("CONTROL FAILED: carol's walk over the SAME page answered %v, so the page is "+
			"broken for everybody and bob's darkness says nothing about the bend", err)
	}
	t.Logf("CONTROL HELD: the same page that made bob dark was followed by carol")

	// ── THE SECOND ROTATION, CLEAN AND COMPLETE ─────────────────────────────────────────────
	second := world.rotate(alice, nil, func() ([]byte, []byte, []byte, error) {
		return alice.handle.Commit(nil)
	})
	bobsWrap := 0
	for _, target := range second.targets {
		if target.leaf == bob.leaf {
			bobsWrap += 1
		}
	}
	if bobsWrap != 1 {
		t.Fatalf("CONTROL FAILED: the second fan-out addresses bob's leaf %d times, want 1; a "+
			"rotation that left bob out would prove nothing about repair", bobsWrap)
	}
	if err := world.deliver(carol, second.page()...); err != nil {
		t.Fatalf("CONTROL FAILED: carol's walk over the second rotation answered %v, so that "+
			"rotation is not the clean one this case needs", err)
	}

	healed := world.deliver(bob, second.page()...)
	if healed == nil {
		t.Fatalf("bob's walk over the NEXT, clean, complete rotation answered nil: the deleted " +
			"sentence would be true and this file is wrong")
	}
	if !errors.Is(healed, ErrOrphanWrap) {
		t.Fatalf("bob's walk over the next rotation answered %v, want the same sticky ErrOrphanWrap", healed)
	}
	if !strings.Contains(healed.Error(), fmt.Sprintf("epoch %d", first.opens)) {
		t.Fatalf("bob's answer after the second rotation is %v, which does not name epoch %d -- "+
			"the sticky sentence is supposed to be the one taken at the epoch it went dark at",
			healed, first.opens)
	}
	if bob.group.epoch != first.opens {
		t.Fatalf("bob moved to epoch %d across the second rotation; a dark group is not supposed "+
			"to be able to follow anything", bob.group.epoch)
	}
	if carol.group.epoch != second.opens {
		t.Fatalf("CONTROL FAILED: carol stands at epoch %d after the second rotation, want %d",
			carol.group.epoch, second.opens)
	}
	if bytes.Equal(world.storageRootOf(bob), world.storageRootOf(carol)) {
		t.Fatalf("bob and carol derive one storage root, so bob is not dark at all")
	}
	if _, err := bob.group.sendableLocked(KindText); !errors.Is(err, ErrOrphanWrap) {
		t.Fatalf("bob's Send after the clean rotation is refused with %v, want the same ErrOrphanWrap", err)
	}
}

// ── 2. THE DIAGNOSIS SURVIVES THE PROCESS ────────────────────────────────────────────────────

// A DARK GROUP COMES BACK DARK, BY NAME, WITH THE EPOCH IN THE SENTENCE.
//
// bob is served the commit and NOT its wrap -- item 132's omission at the victim -- so it takes
// ErrNoWrapForEpoch and files the stale fallback at epoch 2. Then the process ends and a second
// one opens over the same disk.
//
// THE CONTROL IS carol, WHO TAKES THE WHOLE PAGE AND RESTARTS TOO: her restored group is NOT dark.
// Without it "the restored group is dark" would also be satisfied by a restore that marked every
// group dark, which is the failure in the other direction and is the one that would take the alpha
// down.
func TestADarkGroupComesBackDarkAndAHealthyOneDoesNot(t *testing.T) {
	world := newRotWorld(t, "alice", "bob", "carol")
	alice, bob, carol := world.member("alice"), world.member("bob"), world.member("carol")
	bobLeaf, carolLeaf := bob.leaf, carol.leaf

	published := world.rotate(alice, nil, func() ([]byte, []byte, []byte, error) {
		return alice.handle.Commit(nil)
	})
	// THE OMISSION: bob is handed the commit and none of the wraps. carol is handed everything.
	darkErr := world.deliver(bob, published.commit)
	if !errors.Is(darkErr, ErrNoWrapForEpoch) {
		t.Fatalf("bob's walk over a commit with no wrap answered %v, want ErrNoWrapForEpoch", darkErr)
	}
	if err := world.deliver(carol, published.page()...); err != nil {
		t.Fatalf("CONTROL FAILED: carol's walk over the whole page answered %v", err)
	}

	// THE DISK, BEFORE THE RESTART, because the claim is about what was WRITTEN and not about
	// what a second process reconstructs.
	records, err := bob.dev.store.GroupRecords()
	if err != nil {
		t.Fatalf("bob's GroupRecords: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("bob's disk holds %d group record(s), want 1", len(records))
	}
	if records[0].WrapDarkKind != wrapDarkNoWrap {
		t.Fatalf("bob's persisted record carries wrap_dark kind %d, want %d (ErrNoWrapForEpoch)",
			records[0].WrapDarkKind, wrapDarkNoWrap)
	}
	if records[0].WrapDarkEpoch != published.opens {
		t.Fatalf("bob's persisted record names dark epoch %d, want %d",
			records[0].WrapDarkEpoch, published.opens)
	}
	// AND THE TABLE STILL READS AS HEALTHY, which is why the kind has to be there at all. The
	// fallback wrote the SAME octets as the epoch below, so the only evidence a restart could
	// otherwise have -- two different values -- does not exist.
	table, _, err := restoredPqSecrets(records[0])
	if err != nil {
		t.Fatalf("bob's restored table: %v", err)
	}
	if pqSecretsShowRotation(table) {
		t.Fatalf("bob's persisted table reads as rotated, so this case is not measuring the " +
			"state it was written for -- the fallback is supposed to be indistinguishable in the octets")
	}

	carolRecords, err := carol.dev.store.GroupRecords()
	if err != nil {
		t.Fatalf("carol's GroupRecords: %v", err)
	}
	if len(carolRecords) != 1 || carolRecords[0].WrapDarkKind != wrapDarkNone {
		t.Fatalf("CONTROL FAILED: carol's persisted record carries wrap_dark kind %d, want 0",
			carolRecords[0].WrapDarkKind)
	}

	// ── THE RESTART ─────────────────────────────────────────────────────────────────────────
	revivedBob := restoredRotDevice(t, bob)
	restoredBob, err := revivedBob.device.restoreOne(revivedBob.store, records[0], restoreTestNonce(), 1)
	if err != nil {
		t.Fatalf("restoreOne over bob's dark record: %v", err)
	}
	defer restoredBob.Close()
	restoredBob.reconciled = true
	if restoredBob.wrapDark == nil {
		t.Fatalf("the restored group carries NO diagnosis although its record names dark epoch %d",
			records[0].WrapDarkEpoch)
	}
	if !errors.Is(restoredBob.wrapDark, ErrNoWrapForEpoch) {
		t.Fatalf("the restored diagnosis is %v, want an ErrNoWrapForEpoch", restoredBob.wrapDark)
	}
	if !strings.Contains(restoredBob.wrapDark.Error(), fmt.Sprintf("epoch %d", published.opens)) {
		t.Fatalf("the restored diagnosis is %v and does not name epoch %d", restoredBob.wrapDark, published.opens)
	}
	if _, err := restoredBob.sendableLocked(KindText); !errors.Is(err, ErrNoWrapForEpoch) {
		t.Fatalf("the restored group's Send is refused with %v, want ErrNoWrapForEpoch", err)
	}
	if err := restoredBob.committableLocked(); !errors.Is(err, ErrNoWrapForEpoch) {
		t.Fatalf("the restored group's commit path is refused with %v, want ErrNoWrapForEpoch", err)
	}
	_ = bobLeaf

	revivedCarol := restoredRotDevice(t, carol)
	restoredCarol, err := revivedCarol.device.restoreOne(revivedCarol.store, carolRecords[0], restoreTestNonce(), 1)
	if err != nil {
		t.Fatalf("restoreOne over carol's healthy record: %v", err)
	}
	defer restoredCarol.Close()
	if restoredCarol.wrapDark != nil {
		t.Fatalf("CONTROL FAILED: a group that was never dark came back dark: %v", restoredCarol.wrapDark)
	}
	_ = carolLeaf
}

// A SIX-PART RECORD RESTORES AS NOT DARK, AND A SEVENTH PART THIS BUILD DID NOT WRITE IS REFUSED.
//
// The first clause is the compatibility direction -- every disk written before this commit -- and
// the second is what keeps it from becoming "anything short is healthy": a part of the wrong
// length, or naming a kind this build does not know, refuses the group by name rather than
// answering the safest-sounding thing about a file that has been altered.
func TestTheWrapDarkPartIsOptionalAndRefusesWhatThisBuildDidNotWrite(t *testing.T) {
	base := func(parts int, dark []byte) [][]byte {
		rows := [][]byte{
			make([]byte, GroupIdBytes),
			bytes.Repeat([]byte{0x11}, messagegroup.PqSecretBytes),
			bytes.Repeat([]byte{0x22}, 32),
			{0, 0, 0, 0, 0, 0, 0, 3},
			{1},
		}
		if 6 <= parts {
			table, err := encodePqSecretTable([]EpochPqSecret{{Epoch: 3, PqSecret: bytes.Repeat([]byte{0x11}, messagegroup.PqSecretBytes)}})
			if err != nil {
				t.Fatalf("encodePqSecretTable: %v", err)
			}
			rows = append(rows, table)
		}
		if 7 <= parts {
			rows = append(rows, dark)
		}
		return rows
	}
	for _, one := range []struct {
		name  string
		parts [][]byte
		kind  uint8
		epoch uint64
		bad   bool
	}{
		{name: "five parts: the deployed alpha's disk", parts: base(5, nil), kind: wrapDarkNone},
		{name: "six parts: written before the wrap_dark part", parts: base(6, nil), kind: wrapDarkNone},
		{name: "seven parts, empty: this build, not dark", parts: base(7, nil), kind: wrapDarkNone},
		{name: "seven parts, dark", parts: base(7, []byte{wrapDarkOrphan, 0, 0, 0, 0, 0, 0, 0, 3}),
			kind: wrapDarkOrphan, epoch: 3},
		{name: "a wrap_dark part of the wrong width", parts: base(7, []byte{wrapDarkOrphan}), bad: true},
		{name: "a wrap_dark kind this build does not name",
			parts: base(7, []byte{0x7f, 0, 0, 0, 0, 0, 0, 0, 3}), bad: true},
		{name: "eight parts", parts: append(base(7, nil), nil), bad: true},
	} {
		t.Run(one.name, func(t *testing.T) {
			record, err := groupRecordOf("a-group", one.parts)
			if one.bad {
				if err == nil {
					t.Fatalf("a record this build did not write decoded to %+v", record)
				}
				if !errors.Is(err, ErrStateStoreFormat) {
					t.Fatalf("the refusal is %v, want an ErrStateStoreFormat", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("groupRecordOf: %v", err)
			}
			if record.WrapDarkKind != one.kind || record.WrapDarkEpoch != one.epoch {
				t.Fatalf("decoded kind %d epoch %d, want kind %d epoch %d",
					record.WrapDarkKind, record.WrapDarkEpoch, one.kind, one.epoch)
			}
			if wrapDarkErrorOf(record.WrapDarkKind, record.WrapDarkEpoch) == nil && one.kind != wrapDarkNone {
				t.Fatalf("a record naming kind %d rebuilt no diagnosis", one.kind)
			}
		})
	}
}

// ── 3. A REMOVAL MAY NOT BE FOLLOWED ON THE SECRET THE REMOVED MEMBER HOLDS ──────────────────

// THE COMMIT SHAPE EVERY BUILD BEFORE THIS ONE EMITTED, REFUSED: a CommitRemove whose digest was
// computed over the HELD secret.
//
// THE COUNTERFACTUAL IS THE FINDING AND IT IS ASSERTED, not described: the removed member's
// retained pq_secret, mixed with the exporter of the epoch it was removed at, reproduces the
// committer's own storage root for that epoch. That is item 243's whole subject. So the refusal is
// not a fussy rule -- it is the only thing standing between this build and a removal that removes
// nothing.
//
// AND IT IS REFUSED BEFORE ApplyCommit, which the case asserts by the epoch: bob does not move.
// A rule enforced only at the resolution would leave bob at the new epoch and permanently dark,
// which would hand any client on an older build a way to brick every up-to-date member.
func TestARemovalThatDoesNotRotateIsRefusedAndTheGroupDoesNotFollowIt(t *testing.T) {
	world := newRotWorld(t, "alice", "bob", "carol")
	alice, bob, carol := world.member("alice"), world.member("bob"), world.member("carol")

	retained := append([]byte(nil), carol.group.pqSecretLocked()...)
	atOne := world.storageRootOf(bob)
	published := world.advanceWithoutRotating(alice, func() ([]byte, []byte, []byte, error) {
		return alice.handle.CommitRemove([]uint32{carol.leaf})
	})
	if published.opens != 2 {
		t.Fatalf("the removal opens epoch %d, want 2", published.opens)
	}

	// ── THE COUNTERFACTUAL, FIRST, so the refusal below is about something ──────────────────
	granted, err := alice.handle.Export(storageExporterLabel, nil, storageExporterBytes)
	if err != nil {
		t.Fatalf("the epoch-2 exporter: %v", err)
	}
	committerRoot := messagegroup.StorageRoot(granted, published.pqSecret)
	withRetained := messagegroup.StorageRoot(granted, retained)
	if !bytes.Equal(withRetained, committerRoot) {
		t.Fatalf("CONTROL FAILED: this fixture's removal DID rotate, so it is not the shape this " +
			"case refuses and the refusal below would be about nothing")
	}
	t.Logf("the removed member's retained pq_secret reproduces the committer's storage_root[2]: " +
		"that is what the refusal below prevents this group from following")

	// ── THE REFUSAL ─────────────────────────────────────────────────────────────────────────
	refused := world.deliver(bob, published.page()...)
	if !errors.Is(refused, ErrRemovalWithoutRotation) {
		t.Fatalf("bob's walk over an unrotated removal answered %v, want ErrRemovalWithoutRotation", refused)
	}
	if bob.group.epoch != 1 {
		t.Fatalf("bob stands at epoch %d after refusing the removal, want 1: the refusal is "+
			"supposed to run BEFORE ApplyCommit", bob.group.epoch)
	}
	if bob.group.wrapDark != nil {
		t.Fatalf("bob went dark over a commit it refused before applying: %v", bob.group.wrapDark)
	}
	if !bytes.Equal(world.storageRootOf(bob), atOne) {
		t.Fatalf("bob's storage root moved although it did not follow the commit")
	}
	if _, err := bob.group.sendableLocked(KindText); err != nil {
		t.Fatalf("bob's Send is refused with %v; a group that refused a commit is still a working "+
			"group at the epoch it is at", err)
	}

	// ── THE POSITIVE CONTROL: a removal that DOES rotate is followed ────────────────────────
	//
	// In a second world, because bob above is now behind alice and cannot be handed anything.
	// Without this clause the rule would be satisfied by a build that refuses every removal.
	clean := newRotWorld(t, "alice", "bob", "carol")
	cleanAlice, cleanBob, cleanCarol := clean.member("alice"), clean.member("bob"), clean.member("carol")
	rotated := clean.rotate(cleanAlice, []uint32{cleanCarol.leaf}, func() ([]byte, []byte, []byte, error) {
		return cleanAlice.handle.CommitRemove([]uint32{cleanCarol.leaf})
	})
	if err := clean.deliver(cleanBob, rotated.page()...); err != nil {
		t.Fatalf("CONTROL FAILED: a removal that DOES rotate was refused with %v, so the rule "+
			"refuses everything and proves nothing", err)
	}
	if cleanBob.group.epoch != rotated.opens {
		t.Fatalf("CONTROL FAILED: bob stands at epoch %d after a clean removal, want %d",
			cleanBob.group.epoch, rotated.opens)
	}
}

// THE SHAPE THAT DEFEATED ITEM 243's OWN PURPOSE: a removal with a COMPLETE, OPENABLE FAN-OUT
// CARRYING THE SECRET THE GROUP ALREADY HELD.
//
// WHAT IT IS. The committer removes carol and writes one well-formed device wrap per survivor,
// each sealed to that survivor's own published X-Wing key and each carrying pq_secret[1] -- the
// value carol holds by construction. Every wrap OPENS. So the pre-apply refusal sees a candidate
// and the resolution's FIRST arm, the wrap-candidate arm, reproduces the commit's digest and
// answers that candidate. Until this commit that arm carried no removal guard at all: it returned
// `candidate.secret, nil`, every survivor followed with no error, no dark state and no refusal,
// and carol's retained secret reproduced their storage_root[2] exactly.
//
// THE COUNTERFACTUAL IS ASSERTED AND NOT DESCRIBED, first, so the refusal below is about
// something: the removed member's retained pq_secret, mixed with the exporter of the epoch it was
// removed at, reproduces the committer's own storage root for that epoch.
//
// THREE CONTROLS, ALL INLINE, EACH FIRING FOR ITS OWN REASON:
//
//  1. THE FAN-OUT IS REAL. bob's wrap is in the page, it OPENS, and the candidate it stages is the
//     one the digest names -- asserted through Stats.WrapOpened and the staged candidate itself.
//     Without it "bob refused" would also be satisfied by a page bob could not read, which is a
//     different sentinel and a different bug.
//  2. THE HONEST ROTATED REMOVAL, in the same test, in a second world: it is FOLLOWED. Without it
//     the rule would be satisfied by a build that refuses every removal, which removes the feature
//     rather than the member.
//  3. THE REFUSAL IS PRE-APPLY, asserted by the epoch and by the absence of a dark state, which is
//     ruling 41: an unrotated removal is an INVALID commit and is refused the way an unauthorized
//     one is -- the receiver stays at n. It does not advance into a permanent brick on a commit it
//     has just judged invalid.
func TestARemovalFannedOutOnTheHeldSecretIsRefusedAndTheGroupStaysAtItsEpoch(t *testing.T) {
	world := newRotWorld(t, "alice", "bob", "carol")
	alice, bob, carol := world.member("alice"), world.member("bob"), world.member("carol")

	retained := append([]byte(nil), carol.group.pqSecretLocked()...)
	atOne := world.storageRootOf(bob)
	published := world.fanOutOnTheHeldSecret(alice, []uint32{carol.leaf}, func() ([]byte, []byte, []byte, error) {
		return alice.handle.CommitRemove([]uint32{carol.leaf})
	}, unrotatedFanOut{})
	if published.opens != 2 {
		t.Fatalf("the removal opens epoch %d, want 2", published.opens)
	}

	// ── THE COUNTERFACTUAL ──────────────────────────────────────────────────────────────────
	granted, err := alice.handle.Export(storageExporterLabel, nil, storageExporterBytes)
	if err != nil {
		t.Fatalf("the epoch-2 exporter: %v", err)
	}
	if !bytes.Equal(messagegroup.StorageRoot(granted, retained), messagegroup.StorageRoot(granted, published.pqSecret)) {
		t.Fatalf("CONTROL FAILED: this fixture's removal DID rotate, so it is not the shape this " +
			"case refuses and the refusal below would be about nothing")
	}
	t.Logf("the REMOVED member's retained pq_secret reproduces the committer's storage_root[2]; " +
		"the fan-out that delivers it is complete and every wrap opens")

	// ── CONTROL 1: THE FAN-OUT IS REAL, measured on the receiver before the commit is met ───
	//
	// The wraps are delivered on their own, so what is asserted is that they OPENED -- a page in
	// which bob simply could not read anything would produce the same refusal below for an
	// entirely different reason.
	if err := world.deliver(bob, published.wraps...); err != nil {
		t.Fatalf("CONTROL FAILED: bob's walk over the fan-out alone answered %v", err)
	}
	if opened := bob.group.Stats().WrapOpened; opened != 1 {
		t.Fatalf("CONTROL FAILED: bob opened %d wrap(s) of this fan-out, want 1; a refusal below "+
			"would then be about a wrap that did not arrive and not about the value it carries", opened)
	}
	staged := bob.group.wrapsFor[published.opens]
	if len(staged) != 1 || !bytes.Equal(staged[0].secret, retained) {
		t.Fatalf("CONTROL FAILED: bob staged %d candidate(s) for epoch %d and this case needs exactly "+
			"one carrying the value the removed member holds", len(staged), published.opens)
	}

	// ── THE REFUSAL ─────────────────────────────────────────────────────────────────────────
	refused := world.deliver(bob, published.commit)
	if refused == nil {
		t.Fatalf("bob FOLLOWED a removal fanned out on the secret the removed member holds. carol's "+
			"retained pq_secret reproduces bob's storage_root[%d] and the removal removed nothing",
			published.opens)
	}
	if !errors.Is(refused, ErrRemovalWithoutRotation) {
		t.Fatalf("bob's walk over the unrotated fan-out answered %v, want ErrRemovalWithoutRotation", refused)
	}
	if bob.group.epoch != 1 {
		t.Fatalf("bob stands at epoch %d after refusing the removal, want 1: ruling 41 refuses an "+
			"invalid commit the way an unauthorized one is refused, and the receiver stays at n", bob.group.epoch)
	}
	if bob.group.wrapDark != nil {
		t.Fatalf("bob went DARK over a commit it refused: %v. Ruling 41 is that the two are "+
			"different outcomes -- refused-and-halted is not valid-and-dark", bob.group.wrapDark)
	}
	if !bytes.Equal(world.storageRootOf(bob), atOne) {
		t.Fatalf("bob's storage root moved although it did not follow the commit")
	}
	if _, err := bob.group.sendableLocked(KindText); err != nil {
		t.Fatalf("bob's Send is refused with %v; a group that HALTED is still a working group at "+
			"the epoch it is at, which is the whole of the distinction ruling 41 draws", err)
	}

	// ── CONTROL 2: THE HONEST ROTATED REMOVAL IS FOLLOWED ───────────────────────────────────
	clean := newRotWorld(t, "alice", "bob", "carol")
	cleanAlice, cleanBob, cleanCarol := clean.member("alice"), clean.member("bob"), clean.member("carol")
	cleanRetained := append([]byte(nil), cleanCarol.group.pqSecretLocked()...)
	rotated := clean.rotate(cleanAlice, []uint32{cleanCarol.leaf}, func() ([]byte, []byte, []byte, error) {
		return cleanAlice.handle.CommitRemove([]uint32{cleanCarol.leaf})
	})
	if err := clean.deliver(cleanBob, rotated.page()...); err != nil {
		t.Fatalf("CONTROL FAILED: a removal that DOES rotate was refused with %v, so the new guard "+
			"refuses everything and proves nothing", err)
	}
	if cleanBob.group.epoch != rotated.opens {
		t.Fatalf("CONTROL FAILED: bob stands at epoch %d after a clean removal, want %d",
			cleanBob.group.epoch, rotated.opens)
	}
	if !bytes.Equal(cleanBob.group.pqSecretLocked(), rotated.pqSecret) {
		t.Fatalf("CONTROL FAILED: bob followed the clean removal onto a secret that is not the " +
			"epoch's own, so the control is not measuring the honest path")
	}
	if bytes.Equal(cleanBob.group.pqSecretLocked(), cleanRetained) {
		t.Fatalf("CONTROL FAILED: the clean removal's own secret IS the retained one, so the two " +
			"arms of this case are the same arm")
	}
}

// AND THE RULE IS ON THE WHOLE TABLE, NOT ON THE CURRENT EPOCH'S ROW: a removal fanned out on an
// EARLIER epoch's pq_secret.
//
// THIS IS THE MUTATION OF THE MECHANISM, WRITTEN AS A CASE. The guard's subject is
// [Group.pqSecretHeldAtLocked], and the tempting narrowing -- compare against
// `self.pqSecrets[self.epoch]`, the value the previous rule called "held" -- is defeated by one
// line of adversary: fan out pq_secret[n-1] instead of pq_secret[n]. A different octet string, so
// every equality against the current row answers no; the same removed member holding it, because a
// member keeps every row of the window it was a member for; and the same storage_root reproduced
// at the epoch it was removed at. Narrow the subject and this case goes red while every other
// removal case in this file stays green.
//
// THE WORLD IS TWO EPOCHS DEEP BECAUSE IT HAS TO BE. A group at epoch 1 has one row, so "the
// current row" and "the whole table" are the same set and the narrowing is invisible. The honest
// rotation that builds the second row is also this case's first control: it is FOLLOWED.
func TestARemovalFannedOutOnAnEarlierEpochsSecretIsRefusedToo(t *testing.T) {
	world := newRotWorld(t, "alice", "bob", "carol")
	alice, bob, carol := world.member("alice"), world.member("bob"), world.member("carol")
	atOne := append([]byte(nil), carol.group.pqSecretLocked()...)

	// ── CONTROL 1: AN HONEST ROTATION, FOLLOWED, which is what gives bob a second row ────────
	first := world.rotate(alice, nil, func() ([]byte, []byte, []byte, error) {
		return alice.handle.Commit(nil)
	})
	for _, member := range []*rotMember{bob, carol} {
		if err := world.deliver(member, first.page()...); err != nil {
			t.Fatalf("CONTROL FAILED: %s's walk over an honest rotation answered %v", member.name, err)
		}
	}
	if len(bob.group.pqSecrets) < 2 {
		t.Fatalf("CONTROL FAILED: bob holds %d row(s) after one rotation; with one row the current "+
			"row and the whole table are the same set and this case measures nothing",
			len(bob.group.pqSecrets))
	}
	if bytes.Equal(bob.group.pqSecretLocked(), atOne) {
		t.Fatalf("CONTROL FAILED: epoch 2's secret IS epoch 1's, so 'an EARLIER epoch's value' is " +
			"not a different octet string here")
	}
	if _, heldAtOne := bob.group.pqSecretHeldAtLocked(atOne); !heldAtOne {
		t.Fatalf("CONTROL FAILED: bob no longer holds epoch 1's secret, so the replay below is of " +
			"a value the removed member does not keep either")
	}

	// ── THE REPLAY: the removal opens epoch 3 on pq_secret[1] ────────────────────────────────
	published := world.fanOutOnTheHeldSecret(alice, []uint32{carol.leaf}, func() ([]byte, []byte, []byte, error) {
		return alice.handle.CommitRemove([]uint32{carol.leaf})
	}, unrotatedFanOut{opensOn: atOne})
	if !bytes.Equal(published.pqSecret, atOne) {
		t.Fatalf("CONTROL FAILED: the fixture opened epoch %d on something other than epoch 1's secret",
			published.opens)
	}
	granted, err := alice.handle.Export(storageExporterLabel, nil, storageExporterBytes)
	if err != nil {
		t.Fatalf("the epoch-%d exporter: %v", published.opens, err)
	}
	if !bytes.Equal(messagegroup.StorageRoot(granted, atOne), messagegroup.StorageRoot(granted, published.pqSecret)) {
		t.Fatalf("CONTROL FAILED: the removed member's epoch-1 secret does not reproduce the " +
			"committer's root, so there is nothing here to refuse")
	}

	refused := world.deliver(bob, published.page()...)
	if !errors.Is(refused, ErrRemovalWithoutRotation) {
		t.Fatalf("bob's walk over a removal fanned out on epoch 1's secret answered %v, want "+
			"ErrRemovalWithoutRotation. A guard whose subject is only the CURRENT epoch's row "+
			"answers no to this and carol keeps the post-quantum half of epoch %d", refused, published.opens)
	}
	if bob.group.epoch != first.opens {
		t.Fatalf("bob stands at epoch %d, want %d", bob.group.epoch, first.opens)
	}
	if bob.group.wrapDark != nil {
		t.Fatalf("bob went dark on a commit it refused: %v", bob.group.wrapDark)
	}
}

// THE WRAP-CANDIDATE ARM, DRIVEN DIRECTLY, BOTH WAYS.
//
// The page-level case above is the one that matters in the field, and it is answered BEFORE
// ApplyCommit -- which means the resolution's own first arm is not what refuses it there. This
// drives that arm with the values production would hand it, for the reason the compatibility arm's
// case gives below: a property whose only gate is structural is one refactor away from being
// unmeasured, and this arm's guard is the one that was missing.
//
// BOTH DIRECTIONS, and the control is the whole point: with no removal the arm answers the
// candidate, which is every honest rotation in this package; with one, and the candidate carrying
// a value the group already holds, it refuses.
func TestTheWrapCandidateArmOfTheResolutionIsClosedToARemoval(t *testing.T) {
	world := newRotWorld(t, "alice", "bob", "carol")
	alice, bob, carol := world.member("alice"), world.member("bob"), world.member("carol")
	retained := append([]byte(nil), carol.group.pqSecretLocked()...)

	published := world.fanOutOnTheHeldSecret(alice, []uint32{carol.leaf}, func() ([]byte, []byte, []byte, error) {
		return alice.handle.CommitRemove([]uint32{carol.leaf})
	}, unrotatedFanOut{})
	// bob opens its wrap and stops there: the commit is not delivered to it, so what the
	// resolution is asked below is the question production asks at (4a).
	if err := world.deliver(bob, published.wraps...); err != nil {
		t.Fatalf("bob's walk over the fan-out answered %v", err)
	}
	staged := bob.group.wrapsFor[published.opens]
	if len(staged) != 1 || !bytes.Equal(staged[0].secret, retained) {
		t.Fatalf("CONTROL FAILED: bob staged %d candidate(s) and this case needs one carrying the "+
			"value the removed member holds", len(staged))
	}
	digest, err := epochDigestOf(&published.commit.record.Header)
	if err != nil || digest == nil {
		t.Fatalf("the digest on the removal commit: %v %v", digest, err)
	}
	// THE COMMITTER IS THE ONE MEMBER THAT CAN ASK: judging a candidate needs mls_secret at the
	// epoch the commit OPENS, and only a device that has merged holds it. alice has. The
	// candidate is staged on alice's group because that is what the arm reads.
	mlsSecret, err := alice.handle.Export(storageExporterLabel, nil, storageExporterBytes)
	if err != nil {
		t.Fatalf("the epoch-%d exporter: %v", published.opens, err)
	}

	// THE CONTROL, FIRST: with no removal the arm answers the candidate. That is every honest
	// rotation this package performs, and without it the refusal below would also be satisfied by
	// an arm that refuses everything.
	alice.group.wrapsFor[published.opens] = []wrapCandidate{{recordId: 1, secret: append([]byte(nil), retained...)}}
	answered, err := alice.group.resolvePqSecretLocked(mlsSecret, published.opens, digest, nil)
	if err != nil {
		t.Fatalf("CONTROL FAILED: the wrap-candidate arm refused a non-removing commit with %v", err)
	}
	if !bytes.Equal(answered, retained) {
		t.Fatalf("CONTROL FAILED: the arm answered a value that is not the staged candidate, so the " +
			"clause below is about some other arm")
	}

	// THE PROPERTY. This is the return that was `candidate.secret, nil` with no guard at all.
	alice.group.wrapsFor[published.opens] = []wrapCandidate{{recordId: 1, secret: append([]byte(nil), retained...)}}
	secret, err := alice.group.resolvePqSecretLocked(mlsSecret, published.opens, digest, []uint32{carol.leaf})
	if err == nil {
		t.Fatalf("a commit removing leaf %d was followed on a wrap candidate carrying the value "+
			"the removed member also holds (%d octets of it)", carol.leaf, len(secret))
	}
	if !errors.Is(err, ErrRemovalWithoutRotation) {
		t.Fatalf("the refusal is %v, want ErrRemovalWithoutRotation", err)
	}
}

// AND THE RESIDUAL, DRIVEN RATHER THAN NAMED: a removal whose fan-out is FRESH and whose digest
// still names the held secret.
//
// WHY IT EXISTS AT ALL. The pre-apply refusal cannot evaluate the digest -- judging a candidate
// needs mls_secret at the epoch the commit OPENS and there is no exporter over a PROCESSED commit
// -- so it asks the one question that is decidable before the apply: does this device hold a
// candidate carrying a value it does not already have? A committer that writes a decoy nobody can
// use answers yes to that and is let past, and the digest then says the epoch was opened on the
// held secret after all. This case builds exactly that.
//
// WHAT IS ASSERTED IS RULING 41's OUTCOME AND THE RESIDUAL BESIDE IT. The commit is refused with
// the same sentinel, the group does NOT go dark and its own epoch does not move -- and the MLS
// handle HAS moved, because ApplyCommit ran before the resolution could be asked. That divergence
// is the residual and it is named here rather than papered over: the group is halted at n, its
// session and its persisted record agree with each other at n, and the next process re-derives the
// same refusal from the same record.
func TestTheResidualUnrotatedRemovalIsRefusedAfterTheApplyAndStillDoesNotGoDark(t *testing.T) {
	world := newRotWorld(t, "alice", "bob", "carol")
	alice, bob, carol := world.member("alice"), world.member("bob"), world.member("carol")
	retained := append([]byte(nil), carol.group.pqSecretLocked()...)

	published := world.fanOutOnAFreshSecret(alice, []uint32{carol.leaf}, func() ([]byte, []byte, []byte, error) {
		return alice.handle.CommitRemove([]uint32{carol.leaf})
	})
	// THE CONTROL, INLINE: the decoy this case rests on is genuinely NOT a value bob holds, or the
	// pre-apply refusal would fence the commit and this case would be the previous one again.
	if err := world.deliver(bob, published.wraps...); err != nil {
		t.Fatalf("CONTROL FAILED: bob's walk over the decoy fan-out answered %v", err)
	}
	staged := bob.group.wrapsFor[published.opens]
	if len(staged) != 1 {
		t.Fatalf("CONTROL FAILED: bob staged %d candidate(s), want 1", len(staged))
	}
	if bytes.Equal(staged[0].secret, retained) {
		t.Fatalf("CONTROL FAILED: the decoy IS the held secret, so this case is the pre-apply one")
	}
	if _, alreadyHeld := bob.group.pqSecretHeldAtLocked(staged[0].secret); alreadyHeld {
		t.Fatalf("CONTROL FAILED: bob already holds the decoy, so the pre-apply refusal fences this " +
			"commit and the resolution is never reached")
	}

	refused := world.deliver(bob, published.commit)
	if !errors.Is(refused, ErrRemovalWithoutRotation) {
		t.Fatalf("bob's walk over the residual shape answered %v, want ErrRemovalWithoutRotation", refused)
	}
	if bob.group.wrapDark != nil {
		t.Fatalf("bob went dark on an unrotated removal: %v. Ruling 41 says an invalid commit is "+
			"refused and not followed into a brick", bob.group.wrapDark)
	}
	if bob.group.epoch != 1 {
		t.Fatalf("bob's group stands at epoch %d, want 1", bob.group.epoch)
	}
	if held, isHeld := bob.group.pqSecretAtLocked(published.opens); isHeld {
		t.Fatalf("bob filed a pq_secret for epoch %d (%d octets) although it refused the commit that "+
			"opens it", published.opens, len(held))
	}
	// THE RESIDUAL, ASSERTED RATHER THAN CLAIMED CLOSED: the MLS handle is one epoch ahead,
	// because this refusal is the only one of the two that is taken after ApplyCommit.
	if bob.handle.Epoch() != published.opens {
		t.Fatalf("this case is supposed to be the AFTER-apply refusal and bob's handle stands at "+
			"epoch %d, want %d; if the pre-apply refusal now covers this shape, move this case and "+
			"say so", bob.handle.Epoch(), published.opens)
	}
	t.Logf("THE RESIDUAL, MEASURED: the refusal is taken after ApplyCommit, so bob's MLS handle "+
		"stands at epoch %d while its group, its session and its persisted record stand at %d. "+
		"The group is halted, not dark, and the repair is a committer that re-commits properly",
		bob.handle.Epoch(), bob.group.epoch)
	records, err := bob.dev.store.GroupRecords()
	if err != nil {
		t.Fatalf("bob's GroupRecords: %v", err)
	}
	if len(records) != 1 || records[0].Epoch != 1 || records[0].WrapDarkKind != wrapDarkNone {
		t.Fatalf("bob's disk names epoch %d and wrap_dark kind %d, want 1 and %d",
			records[0].Epoch, records[0].WrapDarkKind, wrapDarkNone)
	}
}

// AND THE OTHER HELD-SECRET ARM: a removal on a commit carrying NO epoch digest at all.
//
// It is a separate case because it is a separate arm. A kind 0x0001 commit -- Spec B section 5.4's
// acceptance window is dated and open -- never reaches the compatibility comparison; it takes the
// held secret at the top of the resolution and returns. A single guard in front of the function
// would have covered both and would ALSO have refused a removal that rotated, which is the case
// this package exists to serve.
//
// IT IS DRIVEN THROUGH THE RESOLUTION DIRECTLY, and WHY is a claim this file got wrong once. It
// used to say that (3a) "catches every unfanned removal before ApplyCommit and no page can
// therefore reach the no-digest arm through a walk". That was FALSE, not merely unmeasured, and
// the counterexample was found on the first try: a committer that removes a leaf, writes a
// COMPLETE fan-out and seals its commit with no attachment is not unfanned, passed an
// unfanned-ness check, and landed here through an ordinary walk. (3a) asks a different question
// now -- see [Group.refuseUnrotatedRemovalLocked] -- and the claim is no longer argued: the page
// that reached this arm is built and delivered by
// TestNoPageReachesTheNoDigestArmOfTheResolutionThroughAWalk, which measures where the refusal is
// taken instead of asserting where it cannot be. This case stays a direct call because a property
// whose only driver is a page is one pre-apply repair away from being unmeasured.
func TestTheNoDigestArmOfTheResolutionIsAlsoClosedToARemoval(t *testing.T) {
	world := newRotWorld(t, "alice", "bob", "carol")
	bob, carol := world.member("bob"), world.member("carol")
	mlsSecret, err := bob.handle.Export(storageExporterLabel, nil, storageExporterBytes)
	if err != nil {
		t.Fatalf("bob's exporter: %v", err)
	}

	// THE CONTROL FIRST, IN THE SAME CALL SHAPE: with no removal, a digest-less commit is
	// followed on the held secret. That is the compatibility path and every group on the alpha
	// is on it, so a refusal that also caught this would be a refusal nobody could ship.
	held, err := bob.group.resolvePqSecretLocked(mlsSecret, bob.group.epoch+1, nil, nil)
	if err != nil {
		t.Fatalf("CONTROL FAILED: a digest-less commit that removes nobody was refused with %v", err)
	}
	if !bytes.Equal(held, bob.group.pqSecretLocked()) {
		t.Fatalf("CONTROL FAILED: the compatibility arm answered a secret this group does not hold")
	}

	secret, err := bob.group.resolvePqSecretLocked(mlsSecret, bob.group.epoch+1, nil, []uint32{carol.leaf})
	if err == nil {
		t.Fatalf("a digest-less commit that removes leaf %d was followed on the held secret, and "+
			"the value it answered is the one the removed member also holds (%d octets of it)", carol.leaf, len(secret))
	}
	if !errors.Is(err, ErrRemovalWithoutRotation) {
		t.Fatalf("the refusal is %v, want ErrRemovalWithoutRotation", err)
	}
}

// THE COUNTEREXAMPLE TO THE SENTENCE ABOVE, BUILT AND DELIVERED: the page that DID reach the
// no-digest arm through a walk, and where its refusal is taken now.
//
// THE SHAPE. A committer removes carol, writes a complete openable fan-out -- so no check on the
// ABSENCE of a candidate can see it -- and seals its commit with no server attachment at all,
// which is what [epochDigestOf] answers nil for. Under the old (3a) this walked straight past the
// pre-apply refusal, applied the commit, and was refused at the resolution: dark at n+1, on a
// commit the build had just judged invalid, which is the outcome ruling 41 took away.
//
// WHAT IS ASSERTED IS WHERE, AND NOT WHETHER. Both builds refuse this page; the difference is the
// epoch the receiver is standing at afterwards and whether it is dark. So this case asserts the
// refusal is taken BEFORE ApplyCommit -- bob's own MLS handle has not moved, which the residual
// case next door shows is a genuinely different observable and not a restatement of the epoch.
//
// THE CONTROL IS INLINE AND FIRES FOR ITS OWN REASON: the same committer, the same fan-out, the
// same missing attachment, removing NOBODY -- which is every kind 0x0001 commit on the deployed
// alpha -- is FOLLOWED. Without it this would also be satisfied by a build that refuses every
// commit carrying no digest, which would take the whole acceptance window down with it.
func TestNoPageReachesTheNoDigestArmOfTheResolutionThroughAWalk(t *testing.T) {
	world := newRotWorld(t, "alice", "bob", "carol")
	alice, bob, carol := world.member("alice"), world.member("bob"), world.member("carol")

	published := world.fanOutOnTheHeldSecret(alice, []uint32{carol.leaf}, func() ([]byte, []byte, []byte, error) {
		return alice.handle.CommitRemove([]uint32{carol.leaf})
	}, unrotatedFanOut{noDigest: true})
	if digest, err := epochDigestOf(&published.commit.record.Header); err != nil || digest != nil {
		t.Fatalf("CONTROL FAILED: this commit carries a digest (%v, %v), so it is not the shape "+
			"that reaches the no-digest arm", digest, err)
	}
	if len(published.wraps) == 0 {
		t.Fatalf("CONTROL FAILED: this commit is unfanned, so it is refused by the absence of a " +
			"candidate and says nothing about the arm this case is named for")
	}

	refused := world.deliver(bob, published.page()...)
	if !errors.Is(refused, ErrRemovalWithoutRotation) {
		t.Fatalf("bob's walk over a fanned, digest-less removal answered %v, want ErrRemovalWithoutRotation", refused)
	}
	if bob.group.epoch != 1 {
		t.Fatalf("bob stands at epoch %d, want 1", bob.group.epoch)
	}
	if bob.group.wrapDark != nil {
		t.Fatalf("bob went dark on a commit it refused: %v", bob.group.wrapDark)
	}
	// THE MEASUREMENT THIS CASE EXISTS FOR: the MLS handle has NOT moved, so the refusal was taken
	// before ApplyCommit and the resolution was never asked. A refusal at the resolution leaves
	// the handle at n+1 -- which is exactly what the residual case asserts, so the two are
	// distinguishable and this is not a restatement of the epoch check above.
	if bob.handle.Epoch() != 1 {
		t.Fatalf("bob's MLS handle stands at epoch %d, want 1: the commit was APPLIED and the "+
			"refusal was therefore taken at the resolution, which is the arm this page is supposed "+
			"to no longer reach", bob.handle.Epoch())
	}

	// ── THE SECOND SHAPE, AND IT IS HERE BECAUSE A MUTANT SURVIVED ──────────────────────────
	//
	// Deleting the `digest == nil` arm of the pre-apply refusal left the whole suite GREEN. The
	// page above does not need it: its wraps carry the held secret, so the candidate clause
	// refuses that commit anyway and neither the epoch nor the handle can tell the two refusals
	// apart. The arm is load-bearing for exactly one shape -- a digest-less removal whose fan-out
	// carries something FRESH -- because a fresh candidate satisfies the candidate clause, and
	// nothing else available before ApplyCommit can say that a commit with no digest could only
	// ever be followed on a value this group already holds. That shape is built here, and it is
	// what kills the mutant.
	fresh := newRotWorld(t, "alice", "bob", "carol")
	freshAlice, freshBob, freshCarol := fresh.member("alice"), fresh.member("bob"), fresh.member("carol")
	decoy := make([]byte, messagegroup.PqSecretBytes)
	for at := range decoy {
		decoy[at] = 0x3D
	}
	fanned := fresh.fanOutOnTheHeldSecret(freshAlice, []uint32{freshCarol.leaf}, func() ([]byte, []byte, []byte, error) {
		return freshAlice.handle.CommitRemove([]uint32{freshCarol.leaf})
	}, unrotatedFanOut{noDigest: true, payload: decoy})
	if err := fresh.deliver(freshBob, fanned.wraps...); err != nil {
		t.Fatalf("CONTROL FAILED: bob's walk over the fresh fan-out answered %v", err)
	}
	if _, alreadyHeld := freshBob.group.pqSecretHeldAtLocked(decoy); alreadyHeld {
		t.Fatalf("CONTROL FAILED: bob already holds the decoy, so the candidate clause refuses this " +
			"commit and the digest clause is not what this case measures")
	}
	if staged := freshBob.group.wrapsFor[fanned.opens]; len(staged) != 1 {
		t.Fatalf("CONTROL FAILED: bob staged %d candidate(s), want 1", len(staged))
	}
	freshRefused := fresh.deliver(freshBob, fanned.commit)
	if !errors.Is(freshRefused, ErrRemovalWithoutRotation) {
		t.Fatalf("bob's walk over a digest-less removal with a FRESH fan-out answered %v, want "+
			"ErrRemovalWithoutRotation", freshRefused)
	}
	if freshBob.handle.Epoch() != 1 || freshBob.group.epoch != 1 || freshBob.group.wrapDark != nil {
		t.Fatalf("bob's handle is at epoch %d, its group at %d, dark %v; the digest clause is what "+
			"keeps this refusal BEFORE ApplyCommit, and without it the commit is applied and refused "+
			"at the resolution instead",
			freshBob.handle.Epoch(), freshBob.group.epoch, freshBob.group.wrapDark)
	}

	// ── THE CONTROL: THE SAME COMMIT SHAPE, REMOVING NOBODY, IS FOLLOWED ────────────────────
	plain := newRotWorld(t, "alice", "bob", "carol")
	plainAlice, plainBob := plain.member("alice"), plain.member("bob")
	ordinary := plain.fanOutOnTheHeldSecret(plainAlice, nil, func() ([]byte, []byte, []byte, error) {
		return plainAlice.handle.Commit(nil)
	}, unrotatedFanOut{noDigest: true})
	if err := plain.deliver(plainBob, ordinary.page()...); err != nil {
		t.Fatalf("CONTROL FAILED: a digest-less commit that removes NOBODY was refused with %v. "+
			"That is the compatibility path and every group on the deployed alpha is on it", err)
	}
	if plainBob.group.epoch != ordinary.opens {
		t.Fatalf("CONTROL FAILED: bob stands at epoch %d after an ordinary digest-less commit, want %d",
			plainBob.group.epoch, ordinary.opens)
	}
}

// AND THE COMPATIBILITY ARM: a removal whose DIGEST names the secret this group already holds.
//
// IT IS DRIVEN DIRECTLY, AND THE REASON IS A MEASUREMENT RATHER THAN A CONVENIENCE. Mutation row
// M5 -- the digest arm's guard deleted -- was killed by the structural gate below and by NOTHING
// ELSE, because the (3a) refusal fences every unfanned removal before ApplyCommit and no page can
// carry one this far. A property whose only gate is structural is one refactor away from being
// unmeasured, so this drives the arm with the value production would hand it.
//
// THE COMMITTER IS THE ONE MEMBER THAT CAN ASK. Judging a candidate needs mls_secret at the epoch
// the commit opens, and only a device that has merged holds it; alice has. The digest is read back
// off the commit RECORD rather than rebuilt here, so what this asks the resolution is the same
// question a receiver asks.
//
// BOTH DIRECTIONS: with no removal the arm answers the held secret -- which is every group on the
// deployed alpha and must keep working -- and with one it refuses.
func TestTheCompatibilityArmOfTheResolutionIsClosedToARemoval(t *testing.T) {
	world := newRotWorld(t, "alice", "bob", "carol")
	alice, carol := world.member("alice"), world.member("carol")
	held := append([]byte(nil), alice.group.pqSecretLocked()...)

	published := world.advanceWithoutRotating(alice, func() ([]byte, []byte, []byte, error) {
		return alice.handle.CommitRemove([]uint32{carol.leaf})
	})
	digest, err := epochDigestOf(&published.commit.record.Header)
	if err != nil {
		t.Fatalf("the digest on the removal commit: %v", err)
	}
	if digest == nil {
		t.Fatalf("the removal commit carries no epoch digest, so this case is driving the OTHER arm")
	}
	mlsSecret, err := alice.handle.Export(storageExporterLabel, nil, storageExporterBytes)
	if err != nil {
		t.Fatalf("the epoch-%d exporter: %v", published.opens, err)
	}

	// THE CONTROL, FIRST: with no removal this digest is reproduced by the held secret and the
	// arm answers it. Without this clause the refusal below would also be satisfied by a digest
	// no candidate matches at all, which is a different arm and a different sentinel.
	answered, err := alice.group.resolvePqSecretLocked(mlsSecret, published.opens, digest, nil)
	if err != nil {
		t.Fatalf("CONTROL FAILED: the compatibility arm refused a non-removing commit with %v, so "+
			"this digest is not one the held secret reproduces and the clause below is vacuous", err)
	}
	if !bytes.Equal(answered, held) {
		t.Fatalf("CONTROL FAILED: the compatibility arm answered a secret that is not the held one")
	}

	// THE PROPERTY.
	secret, err := alice.group.resolvePqSecretLocked(mlsSecret, published.opens, digest, []uint32{carol.leaf})
	if err == nil {
		t.Fatalf("a commit removing leaf %d was followed on the held secret, which is the value "+
			"the removed member also holds (%d octets of it)", carol.leaf, len(secret))
	}
	if !errors.Is(err, ErrRemovalWithoutRotation) {
		t.Fatalf("the refusal is %v, want ErrRemovalWithoutRotation", err)
	}
}

// ── 4. THE STRUCTURAL HALF: EVERY RETURN THAT CAN CARRY A pq_secret LEAVES BY THE ONE EXIT ───

// EVERY RETURN OF THE RESOLUTION THAT CAN CARRY A pq_secret GOES THROUGH THE GUARDED EXIT, AND
// EVERY OTHER RETURN CARRIES NOTHING.
//
// ── WHY THIS GATE WAS REWRITTEN, WHICH IS THE WHOLE POINT OF IT ───────────────────────────────
//
// The gate that stood here walked "every return of the identifier `held`". It found two, both
// guarded, logged
//
//	the resolution returns the held secret at 2 site(s), 2 guarded;
//	the complement is [candidate.secret nil nil ...]
//
// and PASSED -- with `candidate.secret`, the unguarded arm through which a removal was followed on
// the secret the removed member keeps, sitting in its own printed complement. Two failures, and
// both are classes this project has been bitten by before:
//
//  1. THE NARROWING WAS PRINTED AND NOT ASSERTED. The complement went to t.Logf and nothing
//     decided anything about it. A narrowing that only prints is a narrowing nobody can fail.
//  2. THE CLASS WAS THE DEFECT'S CURRENT SPELLING. "Returns the identifier `held`" is not the
//     property; the property is "returns a pq_secret". The wrap-candidate arm returns one under a
//     different name, so it was outside the subject by construction -- a gate whose complement
//     contains the defect is a gate scoped to how the defect happens to be spelled today.
//
// ── WHAT IT ASKS NOW ──────────────────────────────────────────────────────────────────────────
//
// The subject is EVERY return statement in the function, including the exit's own, keyed by the
// source text of whatever sits in the secret position. Each key is held against a written
// disposition BOTH WAYS -- a site with no entry is a refusal, an entry naming no site is a refusal
// -- and the dispositions say, for each, whether that return can carry a pq_secret.
//
// THE ASSERTION IS THE COMPLEMENT ITSELF, and it is one sentence: a return of this function either
// puts `nil` in the secret position, or it is the one guarded exit or a call to it. So a new arm
// spelled `return candidate.secret, nil`, `return self.pqSecrets[e], nil`, `return staged[0], nil`
// or anything else lands as a key with no disposition and the gate goes red BY CLASS -- not
// because a case was added for one site.
//
// AND THE EXIT IS ASSERTED TO BE GUARDED, structurally: there is exactly one local function value
// in the resolution, it is the one every secret leaves by, and its body refuses a removal with
// [refuseRemovalOnHeldSecret] before it answers anything.
func TestEveryReturnOfTheResolutionThatCanCarryAPqSecretGoesThroughTheGuardedExit(t *testing.T) {
	// THE DISPOSITIONS, keyed by the SOURCE TEXT of the expression in the secret position. `why`
	// is a sentence and not a label because a disposition nobody can disagree with is a row that
	// stops being read.
	const exit = "answerSecret"
	dispositions := map[string]struct {
		carries bool
		why     string
	}{
		"nil": {carries: false,
			why: "a refusal. Every failure this function returns puts nil in the secret " +
				"position, which is what makes 'the complement is exactly nil' the whole assertion"},
		exit + "(...)": {carries: true,
			why: "an arm answering through the one exit. Whatever it hands over is compared " +
				"against this group's WHOLE pq_secret table before it leaves"},
		"secret": {carries: true,
			why: "the exit's own answer, which is the single place a pq_secret leaves this " +
				"function at all, and the removal rule is the statement above it"},
	}

	body := parseFunc(t, "pqepoch.go", "resolvePqSecretLocked")

	// THE EXIT, FOUND BY SHAPE AND REQUIRED TO BE UNIQUE. Two local function values would be two
	// places a secret could leave by and this gate would be measuring one of them.
	exits := []*ast.FuncLit{}
	for _, statement := range body.List {
		assign, isAssign := statement.(*ast.AssignStmt)
		if !isAssign {
			continue
		}
		for at, value := range assign.Rhs {
			literal, isLiteral := value.(*ast.FuncLit)
			if !isLiteral {
				continue
			}
			if name, ok := assign.Lhs[at].(*ast.Ident); !ok || name.Name != exit {
				t.Fatalf("the resolution holds a local function value named %q; this gate is "+
					"written against exactly one, named %q, and a second one is a second way out "+
					"with a secret in hand", exprText(assign.Lhs[at]), exit)
			}
			exits = append(exits, literal)
		}
	}
	if len(exits) != 1 {
		t.Fatalf("the resolution holds %d local function value(s) and this gate needs exactly one, "+
			"the guarded exit %q. If the exit was inlined back into the arms, every arm needs the "+
			"rule again and this gate has to be rewritten to find it there", len(exits), exit)
	}
	if !blockGuardsRemoval(exits[0].Body) {
		t.Fatalf("%q does not refuse a removal with refuseRemovalOnHeldSecret before it answers. "+
			"Every secret this function returns leaves by it, so an unguarded exit is every arm "+
			"unguarded at once", exit)
	}

	// THE WALK: every return in the function, the exit's own included.
	sites := map[string]int{}
	inExit := map[string]int{}
	within := false
	var visit func(node ast.Node)
	visit = func(node ast.Node) {
		ast.Inspect(node, func(child ast.Node) bool {
			if child == nil {
				return true
			}
			if literal, isLiteral := child.(*ast.FuncLit); isLiteral && child != node {
				was := within
				within = literal == exits[0]
				visit(literal.Body)
				within = was
				return false
			}
			ret, isReturn := child.(*ast.ReturnStmt)
			if !isReturn || len(ret.Results) == 0 {
				return true
			}
			key := exprText(ret.Results[0])
			sites[key] += 1
			if within {
				inExit[key] += 1
			}
			return true
		})
	}
	visit(body)

	keys := []string{}
	for key := range sites {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	carrying, complement := []string{}, []string{}
	for _, key := range keys {
		entry, dispositioned := dispositions[key]
		if dispositioned && entry.carries {
			carrying = append(carrying, fmt.Sprintf("%s x%d", key, sites[key]))
			continue
		}
		complement = append(complement, fmt.Sprintf("%s x%d", key, sites[key]))
	}
	t.Logf("the resolution returns a pq_secret at %v; THE COMPLEMENT IS %v, and the assertion "+
		"below is that the complement is exactly the refusals", carrying, complement)

	// ── BOTH WAYS ───────────────────────────────────────────────────────────────────────────
	for _, key := range keys {
		entry, dispositioned := dispositions[key]
		if !dispositioned {
			t.Fatalf("the resolution returns %q in the secret position at %d site(s) and this gate "+
				"has no disposition for it. If it can carry a pq_secret it must leave through %q, "+
				"which compares it against this group's whole table before a removal is followed on "+
				"it; if it cannot, say so here. This is the exact reading under which "+
				"`candidate.secret` sat in this gate's printed complement while a removal removed "+
				"nothing", key, sites[key], exit)
		}
		if !entry.carries {
			// THE COMPLEMENT, ASSERTED. Anything that is not the one exit has to be a refusal, and
			// a refusal puts nil in the secret position. There is no third reading.
			if key != "nil" {
				t.Fatalf("%q is dispositioned as carrying no pq_secret (%s) and it is not `nil`; "+
					"the complement of the exit is supposed to be the refusals and nothing else",
					key, entry.why)
			}
			continue
		}
		// A CARRYING SITE IS THE EXIT OR A CALL TO IT, and which one is decided by where it is
		// rather than by the disposition's say-so.
		if key == exit+"(...)" {
			if inExit[key] != 0 {
				t.Fatalf("%q calls itself, which is not a shape this gate can reason about", exit)
			}
			continue
		}
		if inExit[key] != sites[key] {
			t.Fatalf("%q is dispositioned as the exit's own answer (%s) and %d of its %d site(s) "+
				"are OUTSIDE %q, so a secret leaves this function without the removal rule",
				key, entry.why, sites[key]-inExit[key], sites[key], exit)
		}
	}
	for key, entry := range dispositions {
		if sites[key] == 0 {
			t.Fatalf("this gate disposes of %q (%s) and the resolution has no such return. A gate "+
				"that keeps rows for arms nobody has is a gate that has stopped measuring", key, entry.why)
		}
	}

	// ── AND THE FLOOR, so an empty or mis-aimed walk cannot pass ────────────────────────────
	if sites[exit+"(...)"] < 3 {
		t.Fatalf("only %d arm(s) answer through %q. There are three that can carry a pq_secret -- "+
			"the no-digest arm, the wrap-candidate arm and the compatibility arm -- and a walk that "+
			"finds fewer is not reading this function", sites[exit+"(...)"], exit)
	}
	if sites["nil"] < 5 {
		t.Fatalf("the walk found %d refusal(s) in the resolution, which is fewer than this function "+
			"has; it is not walking the whole body", sites["nil"])
	}
}

// blockGuardsRemoval is whether a block refuses a removal before it answers a secret: an
// `if removesLeaves { ... refuseRemovalOnHeldSecret(...) ... }`.
//
// IT LOOKS FOR THE CALL AND NOT ONLY FOR THE IDENTIFIER `removesLeaves`, because the condition is
// the cheap half to fake and the refusal is the load-bearing one -- a block whose guard returned
// nil, or returned some other error, would satisfy a check that only read the `if`.
func blockGuardsRemoval(block *ast.BlockStmt) bool {
	found := false
	for _, statement := range block.List {
		conditional, isIf := statement.(*ast.IfStmt)
		if !isIf {
			continue
		}
		if name, ok := conditional.Cond.(*ast.Ident); !ok || name.Name != "removesLeaves" {
			continue
		}
		ast.Inspect(conditional.Body, func(node ast.Node) bool {
			call, isCall := node.(*ast.CallExpr)
			if !isCall {
				return true
			}
			if name, ok := call.Fun.(*ast.Ident); ok && name.Name == "refuseRemovalOnHeldSecret" {
				found = true
			}
			return true
		})
	}
	return found
}

// ── 5. THE CENSUS: EVERY DIAGNOSIS THE RESOLUTION CAN RETURN IS PERSISTED AS A DARK KIND ─────

// EVERY ERROR THE RESOLUTION CAN RETURN IS DISPOSITIONED, AND EACH ONE SAYS WHETHER IT MAKES THE
// GROUP DARK OR HALTS IT.
//
// [Group.ingestCommitLocked] used to make a group dark on ANY error the resolution returned, and
// this census used to assert exactly that. RULING 41 SPLIT IT IN TWO and the split is the point:
//
//   - A VALID COMMIT whose wrap did not arrive or did not open -> DARK at n+1, diagnosable, with
//     the sentinel that says which of the three states it is. `sticky` is true, the kind reaches
//     [GroupRecord.WrapDarkKind], and a restart comes back dark by name.
//   - AN INVALID COMMIT -- an unrotated removal -- -> REFUSED. The group stays at the epoch it is
//     at and does NOT go dark, because advancing into a permanent brick on a commit just judged
//     invalid is how any client on an older build bricks every up-to-date member by removing
//     somebody. `sticky` is false.
//
// A kind octet with a silent default would persist a genuinely dark group as HEALTHY -- the exact
// failure the durable diagnosis exists to close, arriving through its own default arm -- so the
// kind is still asserted for EVERY entry, sticky or not: the halting one keeps its kind so that a
// later build which does persist it cannot persist it as healthy.
//
// IT FAILS BOTH WAYS: a return with no entry aborts, an entry naming no site aborts. And the
// `sticky` column is not taken on trust -- [Group.ingestCommitLocked]'s exemption is read off the
// syntax tree and asserted to name exactly the non-sticky sentinels, with the behaviour itself
// driven by TestTheResidualUnrotatedRemovalIsRefusedAfterTheApplyAndStillDoesNotGoDark (halts,
// does not go dark) and TestADarkGroupComesBackDarkAndAHealthyOneDoesNot (goes dark, persists).
func TestEveryDiagnosisTheResolutionCanReturnIsPersistedAsADarkKind(t *testing.T) {
	// THE DISPOSITIONS. `build` is an error of that shape, built here, so the mapping is
	// asserted against the PRODUCTION function rather than re-derived.
	dispositions := map[string]struct {
		kind     uint8
		sticky   bool
		sentinel string
		why      string
		build    func() error
	}{
		"ErrNoWrapForEpoch": {kind: wrapDarkNoWrap, sticky: true,
			why:   "item 132's omission at the victim; the whole reason the wrap sentinels are three",
			build: func() error { return fmt.Errorf("%w: epoch 2", ErrNoWrapForEpoch) }},
		"ErrWrapUnreadable": {kind: wrapDarkUnreadable, sticky: true,
			why:   "a wrap at this device's own handle that did not open",
			build: func() error { return fmt.Errorf("%w: epoch 2", ErrWrapUnreadable) }},
		"ErrOrphanWrap": {kind: wrapDarkOrphan, sticky: true,
			why:   "the loser of a CAS race, and as permanent as the other two",
			build: func() error { return fmt.Errorf("%w: epoch 2", ErrOrphanWrap) }},
		"ErrCommitIngest": {kind: wrapDarkUnfollowable, sticky: true,
			why: "the digest-epoch mismatch arm: a record no server served. The epoch has already " +
				"been applied when it is reached, so the group IS dark and must not persist as healthy",
			build: func() error { return fmt.Errorf("%w: a digest for another epoch", ErrCommitIngest) }},
		"refuseRemovalOnHeldSecret": {kind: wrapDarkRemoval, sticky: false,
			sentinel: "ErrRemovalWithoutRotation",
			why: "RULING 41: an unrotated removal is an INVALID commit, so the group is HALTED " +
				"and not dark. It keeps a kind anyway, because a kind that maps to 'not dark' is " +
				"how a dark group comes back reading as healthy and this sentinel must never be " +
				"the one that does it",
			build: func() error { return refuseRemovalOnHeldSecret(2, []uint32{3}, 1, "did not rotate") }},
		"a foreign error": {kind: wrapDarkUnfollowable, sticky: true,
			why: "the `return nil, err` passthroughs: matchesEpochDigestLocked's own refusal and " +
				"whatever epochDigestGroupId or message.EpochKeysDigest answer. They are not this " +
				"package's sentinels and there is no kind for them by name",
			build: func() error { return errors.New("something connect said") }},
	}
	body := parseFunc(t, "pqepoch.go", "resolvePqSecretLocked")
	sites := map[string][]string{}
	ast.Inspect(body, func(node ast.Node) bool {
		ret, isReturn := node.(*ast.ReturnStmt)
		if !isReturn || len(ret.Results) != 2 {
			return true
		}
		switch failure := ret.Results[1].(type) {
		case *ast.Ident:
			if failure.Name == "nil" {
				return true
			}
			sites["a foreign error"] = append(sites["a foreign error"], exprText(ret.Results[1]))
		case *ast.CallExpr:
			sites[returnedErrorName(failure)] = append(sites[returnedErrorName(failure)], exprText(ret.Results[1]))
		default:
			sites[exprText(ret.Results[1])] = append(sites[exprText(ret.Results[1])], exprText(ret.Results[1]))
		}
		return true
	})
	names := []string{}
	for name := range sites {
		names = append(names, name)
	}
	sort.Strings(names)
	t.Logf("the resolution can return %d distinct failure(s): %v", len(names), names)
	for _, name := range names {
		entry, dispositioned := dispositions[name]
		if !dispositioned {
			t.Fatalf("the resolution can return %q (%d site(s): %v) and this census has no entry "+
				"for it. Give it a wrap_dark kind and a reason, or it is persisted as whatever "+
				"wrapDarkKindOf's default says and a dark group comes back reading as healthy",
				name, len(sites[name]), sites[name])
		}
		sample := entry.build()
		if got := wrapDarkKindOf(sample); got != entry.kind {
			t.Fatalf("%q is dispositioned as kind %d (%s) and wrapDarkKindOf answers %d",
				name, entry.kind, entry.why, got)
		}
		if entry.kind == wrapDarkNone {
			t.Fatalf("%q is dispositioned as kind zero, which is what a record that has NEVER been "+
				"dark carries. A refusal mapping to it is a dark group persisting as healthy", name)
		}
		if wrapDarkErrorOf(entry.kind, 7) == nil {
			t.Fatalf("kind %d (%q) rebuilds no diagnosis at a restart", entry.kind, name)
		}
		if !entry.sticky && entry.sentinel == "" {
			t.Fatalf("%q is dispositioned as NOT sticky (%s) and names no sentinel; the exemption "+
				"in ingestCommitLocked is by sentinel, so a row without one cannot be checked "+
				"against it", name, entry.why)
		}
	}
	// ── THE `sticky` COLUMN, READ OFF THE PRODUCTION FUNCTION AND NOT TAKEN ON TRUST ────────
	//
	// [Group.ingestCommitLocked] exempts the halting refusals from the dark state with an
	// errors.Is over `resolveErr`. The set of sentinels it names must be exactly the set this
	// census dispositions as non-sticky: a sentinel exempted here and sticky there would persist
	// a halted group as dark, and one sticky here and exempted there would advance into a brick
	// on a commit this build judged invalid, which is the outcome ruling 41 removed.
	exempted := map[string]bool{}
	ast.Inspect(parseFunc(t, "group.go", "ingestCommitLocked"), func(node ast.Node) bool {
		call, isCall := node.(*ast.CallExpr)
		if !isCall || exprText(call.Fun) != "errors.Is" || len(call.Args) != 2 {
			return true
		}
		if exprText(call.Args[0]) != "resolveErr" {
			return true
		}
		exempted[exprText(call.Args[1])] = true
		return true
	})
	halting := map[string]bool{}
	for name, entry := range dispositions {
		if !entry.sticky {
			halting[entry.sentinel] = true
			t.Logf("HALTING, not dark: %q -> %s (%s)", name, entry.sentinel, entry.why)
		}
	}
	if len(exempted) == 0 {
		t.Fatalf("ingestCommitLocked exempts NO sentinel from the dark state, so every refusal the " +
			"resolution returns advances the group into a permanent brick -- including the unrotated " +
			"removal, which ruling 41 says is an invalid commit and must be refused instead")
	}
	for sentinel := range exempted {
		if !halting[sentinel] {
			t.Fatalf("ingestCommitLocked exempts %s from the dark state and this census dispositions "+
				"it as sticky. One of the two is wrong, and the failure mode of getting it wrong "+
				"this way round is a genuinely dark group that persists as healthy", sentinel)
		}
	}
	for sentinel := range halting {
		if !exempted[sentinel] {
			t.Fatalf("this census dispositions %s as HALTING and ingestCommitLocked does not exempt "+
				"it, so a group takes it and goes dark at n+1 -- which is ruling 41's own defect: "+
				"advancing into a permanent brick on a commit just judged invalid", sentinel)
		}
	}
	// THE OTHER DIRECTION: an entry that names no site is a disposition for a refusal that has
	// been removed, and it is exactly as much of a defect as a site with no entry -- it is the
	// state in which this census keeps passing while measuring less than it says.
	for name := range dispositions {
		if len(sites[name]) == 0 {
			t.Fatalf("this census disposes of %q and the resolution cannot return it; a census "+
				"that keeps rows for refusals nobody makes is a census that has stopped measuring", name)
		}
	}
	// AND THE FLOOR: nil is the ONLY thing that maps to "not dark".
	if wrapDarkKindOf(nil) != wrapDarkNone {
		t.Fatalf("a nil diagnosis maps to kind %d", wrapDarkKindOf(nil))
	}
}

// ── 6. THE PROSE GATE ────────────────────────────────────────────────────────────────────────

// NO PRODUCTION DOC COMMENT IN EITHER PACKAGE MAY CLAIM THAT A DARK OR ORPHANED GROUP REPAIRS
// ITSELF.
//
// THREE FILES CARRIED THE CLAIM AND THEY WERE IN TWO PACKAGES: urmessage/pqepoch.go,
// urmessage/errors.go and cgo/exports_message.go. A gate that read one file by name -- which is a
// shape this project has already been bitten by twice -- would have covered at most one of them.
// So the subject here is EVERY production .go file under the module, and the file list is printed
// with its own controls: the count, and three files that are known to talk about the dark state
// and are known not to claim it heals.
//
// IT MATCHES ON THE CLAIM AND NOT ON THE WORD, AND THE SUBJECT IS A COMMENT BLOCK AND NOT A LINE.
// Two things the first draft of this gate got wrong, both caught by running it:
//
//   - A bare substring search hit `on the prefix itself` in message_stream_store.go. The claims
//     are matched on WORD BOUNDARIES now, and that line is the standing negative control for it.
//   - A sentence that REFUTES the claim has to state the claim, and the refutation is usually a
//     line or two away from it -- "resolves itself at the next commit". The first half is true and
//     the second is FALSE -- so a line-scoped gate refuses exactly the paragraphs that exist to
//     refuse the defect. The subject is the contiguous run of `//` lines, and a block that says
//     the claim must also say IN THE SAME BLOCK that it is false.
//
// BOTH DIRECTIONS ARE CONTROLLED, inline, on synthetic blocks: a block carrying only the claim
// must fire, and the same block with a refutation must not. Without the first the gate could be
// matching nothing; without the second it would be refusing its own documentation.
func TestNoProductionCommentClaimsADarkGroupRepairsItself(t *testing.T) {
	claims := []string{
		"repairs itself", "repair itself", "resolves itself", "resolve itself",
		"heals itself", "heal itself", "fixes itself", "fix itself",
		"self-healing", "self healing", "recovers by itself", "sorts itself out",
	}
	// A BLOCK MAY STATE THE CLAIM IN ORDER TO DENY IT, and these are the denials. They are exact
	// phrases rather than a search for "not", because the difference between the claim and its
	// refusal is three characters and a loose rule here would readmit the defect.
	denials := []string{
		"is false", "was false", "were false", "are false", "false rather than",
		"does not repair", "does not resolve", "does not heal", "cannot repair",
		"used to say", "this comment used to", "the deleted sentence", "used to be one sentence",
	}
	claimed := func(block string) string {
		lowered := strings.ToLower(block)
		for _, claim := range claims {
			at := strings.Index(lowered, claim)
			for 0 <= at {
				before := byte(' ')
				if 0 < at {
					before = lowered[at-1]
				}
				if !isWordOctet(before) {
					return claim
				}
				next := strings.Index(lowered[at+1:], claim)
				if next < 0 {
					break
				}
				at = at + 1 + next
			}
		}
		return ""
	}
	denied := func(block string) bool {
		lowered := strings.ToLower(block)
		for _, denial := range denials {
			if strings.Contains(lowered, denial) {
				return true
			}
		}
		return false
	}

	// ── THE CONTROLS, FIRST, ON SYNTHETIC BLOCKS ────────────────────────────────────────────
	plant := "// the orphan is nobody's fault and resolves itself at the next commit"
	if claimed(plant) == "" {
		t.Fatalf("CONTROL FAILED: the matcher does not fire on the sentence this gate refuses: %q", plant)
	}
	if denied(plant) {
		t.Fatalf("CONTROL FAILED: the bare claim reads as a refutation")
	}
	refuted := plant + "\n// -- and that is FALSE, because its fetches are refused."
	if claimed(refuted) == "" || !denied(refuted) {
		t.Fatalf("CONTROL FAILED: a block that states the claim in order to refute it is not " +
			"recognised as refuting it, so this gate would refuse its own documentation")
	}
	if claimed("// shapes and on the prefix itself.") != "" {
		t.Fatalf("CONTROL FAILED: the matcher fires on \"prefix itself\", which is the word-boundary " +
			"defect this gate was repaired for")
	}

	root := moduleRoot(t)
	scanned, hits := 0, []string{}
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if name := info.Name(); name == ".git" || name == "testdata" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		source, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		scanned += 1
		rel, _ := filepath.Rel(root, path)
		lines := strings.Split(string(source), "\n")
		for at := 0; at < len(lines); at += 1 {
			if !strings.HasPrefix(strings.TrimSpace(lines[at]), "//") {
				continue
			}
			from := at
			block := []string{}
			for at < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[at]), "//") {
				block = append(block, strings.TrimSpace(lines[at]))
				at += 1
			}
			joined := strings.Join(block, " ")
			claim := claimed(joined)
			if claim == "" || denied(joined) {
				continue
			}
			hits = append(hits, fmt.Sprintf("%s:%d: the block says %q and nothing in it says otherwise",
				filepath.ToSlash(rel), from+1, claim))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}
	// THE WALK'S OWN CONTROLS. A walk that found nothing because it scanned nothing is the
	// failure mode of every absence, so the file count is held against a floor and the three
	// files that DID carry the claim are asserted to be inside this subject.
	if scanned < 20 {
		t.Fatalf("CONTROL FAILED: this gate scanned %d production file(s) under %s, which is not "+
			"this module; an empty result would mean the walk is wrong and not that the prose is clean",
			scanned, root)
	}
	for _, mustScan := range []string{"urmessage/pqepoch.go", "urmessage/errors.go", "cgo/exports_message.go"} {
		if _, statErr := os.Stat(filepath.Join(root, mustScan)); statErr != nil {
			t.Fatalf("CONTROL FAILED: %s is not under %s, so the three files that carried the "+
				"claim are not in this gate's subject", mustScan, root)
		}
	}
	t.Logf("CONTROLS HELD: %d production files scanned; the matcher fires on the deleted sentence, "+
		"does not fire on \"prefix itself\", and a refutation of the claim is not a claim", scanned)
	if 0 < len(hits) {
		t.Fatalf("a production comment claims a dark or orphaned group repairs itself. It does "+
			"not: the group has followed a commit into an epoch it holds no pq_secret for, its "+
			"fetches are refused before a row is read, and there is nowhere to put a later wrap.\n%s",
			strings.Join(hits, "\n"))
	}
}

// isWordOctet is whether an octet can be part of a word, for the boundary the claim match needs.
func isWordOctet(octet byte) bool {
	return ('a' <= octet && octet <= 'z') || ('A' <= octet && octet <= 'Z') ||
		('0' <= octet && octet <= '9') || octet == '_'
}

// ── the small shared machinery ───────────────────────────────────────────────────────────────

// parseFunc is one production function's body, off the syntax tree.
func parseFunc(t *testing.T, file string, name string) *ast.BlockStmt {
	t.Helper()
	fileSet := token.NewFileSet()
	parsed, err := parser.ParseFile(fileSet, file, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("parsing %s: %v", file, err)
	}
	for _, declaration := range parsed.Decls {
		function, isFunc := declaration.(*ast.FuncDecl)
		if !isFunc || function.Name.Name != name || function.Body == nil {
			continue
		}
		return function.Body
	}
	t.Fatalf("%s holds no function named %s", file, name)
	return nil
}

// returnedErrorName is what a returned call expression should be dispositioned under: the sentinel
// a fmt.Errorf wraps, or the name of the helper that built the error.
func returnedErrorName(call *ast.CallExpr) string {
	if name, ok := call.Fun.(*ast.Ident); ok {
		return name.Name
	}
	selector, isSelector := call.Fun.(*ast.SelectorExpr)
	if !isSelector || selector.Sel.Name != "Errorf" {
		return exprText(call.Fun)
	}
	for _, argument := range call.Args[1:] {
		if name, ok := argument.(*ast.Ident); ok && strings.HasPrefix(name.Name, "Err") {
			return name.Name
		}
	}
	return "a fmt.Errorf wrapping no sentinel"
}

// exprText is one expression as source, for a log line and for a disposition key.
func exprText(node ast.Expr) string {
	switch typed := node.(type) {
	case *ast.Ident:
		return typed.Name
	case *ast.SelectorExpr:
		return exprText(typed.X) + "." + typed.Sel.Name
	case *ast.CallExpr:
		return exprText(typed.Fun) + "(...)"
	case *ast.IndexExpr:
		return exprText(typed.X) + "[...]"
	case *ast.SliceExpr:
		return exprText(typed.X) + "[:]"
	default:
		return fmt.Sprintf("%T", node)
	}
}

// moduleRoot is the directory holding this module's go.mod, found by walking up from the package.
func moduleRoot(t *testing.T) string {
	t.Helper()
	at, err := os.Getwd()
	if err != nil {
		t.Fatalf("the working directory: %v", err)
	}
	for depth := 0; depth < 8; depth += 1 {
		if _, statErr := os.Stat(filepath.Join(at, "go.mod")); statErr == nil {
			return at
		}
		parent := filepath.Dir(at)
		if parent == at {
			break
		}
		at = parent
	}
	t.Fatalf("no go.mod above %s", at)
	return ""
}
