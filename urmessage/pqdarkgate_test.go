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
// AND A REMOVAL MAY NOT BE FOLLOWED ON THE HELD SECRET, which is item 243's own property arriving
// inverted through the one arm the prose calls "the whole of the compatibility path".
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
		t.Fatalf("CONTROL FAILED: this fixture's removal DID rotate, so it is not the shape this "+
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

// AND THE OTHER HELD-SECRET ARM: a removal on a commit carrying NO epoch digest at all.
//
// It is a separate case because it is a separate arm. A kind 0x0001 commit -- Spec B section 5.4's
// acceptance window is dated and open -- never reaches the compatibility comparison; it takes the
// held secret at the top of the resolution and returns. A single guard in front of the function
// would have covered both and would ALSO have refused a removal that rotated, which is the case
// this package exists to serve.
//
// IT IS DRIVEN THROUGH THE RESOLUTION DIRECTLY, because the (3a) refusal above catches every
// unfanned removal before ApplyCommit and no page can therefore reach the no-digest arm through a
// walk. That is the right order for production and it would make this arm untestable through one,
// so the arm is called with the value it would be called with.
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

// ── 4. THE STRUCTURAL HALF: NO THIRD HELD-SECRET ARM MAY BE ADDED WITHOUT THE RULE ───────────

// EVERY RETURN OF THE HELD SECRET OUT OF THE RESOLUTION IS GUARDED BY THE REMOVAL RULE.
//
// The two cases above drive the two arms that exist. This refuses the SHAPE, so a third arm added
// later -- a second compatibility path, a cache, a fast path for a digest that matched last time --
// cannot answer the held secret without the rule, and the failure is a test rather than a removal
// that removes nothing.
//
// THE NARROWING IS ASSERTED AND NOT PRINTED: the set of `held` returns is held against a written
// count and against the presence of a guard in each one's enclosing block, and the complement --
// every OTHER return the function makes -- is listed so that a repair which turns a held return
// into something else has to move a number here.
func TestEveryHeldSecretArmOfTheResolutionIsGuardedByTheRemovalRule(t *testing.T) {
	body := parseFunc(t, "pqepoch.go", "resolvePqSecretLocked")
	heldReturns := 0
	guarded := 0
	others := []string{}
	var walk func(node ast.Node, guards bool)
	walk = func(node ast.Node, guards bool) {
		switch typed := node.(type) {
		case *ast.BlockStmt:
			inner := guards || blockGuardsRemoval(typed)
			for _, statement := range typed.List {
				walk(statement, inner)
			}
			return
		case *ast.ReturnStmt:
			if len(typed.Results) == 2 {
				if name, ok := typed.Results[0].(*ast.Ident); ok && name.Name == "held" {
					heldReturns += 1
					if guards {
						guarded += 1
					} else {
						others = append(others, "UNGUARDED held return")
					}
					return
				}
				others = append(others, exprText(typed.Results[0]))
			}
			return
		}
		ast.Inspect(node, func(child ast.Node) bool {
			if child == nil || child == node {
				return true
			}
			switch child.(type) {
			case *ast.BlockStmt, *ast.ReturnStmt:
				walk(child, guards)
				return false
			}
			return true
		})
	}
	walk(body, false)
	sort.Strings(others)
	t.Logf("the resolution returns the held secret at %d site(s), %d guarded; the complement is %v",
		heldReturns, guarded, others)
	if heldReturns != 2 {
		t.Fatalf("the resolution has %d held-secret return(s) and this gate was written against 2 "+
			"(the no-digest arm and the compatibility arm). A third one is exactly what this gate "+
			"exists to notice: guard it and change this number", heldReturns)
	}
	if guarded != heldReturns {
		t.Fatalf("%d of %d held-secret returns are not inside a block that refuses a removal first; "+
			"a removal followed on the held secret reproduces the removed member's own storage root",
			heldReturns-guarded, heldReturns)
	}
	// THE COMPLEMENT IS NOT EMPTY, which is the tell that the walk found anything at all: the
	// function also returns a wrap candidate and several refusals.
	if len(others) == 0 {
		t.Fatalf("the walk found no returns other than the held ones, which means it is not "+
			"walking this function's body: %d held return(s) found", heldReturns)
	}
}

// blockGuardsRemoval is whether a block refuses a removal before it does anything else with the
// held secret: an `if removesLeaves { return ..., refuseRemovalOnHeldSecret(...) }`.
//
// IT LOOKS FOR THE CALL AND NOT FOR THE IDENTIFIER `removesLeaves`, because the condition is the
// cheap half to fake and the refusal is the load-bearing one -- a block whose guard returned nil,
// or returned some other error, would satisfy a check that only read the `if`.
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

// A GROUP GOES DARK ON *ANY* ERROR THE RESOLUTION RETURNS, NOT ONLY ON THE THREE WRAP SENTINELS.
//
// [Group.ingestCommitLocked]'s `if resolveErr != nil` does not look at which error it is, so a
// kind octet with a silent default would persist a genuinely dark group as HEALTHY -- the exact
// failure the durable diagnosis exists to close, arriving through its own default arm.
//
// SO THIS ENUMERATES WHAT THE FUNCTION CAN RETURN and holds each against a written disposition,
// failing BOTH ways: a return with no entry aborts, an entry naming no site aborts, and every
// dispositioned error is then mapped through the production [wrapDarkKindOf] and asserted to be
// the kind the disposition claims and to be non-zero. A new refusal added to the resolution lands
// here rather than in a record that reads as healthy.
func TestEveryDiagnosisTheResolutionCanReturnIsPersistedAsADarkKind(t *testing.T) {
	// THE DISPOSITIONS. `sample` is an error of that shape, built here, so the mapping is
	// asserted against the PRODUCTION function rather than re-derived.
	dispositions := map[string]struct {
		kind  uint8
		why   string
		build func() error
	}{
		"ErrNoWrapForEpoch": {kind: wrapDarkNoWrap,
			why:   "item 132's omission at the victim; the whole reason the wrap sentinels are three",
			build: func() error { return fmt.Errorf("%w: epoch 2", ErrNoWrapForEpoch) }},
		"ErrWrapUnreadable": {kind: wrapDarkUnreadable,
			why:   "a wrap at this device's own handle that did not open",
			build: func() error { return fmt.Errorf("%w: epoch 2", ErrWrapUnreadable) }},
		"ErrOrphanWrap": {kind: wrapDarkOrphan,
			why:   "the loser of a CAS race, and as permanent as the other two",
			build: func() error { return fmt.Errorf("%w: epoch 2", ErrOrphanWrap) }},
		"ErrCommitIngest": {kind: wrapDarkUnfollowable,
			why: "the digest-epoch mismatch arm: a record no server served. The epoch has already " +
				"been applied when it is reached, so the group IS dark and must not persist as healthy",
			build: func() error { return fmt.Errorf("%w: a digest for another epoch", ErrCommitIngest) }},
		"refuseRemovalOnHeldSecret": {kind: wrapDarkRemoval,
			why:   "a removal followed on the held secret, refused at the resolution rather than at (3a)",
			build: func() error { return refuseRemovalOnHeldSecret(2, []uint32{3}, "did not rotate") }},
		"a foreign error": {kind: wrapDarkUnfollowable,
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
			t.Fatalf("%q is dispositioned as NOT DARK, and every failure this function returns is "+
				"taken by a group that has already applied the commit", name)
		}
		if wrapDarkErrorOf(entry.kind, 7) == nil {
			t.Fatalf("kind %d (%q) rebuilds no diagnosis at a restart", entry.kind, name)
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
