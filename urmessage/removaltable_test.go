// THE REMOVAL RULE IS HELD BY A DRIVEN TABLE OF INPUT SHAPES, AND NOT BY A READING OF THE SOURCE.
//
// ── WHY THIS FILE EXISTS, WHICH IS LEDGER RULING 46 ──────────────────────────────────────────
//
// Six consecutive rounds built or repaired a static gate over [refuseRemovalOnHeldSecret] and
// [Group.refuseUnrotatedRemovalLocked], and every one of them was defeated ONE LEVEL OF
// INDIRECTION FURTHER OUT. The VALUE was named (`held` against `candidate.secret`), then the CALL
// was named and its result was not, then the RESULT was named and the path to it was not, then the
// POSITION was named and the binding was not, then the BINDING was deleted and the held test's
// ARGUMENT took the narrowing, and the caller's list after that. Each round widened what the gate
// READS; each round's defeat was a new spelling outside that reading.
//
// Enforcement is a semantic property. A gate that must prove *this refusal actually fires for
// every input it should* is trying to decide a runtime question out of syntax, and every reading
// it adds is one more surface to route around. What the gate was standing in for is A SET OF
// INPUTS THAT MUST BE REFUSED. So this file drives them.
//
// ── WHAT A ROW IS ────────────────────────────────────────────────────────────────────────────
//
// One input shape, built by the production sealers ([Group.stageEpochRotationLocked],
// [Group.sealEpochWrapLocked], [messagegroup.GroupSession.SealRecord]) and put through the
// production receive path -- [Group.openPageLocked] driving [Group.ingestWrapLocked] and
// [Group.ingestCommitLocked], which is what [Group.Receive] does below the fetch -- and asserted
// to be REFUSED or to be FOLLOWED. The honest rows are not a separate suite: they are rows of this
// table, in this function, because a rule that refuses everything removes the feature rather than
// the member and a table with no followed row cannot tell the two apart.
//
// THE TWO DOORS ARE BOTH DRIVEN AND THEY ARE MARKED AS TWO, because they are reached by different
// records and take the decision at different points:
//
//   - `noDigest` is [Group.refuseUnrotatedRemovalLocked], the kind 0x0001 class: a removal on a
//     commit carrying no epoch digest at all. It is decided BEFORE ApplyCommit, so the receiver's
//     MLS handle does not move, and every row of that door asserts exactly that. An adversary
//     found this door had no gate on its own predicate at any point in the six rounds.
//   - `digest` is [Group.resolvePqSecretLocked]'s one guarded exit: everything that carries a
//     digest, judged against the value that digest NAMES. It runs after ApplyCommit -- judging a
//     candidate needs mls_secret[n+1] -- so the handle HAS moved and every row of that door
//     asserts that too, which is the residual stated rather than glossed.
//
// ── WHAT THE RULE DELIVERS, AND THE THREE SHAPES IT DOES NOT: LEDGER RULINGS 42-45 ───────────
//
// A reader meeting the rule here meets its limits here. This table does not measure a group
// property and the code cannot deliver one. What every refusing row below measures is
//
//	THIS RECEIVER DOES NOT FOLLOW A REMOVAL ONTO A SECRET THIS RECEIVER HAS HELD
//
// and the three shapes outside it are:
//
//  1. A LATE JOINER'S HISTORY IS STRICTLY SMALLER, so it refuses less, and its false negative is a
//     theorem rather than a bug. [Device.Join] files exactly one row. THIS IS NO LONGER PROSE: the
//     row `digest/one-leaf/earlier-epoch/late-joiner` drives it. One page, two receivers -- the
//     founder REFUSES it and the member admitted at epoch 3 FOLLOWS it -- with the control firing
//     for its own reason, because the late joiner does recognise its OWN row.
//  2. IF EVERY SURVIVOR JOINED AFTER EPOCH k AND THE COMMITTER REUSES pq_secret[k], NOBODY
//     REFUSES. Not "the check is weaker": there is no refuser left, because the committer never
//     runs the receive path against its own commit and every other survivor is a late joiner by
//     (1). The group-level effect is a PARTITION BY JOIN EPOCH, which ledger item 242 has already
//     priced as *a hostile committer can HALT a group; it cannot TAKE it*. The row in (1) is the
//     two-receiver half of exactly this; the all-late-joiner world is its limit and no row here
//     drives it, which is said rather than implied.
//  3. AGAINST A HOSTILE ADMIN OR OWNER COMMITTER THIS DELIVERS NOTHING, STRUCTURALLY. Only an
//     ADMIN or the OWNER may commit a removal at all (MASTER section 11), and to build the epoch
//     digest that party must hold read_key[n+1] and write_key[n+1] -- therefore storage_root[n+1]
//     -- inside its own process. It can hand over the ROOT rather than the secret, and no
//     receiver-side check on the VALUE can constrain it. No row here is a defence against it and
//     none could be: the row `digest/one-leaf/committed-by-a-non-owner-admin` drives an ADMIN
//     committer to show the rule is not keyed to WHO commits, which is a different statement.
//
// The full argument, with what holds each clause, is at [refuseRemovalOnHeldSecret].
//
// ── WHAT THIS TABLE CANNOT HOLD, PRINTED RATHER THAN DESCRIBED ───────────────────────────────
//
// A driven table is a finite set of inputs, and the axis every one of the six rounds was bypassed
// on is ARITY -- how many leaves the commit removes. The arity axis is LOGGED per door before
// anything is asserted, as the INTERVAL it drives and as the fact that the interval has a TOP, so
// what is outside it is visible in a line rather than inferred from a count: a bypass keyed on
// `5 <= len(removedLeaves)` is not driven here and would pass.
//
// IT IS AN INTERVAL AND NOT A SET, AND THAT IS THE 2026-09-24 (SEVENTH PASS) CORRECTION. The line
// used to print `{0, 1, 2, 3}`, which reads as a choice of points and leaves the reader to work
// out that the edge is what matters. For any top k this table drives, the narrowing outside it is
// `< k+1` and there is always one, so no number of rows closes the axis -- what a row buys is
// moving the edge, and what the line has to say is where the edge IS. The rows at four leaves
// bought exactly one thing and it was worth buying: the sixth pass's own surviving mutant,
// `len(removedLeaves) < 4`, sat at arity four.
//
// That is the honest residual of this instrument and it is why the predicate readings in
// pqdarkgate_test.go are kept -- for the class no table can cover (an arm that no row drives
// because the arm does not exist yet) and for a narrowing written into the guard's own condition
// above this interval. What NEITHER covers, stated because it is the shape that got through last
// time: a narrowing written into some OTHER statement of the exit, above this interval.
package urmessage

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/urnetwork/connect/messagegroup"
	"github.com/urnetwork/connect/mls"
)

// ── the world's two missing doors ────────────────────────────────────────────────────────────

// admit adds ONE member in its own honest rotation and gives it the single pq_secret row
// [Device.Join] files, so a world can hold a member whose history is strictly smaller than the
// founder's. Before it existed, ledger ruling 43's first residual was measured by a probe and by
// nothing in this package, because [newRotWorld] admits every member in the founding commit.
//
// THE ROTATION IS HONEST AND IS DELIVERED TO `receivers`, so the members named there stand where
// the new one does and the case that follows is about the removal and not about a fork.
func (self *rotWorld) admit(committer *rotMember, name string, receivers ...*rotMember) (*rotMember, *rotation) {
	self.t.Helper()
	dev := self.device(name)
	keyPackage, err := dev.engine.NewKeyPackage()
	if err != nil {
		self.t.Fatalf("%s's key package: %v", name, err)
	}
	var welcome, ratchetTree []byte
	published := self.rotate(committer, nil, func() ([]byte, []byte, []byte, error) {
		commit, admission, tree, err := committer.handle.CommitAdd([][]byte{keyPackage})
		welcome, ratchetTree = admission, tree
		return commit, admission, tree, err
	})
	for _, receiver := range receivers {
		if err := self.deliver(receiver, published.page()...); err != nil {
			self.t.Fatalf("%s's walk over the rotation that admits %s: %v", receiver.name, name, err)
		}
	}
	handle, err := dev.engine.JoinFromWelcome(welcome, ratchetTree)
	if err != nil {
		self.t.Fatalf("%s's JoinFromWelcome: %v", name, err)
	}
	self.t.Cleanup(func() { handle.Close() })
	return self.enrollAt(name, dev, handle, published.pqSecret), published
}

// promote makes one member an ADMIN through a real CommitPolicy, published as an honest rotation
// and delivered to `receivers`. It is what lets a row vary the COMMITTER, which every removal case
// written before this table left as a silent premise: all of them are committed by the founder.
func (self *rotWorld) promote(owner *rotMember, member *rotMember, receivers ...*rotMember) *rotation {
	self.t.Helper()
	extensions, err := owner.group.contextExtensionsLocked()
	if err != nil {
		self.t.Fatalf("%s's group context: %v", owner.name, err)
	}
	policy, err := mls.GroupPolicyOf(mlsExtensionsOf(extensions))
	if err != nil {
		self.t.Fatalf("%s's policy: %v", owner.name, err)
	}
	policy.SetRole(member.dev.identityPub, mls.RoleAdmin)
	if err := policy.Canonicalize(); err != nil {
		self.t.Fatalf("canonicalizing the policy: %v", err)
	}
	encoded, err := policy.Encode()
	if err != nil {
		self.t.Fatalf("encoding the policy: %v", err)
	}
	published := self.rotate(owner, nil, func() ([]byte, []byte, []byte, error) {
		return owner.handle.CommitPolicy(encoded.ExtensionData)
	})
	for _, receiver := range receivers {
		if err := self.deliver(receiver, published.page()...); err != nil {
			self.t.Fatalf("%s's walk over the promotion of %s: %v", receiver.name, member.name, err)
		}
	}
	return published
}

// bundleAddAndRemove stages one Add and one Remove as BY-REFERENCE proposals and hands back the
// commit arm that folds both in, plus the key package the add carries.
//
// IT HAS TO BE BY REFERENCE AND THAT IS A PROPERTY OF THE SEAM, not a preference. The seam's
// by-value arms are one kind each -- [messagegroup.GroupHandle.CommitAdd] and CommitRemove build a
// commit carrying one kind of proposal and nothing by reference -- so a commit that both adds and
// removes cannot be built through either. `Commit(nil)` folds in every proposal the committer has
// cached, which is the one arm that can carry both, and the cost is that every receiver must have
// been handed both proposals first: a reference resolves against the RECEIVER's own cache, and a
// member that never saw the proposal answers `proposal reference is not cached for this epoch`.
// The proposals are handed over through the handle rather than through the record layer because
// this package's page walk carries commits and wraps and no proposal record exists yet; what is
// under test here is the commit, and the caching is MLS plumbing beneath it.
func (self *rotWorld) bundleAddAndRemove(committer *rotMember, removing uint32, joining string,
	receivers ...*rotMember) (func() ([]byte, []byte, []byte, error), *crossProcessDevice) {

	self.t.Helper()
	dev := self.device(joining)
	keyPackage, err := dev.engine.NewKeyPackage()
	if err != nil {
		self.t.Fatalf("%s's key package: %v", joining, err)
	}
	add, err := committer.handle.ProposeAdd(keyPackage)
	if err != nil {
		self.t.Fatalf("%s's ProposeAdd: %v", committer.name, err)
	}
	remove, err := committer.handle.ProposeRemove(removing)
	if err != nil {
		self.t.Fatalf("%s's ProposeRemove(%d): %v", committer.name, removing, err)
	}
	for _, receiver := range receivers {
		for at, proposal := range [][]byte{add, remove} {
			if _, err := receiver.handle.Process(proposal); err != nil {
				self.t.Fatalf("%s caching proposal %d of the bundle: %v. A receiver that has not "+
					"cached both refuses the commit for the cache's reason and this row would be "+
					"measuring that instead", receiver.name, at, err)
			}
		}
	}
	return func() ([]byte, []byte, []byte, error) { return committer.handle.Commit(nil) }, dev
}

// holdsIdentity reports whether a handle's CURRENT tree holds a leaf under `identity`. It is the
// control on a bundled commit: a commit that quietly dropped one of its two proposals would
// otherwise make that row a slow copy of the plain removal.
func (self *rotWorld) holdsIdentity(member *rotMember, identity []byte) bool {
	self.t.Helper()
	for at := 0; at < member.handle.MemberCount(); at += 1 {
		_, leafIdentity, _, err := member.handle.MemberAt(at)
		if err != nil {
			self.t.Fatalf("%s's member %d: %v", member.name, at, err)
		}
		if bytes.Equal(leafIdentity, identity) {
			return true
		}
	}
	return false
}

// reproduces is the counterfactual every refusing row is about, asked of the COMMITTER's own
// exporter at the epoch it has just opened: does `retained` -- the value the removed member keeps
// by construction -- mix to the same storage_root as the value the epoch actually runs on.
func (self *rotWorld) reproduces(committer *rotMember, retained []byte, opensOn []byte) bool {
	self.t.Helper()
	granted, err := committer.handle.Export(storageExporterLabel, nil, storageExporterBytes)
	if err != nil {
		self.t.Fatalf("%s's exporter at epoch %d: %v", committer.name, committer.handle.Epoch(), err)
	}
	return bytes.Equal(messagegroup.StorageRoot(granted, retained),
		messagegroup.StorageRoot(granted, opensOn))
}

// ── the table ────────────────────────────────────────────────────────────────────────────────

// removalDoor names which of the two detectors a row is aimed at. It decides one assertion and
// nothing else: whether the receiver's MLS handle may have moved by the time the refusal is taken.
type removalDoor string

const (
	// noDigestDoor is [Group.refuseUnrotatedRemovalLocked], pre-apply, the kind 0x0001 class.
	noDigestDoor removalDoor = "no digest (pre-apply)"
	// digestDoor is [Group.resolvePqSecretLocked]'s one guarded exit, after ApplyCommit.
	digestDoor removalDoor = "digest (the resolution)"
)

// removalPage is one built input shape, everything the shared assertions need to judge it, and the
// row's OWN controls as two closures. The controls are on the page rather than on the row because
// they are written by the builder and read what the builder measured.
type removalPage struct {
	world     *rotWorld
	committer *rotMember
	receiver  *rotMember
	page      []*sealed
	opens     uint64
	// removes is the leaf list the commit carries. The refusal PRINTS it, and asserting that the
	// printed list is this list whole is what holds every narrowing between connect's
	// `processed.Commit.RemovedLeaves()` and the guard -- `decision.RemovedLeaves[:1]` at either
	// call site, a rewrite of `decision` between the two doors, a `removedLeaves = removedLeaves
	// [:1]` inside the resolution -- without a gate reading any of those spellings.
	removes []uint32
	// opensOn is the pq_secret the epoch this commit opens actually runs on.
	opensOn []byte
	// retained is the value a removed member keeps by construction, or nil when the row removes
	// nobody. Non-nil turns on the counterfactual: it must reproduce the committer's root on a
	// refusing row and must NOT on a followed one, so a fixture that quietly rotated (or quietly
	// did not) is caught before the disposition is read.
	retained []byte
	// also runs before the page is delivered; then runs after the shared assertions.
	also func(t *testing.T)
	then func(t *testing.T)
}

type removalInput struct {
	name     string
	door     removalDoor
	shape    string
	arity    int
	followed bool
	build    func(t *testing.T) *removalPage
}

// EVERY REMOVAL SHAPE THIS PACKAGE CAN PUT ON THE WIRE, DRIVEN THROUGH THE PRODUCTION RECEIVE PATH
// AND ASSERTED TO BE REFUSED OR FOLLOWED.
//
// The header of this file says why the instrument is a table and what it cannot hold. Each row is
// built by the production sealers and delivered by [rotWorld.deliver]; the assertions below are
// shared, so a row is a SHAPE and not a copy of the assertions with one thing changed.
func TestEveryRemovalShapeThisPackageCanPutOnTheWireIsRefusedOrFollowedByTheProductionReceivePath(t *testing.T) {
	rows := []removalInput{
		// ── the digest door: one to FOUR leaves on the secret the victims hold ──────────────
		{name: "digest/one-leaf/current-epoch", door: digestDoor, arity: 1, followed: false,
			shape: "a removal with a complete openable fan-out carrying the secret the group is " +
				"standing on, under a digest that names it",
			build: buildHeldFanOut(1, unrotatedFanOut{})},
		{name: "digest/two-leaves/current-epoch", door: digestDoor, arity: 2, followed: false,
			shape: "the same, removing two leaves: one ADMIN ejecting two devices at once",
			build: buildHeldFanOut(2, unrotatedFanOut{})},
		{name: "digest/three-leaves/current-epoch", door: digestDoor, arity: 3, followed: false,
			shape: "the same, removing THREE leaves. This is the axis three separate mutants " +
				"survived on: `len(removedLeaves) < 3` in the guard's binding left every other " +
				"case in this package green",
			build: buildHeldFanOut(3, unrotatedFanOut{})},
		{name: "digest/three-leaves/fresh-wraps-held-digest", door: digestDoor, arity: 3, followed: false,
			shape: "three leaves, wraps carrying FRESH octets and a digest naming the held value: " +
				"the compatibility arm reached at arity three, which no candidate-reading check " +
				"could ever have refused",
			build: buildFreshFanOutHeldDigest(3)},
		{name: "digest/four-leaves/current-epoch", door: digestDoor, arity: 4, followed: false,
			shape: "the same, removing FOUR leaves. THIS IS THE ARITY THE SIXTH PASS LEFT " +
				"OUTSIDE THE TABLE, and it is here because the static reading that was supposed " +
				"to cover the rest of the axis did not: while the guard was two nested " +
				"conditionals that reading took the OUTER one, and `alreadyHeld && " +
				"len(removedLeaves) < 4` written into the INNER one passed the reading, this " +
				"table and this package (pqepoch.go sha256 553bd9fffa2c). A narrowing a driven " +
				"case can catch belongs in the table as a row",
			build: buildHeldFanOut(4, unrotatedFanOut{})},

		// ── the digest door: what must be FOLLOWED, in the same test ────────────────────────
		{name: "digest/one-leaf/honest-rotated", door: digestDoor, arity: 1, followed: true,
			shape: "THE CONTROL. An honest rotated removal of one leaf. Without it the rule is " +
				"satisfied by a build that refuses every removal, which removes the feature " +
				"rather than the member",
			build: buildHonestRotation(1)},
		{name: "digest/three-leaves/honest-rotated", door: digestDoor, arity: 3, followed: true,
			shape: "THE CONTROL AT THE NEW ARITY. An honest rotated removal of three leaves, so " +
				"the three-leaf rows above are not refusals of arity itself",
			build: buildHonestRotation(3)},
		{name: "digest/four-leaves/honest-rotated", door: digestDoor, arity: 4, followed: true,
			shape: "THE CONTROL AT THE TOP OF THE INTERVAL. An honest rotated removal of four " +
				"leaves, so the four-leaf row above is not a refusal of arity itself -- every " +
				"arity this table drives carries both dispositions or the refusing row at it " +
				"proves nothing",
			build: buildHonestRotation(4)},
		{name: "digest/no-removal/unrotated", door: digestDoor, arity: 0, followed: true,
			shape: "THE COMPLEMENT OF THE GUARD'S PREDICATE. An epoch change on the secret the " +
				"group already holds that removes NOBODY -- every group on the deployed alpha -- " +
				"is followed. A guard that refuses everything goes red here",
			build: buildUnrotatedNoRemoval},
		{name: "digest/one-leaf/one-octet-from-a-held-secret", door: digestDoor, arity: 1, followed: true,
			shape: "A REMOVAL FANNED OUT ON A SECRET THAT DIFFERS FROM A HELD ONE IN A SINGLE " +
				"OCTET. It is FRESH, so it must be FOLLOWED: the rule is on the octets and not " +
				"on a resemblance, and a comparison narrowed to a prefix or to a length goes red",
			build: buildOneOctetFromHeld},

		// ── the digest door: the table, not the current row; and the committer axis ─────────
		{name: "digest/one-leaf/earlier-epoch", door: digestDoor, arity: 1, followed: false,
			shape: "a removal opening epoch 3 on pq_secret[1]: a different octet string, the same " +
				"removed member holding it, and a subject narrowed to the current row answers no",
			build: buildEarlierEpochReplay},
		{name: "digest/one-leaf/earlier-epoch/late-joiner", door: digestDoor, arity: 1, followed: false,
			shape: "the same replay in a world holding a member admitted at epoch 3. The FOUNDER " +
				"refuses it; the late joiner FOLLOWS it, in this row's own `then`, which is " +
				"ledger ruling 43's first residual driven rather than described",
			build: buildLateJoinerResidual},
		{name: "digest/one-leaf/committed-by-a-non-owner-admin", door: digestDoor, arity: 1, followed: false,
			shape: "the removal is committed by a promoted ADMIN and not by the founder, so " +
				"`the committer is the group's owner` stops being a silent premise of every " +
				"removal case in this package",
			build: buildAdminCommitter},

		// ── the digest door: a removal bundled with an add ──────────────────────────────────
		{name: "digest/one-leaf-and-one-add/current-epoch", door: digestDoor, arity: 1, followed: false,
			shape: "ONE COMMIT THAT BOTH ADDS AND REMOVES, on the held secret. The removed-leaf " +
				"list is not the whole of what the commit does, and the rule is keyed to the " +
				"removal inside it",
			build: buildBundledRemoval(false)},
		{name: "digest/one-leaf-and-one-add/honest-rotated", door: digestDoor, arity: 1, followed: true,
			shape: "THE CONTROL for the bundle: the same add-and-remove commit, rotated honestly, " +
				"is followed",
			build: buildBundledRemoval(true)},

		// ── the other door: the 0x0001 class, which had no gate on its own predicate ────────
		{name: "noDigest/one-leaf", door: noDigestDoor, arity: 1, followed: false,
			shape: "a removal on a commit carrying no epoch digest at all -- the shape every " +
				"build before the rotation emits -- refused BEFORE ApplyCommit",
			build: buildNoDigestRemoval(1)},
		{name: "noDigest/two-leaves", door: noDigestDoor, arity: 2, followed: false,
			shape: "the same, two leaves",
			build: buildNoDigestRemoval(2)},
		{name: "noDigest/three-leaves", door: noDigestDoor, arity: 3, followed: false,
			shape: "the same, THREE leaves. This door's predicate was held by neither behaviour " +
				"nor structure at any arity above one",
			build: buildNoDigestRemoval(3)},
		{name: "noDigest/four-leaves", door: noDigestDoor, arity: 4, followed: false,
			shape: "the same, FOUR leaves. The two doors carry the same arity interval on " +
				"purpose: a narrowing written at one arity above the table is a mutant at EITHER " +
				"door, and an interval that stopped a leaf short here would be the door's own " +
				"edge sitting somewhere a reader has to work out",
			build: buildNoDigestRemoval(4)},
		{name: "noDigest/one-leaf-and-one-add", door: noDigestDoor, arity: 1, followed: false,
			shape: "a digest-less commit that both adds and removes, refused before the apply",
			build: buildNoDigestBundle},
		{name: "noDigest/no-removal", door: noDigestDoor, arity: 0, followed: true,
			shape: "THE COMPLEMENT AT THIS DOOR. A digest-less commit that removes NOBODY reaches " +
				"the resolution's no-digest arm and is followed; a door that refused every " +
				"digest-less commit goes red here",
			build: buildNoDigestNoRemoval},
	}

	// ── THE COMPLEMENT, PRINTED BEFORE ANYTHING IS ASSERTED ─────────────────────────────────
	//
	// What this instrument does NOT drive is the thing a reader has to be able to see, because a
	// finite table reads as complete unless its edges are written down. The arities are the axis
	// every one of the six bypassed gates was defeated on.
	drivenArities := map[removalDoor][]int{}
	dispositions := map[string]int{}
	for _, row := range rows {
		if !slices.Contains(drivenArities[row.door], row.arity) {
			drivenArities[row.door] = append(drivenArities[row.door], row.arity)
		}
		key := string(row.door) + "/followed"
		if !row.followed {
			key = string(row.door) + "/refused"
		}
		dispositions[key] += 1
	}
	// THE AXIS IS PRINTED AS AN INTERVAL AND AS THE FACT THAT IT IS BOUNDED, which is the
	// 2026-09-24 (seventh pass) correction. It was printed as the SET {0, 1, 2, 3}, and a set
	// reads as a choice of points while the thing a reader needs is the EDGE: for any constant k
	// this table drives, `< k+1` is the narrowing outside it, so what matters is where the top is
	// and that there IS a top. Both are in the line now, with the first undriven arity named.
	for _, door := range []removalDoor{digestDoor, noDigestDoor} {
		arities := drivenArities[door]
		slices.Sort(arities)
		t.Logf("DOOR %q drives len(removedLeaves) over the INTERVAL [%d, %d], every arity in it "+
			"and NOTHING ABOVE IT: %d followed row(s), %d refused. The axis is BOUNDED, so a "+
			"bypass keyed on %d <= len(removedLeaves) -- `len(removedLeaves) < %d` at either "+
			"door, or on the held answer between its binding and the guard -- passes this table, "+
			"and above this interval the predicate readings in pqdarkgate_test.go cover the "+
			"guard's own condition and nothing else",
			door, arities[0], arities[len(arities)-1],
			dispositions[string(door)+"/followed"], dispositions[string(door)+"/refused"],
			arities[len(arities)-1]+1, arities[len(arities)-1]+1)
	}

	// ── AND THE TABLE'S OWN CONTROLS ────────────────────────────────────────────────────────
	for _, door := range []removalDoor{digestDoor, noDigestDoor} {
		if dispositions[string(door)+"/followed"] == 0 || dispositions[string(door)+"/refused"] == 0 {
			t.Fatalf("CONTROL FAILED: door %q has %d followed row(s) and %d refused one(s). A door "+
				"with no followed row is satisfied by a build that refuses everything, and one "+
				"with no refused row measures nothing at all", door,
				dispositions[string(door)+"/followed"], dispositions[string(door)+"/refused"])
		}
		// THE PRINTED INTERVAL IS AN INTERVAL, which is what makes the line above a complement
		// rather than a summary: a hole in it would make `[0, 4]` false while the two endpoints
		// stayed true, and a deleted middle row is exactly how that happens.
		arities := drivenArities[door]
		for at, arity := range arities {
			if arity != arities[0]+at {
				t.Fatalf("CONTROL FAILED: door %q drives %v, which is not the contiguous interval "+
					"the line above prints -- arity %d is missing. A hole makes that line false "+
					"in the one direction it exists to be true in", door, arities, arities[0]+at)
			}
		}
		if arities[0] != 0 {
			t.Fatalf("CONTROL FAILED: door %q drives %v and does not start at zero, so the "+
				"COMPLEMENT of the rule -- a commit that removes nobody -- is not driven here",
				door, arities)
		}
		if arities[len(arities)-1] < 4 {
			t.Fatalf("CONTROL FAILED: door %q drives %v and stops below FOUR leaves. Three is the "+
				"axis three separate mutants survived on; four is where the sixth pass's own "+
				"narrowing sat -- `len(removedLeaves) < 4` written one line below the condition "+
				"the static reading reads -- and it passed everything while this table stopped "+
				"at three", door, arities)
		}
	}

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			built := row.build(t)
			built.drive(t, row)
		})
	}
}

// drive puts one built page through the production receive path and holds everything a
// disposition means. It is shared by every row, so what a row says is a SHAPE.
func (self *removalPage) drive(t *testing.T, row removalInput) {
	t.Helper()
	world, receiver := self.world, self.receiver
	t.Logf("SHAPE: %s", row.shape)

	// ── THE COUNTERFACTUAL, FIRST, so the disposition below is about something ──────────────
	if self.retained != nil {
		reproduces := world.reproduces(self.committer, self.retained, self.opensOn)
		switch {
		case !row.followed && !reproduces:
			t.Fatalf("CONTROL FAILED: this fixture's removal DID rotate -- the removed member's " +
				"retained pq_secret does not reproduce the committer's storage root at the epoch " +
				"it was removed at -- so it is not the shape this row refuses and the refusal " +
				"below would be about nothing")
		case row.followed && reproduces:
			t.Fatalf("CONTROL FAILED: this fixture's removal did NOT rotate, so the row is " +
				"asserting that an unrotated removal is followed. Either the builder is wrong or " +
				"the rule is gone")
		}
		t.Logf("the counterfactual: the removed member's retained pq_secret %s the committer's "+
			"storage_root at epoch %d", map[bool]string{true: "REPRODUCES", false: "does NOT reproduce"}[reproduces],
			self.opens)
	}
	if self.also != nil {
		self.also(t)
	}

	at := receiver.group.epoch
	handleAt := receiver.handle.Epoch()
	before := append([]byte(nil), receiver.group.pqSecretLocked()...)
	refusedBefore := receiver.group.Stats().CommitRefused

	err := world.deliver(receiver, self.page...)

	if row.followed {
		if err != nil {
			t.Fatalf("%s REFUSED a shape that must be followed: %v", receiver.name, err)
		}
		if receiver.group.epoch != self.opens {
			t.Fatalf("%s stands at epoch %d after following, want %d", receiver.name,
				receiver.group.epoch, self.opens)
		}
		if receiver.group.halted != nil {
			t.Fatalf("%s halted on a shape it followed: %v", receiver.name, receiver.group.halted)
		}
		if receiver.group.wrapDark != nil {
			t.Fatalf("%s went dark on a shape it followed: %v", receiver.name, receiver.group.wrapDark)
		}
		if !bytes.Equal(receiver.group.pqSecretLocked(), self.opensOn) {
			t.Fatalf("%s followed onto a pq_secret that is not the one this epoch runs on, so it "+
				"is in the epoch and cannot read it", receiver.name)
		}
		if self.then != nil {
			self.then(t)
		}
		return
	}

	// ── THE REFUSAL, BY NAME ────────────────────────────────────────────────────────────────
	if err == nil {
		t.Fatalf("%s FOLLOWED this removal. The removed member's retained pq_secret reproduces "+
			"the survivors' storage_root at epoch %d, so the removal removed nothing",
			receiver.name, self.opens)
	}
	if !errors.Is(err, ErrRemovalWithoutRotation) {
		t.Fatalf("%s's walk answered %v, want ErrRemovalWithoutRotation", receiver.name, err)
	}
	// ── AND IT NAMES THE COMMIT'S WHOLE REMOVED-LEAF LIST ───────────────────────────────────
	//
	// This is what holds every narrowing of that list without a gate reading one: a truncation
	// anywhere between connect's `processed.Commit.RemovedLeaves()` and the refusal still REFUSES
	// -- the predicate is `0 < len(...)` -- and is invisible to a disposition, but it cannot print
	// leaves it no longer has.
	self.assertNamesEveryRemovedLeaf(t, err)
	// ── THE GROUP DID NOT FOLLOW IT, WHICH IS RULING 41 ─────────────────────────────────────
	if receiver.group.epoch != at {
		t.Fatalf("%s stands at epoch %d after refusing, want %d: a refused commit is not followed",
			receiver.name, receiver.group.epoch, at)
	}
	if receiver.group.wrapDark != nil {
		t.Fatalf("%s went DARK over a commit it refused: %v. Ruling 41's two outcomes are two "+
			"fields, and an invalid commit is refused the way an unauthorized one is",
			receiver.name, receiver.group.wrapDark)
	}
	if receiver.group.halted == nil {
		t.Fatalf("%s refused the commit and did not halt, so the refusal is answered once and the "+
			"next walk sees a group an epoch behind its own log", receiver.name)
	}
	if !bytes.Equal(receiver.group.pqSecretLocked(), before) {
		t.Fatalf("%s's pq_secret moved although it did not follow the commit", receiver.name)
	}
	if _, isHeld := receiver.group.pqSecretAtLocked(self.opens); isHeld {
		t.Fatalf("%s filed a pq_secret for epoch %d although it refused the commit that opens it",
			receiver.name, self.opens)
	}
	if got := receiver.group.Stats().CommitRefused; got != refusedBefore+1 {
		t.Fatalf("%s counted %d refusal(s) over this page, want %d", receiver.name, got, refusedBefore+1)
	}
	// ── THE HALT IS STICKY AND IS ANSWERED BY SEND AND BY COMMIT ────────────────────────────
	if _, err := receiver.group.sendableLocked(KindText); !errors.Is(err, ErrRemovalWithoutRotation) {
		t.Fatalf("%s's Send answers %v; a halted group stands at an epoch the server has already "+
			"left, so leaving Send open hands the user an undiagnosable refusal by another road",
			receiver.name, err)
	}
	if err := receiver.group.committableLocked(); !errors.Is(err, ErrRemovalWithoutRotation) {
		t.Fatalf("%s's Commit answers %v, want the halt", receiver.name, err)
	}
	// ── AND WHICH DOOR TOOK IT, WHICH IS WHERE THE MLS HANDLE IS ────────────────────────────
	switch row.door {
	case noDigestDoor:
		if receiver.handle.Epoch() != handleAt {
			t.Fatalf("%s's MLS handle stands at epoch %d and it stood at %d before the page. This "+
				"row is the 0x0001 class and its whole claim is that the decision is taken BEFORE "+
				"ApplyCommit; if it has moved to the resolution, move the row and say what "+
				"evidence it uses", receiver.name, receiver.handle.Epoch(), handleAt)
		}
	case digestDoor:
		if receiver.handle.Epoch() != self.opens {
			t.Fatalf("%s's MLS handle stands at epoch %d, want %d. Judging a digest needs "+
				"mls_secret[n+1], so the apply has run by then and the handle HAS moved -- that "+
				"is the residual of taking the decision here and it is asserted rather than "+
				"glossed", receiver.name, receiver.handle.Epoch(), self.opens)
		}
	}
	if self.then != nil {
		self.then(t)
	}
}

// assertNamesEveryRemovedLeaf holds that the refusal an operator reads names the commit's WHOLE
// removed-leaf list, as a set and not in a fixed order -- the order is connect's application order
// and is not this package's to assert.
func (self *removalPage) assertNamesEveryRemovedLeaf(t *testing.T, err error) {
	t.Helper()
	message := err.Error()
	named, readable := leavesNamedIn(message)
	if !readable {
		// The pre-apply door names a COUNT rather than a list, because it is refusing before the
		// authorization decision's list has anything else read off it.
		want := fmt.Sprintf("removes %d leaf/leaves", len(self.removes))
		if !strings.Contains(message, want) {
			t.Fatalf("the refusal reads %q and names neither a leaf list nor %q. A truncation of "+
				"the removed-leaf list between connect and the guard still refuses -- the "+
				"predicate is `0 < len(...)` -- and this sentence is the only thing that can show "+
				"it", message, want)
		}
		return
	}
	slices.Sort(named)
	want := append([]uint32(nil), self.removes...)
	slices.Sort(want)
	if !slices.Equal(named, want) {
		t.Fatalf("the refusal names leaves %v and the commit removes %v. A list narrowed anywhere "+
			"between connect's processed.Commit.RemovedLeaves() and the guard still REFUSES, so "+
			"the disposition cannot see it and this sentence is what does", named, want)
	}
}

// leavesNamedIn reads the leaf list out of [refuseRemovalOnHeldSecret]'s sentence, or reports that
// the sentence does not carry one.
func leavesNamedIn(message string) ([]uint32, bool) {
	const opener = "removes leaf/leaves ["
	at := strings.Index(message, opener)
	if at < 0 {
		return nil, false
	}
	rest := message[at+len(opener):]
	end := strings.Index(rest, "]")
	if end < 0 {
		return nil, false
	}
	named := []uint32{}
	for _, field := range strings.Fields(rest[:end]) {
		value, err := strconv.ParseUint(field, 10, 32)
		if err != nil {
			return nil, false
		}
		named = append(named, uint32(value))
	}
	return named, true
}

// ── the builders ─────────────────────────────────────────────────────────────────────────────

// removalCohort founds a world with one committer, one receiver and `victims` members to remove,
// and answers the three things every builder needs. THE RECEIVER IS NEVER THE COMMITTER: a
// committer does not run the receive path against its own commit, which is ledger ruling 43's
// second residual and is why it cannot be the subject here.
func removalCohort(t *testing.T, victims int) (*rotWorld, *rotMember, *rotMember, []uint32, []byte) {
	t.Helper()
	names := []string{"alice", "bob"}
	for at := 0; at < victims; at += 1 {
		names = append(names, fmt.Sprintf("victim%d", at))
	}
	world := newRotWorld(t, names...)
	committer, receiver := world.member("alice"), world.member("bob")
	removing := []uint32{}
	for at := 0; at < victims; at += 1 {
		removing = append(removing, world.member(fmt.Sprintf("victim%d", at)).leaf)
	}
	retained := []byte(nil)
	if 0 < victims {
		retained = append([]byte(nil), world.member("victim0").group.pqSecretLocked()...)
	}
	return world, committer, receiver, removing, retained
}

func buildHeldFanOut(victims int, how unrotatedFanOut) func(t *testing.T) *removalPage {
	return func(t *testing.T) *removalPage {
		world, committer, receiver, removing, retained := removalCohort(t, victims)
		published := world.fanOutOnTheHeldSecret(committer, removing, func() ([]byte, []byte, []byte, error) {
			return committer.handle.CommitRemove(removing)
		}, how)
		page := &removalPage{world: world, committer: committer, receiver: receiver,
			page: published.page(), opens: published.opens, removes: removing,
			opensOn: published.pqSecret, retained: retained}
		page.also = func(t *testing.T) {
			// THE FAN-OUT IS REAL AND THE RECEIVER OPENS ITS OWN WRAP, so the refusal is not an
			// absence. Without it a page the receiver could not read would satisfy the row, and
			// that is a different sentinel and a different defect.
			if err := world.deliver(receiver, published.wraps...); err != nil {
				t.Fatalf("CONTROL FAILED: %s's walk over the fan-out alone answered %v", receiver.name, err)
			}
			if opened := receiver.group.Stats().WrapOpened; opened != 1 {
				t.Fatalf("CONTROL FAILED: %s opened %d wrap(s) of this fan-out, want 1", receiver.name, opened)
			}
			if len(removing) != victims || len(slices.Compact(slices.Sorted(slices.Values(removing)))) != victims {
				t.Fatalf("CONTROL FAILED: this row removes %v, which is not %d distinct leaves",
					removing, victims)
			}
			page.page = []*sealed{published.commit}
		}
		return page
	}
}

func buildFreshFanOutHeldDigest(victims int) func(t *testing.T) *removalPage {
	return func(t *testing.T) *removalPage {
		fresh := make([]byte, messagegroup.PqSecretBytes)
		if _, err := rand.Read(fresh); err != nil {
			t.Fatalf("the fresh wrap payload: %v", err)
		}
		return buildHeldFanOut(victims, unrotatedFanOut{payload: fresh})(t)
	}
}

func buildHonestRotation(victims int) func(t *testing.T) *removalPage {
	return func(t *testing.T) *removalPage {
		world, committer, receiver, removing, retained := removalCohort(t, victims)
		published := world.rotate(committer, removing, func() ([]byte, []byte, []byte, error) {
			return committer.handle.CommitRemove(removing)
		})
		return &removalPage{world: world, committer: committer, receiver: receiver,
			page: published.page(), opens: published.opens, removes: removing,
			opensOn: published.pqSecret, retained: retained}
	}
}

func buildUnrotatedNoRemoval(t *testing.T) *removalPage {
	world, committer, receiver, _, _ := removalCohort(t, 0)
	published := world.advanceWithoutRotating(committer, func() ([]byte, []byte, []byte, error) {
		return committer.handle.Commit(nil)
	})
	return &removalPage{world: world, committer: committer, receiver: receiver,
		page: published.page(), opens: published.opens, removes: nil,
		opensOn: published.pqSecret}
}

func buildOneOctetFromHeld(t *testing.T) *removalPage {
	world, committer, receiver, removing, retained := removalCohort(t, 1)
	// ONE OCTET, AND IT IS THE LAST ONE. A value that differs from a held secret anywhere is a
	// fresh value; a rule that answered "held" for this would be answering about a resemblance.
	bent := append([]byte(nil), retained...)
	bent[len(bent)-1] ^= 0x01
	published := world.fanOutOnTheHeldSecret(committer, removing, func() ([]byte, []byte, []byte, error) {
		return committer.handle.CommitRemove(removing)
	}, unrotatedFanOut{opensOn: bent})
	page := &removalPage{world: world, committer: committer, receiver: receiver,
		page: published.page(), opens: published.opens, removes: removing,
		opensOn: published.pqSecret, retained: retained}
	page.also = func(t *testing.T) {
		differing := 0
		for at := range retained {
			if retained[at] != bent[at] {
				differing += 1
			}
		}
		if differing != 1 {
			t.Fatalf("CONTROL FAILED: the value this epoch is opened on differs from the held one "+
				"in %d octet(s), want exactly 1", differing)
		}
		if !bytes.Equal(published.pqSecret, bent) {
			t.Fatalf("CONTROL FAILED: the fixture opened epoch %d on something other than the "+
				"bent value", published.opens)
		}
		if _, held := receiver.group.pqSecretHeldAtLocked(bent); held {
			t.Fatalf("CONTROL FAILED: %s answers HELD for a value it has never filed, so this row "+
				"would be followed for the wrong reason", receiver.name)
		}
		if _, held := receiver.group.pqSecretHeldAtLocked(retained); !held {
			t.Fatalf("CONTROL FAILED: %s does not answer held for the value one octet away, so "+
				"there is no near miss here and the row measures nothing", receiver.name)
		}
	}
	return page
}

func buildEarlierEpochReplay(t *testing.T) *removalPage {
	world, committer, receiver, removing, atOne := removalCohort(t, 1)
	victim := world.member("victim0")
	// THE HONEST ROTATION THAT GIVES THE RECEIVER A SECOND ROW. At epoch 1 there is one row, so
	// "the current row" and "the whole table" are the same set and the replay below is invisible.
	first := world.rotate(committer, nil, func() ([]byte, []byte, []byte, error) {
		return committer.handle.Commit(nil)
	})
	for _, member := range []*rotMember{receiver, victim} {
		if err := world.deliver(member, first.page()...); err != nil {
			t.Fatalf("CONTROL FAILED: %s's walk over an honest rotation answered %v", member.name, err)
		}
	}
	published := world.fanOutOnTheHeldSecret(committer, removing, func() ([]byte, []byte, []byte, error) {
		return committer.handle.CommitRemove(removing)
	}, unrotatedFanOut{opensOn: atOne})
	page := &removalPage{world: world, committer: committer, receiver: receiver,
		page: published.page(), opens: published.opens, removes: removing,
		opensOn: published.pqSecret, retained: atOne}
	page.also = func(t *testing.T) {
		if len(receiver.group.pqSecrets) < 2 {
			t.Fatalf("CONTROL FAILED: %s holds %d row(s) after one rotation; with one row this "+
				"row measures the case above it", receiver.name, len(receiver.group.pqSecrets))
		}
		if bytes.Equal(receiver.group.pqSecretLocked(), atOne) {
			t.Fatalf("CONTROL FAILED: epoch 2's secret IS epoch 1's, so the replay is not of a " +
				"different octet string")
		}
		if !bytes.Equal(published.pqSecret, atOne) {
			t.Fatalf("CONTROL FAILED: the fixture opened epoch %d on something other than epoch "+
				"1's secret", published.opens)
		}
	}
	return page
}

// buildLateJoinerResidual is ledger ruling 43's first residual, driven. One page, two receivers,
// and the difference between them is a HISTORY and nothing else.
func buildLateJoinerResidual(t *testing.T) *removalPage {
	world, committer, receiver, removing, atOne := removalCohort(t, 1)
	victim := world.member("victim0")
	first := world.rotate(committer, nil, func() ([]byte, []byte, []byte, error) {
		return committer.handle.Commit(nil)
	})
	for _, member := range []*rotMember{receiver, victim} {
		if err := world.deliver(member, first.page()...); err != nil {
			t.Fatalf("CONTROL FAILED: %s's walk over an honest rotation answered %v", member.name, err)
		}
	}
	joiner, admission := world.admit(committer, "dave", receiver, victim)
	published := world.fanOutOnTheHeldSecret(committer, removing, func() ([]byte, []byte, []byte, error) {
		return committer.handle.CommitRemove(removing)
	}, unrotatedFanOut{opensOn: atOne})
	page := &removalPage{world: world, committer: committer, receiver: receiver,
		page: published.page(), opens: published.opens, removes: removing,
		opensOn: published.pqSecret, retained: atOne}
	page.also = func(t *testing.T) {
		if len(joiner.group.pqSecrets) != 1 {
			t.Fatalf("CONTROL FAILED: the member admitted at epoch %d holds %d pq_secret row(s), "+
				"want 1. Device.Join files exactly one and this row is about that",
				admission.opens, len(joiner.group.pqSecrets))
		}
		if _, held := receiver.group.pqSecretHeldAtLocked(atOne); !held {
			t.Fatalf("CONTROL FAILED: the founder does not answer held for epoch 1's secret, so " +
				"the refusal below is not about a history")
		}
		if _, held := joiner.group.pqSecretHeldAtLocked(atOne); held {
			t.Fatalf("CONTROL FAILED: the late joiner answers HELD for a value drawn before it " +
				"was admitted, so the two receivers do not differ and this row measures nothing")
		}
		// AND THE CONTROL FIRES FOR ITS OWN REASON: the late joiner DOES recognise its own row.
		// Without this, "the joiner answers not held" would also be satisfied by a joiner whose
		// table is empty or whose lookup is broken.
		if _, held := joiner.group.pqSecretHeldAtLocked(admission.pqSecret); !held {
			t.Fatalf("CONTROL FAILED: the late joiner does not answer held for its OWN row, so " +
				"its `not held` above is a broken lookup and not a smaller history")
		}
	}
	page.then = func(t *testing.T) {
		// THE RESIDUAL ITSELF. The same page, the same removal, a receiver with a smaller
		// history: it is FOLLOWED, and nothing in this package can make it otherwise.
		if err := world.deliver(joiner, published.page()...); err != nil {
			t.Fatalf("the late joiner answered %v. It cannot refuse -- it has never held the "+
				"replayed value -- so a refusal here means this row is measuring something else", err)
		}
		if joiner.group.epoch != published.opens {
			t.Fatalf("the late joiner stands at epoch %d after following, want %d",
				joiner.group.epoch, published.opens)
		}
		if joiner.group.halted != nil {
			t.Fatalf("the late joiner halted: %v", joiner.group.halted)
		}
		t.Logf("RULING 43's FIRST RESIDUAL, DRIVEN: one page removing leaf %v on pq_secret[1]; "+
			"the founder REFUSED it and the member admitted at epoch %d FOLLOWED it. A receiver "+
			"cannot check a property about a history it does not have, and if every survivor had "+
			"joined after that epoch there would be no refuser at all",
			removing, admission.opens)
	}
	return page
}

func buildAdminCommitter(t *testing.T) *removalPage {
	world, owner, admin, removing, _ := removalCohort(t, 1)
	victim := world.member("victim0")
	world.promote(owner, admin, admin, victim)
	// THE VALUE THE VICTIM KEEPS IS READ AFTER THE PROMOTION AND NOT BEFORE IT. The promotion is
	// an honest rotation, so the group has moved to a second secret and the removal below is
	// fanned out on THAT one; a counterfactual built on the founding value would be asking about
	// a row nobody is replaying.
	retained := append([]byte(nil), victim.group.pqSecretLocked()...)
	// THE COMMITTER IS THE PROMOTED ADMIN AND THE RECEIVER IS THE OWNER, so this row is the only
	// one in the table whose commit was not written by the group's founder.
	published := world.fanOutOnTheHeldSecret(admin, removing, func() ([]byte, []byte, []byte, error) {
		return admin.handle.CommitRemove(removing)
	}, unrotatedFanOut{})
	page := &removalPage{world: world, committer: admin, receiver: owner,
		page: published.page(), opens: published.opens, removes: removing,
		opensOn: published.pqSecret, retained: retained}
	page.also = func(t *testing.T) {
		// THE COMMITTER REALLY IS AN ADMIN, read off the receiver's own policy. Without it a
		// promotion that silently did nothing would make this a copy of the first row.
		extensions, err := owner.group.contextExtensionsLocked()
		if err != nil {
			t.Fatalf("the owner's group context: %v", err)
		}
		policy, err := mls.GroupPolicyOf(mlsExtensionsOf(extensions))
		if err != nil {
			t.Fatalf("the owner's policy: %v", err)
		}
		if role, named := policy.RoleOf(admin.dev.identityPub); !named || role != mls.RoleAdmin {
			t.Fatalf("CONTROL FAILED: the committer is named %v (named=%v) in the policy the "+
				"receiver holds, want ADMIN", role, named)
		}
		// AND THE VICTIM HAS NO SECOND DEVICE TO COMMIT WITH, MEASURED RATHER THAN ASSERTED.
		// A removal committed by the removed member's OWN second device is not a shape this
		// build can put on the wire: credential identity IS the device signer (ledger item 242's
		// M7), so an identity holds exactly one leaf, and mls refuses a second leaf under one
		// signature key by name. The control is in the same call: the refusal is the mls error
		// and not some other failure.
		keyPackage, err := victim.dev.engine.NewKeyPackage()
		if err != nil {
			t.Fatalf("the victim's key package: %v", err)
		}
		if _, _, _, err := owner.handle.CommitAdd([][]byte{keyPackage}); !errors.Is(err, mls.ErrAddDuplicateSignatureKey) {
			t.Fatalf("a second leaf under the victim's own identity was accepted with %v. If this "+
				"build now admits one, a removal committed by the victim's own second device "+
				"becomes constructible and this table owes it a row", err)
		}
		owner.handle.ClearPendingCommit()
	}
	return page
}

func buildBundledRemoval(honest bool) func(t *testing.T) *removalPage {
	return func(t *testing.T) *removalPage {
		world, committer, receiver, removing, retained := removalCohort(t, 1)
		victim := world.member("victim0")
		arm, joining := world.bundleAddAndRemove(committer, removing[0], "dave", receiver, victim)
		published := (*rotation)(nil)
		if honest {
			published = world.rotate(committer, removing, arm)
		} else {
			published = world.fanOutOnTheHeldSecret(committer, removing, arm, unrotatedFanOut{})
		}
		page := &removalPage{world: world, committer: committer, receiver: receiver,
			page: published.page(), opens: published.opens, removes: removing,
			opensOn: published.pqSecret, retained: retained}
		page.also = func(t *testing.T) {
			// THE COMMIT REALLY DOES BOTH, read off the committer's own post-commit tree. A
			// commit that quietly dropped one of its two proposals would make this row a slower
			// copy of the plain removal, and the disposition would not show it.
			if !world.holdsIdentity(committer, joining.identityPub) {
				t.Fatalf("CONTROL FAILED: the committer's tree does not hold the ADDED identity " +
					"after the commit, so this row is not a bundle")
			}
			if world.holdsIdentity(committer, victim.dev.identityPub) {
				t.Fatalf("CONTROL FAILED: the committer's tree still holds the REMOVED identity " +
					"after the commit, so this row is not a removal")
			}
		}
		return page
	}
}

func buildNoDigestRemoval(victims int) func(t *testing.T) *removalPage {
	return func(t *testing.T) *removalPage {
		world, committer, receiver, removing, retained := removalCohort(t, victims)
		published := world.fanOutOnTheHeldSecret(committer, removing, func() ([]byte, []byte, []byte, error) {
			return committer.handle.CommitRemove(removing)
		}, unrotatedFanOut{noDigest: true})
		return &removalPage{world: world, committer: committer, receiver: receiver,
			page: published.page(), opens: published.opens, removes: removing,
			opensOn: published.pqSecret, retained: retained}
	}
}

func buildNoDigestBundle(t *testing.T) *removalPage {
	world, committer, receiver, removing, retained := removalCohort(t, 1)
	victim := world.member("victim0")
	arm, _ := world.bundleAddAndRemove(committer, removing[0], "dave", receiver, victim)
	published := world.fanOutOnTheHeldSecret(committer, removing, arm, unrotatedFanOut{noDigest: true})
	return &removalPage{world: world, committer: committer, receiver: receiver,
		page: published.page(), opens: published.opens, removes: removing,
		opensOn: published.pqSecret, retained: retained}
}

func buildNoDigestNoRemoval(t *testing.T) *removalPage {
	world, committer, receiver, _, _ := removalCohort(t, 0)
	published := world.fanOutOnTheHeldSecret(committer, nil, func() ([]byte, []byte, []byte, error) {
		return committer.handle.Commit(nil)
	}, unrotatedFanOut{noDigest: true})
	return &removalPage{world: world, committer: committer, receiver: receiver,
		page: published.page(), opens: published.opens, removes: nil,
		opensOn: published.pqSecret}
}
