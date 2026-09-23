package urmessage

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"testing"
)

// ══════════════════════════════════════════════════════════════════════════════════════════════
// RULING 33's GATE: AN EPOCH KEY GOES WHERE THE DISPOSITION BELOW SAYS IT GOES, AND NOWHERE ELSE
// ══════════════════════════════════════════════════════════════════════════════════════════════
//
// connect holds the DESCRIPTOR half of ruling 33 -- no server→client message transitively carries
// an EpochKeyDelivery, and `protocol.Record` declares no key field. That is a property of
// message.proto and it is held in message_keydelivery_test.go. It says nothing about what THIS
// package does with the two keys it derives, and the two halves fail differently: connect's catches
// a key field appearing on a served type, this one catches a key VALUE reaching a site nobody
// weighed.
//
// THE MECHANISM IS THE VALUE AND NOT THE FIELD NAME, and that is deliberate. Step 3's version of
// this gate in connect was defeated three times, and the last of the three is the one worth
// carrying over: a nested type carrying the two keys under the field names `wk` and `rk` walked
// through every check green, because every check -- and every mutant in that commit's table -- was
// keyed on the strings "write_key" and "read_key". So this gate never reads a field name to decide
// whether something is a key. It starts at the four call sites that PRODUCE one, follows the value
// through assignment, and censuses every place the value lands. `BlobId: writeKey` is caught by the
// same clause `WriteKey: writeKey` is, and the mutation table below drives exactly that.
//
// THE NARROWING IS ASSERTED IN BOTH DIRECTIONS AND IS NOT MERELY PRINTED. A site with no entry in
// the disposition is a failure, and an entry no site needs is a failure. Printing alone is what
// connect's step-3 repair did, and item 244's own shape rode back in green underneath it: a printed
// complement tells a reader what was narrowed away, and only an assertion tells the NEXT COMMIT
// that it may not narrow further.

// The names a call has to carry for its result to be an epoch key. This is the SEARCH NET rather
// than a disposition: a name here that no site uses costs nothing and widens the net, while a
// producer spelled some other way is a blindness this gate cannot see -- which is what
// epochKeyProducerSites is held both ways for.
//
// `WriteKey` and `ReadKey` cover both spellings this package uses: the method on
// messagegroup.EpochKeys, which hands back an epoch's own pair, and the package function
// message.WriteKey/message.ReadKey, which derives one off a storage root. `GetWriteKey` and
// `GetReadKey` cover a key read back OFF a protobuf, which is how one would re-enter this package
// from a message it had already been put on.
var epochKeyProducerSelectors = map[string]bool{
	"WriteKey":    true,
	"ReadKey":     true,
	"GetWriteKey": true,
	"GetReadKey":  true,
}

// Every call site in this package's production source that produces an epoch key, as
// "<enclosing function>|<callee as written>" -> why it is there.
//
// IT IS HELD BOTH WAYS, and the direction that matters most is the one that looks pedantic: an
// entry no site needs is a FAILURE, because that is how this gate reports that its own search has
// gone blind. Spell `message.WriteKey` through a local alias and the site disappears from the
// census; the sink clauses below would then be searching a value nothing tainted, would find
// nothing, and would pass. A gate that can go quiet by being avoided is not a gate, so the day the
// census stops finding one of these, this map says so in a FAILURE.
var epochKeyProducerSites = map[string]string{
	"Open|keys.WriteKey":                   "epoch 1's write key, off the session the founding commit opens",
	"Open|keys.ReadKey":                    "epoch 1's read key, the same",
	"Open|bootstrap.WriteKey":              "write_key[0], §4.3.2's bootstrap key, which certifies the founding commit and is NOT what it opens",
	"publishCommitLocked|message.WriteKey": "the write key of the epoch the staged commit opens, off the staged exporter",
	"publishCommitLocked|message.ReadKey":  "the read key of the same",
	"Receive|next.ReadKey":                 "the read key §4.3.8's req_auth is computed under, re-derived when the walk crosses an epoch",
}

// Every place an epoch key VALUE lands, as "<enclosing function>|<site>" -> why it is allowed.
//
// THREE OF THESE ENTRIES SAY "ITEM 244 IS STILL OPEN HERE", AND THAT IS WHAT A DISPOSITION IS FOR.
// A gate that refused the tree it is committed beside would be deleted within the week; a gate that
// quietly excused it would be the printed-not-asserted defect again. So the two EpochAttachment
// literals and the two sealed records that carry them are written down, by name, with the
// measurement that says why they cannot move yet -- and because the map is held BOTH ways, the day
// they do move this file goes red until somebody deletes the entry and the sentence with it.
var epochKeySinks = map[string]string{
	"Open|call epochKeysFor": "RULING 33's ROAD, and the DECISION that gates it. epochKeysFor " +
		"reads the sealed record's attachment kind and answers the pair for a kind 0x0005 commit or " +
		"nil for a kind 0x0001 one, then epochKeyDelivery copies. Every commit this package can seal " +
		"today is 0x0001, so what actually travels this sink today is nil -- which is the shape the " +
		"server accepts, and NOT a feature switch.",
	"publishCommitLocked|call epochKeysFor": "RULING 33's ROAD, the other commit path: the pair " +
		"the staged commit opens its epoch with, through the same one decision. `commitRecord` " +
		"reaches here too, and it is tainted because its kind 0x0001 attachment holds the pair IN " +
		"THE CLEAR.",

	"Open|literal protocol.CreateGroupRequest.EpochKeys": "§4.3.2's SINGULAR carrier. The request " +
		"holds exactly one record and it is always a commit, so there is no alignment to compute and " +
		"no list to keep in step. Present iff the initial commit is kind 0x0005, which is §5.4's " +
		"acceptance window and is the server's own rule read off the same octets.",
	"publishCommitLocked|call self.submitLocked": "TWO VALUES REACH THIS ONE CALL and they are there " +
		"for opposite reasons. `delivery` is §4.3.3's REPEATED carrier, held against the record by " +
		"alignedEpochKeys in both directions, and it is nil for as long as the attachment is kind " +
		"0x0001. `commitRecord` is tainted because that attachment still holds the pair IN THE " +
		"CLEAR -- item 244 open, see below -- and the day the attachment becomes a digest it stops " +
		"being tainted and this entry has to lose that half.",

	"Open|literal protocol.CreateGroupRequest.BootstrapWriteKey": "write_key[0], and it is NOT what " +
		"the commit opens. §4.3.2 declares it and calls it self-certification: the server verifies " +
		"the founding commit's write_auth under it and nothing but a 20/day rate limit protects it. " +
		"It is a RULED field, it is epoch zero's, and item 244 is about the chained NEXT epoch.",
	"Open|call append": "the copy of that bootstrap key. messagegroup.EpochKeys.WriteKey hands back " +
		"the session's own backing array and Destroy zeroizes it, so the request would carry an " +
		"erased key without this.",

	"Receive|call authorizeFetch": "the READ key into §4.3.8's req_auth, which is a mac COMPUTED " +
		"under the key. Nothing of the key reaches the wire: what does is ComputeRequestAuth's " +
		"output. This is the one sink in this package that consumes a key rather than carrying it.",

	"Open|literal message.EpochAttachment.WriteKey": "ITEM 244, STILL OPEN AT THIS SITE. " +
		"Ruling 27 replaces these two fields with LP(H(epoch_keys)) under attachment kind 0x0005, and " +
		"this package CANNOT EMIT ONE: messagegroup.GroupSession.SealRecord is the only seal door, it " +
		"encodes through message.EncodeServerAttachment, and that encoder asks " +
		"serverAttachmentKindServed, which excludes AttachmentEpochDigest. Measured: kind 0x0005 is " +
		"refused by name while kind 0x0001 encodes at 136 octets in the same call. Owned by connect.",
	"Open|literal message.EpochAttachment.ReadKey":                 "ITEM 244, STILL OPEN AT THIS SITE, for the reason above.",
	"publishCommitLocked|literal message.EpochAttachment.WriteKey": "ITEM 244, STILL OPEN AT THIS SITE, for the reason above.",
	"publishCommitLocked|literal message.EpochAttachment.ReadKey":  "ITEM 244, STILL OPEN AT THIS SITE, for the reason above.",
	"Open|call self.sendSealedLocked": "the FOUNDING RECORD, tainted because the literal above put " +
		"the pair inside it. It is the same item 244 fact one hop on, and it is the clause that " +
		"reports the fix: when the attachment becomes a digest, this record stops being tainted and " +
		"this entry becomes an entry nothing needs.",
}

// The types in this package's production source that are built AROUND an epoch key, as
// "<enclosing function>|<type>" -> why.
//
// THIS CLAUSE IS INDEPENDENT OF THE TAINT AND THAT IS ITS JOB. Move the two keys into a helper and
// the sink census above loses them -- the taint does not cross a call boundary -- but a literal of
// a key-carrying type is a site wherever it is written. The two clauses fail on different mutants
// on purpose: a mutation table where every entry varies the same attribute cannot see a change of
// mechanism, which is exactly how connect's step-3 gate was defeated.
var epochKeyCarrierLiterals = map[string]string{
	"epochKeyDelivery|protocol.EpochKeyDelivery": "THE ONE CONSTRUCTOR of the request carrier, in " +
		"record.go. A second one anywhere is a second place the copy could be forgotten.",
	"Open|message.EpochAttachment": "ITEM 244, STILL OPEN. Kind 0x0001 with the pair in the clear, " +
		"because connect's seal door will not encode kind 0x0005. When it will, this literal becomes " +
		"a message.NewEpochDigestAttachment call, this census loses the site, and this entry must go " +
		"in the same commit.",
	"publishCommitLocked|message.EpochAttachment": "ITEM 244, STILL OPEN, for the reason above.",
}

// The literal types the clause above looks for. The net again, not a disposition.
var epochKeyCarrierTypes = map[string]bool{
	"protocol.EpochKeyDelivery":     true,
	"message.EpochAttachment":       true,
	"message.EpochDigestAttachment": true,
}

func TestEveryEpochKeyInThisPackageGoesWhereTheDispositionSaysItGoes(t *testing.T) {
	producers := map[string][]string{}
	sinks := map[string][]string{}
	carriers := map[string][]string{}
	unspent := map[string][]string{}

	sources := stateTestProductionSources(t)
	for _, name := range sources {
		content, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		fileSet := token.NewFileSet()
		parsed, err := parser.ParseFile(fileSet, name, content, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, declaration := range parsed.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			where := function.Name.Name

			// the carrier clause, which is independent of the taint: a literal of one of the
			// key-carrying types is a site whatever its fields are built from.
			ast.Inspect(function.Body, func(node ast.Node) bool {
				literal, ok := node.(*ast.CompositeLit)
				if !ok {
					return true
				}
				spelled := epochKeyExpr(literal.Type)
				if epochKeyCarrierTypes[spelled] {
					carriers[where+"|"+spelled] = append(carriers[where+"|"+spelled],
						fmt.Sprintf("%s:%d", name, fileSet.Position(literal.Pos()).Line))
				}
				return true
			})

			// the producers, and the taint they seed
			tainted := map[string]bool{}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				selector, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || !epochKeyProducerSelectors[selector.Sel.Name] {
					return true
				}
				site := where + "|" + epochKeyExpr(selector)
				producers[site] = append(producers[site],
					fmt.Sprintf("%s:%d", name, fileSet.Position(call.Pos()).Line))
				return true
			})
			// the fixpoint: a binding whose right hand side mentions a producer call or an
			// already-tainted identifier binds a key. It runs to a fixpoint rather than once
			// because a key reaches its sink through as many hops as the source cares to take,
			// and an analysis that followed one hop would be defeated by writing two.
			for spin := 0; spin < 16; spin += 1 {
				grew := false
				ast.Inspect(function.Body, func(node ast.Node) bool {
					assign, ok := node.(*ast.AssignStmt)
					if !ok {
						return true
					}
					if !epochKeyRhsCarriesAKey(assign.Rhs, tainted) {
						return true
					}
					for _, target := range assign.Lhs {
						identifier, ok := target.(*ast.Ident)
						if !ok || identifier.Name == "_" || identifier.Name == "err" {
							continue
						}
						if !tainted[identifier.Name] {
							tainted[identifier.Name] = true
							grew = true
						}
					}
					return true
				})
				if !grew {
					break
				}
			}
			if len(tainted) == 0 {
				continue
			}

			// the sinks, and the complement: a tainted identifier that reaches no sink at all is
			// printed rather than asserted, because it is the part of the census that is NOT the
			// property -- a value that goes nowhere is a value that leaked nowhere.
			landed := map[string]bool{}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				switch shape := node.(type) {
				case *ast.CompositeLit:
					spelled := epochKeyExpr(shape.Type)
					for _, element := range shape.Elts {
						pair, ok := element.(*ast.KeyValueExpr)
						if !ok {
							continue
						}
						identifier, ok := pair.Value.(*ast.Ident)
						if !ok || !tainted[identifier.Name] {
							continue
						}
						field := epochKeyExpr(pair.Key)
						site := fmt.Sprintf("%s|literal %s.%s", where, spelled, field)
						sinks[site] = append(sinks[site],
							fmt.Sprintf("%s:%d %s", name, fileSet.Position(pair.Pos()).Line, identifier.Name))
						landed[identifier.Name] = true
					}
				case *ast.CallExpr:
					for _, argument := range shape.Args {
						identifier, ok := argument.(*ast.Ident)
						if !ok || !tainted[identifier.Name] {
							continue
						}
						site := fmt.Sprintf("%s|call %s", where, epochKeyExpr(shape.Fun))
						sinks[site] = append(sinks[site],
							fmt.Sprintf("%s:%d %s", name, fileSet.Position(shape.Pos()).Line, identifier.Name))
						landed[identifier.Name] = true
					}
				case *ast.AssignStmt:
					for at, target := range shape.Lhs {
						selector, ok := target.(*ast.SelectorExpr)
						if !ok || at >= len(shape.Rhs) {
							continue
						}
						identifier, ok := shape.Rhs[at].(*ast.Ident)
						if !ok || !tainted[identifier.Name] {
							continue
						}
						site := fmt.Sprintf("%s|assign %s", where, epochKeyExpr(selector))
						sinks[site] = append(sinks[site],
							fmt.Sprintf("%s:%d %s", name, fileSet.Position(shape.Pos()).Line, identifier.Name))
						landed[identifier.Name] = true
					}
				}
				return true
			})
			for identifier := range tainted {
				if !landed[identifier] {
					unspent[where] = append(unspent[where], identifier)
				}
			}
		}
	}

	// ── THE COMPLEMENT, PRINTED: what this search covered and what it left out ────────────────
	t.Logf("production sources read (%d): %v", len(sources), sources)
	t.Logf("producer net (a call whose result is taken to be an epoch key): %v",
		epochKeySortedKeys(epochKeyProducerSelectors))
	t.Logf("carrier net (a composite literal taken to be built around an epoch key): %v",
		epochKeySortedKeys(epochKeyCarrierTypes))
	t.Logf("producer sites found (%d):", len(producers))
	for _, site := range epochKeySortedMap(producers) {
		t.Logf("    %s  at %v", site, producers[site])
	}
	t.Logf("sink sites found (%d):", len(sinks))
	for _, site := range epochKeySortedMap(sinks) {
		t.Logf("    %s  at %v", site, sinks[site])
	}
	t.Logf("carrier literals found (%d):", len(carriers))
	for _, site := range epochKeySortedMap(carriers) {
		t.Logf("    %s  at %v", site, carriers[site])
	}
	t.Logf("EXCLUDED, and excluded is not the same as absent -- tainted values that reach no sink "+
		"in their own function, so nothing carried them anywhere: %v", unspent)

	// ── AND ASSERTED, IN BOTH DIRECTIONS, AGAINST THREE WRITTEN-DOWN DISPOSITIONS ─────────────
	epochKeyHold(t, "producer site", producers, epochKeyProducerSites,
		"A call that produces an epoch key is where this gate's whole search begins. A site with no "+
			"entry is a key derived somewhere nobody weighed; an entry with no site is this gate "+
			"having gone BLIND -- the producer was respelled and the sink clauses below are now "+
			"searching a value nothing tainted, which passes by finding nothing.")
	epochKeyHold(t, "sink site", sinks, epochKeySinks,
		"This is ruling 33 held on the value rather than on the field name: the epoch keys travel on "+
			"the REQUEST carrier and nowhere else. A site with no entry is a key landing somewhere "+
			"this package has not weighed -- `BlobId: writeKey` fails here exactly as "+
			"`WriteKey: writeKey` does, which is the defeat connect's step-3 gate took three times. "+
			"An entry with no site is a disposition that has stopped describing the code.")
	epochKeyHold(t, "carrier literal", carriers, epochKeyCarrierLiterals,
		"A structure built AROUND an epoch key is a site whatever its fields are built from, which "+
			"is the clause that survives the keys being moved one function away from the literal. "+
			"The two message.EpochAttachment entries are item 244 STILL OPEN in this package and "+
			"are marked so; the day connect's seal door will encode kind 0x0005 they become "+
			"message.NewEpochDigestAttachment calls, this census loses them, and this map has to be "+
			"emptied in the same commit -- which it will report as an entry nothing needs.")
}

// epochKeyHold is the both-directions assertion the three censuses share.
func epochKeyHold(t *testing.T, what string, found map[string][]string, disposition map[string]string,
	why string) {

	t.Helper()
	if len(found) == 0 {
		t.Errorf("this gate found no %s at all in %d production files. An empty census passes every "+
			"refusal below by having nothing to refuse, which is how a search that has stopped "+
			"reading its own subject reports success.", what, len(stateTestProductionSources(t)))
	}
	for site := range found {
		reason, dispositioned := disposition[site]
		if !dispositioned {
			t.Errorf("%s %q has no entry in the disposition.\n%s", what, site, why)
			continue
		}
		t.Logf("    %s %s is allowed: %s", what, site, reason)
	}
	for site := range disposition {
		if _, ok := found[site]; !ok {
			t.Errorf("the disposition says %s %q is allowed and the census does not find it.\n%s",
				what, site, why)
		}
	}
}

// epochKeyRhsCarriesAKey is the taint step: a right hand side mentioning a producer call or an
// already-tainted identifier binds a key.
//
// IT IS OVER-APPROXIMATE ON PURPOSE. A sealer handed a key returns a record that CONTAINS it, so
// the record is tainted too, and the submit that carries that record is a sink. That is the correct
// answer for as long as the attachment carries the pair in the clear, and it is the clause that
// will report the change when it stops: the record stops being tainted, the submit stops being a
// sink, and the disposition entry for it becomes an entry nothing needs.
func epochKeyRhsCarriesAKey(right []ast.Expr, tainted map[string]bool) bool {
	carries := false
	for _, expression := range right {
		ast.Inspect(expression, func(node ast.Node) bool {
			switch shape := node.(type) {
			case *ast.CallExpr:
				if selector, ok := shape.Fun.(*ast.SelectorExpr); ok &&
					epochKeyProducerSelectors[selector.Sel.Name] {
					carries = true
				}
			case *ast.Ident:
				if tainted[shape.Name] {
					carries = true
				}
			}
			return true
		})
	}
	return carries
}

// epochKeyExpr spells a qualified name the way the source does, so a census entry reads as the code
// reads. Anything it cannot spell answers "?" rather than being dropped: a site this gate could not
// name is still a site, and a silent drop is the blindness the whole file is arranged against.
func epochKeyExpr(expression ast.Expr) string {
	switch shape := expression.(type) {
	case nil:
		return "?"
	case *ast.Ident:
		return shape.Name
	case *ast.SelectorExpr:
		return epochKeyExpr(shape.X) + "." + shape.Sel.Name
	case *ast.StarExpr:
		return "*" + epochKeyExpr(shape.X)
	case *ast.UnaryExpr:
		return epochKeyExpr(shape.X)
	case *ast.IndexExpr:
		return epochKeyExpr(shape.X)
	case *ast.ArrayType:
		return "[]" + epochKeyExpr(shape.Elt)
	}
	return "?"
}

func epochKeySortedKeys(set map[string]bool) []string {
	names := []string{}
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func epochKeySortedMap(sites map[string][]string) []string {
	names := []string{}
	for name := range sites {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
