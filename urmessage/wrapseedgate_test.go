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
// S2-26's CENSUS: THE DEVICE'S X-WING SEED GOES WHERE THE DISPOSITION BELOW SAYS IT GOES
// ══════════════════════════════════════════════════════════════════════════════════════════════
//
// WHY THIS FILE EXISTS, AND IT IS A FINDING RATHER THAN A PRECAUTION. S2-26 added a private key to
// a type in this package and added no census for it. The package's one dataflow gate --
// TestEveryEpochKeyInThisPackageGoesWhereTheDispositionSaysItGoes -- starts its walk at
// `epochKeyProducerSelectors = {WriteKey, ReadKey, GetWriteKey, GetReadKey}`, and the seed's
// producers are `xwing.Seed()`, `deviceIdentity`, `store.GetDeviceIdentity()` and the `wrapSeed`
// field itself. None of those four is in that net, so NO GATE IN THIS PACKAGE CENSUSED WHERE THE
// SEED'S VALUE GOES. Two gates did see the field -- the AST walk in devicewrapkey_test.go reads its
// declaration and refuses an unerasable one, and TestClosingADeviceErasesTheSeedAndNotOnlyTheField
// reads its octets after a Close -- and neither of those asks where the value LANDS, which is the
// gap. MEASURED, on the commit this file repairs: two production sites mutated to leak it --
//
//	device.go:419  fmt.Errorf("urmessage: this device's identity (seed %x) could not be persisted: %w", wrapSeed, err)
//	device.go:621  fmt.Errorf("urmessage: this device's leaf (seed %x) could not open this encapsulation: %w", self.wrapSeed, err)
//
// -- and the mutant passed `go test ./urmessage/ -run '.*' -timeout 1800s` at `ok 6.147s`, with
// TestEveryEpochKeyInThisPackageGoesWhereTheDispositionSaysItGoes,
// TestNoFieldInThisPackageHoldsAnUnerasableXwingPrivateKey and
// TestEveryFsyncInThisPackageIsAtASiteThisSuiteNames all `--- PASS`. The inline control, which
// fires for its own reason: the SAME snapshot/mutate/revert harness applied to `Close`'s
// `zeroizeState(self.wrapSeed)` produced `--- FAIL: TestClosingADeviceErasesTheSeedAndNotOnlyTheField`,
// so the harness and the suite do kill a mutant of this package WHEN A GATE COVERS THE MECHANISM.
// There was no leak in the tree and this file does not pretend to have found one. What was missing
// is the refusal: the epoch-key gate's own header names `fmt.Errorf("%x", writeKey)` -- "an epoch
// key in an error string, in every log that error ever reaches" -- as the exact shape it exists to
// refuse, and nothing refused that shape for the seed. This file does.
//
// IT IS THE EPOCH-KEY GATE'S SHAPE AND IT INHERITS THAT FILE'S THREE SCARS DELIBERATELY. Read its
// header for the measurements; the short form is that a census must match the VALUE and not the
// field name (a nested type spelling the keys `wk`/`rk` walked past a gate keyed on strings), must
// ask every landing place for an EXPRESSION and not an *ast.Ident (`x = writeKey[:]` was censused
// as nothing at all, not refused -- absent), and must follow EVERY binding form (`var leaked =
// writeKey` bound nothing when the fixpoint read *ast.AssignStmt alone). All three clauses are
// here, and the mutation table at the bottom of this file drives all three at the seed.
//
// WHERE IT DIFFERS FROM THE EPOCH-KEY GATE, and it is one clause: A COUNT OF A KEY IS NOT A KEY.
// `len(wrapSeed)` answers an int. Both of this package's store-side refusals format exactly that,
// so a census that called `len(wrapSeed)` a carried value would put `PutDeviceIdentity|call
// fmt.Errorf` in the disposition with `wrapSeed` in its carries list -- and that entry would then
// be a STANDING PERMIT to format the seed itself at that same call, which is the defect this file
// exists for, reintroduced by its own repair. So [wrapSeedBorneBy] refuses to look through the
// builtin `len`. THAT IS A NARROWING AND IT IS ASSERTED RATHER THAN PRINTED: every site the
// narrowing removed is collected in its own census and held both ways against
// [wrapSeedCountedNotCarriedSites] below, so an excluded site is a site somebody weighed and wrote
// down, and the day the tree stops counting the seed at one of them this file goes red. The
// mutation table drives it from the other side too: `len(wrapSeed)` -> `wrapSeed` at that same
// error must be a REFUSAL, and it is.
//
// THE OVER-APPROXIMATION PULLS IN THE SIGNER AND THAT IS COVERAGE AND NOT CONFUSION. The seed is
// born, returned and stored in the same statements as this device's signature private key --
// `deviceIdentity` hands back four values and `PutDeviceIdentity` writes them as one record -- so
// a taint that follows a multi-value binding reaches `signer` and `signerPub` as well. They are
// key material too. They are censused, dispositioned by name, and nothing here pretends the walk
// distinguishes them.

// The names that PRODUCE the seed, in any of the three positions a name can produce one: the
// callee of a call, a bare field read, or a parameter this function was handed. This is the SEARCH
// NET rather than a disposition -- a name here that no site uses costs nothing and widens the net,
// while a producer spelled some other way is a blindness this gate cannot see, which is what
// [wrapSeedProducerSites] is held BOTH WAYS for.
//
//   - `Seed` is `xwing.Seed()` in deviceIdentity, the mint. It answers a copy, which is why the
//     device can hold that array rather than copy it again.
//   - `GetDeviceIdentity` is the store's read, whose FOURTH result is the seed, and `deviceIdentity`
//     is the package helper whose fourth result is the same value one call further out. Both are
//     matched as callees and both are matched as ENCLOSING FUNCTION NAMES -- see the seeding below,
//     which is what censuses their own bodies.
//   - `wrapSeed` is the field read `self.wrapSeed` AND the parameter `PutDeviceIdentity(…, wrapSeed
//     []byte)`. The store's write path receives the value with a name and nothing else about it is
//     distinguishable from the three other parts of the record it goes into, so the name is the
//     only handle there is. Rename that parameter and the producer site disappears, which the
//     both-ways hold reports as an entry nothing needs.
var wrapSeedProducerNames = map[string]bool{
	"Seed":              true,
	"GetDeviceIdentity": true,
	"deviceIdentity":    true,
	"wrapSeed":          true,
}

// Every place in this package's production source that produces the seed, as
// "<enclosing function>|<site as written>" -> why it is there. HELD BOTH WAYS: a site with no
// entry is a seed coming from somewhere nobody weighed, and an entry with no site is this gate
// having gone BLIND -- the producer was respelled and every sink clause below is now searching a
// value nothing tainted, which passes by finding nothing.
var wrapSeedProducerSites = map[string]string{
	"NewDevice|deviceIdentity": "the device's identity, four values at once, on the one road " +
		"into [Device]. Its fourth result is the seed.",
	"deviceIdentity|store.GetDeviceIdentity": "the RESTORE arm: the seed as the durable store " +
		"last wrote it, or empty for a store written before the field existed.",
	"deviceIdentity|xwing.Seed": "the MINT arm: the 32 octets under the public half this same " +
		"call encodes into the leaf keys extension. Seed answers a copy, so this array is this " +
		"call's own -- which is what lets [Device.Close] erase ONE array rather than chase two.",
	"PutDeviceIdentity|parameter wrapSeed": "the store's WRITE path, where the value arrives from " +
		"the caller with a name and is otherwise indistinguishable from the three record parts " +
		"beside it. Seeding here is what puts statestore_durable.go inside this census at all.",
	"DecapsulateToOwnLeaf|self.wrapSeed": "the field read, under [Device.mutex], on the one path " +
		"that uses the seed for what it is for.",
	"Close|self.wrapSeed": "the field read on the ERASE path. It is a producer like any other read " +
		"of the field, and the sink it reaches is [zeroizeState].",

	// ── THE PRODUCER FUNCTIONS' OWN BODIES ───────────────────────────────────────────────────
	//
	// A producer named in the net above hands the seed back; INSIDE it, the value has not been
	// through a producer call and nothing would taint it. `DurableStateStore.GetDeviceIdentity`
	// is the case that matters: its results are unnamed and the seed is spelled `parts[3]`, a
	// generic record part. Without these entries the store's whole READ path -- the function
	// whose doc comment is the backward-compatibility ruling -- would be censused as nothing,
	// and `fmt.Errorf("%x", parts[3])` would be as invisible as the mutants above were. So every
	// result expression of a producer-named function seeds the taint at its own root name.
	"GetDeviceIdentity|result parts": "the record parts the identity read answers, three of them " +
		"or four. `parts[3]` is the seed when there are four; the other three are the signature " +
		"key pair and the leaf keys body, and this walk does not tell them apart.",
	"deviceIdentity|result leafKeys":  "the leaf keys extension, returned beside the seed.",
	"deviceIdentity|result signer":    "this device's signature PRIVATE key, minted in the same arm.",
	"deviceIdentity|result signerPub": "its public half.",
	"deviceIdentity|result wrapSeed":  "the seed itself, from both arms.",
}

// wrapSeedSink is one entry in the disposition below: WHICH VALUES a site may receive, and why. A
// disposition keyed on the site alone excuses the site FOREVER, whatever turns up there later, so
// each entry names the exact spellings it weighed and is held both ways on those too.
type wrapSeedSink struct {
	carries []string
	why     string
}

// Every place the seed VALUE lands, as "<enclosing function>|<site>" -> what may land and why.
//
// NOT ONE `fmt.Errorf` OR LOG SITE IS IN THIS MAP, and that absence is the property. Every
// formatting site in the four functions this census reaches formats a COUNT, which the narrowing
// above declines to carry and [wrapSeedCountedNotCarriedSites] writes down by name. So a
// formatting site appearing here at all is a new site with no entry, and it is refused -- which is
// what the two reproduced mutants do.
var wrapSeedSinks = map[string]wrapSeedSink{
	// ── THE MINT AND THE STORE ───────────────────────────────────────────────────────────────
	"deviceIdentity|call store.PutDeviceIdentity": {
		carries: []string{"leafKeys", "signer", "signerPub", "wrapSeed"},
		why: "THE SEED GOING TO DISK, and the leaf keys body going with it in the SAME CALL. That " +
			"is the point of the arrangement and not an accident of arity: the public half and the " +
			"seed under it come from one XwingGenerateKey and are written as one record, so no crash " +
			"leaves a stored public half beside a seed that does not expand to it. The seed is on " +
			"disk in the clear, like every other secret in this store -- S2-24, still open, and this " +
			"entry is where that fact is written down in a place a gate will keep honest.",
	},
	"deviceIdentity|call mls.SignaturePrivateKey": {
		carries: []string{"priv"},
		why: "the restore arm's cast of the stored signature private key to its named type. It is " +
			"tainted because the multi-value binding that produced it also produced the seed; the " +
			"walk does not separate the two and does not claim to.",
	},
	"deviceIdentity|call mls.SignaturePublicKey": {
		carries: []string{"pub"},
		why:     "the same cast for the public half.",
	},
	"deviceIdentity|return": {
		carries: []string{"leafKeys", "priv", "pub", "signer", "signerPub", "wrapSeed"},
		why: "THE ONE DOOR OUT OF THE MINT, and both arms use it. A seed handed to a caller leaves " +
			"this function by an exit no other clause watches -- the caller binds it from a call " +
			"nothing else taints -- and the caller is [NewDevice], whose own sites are below.",
	},
	"NewDevice|literal Device.wrapSeed": {
		carries: []string{"wrapSeed"},
		why: "THE FIELD. It is HELD rather than copied, which is the erase talking: both of " +
			"deviceIdentity's arms hand back an array nothing else references, so holding it leaves " +
			"ONE array for [Device.Close] to clear where copying would leave the original behind " +
			"with nothing pointing at it.",
	},
	"NewDevice|literal Device.leafKeys": {
		carries: []string{"leafKeys"},
		why:     "the leaf keys body, the PUBLIC half's carrier, tainted by the binding beside the seed.",
	},
	"NewDevice|literal Device.identityPub": {
		carries: []string{"signerPub"},
		why:     "the credential identity, a copy of the signer's public half.",
	},
	"NewDevice|call append": {
		carries: []string{"signerPub"},
		why:     "that copy being taken.",
	},
	"NewDevice|call mls.BasicCredential": {
		carries: []string{"signerPub"},
		why:     "the public half becoming the credential the engine publishes.",
	},
	"NewDevice|call messagegroup.NewConnectMlsEngine": {
		carries: []string{"leafKeys", "signer", "signerPub"},
		why: "the signature private key going into the engine, which is where this device's signer " +
			"LIVES -- [Device] holds no field for it, and the seed is the only key material this " +
			"type holds in a field of its own. The seed is NOT at this call and must never be: the " +
			"engine is `connect`'s and has no door for it.",
	},
	"NewDevice|literal Device.engine": {
		carries: []string{"engine"},
		why: "the engine FIELD, and it is here because the over-approximation is right about it: " +
			"`engine` was bound from a call handed `signer`, and the engine does hold this device's " +
			"signature private key for the rest of the process. It does not hold the seed, which is " +
			"why the two `connect` erase gates cover the one and this package's Close covers the " +
			"other. An entry listing `wrapSeed` here would be a different device.",
	},

	// ── THE STORE'S TWO HALVES ───────────────────────────────────────────────────────────────
	"PutDeviceIdentity|call self.writeRecord": {
		carries: []string{"wrapSeed"},
		why: "THE WRITE. One record, four parts, one fsync -- see " +
			"TestEveryFsyncInThisPackageIsAtASiteThisSuiteNames for the durability half.",
	},
	"PutDeviceIdentity|return": {
		carries: []string{"wrapSeed"},
		why: "the SAME statement as the write above, seen by the return clause as well, because " +
			"`return self.writeRecord(…, wrapSeed)` both passes the seed and hands a value back. " +
			"What is handed back is an `error`; the seed is borne by the call's ARGUMENTS and the " +
			"walk does not separate an expression's arguments from its result. Two clauses reporting " +
			"one statement is the correct answer here and not a duplicate: the day the write moves " +
			"off the return, one of the two entries goes stale and this file says so.",
	},
	"GetDeviceIdentity|return": {
		carries: []string{"parts"},
		why: "THE READ, all five of its returns at once. A three part record answers `parts[0], " +
			"parts[1], parts[2], nil, nil` -- a nil error and an EMPTY seed -- and that is the " +
			"backward-compatibility ruling this package's version lever could not pay for: " +
			"[stateRecordVersion] is read for EVERY record in the directory, so spending it here " +
			"would refuse the group states and the key packages beside the identity, which is a " +
			"device that can never start again. A four part record whose fourth part is not a seed " +
			"is refused instead, at this same read.",
	},

	// ── THE USE, AND THE ERASE ───────────────────────────────────────────────────────────────
	"DecapsulateToOwnLeaf|call messagegroup.XwingKeyGenFromSeed": {
		carries: []string{"self.wrapSeed"},
		why: "THE SEED BEING SPENT FOR WHAT IT IS FOR: re-expanded into the pair whose public half " +
			"this device's leaf publishes. It is re-expanded on EVERY call rather than cached, " +
			"because a cached pair would be a `*messagegroup.XwingPrivateKey` in a field -- " +
			"unerasable from this package, and the thing `connect/mls`'s erase gate excuses on the " +
			"written ground that no production declaration holds one.",
	},
	"DecapsulateToOwnLeaf|call messagegroup.XwingDecapsulate": {
		carries: []string{"private"},
		why: "the expanded pair reaching the decapsulation. `private` is tainted because it was " +
			"bound from a call whose argument was the seed -- by DERIVATION, which is the same " +
			"over-approximation the epoch-key gate records for a sealed record, and it is the " +
			"correct answer here: an expanded X-Wing private key IS the seed's content.",
	},
	"DecapsulateToOwnLeaf|return": {
		carries: []string{"shared"},
		why: "THE SHARED SECRET LEAVING THIS PACKAGE, which is this method's whole purpose and is " +
			"the one place the over-approximation reaches a value that is deliberately handed out. " +
			"It is tainted by derivation from the private key; what it is is " +
			"[messagegroup.XwingSharedSize] octets of ML-KEM/X25519 output, and the caller is the " +
			"party the ciphertext was addressed to. The SEED is not at this return and an entry " +
			"that listed it would be a different method.",
	},
	"Close|call zeroizeState": {
		carries: []string{"self.wrapSeed"},
		why: "THE ERASE. [zeroizeState] overwrites the one array [NewDevice] held, IN PLACE, under " +
			"the mutex a decapsulation also takes; the field is nil'd after, so a second Close " +
			"erases nothing and a decapsulation after a Close refuses by name rather than " +
			"decapsulating under 32 zero octets -- a well formed seed that would answer a perfectly " +
			"uniform-looking wrong secret. See TestClosingADeviceErasesTheSeedAndNotOnlyTheField. " +
			"It does NOT reach the copy inside the transient *messagegroup.XwingPrivateKey, which " +
			"declares no erase and which `connect` is not this step's to change.",
	},
}

// THE NARROWING'S OWN CENSUS: every place this package takes a COUNT of the seed and this gate
// therefore declined to call a carried value. Held both ways, exactly like the three above.
//
// THIS IS THE COMPLEMENT OF [wrapSeedBorneBy]'s ONE EXCLUSION, WRITTEN DOWN AND ASSERTED. A
// narrowing that is merely printed tells a reader what was removed; only an assertion tells the
// NEXT COMMIT that it may not narrow further. An entry here with no site is the tree having
// stopped counting the seed where it used to. That is sometimes a fix nobody deleted the entry
// for, and sometimes it is the exclusion having been switched OFF: M8 in the table at the foot of
// this file declares a local `len`, shadowing the builtin from inside the source this gate reads,
// and both this census's stale direction and the sink disposition go red at that one commit.
// A site here with no entry is a new count nobody weighed, and a count is one edit from a value --
// M9 drives that direction and M3 drives the edit.
var wrapSeedCountedNotCarriedSites = map[string]string{
	"PutDeviceIdentity|len wrapSeed": "the write path's length refusal: 32 and 64 both expand " +
		"into a well formed X-Wing pair and only one of them is the pair whose public half is in " +
		"leafKeys, so the length is checked at the one moment the value is still in the caller's " +
		"hand. The error formats this COUNT and must never format the value.",
	"GetDeviceIdentity|len parts": "the read path's arity switch and its refusal text: three parts " +
		"or four, and anything else is a record this build cannot read.",
	"GetDeviceIdentity|len parts[3]": "the read path's own length check on the STORED seed, and " +
		"its refusal text. It is a site of its own rather than part of the entry above because " +
		"this census spells the index: `len(parts)` counts the record and `len(parts[3])` counts " +
		"the key inside it, and a disposition that called those one site would excuse the second " +
		"by having weighed the first.",
	"DecapsulateToOwnLeaf|len self.wrapSeed": "the EMPTY-seed guard, which is a store written " +
		"before the seed was retained or a device that has been Closed. It refuses by name " +
		"([ErrNoDeviceWrapKey]) rather than expanding zero octets into a valid-looking key.",
}

func TestEveryWrapSeedInThisPackageGoesWhereTheDispositionSaysItGoes(t *testing.T) {
	producers := map[string][]string{}
	sinks := map[string][]string{}
	carried := map[string]map[string]bool{}
	counted := map[string][]string{}
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
			at := func(node ast.Node) string {
				return fmt.Sprintf("%s:%d", name, fileSet.Position(node.Pos()).Line)
			}

			// THE NAMES THIS FUNCTION DECLARED. Two clauses need them. A bare name on the left of
			// an assignment is a REBINDING when this function declared it and a SINK when it did
			// not, because a name that outlives the call parks a key for the lifetime of whatever
			// holds it. And the `len` exclusion below asks this map whether the builtin has been
			// shadowed, because a local named `len` would turn one clause of this gate off.
			local := map[string]bool{"_": true}
			receiver := ""
			declare := func(fields *ast.FieldList) {
				if fields == nil {
					return
				}
				for _, field := range fields.List {
					for _, target := range field.Names {
						local[target.Name] = true
					}
				}
			}
			declare(function.Recv)
			if function.Recv != nil && 0 < len(function.Recv.List) &&
				0 < len(function.Recv.List[0].Names) {
				receiver = function.Recv.List[0].Names[0].Name
			}
			declare(function.Type.Params)
			declare(function.Type.Results)
			ast.Inspect(function.Body, func(node ast.Node) bool {
				switch shape := node.(type) {
				case *ast.AssignStmt:
					if shape.Tok == token.DEFINE {
						for _, target := range shape.Lhs {
							if identifier, ok := target.(*ast.Ident); ok {
								local[identifier.Name] = true
							}
						}
					}
				case *ast.ValueSpec:
					for _, target := range shape.Names {
						local[target.Name] = true
					}
				case *ast.RangeStmt:
					if shape.Tok == token.DEFINE {
						for _, target := range []ast.Expr{shape.Key, shape.Value} {
							if identifier, ok := target.(*ast.Ident); ok {
								local[identifier.Name] = true
							}
						}
					}
				case *ast.FuncLit:
					declare(shape.Type.Params)
					declare(shape.Type.Results)
				}
				return true
			})
			bears := func(expression ast.Expr, tainted map[string]bool, intoLiterals bool) []string {
				return wrapSeedBorneBy(expression, tainted, intoLiterals, local)
			}

			tainted := map[string]bool{}

			// PRODUCER ONE: a PARAMETER or named result carrying a producer's name. This is the
			// store's write path and nothing else -- `PutDeviceIdentity(…, wrapSeed []byte)` --
			// and without it statestore_durable.go is outside this census entirely.
			seedParameters := func(fields *ast.FieldList) {
				if fields == nil {
					return
				}
				for _, field := range fields.List {
					for _, target := range field.Names {
						if !wrapSeedProducerNames[target.Name] {
							continue
						}
						site := where + "|parameter " + target.Name
						producers[site] = append(producers[site], at(target))
						tainted[target.Name] = true
					}
				}
			}
			seedParameters(function.Type.Params)
			seedParameters(function.Type.Results)

			// PRODUCER TWO: the body of a producer-named function. Inside `GetDeviceIdentity` the
			// seed is `parts[3]`, a generic record part off a generic record read, and no call or
			// field read in that function would taint anything at all. So each RESULT EXPRESSION
			// of a producer-named function seeds the taint at its own root name. Calls and
			// literals in result position seed nothing -- `fmt.Errorf(...)` is an error and
			// `mls.SignaturePrivateKey(priv)` already carries `priv` by the walk below -- and the
			// RECEIVER is never a root, so `self.wrapSeed` seeds the field read's clause and not
			// the whole of `self`.
			if wrapSeedProducerNames[where] {
				ast.Inspect(function.Body, func(node ast.Node) bool {
					statement, ok := node.(*ast.ReturnStmt)
					if !ok {
						return true
					}
					for _, result := range statement.Results {
						root := wrapSeedRootName(result)
						if root == "" || root == "_" || root == "err" || root == "nil" ||
							root == receiver || !local[root] {
							continue
						}
						site := where + "|result " + root
						producers[site] = append(producers[site], at(result))
						tainted[root] = true
					}
					return true
				})
			}

			// PRODUCER THREE: a CALL whose callee's final name is in the net, spelled bare
			// (`deviceIdentity(...)`) or qualified (`xwing.Seed()`, `store.GetDeviceIdentity()`).
			// The epoch-key gate's net reads selectors alone; the seed's own package helper is
			// called by its bare name, and a net that could not see it would have left
			// [NewDevice]'s struct literal -- the field this whole step added -- uncensused.
			callee := map[ast.Node]bool{}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				named := wrapSeedCalleeName(call.Fun)
				if named == "" || !wrapSeedProducerNames[named] {
					return true
				}
				callee[call.Fun] = true
				site := where + "|" + wrapSeedExpr(call.Fun)
				producers[site] = append(producers[site], at(call))
				return true
			})

			// PRODUCER FOUR: a bare FIELD READ, `self.wrapSeed`, which is how the one field this
			// step added is spelled everywhere it is used. Not counted twice when the same
			// selector was already spent as a callee.
			ast.Inspect(function.Body, func(node ast.Node) bool {
				selector, ok := node.(*ast.SelectorExpr)
				if !ok || callee[selector] || !wrapSeedProducerNames[selector.Sel.Name] {
					return true
				}
				site := where + "|" + wrapSeedExpr(selector)
				producers[site] = append(producers[site], at(selector)+" field")
				return true
			})

			// THE FIXPOINT, over every binding form the language has. It runs to a fixpoint rather
			// than once because a seed reaches its sink through as many hops as the source cares
			// to take. `var x = wrapSeed` and `for _, b := range wrapSeed` bind here exactly as
			// `x := wrapSeed` does: the epoch-key gate was defeated by the first of those three
			// spellings and its scar is copied here rather than relearned.
			for spin := 0; spin < 16; spin += 1 {
				grew := false
				bind := func(targets []ast.Expr, values []ast.Expr) {
					carries := false
					for _, value := range values {
						if 0 < len(bears(value, tainted, true)) {
							carries = true
						}
					}
					if !carries {
						return
					}
					for _, target := range targets {
						identifier, ok := target.(*ast.Ident)
						if !ok || identifier.Name == "_" || identifier.Name == "err" {
							continue
						}
						if !tainted[identifier.Name] {
							tainted[identifier.Name] = true
							grew = true
						}
					}
				}
				ast.Inspect(function.Body, func(node ast.Node) bool {
					switch shape := node.(type) {
					case *ast.AssignStmt:
						bind(shape.Lhs, shape.Rhs)
					case *ast.ValueSpec:
						declared := []ast.Expr{}
						for _, target := range shape.Names {
							declared = append(declared, target)
						}
						bind(declared, shape.Values)
					case *ast.RangeStmt:
						bind([]ast.Expr{shape.Key, shape.Value}, []ast.Expr{shape.X})
					}
					return true
				})
				if !grew {
					break
				}
			}

			// THE NARROWING'S CENSUS, taken BEFORE the sinks and independently of them: every
			// `len(...)` of a seed-bearing expression. [wrapSeedBorneBy] will decline to look
			// through these, so this is the only place they are seen, and they are ASSERTED
			// against a written-down list rather than dropped.
			ast.Inspect(function.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok || !wrapSeedIsBuiltinLen(call, local) {
					return true
				}
				for _, argument := range call.Args {
					borne := bears(argument, tainted, true)
					if len(borne) == 0 {
						continue
					}
					site := where + "|len " + wrapSeedExpr(argument)
					counted[site] = append(counted[site], at(call)+" "+fmt.Sprint(borne))
				}
				return true
			})

			if len(tainted) == 0 && len(producers) == 0 {
				continue
			}

			// THE SINKS. Every clause asks an EXPRESSION and not a node class, which is the
			// epoch-key gate's second scar: `x = wrapSeed[:]`, `(wrapSeed)`, `[]byte(wrapSeed)`
			// and `any(wrapSeed).([]byte)` are ONE site rather than four holes.
			landed := map[string]bool{}
			record := func(site string, node ast.Node, expression ast.Expr, borne []string) {
				sinks[site] = append(sinks[site], at(node)+" "+wrapSeedExpr(expression))
				if carried[site] == nil {
					carried[site] = map[string]bool{}
				}
				for _, spelled := range borne {
					carried[site][spelled] = true
					if tainted[spelled] {
						landed[spelled] = true
					}
				}
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				switch shape := node.(type) {
				case *ast.CompositeLit:
					spelled := wrapSeedExpr(shape.Type)
					for index, element := range shape.Elts {
						value := element
						field := fmt.Sprintf("element %d", index)
						if pair, ok := element.(*ast.KeyValueExpr); ok {
							value = pair.Value
							field = wrapSeedExpr(pair.Key)
						}
						borne := bears(value, tainted, false)
						if len(borne) == 0 {
							continue
						}
						record(fmt.Sprintf("%s|literal %s.%s", where, spelled, field),
							element, value, borne)
					}
				case *ast.CallExpr:
					// the builtin `len` is not a sink: it is the narrowing, and it has a census
					// of its own two clauses up.
					if wrapSeedIsBuiltinLen(shape, local) {
						return true
					}
					for _, argument := range shape.Args {
						borne := bears(argument, tainted, false)
						if len(borne) == 0 {
							continue
						}
						record(fmt.Sprintf("%s|call %s", where, wrapSeedExpr(shape.Fun)),
							shape, argument, borne)
					}
				case *ast.AssignStmt:
					for index, target := range shape.Lhs {
						if identifier, bare := target.(*ast.Ident); bare && local[identifier.Name] {
							continue
						}
						var source ast.Expr
						switch {
						case len(shape.Lhs) == len(shape.Rhs):
							source = shape.Rhs[index]
						case len(shape.Rhs) == 1:
							source = shape.Rhs[0]
						default:
							continue
						}
						borne := bears(source, tainted, false)
						if len(borne) == 0 {
							continue
						}
						record(fmt.Sprintf("%s|assign %s", where, wrapSeedExpr(target)),
							shape, source, borne)
					}
				case *ast.ReturnStmt:
					for _, result := range shape.Results {
						borne := bears(result, tainted, false)
						if len(borne) == 0 {
							continue
						}
						record(where+"|return", shape, result, borne)
					}
				case *ast.SendStmt:
					borne := bears(shape.Value, tainted, false)
					if 0 < len(borne) {
						record(fmt.Sprintf("%s|send %s", where, wrapSeedExpr(shape.Chan)),
							shape, shape.Value, borne)
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
	t.Logf("producer net (a name whose call, field read or parameter is taken to be the seed): %v",
		epochKeySortedKeys(wrapSeedProducerNames))
	t.Logf("producer sites found (%d):", len(producers))
	for _, site := range epochKeySortedMap(producers) {
		t.Logf("    %s  at %v", site, producers[site])
	}
	t.Logf("sink sites found (%d), each with THE VALUES IT CARRIES, which is what the disposition "+
		"is held against a second time:", len(sinks))
	for _, site := range epochKeySortedMap(sinks) {
		t.Logf("    %s  carries %v  at %v", site, epochKeySortedKeys(carried[site]), sinks[site])
	}
	t.Logf("COUNTED AND NOT CARRIED (%d) -- the sites the one narrowing removed, which are "+
		"asserted below and not merely printed:", len(counted))
	for _, site := range epochKeySortedMap(counted) {
		t.Logf("    %s  at %v", site, counted[site])
	}
	t.Logf("EXCLUDED, and excluded is not the same as absent -- tainted values that reach no sink "+
		"in their own function, so nothing carried them anywhere: %v", unspent)

	// ── AND ASSERTED, IN BOTH DIRECTIONS, AGAINST THREE WRITTEN-DOWN DISPOSITIONS ─────────────
	wrapSeedHold(t, "producer site", producers, wrapSeedProducerSites,
		"A name that produces this device's X-Wing seed is where this gate's whole search begins. "+
			"A site with no entry is a seed coming from somewhere nobody weighed; an entry with no "+
			"site is this gate having gone BLIND -- the producer was respelled, and the sink "+
			"clauses are now searching a value nothing tainted, which passes by finding nothing.")

	sinkWhy := map[string]string{}
	for site, entry := range wrapSeedSinks {
		sinkWhy[site] = entry.why
	}
	sinkNarrowing := "The device's X-Wing decapsulation seed is a PRIVATE KEY, and the shape this " +
		"gate exists to refuse is the one the epoch-key gate names in its own header: " +
		"`fmt.Errorf(\"%x\", seed)` -- a private key in an error string, in every log that error " +
		"ever reaches. It was MEASURED possible on the commit before this file: two such sites were " +
		"added to device.go and the whole ./urmessage suite stayed green. A site with no entry is a " +
		"seed landing somewhere nobody weighed, and `BlobId: wrapSeed[:]` fails here exactly as " +
		"`fmt.Errorf(\"%x\", wrapSeed)` does. An entry with no site is a disposition that has " +
		"stopped describing the code."
	wrapSeedHold(t, "sink site", sinks, sinkWhy, sinkNarrowing)

	// ── THE SECOND NARROWING: NOT ONLY WHERE, BUT WHICH VALUE ─────────────────────────────────
	for _, site := range epochKeySortedMap(sinks) {
		entry, dispositioned := wrapSeedSinks[site]
		if !dispositioned {
			continue // already refused above, by name
		}
		allowed := map[string]bool{}
		for _, spelled := range entry.carries {
			allowed[spelled] = true
		}
		for _, spelled := range epochKeySortedKeys(carried[site]) {
			if !allowed[spelled] {
				t.Errorf("sink site %q carries %q and its disposition entry does not list it "+
					"(it lists %v).\n%s", site, spelled, entry.carries, sinkNarrowing)
			}
		}
		for _, spelled := range entry.carries {
			if !carried[site][spelled] {
				t.Errorf("the disposition says sink site %q carries %q and the census finds only "+
					"%v there. A value that has stopped arriving is either a fix nobody deleted "+
					"the entry for or a rename this gate is now blind to.\n%s",
					site, spelled, epochKeySortedKeys(carried[site]), sinkNarrowing)
			}
		}
	}

	// ── AND THE ONE NARROWING'S OWN COMPLEMENT, ASSERTED THE SAME WAY ─────────────────────────
	wrapSeedHold(t, "counted-not-carried site", counted, wrapSeedCountedNotCarriedSites,
		"A COUNT OF THE SEED IS NOT THE SEED -- `len(wrapSeed)` is an int -- and that single "+
			"exclusion is what keeps the two store-side refusals OUT of the sink disposition, so "+
			"that an entry for them can never become a standing permit to format the value itself "+
			"at the same call. The exclusion is therefore a narrowing, and this is the assertion "+
			"that holds it: every site it removed is named here. A site with no entry is a count "+
			"nobody weighed; an entry with no site means the tree stopped counting the seed there, "+
			"which is a change this file has to be read against before it is deleted.")
}

// wrapSeedHold is the both-directions assertion the three censuses share.
func wrapSeedHold(t *testing.T, what string, found map[string][]string,
	disposition map[string]string, why string) {

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

// wrapSeedBorneBy is THE ONE QUESTION this gate asks of an expression: which seed-bearing values
// does it bear? It answers the tainted identifiers, the producer calls and the producer field
// reads anywhere inside the expression, spelled the way the source spells them, and the taint step
// and all five sink clauses run it. One predicate asked in every position is the point: the defect
// the epoch-key gate took at 4fde7ad was two positions asking a narrower question than the taint
// step did, so `writeKey[:]` was censused nowhere at all.
//
// IT MATCHES THE VALUE AND NOT THE NODE CLASS, for the reason that file records: `wrapSeed` is an
// *ast.Ident, `wrapSeed[:]` an *ast.SliceExpr, `(wrapSeed)` an *ast.ParenExpr, `parts[3]` an
// *ast.IndexExpr, `[]byte(wrapSeed)` an *ast.CallExpr and `any(wrapSeed).([]byte)` an
// *ast.TypeAssertExpr -- six spellings of one private key.
//
// ITS ONE EXCLUSION IS THE BUILTIN `len`, and it is the clause that differs from the epoch-key
// gate. `len(wrapSeed)` is an int and carries no octet of the key; calling it a carried value
// would force a disposition entry at every site that checks a length, and an entry at a
// `fmt.Errorf` is a permit for whatever else is formatted there. The exclusion is asked of the
// CALL and not the name, and it refuses to fire when the function has declared a local called
// `len` -- a shadow would otherwise switch this clause off from inside the code it inspects. Every
// site it removes is censused and asserted; see [wrapSeedCountedNotCarriedSites].
//
// A NAME IN A NAME POSITION IS NOT A VALUE. `Device{wrapSeed: wrapSeed}` names a field on the left
// and reads a value on the right, and a walk that treated the key as a read would make every
// struct literal in the package a site.
//
// WHAT IT DOES NOT WALK INTO, when intoLiterals is false, is a composite or function literal,
// because the clause above censuses every literal AT ITS OWN FIELD wherever it is written. The
// TAINT step walks with intoLiterals true, because a call handed a literal containing the seed
// returns a value derived from it.
func wrapSeedBorneBy(expression ast.Expr, tainted map[string]bool, intoLiterals bool,
	local map[string]bool) []string {

	if expression == nil {
		return nil
	}
	borne := []string{}
	seen := map[string]bool{}
	carry := func(spelled string) {
		if !seen[spelled] {
			seen[spelled] = true
			borne = append(borne, spelled)
		}
	}
	recurse := func(inner ast.Expr) {
		for _, spelled := range wrapSeedBorneBy(inner, tainted, intoLiterals, local) {
			carry(spelled)
		}
	}
	ast.Inspect(expression, func(node ast.Node) bool {
		switch shape := node.(type) {
		case *ast.CallExpr:
			if wrapSeedIsBuiltinLen(shape, local) {
				return false
			}
			named := wrapSeedCalleeName(shape.Fun)
			if named != "" && wrapSeedProducerNames[named] {
				carry(wrapSeedExpr(shape.Fun))
				// the callee is the producer's own name; only its arguments are values
				for _, argument := range shape.Args {
					recurse(argument)
				}
				return false
			}
		case *ast.SelectorExpr:
			if wrapSeedProducerNames[shape.Sel.Name] {
				carry(wrapSeedExpr(shape))
			}
			recurse(shape.X)
			return false
		case *ast.KeyValueExpr:
			if _, named := shape.Key.(*ast.Ident); named {
				recurse(shape.Value)
				return false
			}
		case *ast.CompositeLit:
			if !intoLiterals {
				return false
			}
		case *ast.FuncLit:
			if !intoLiterals {
				return false
			}
		case *ast.Ident:
			if tainted[shape.Name] {
				carry(shape.Name)
			}
		}
		return true
	})
	sort.Strings(borne)
	return borne
}

// wrapSeedIsBuiltinLen answers whether this call is the builtin `len` and not some local of that
// name. A function that declared `len` would otherwise turn the one exclusion of [wrapSeedBorneBy]
// into a hole, from inside the source this gate inspects.
func wrapSeedIsBuiltinLen(call *ast.CallExpr, local map[string]bool) bool {
	identifier, bare := call.Fun.(*ast.Ident)
	return bare && identifier.Name == "len" && !local["len"] && len(call.Args) == 1
}

// wrapSeedCalleeName is the last name of a callee, bare or qualified: `deviceIdentity` and
// `xwing.Seed` both answer their own final name. The epoch-key gate reads selectors alone, and the
// seed's own package helper is called by its bare name.
func wrapSeedCalleeName(callee ast.Expr) string {
	switch shape := callee.(type) {
	case *ast.Ident:
		return shape.Name
	case *ast.SelectorExpr:
		return shape.Sel.Name
	case *ast.ParenExpr:
		return wrapSeedCalleeName(shape.X)
	}
	return ""
}

// wrapSeedRootName is the identifier an expression is rooted at, or "" for an expression with no
// single root -- a call, a literal, an arithmetic. It is what the producer-function seeding binds:
// `parts[3]` is rooted at `parts` and `leafKeys.ExtensionData` at `leafKeys`. A SELECTOR whose
// field is itself in the producer net has no root here, because the field read is a producer in
// its own right and seeding its receiver would taint the whole of `self`.
func wrapSeedRootName(expression ast.Expr) string {
	switch shape := expression.(type) {
	case *ast.Ident:
		return shape.Name
	case *ast.ParenExpr:
		return wrapSeedRootName(shape.X)
	case *ast.IndexExpr:
		return wrapSeedRootName(shape.X)
	case *ast.SliceExpr:
		return wrapSeedRootName(shape.X)
	case *ast.StarExpr:
		return wrapSeedRootName(shape.X)
	case *ast.UnaryExpr:
		return wrapSeedRootName(shape.X)
	case *ast.SelectorExpr:
		if wrapSeedProducerNames[shape.Sel.Name] {
			return ""
		}
		return wrapSeedRootName(shape.X)
	}
	return ""
}

// wrapSeedExpr spells an expression the way the source does, so a census entry reads as the code
// reads. It is [epochKeyExpr] with the INDEX kept -- `parts[3]` rather than `parts` -- because the
// store's read path spells the seed as one part of a generic record and a census that printed
// `parts` four times over would name the same site for four different values.
func wrapSeedExpr(expression ast.Expr) string {
	if index, ok := expression.(*ast.IndexExpr); ok {
		return wrapSeedExpr(index.X) + "[" + wrapSeedExpr(index.Index) + "]"
	}
	return epochKeyExpr(expression)
}

// ══════════════════════════════════════════════════════════════════════════════════════════════
// THE MUTATION TABLE, MEASURED
// ══════════════════════════════════════════════════════════════════════════════════════════════
//
// NINE MUTANTS, AND EVERY ONE VARIES A DIFFERENT MECHANISM. That is the whole discipline of this
// table and it is the one four gates in this track were beaten for want of: a table whose every
// entry varies the same attribute -- a different destination for the same bare identifier --
// cannot see a change of mechanism, and a change of mechanism is what defeats a gate. So M1 and M2
// vary the PRODUCER the taint starts at, M3 and M8 come at the one narrowing from its two opposite
// sides, M4 is the source file the net could most easily not reach, M5 varies the SPELLING of the
// value, M6 varies the BINDING FORM, M7 does not attack the gate at all but AVOIDS it, and M9 is
// the second direction of the narrowing's own census. A SURVIVING MUTANT IS FIRST A CLAIM ABOUT
// THE QUERY, so each row below names the failure text it produced rather than the word "killed".
//
// Applied one at a time with a python edit that ASSERTS count == 1, and reverted by a byte copy of
// a snapshot taken before the run whose sha256 is verified after: no `git checkout --`, no stash.
// The clean tree was re-run as a control after every single row and answered
// `ok github.com/urnetwork/sdk/urmessage` each time.
//
//	M1  the finding's own mutant A: fmt.Errorf("…(seed %x)…", wrapSeed, err) at deviceIdentity's
//	    persist failure -- the taint started at a PRODUCER CALL
//	    -> sink site "deviceIdentity|call fmt.Errorf" has no entry in the disposition
//	M2  the finding's own mutant B: the same leak at DecapsulateToOwnLeaf, the taint started at a
//	    FIELD READ in a different function
//	    -> sink site "DecapsulateToOwnLeaf|call fmt.Errorf" has no entry in the disposition
//	    -> AND sink site "DecapsulateToOwnLeaf|return" carries "self.wrapSeed" and its disposition
//	       entry does not list it (it lists [shared])  -- two clauses, independently
//	M3  the ONE NARROWING, from the side that would make it a permit: `len(wrapSeed)` -> `wrapSeed`
//	    inside PutDeviceIdentity's own length refusal, the exact call a length-carrying census
//	    would have had to excuse
//	    -> sink site "PutDeviceIdentity|call fmt.Errorf" has no entry in the disposition
//	    (the counted-not-carried entry does NOT go stale here, and that is correct rather than a
//	    miss: the `if len(wrapSeed) != messagegroup.XwingSeedSize` guard that this error belongs to
//	    is still a count of the seed in the same function, so the site is still occupied. M8 is the
//	    row that drives that entry's stale direction, and M9 its unentered direction.)
//	M4  the STORE'S READ PATH: `len(parts[3])` -> `parts[3]` in GetDeviceIdentity's refusal, where
//	    the seed has no name, no producer call and no field read, and only the producer-function
//	    result seeding reaches it at all
//	    -> sink site "GetDeviceIdentity|call fmt.Errorf" has no entry in the disposition
//	M5  the SPELLING: `identityPub: append([]byte(nil), signerPub...)` -> `identityPub: wrapSeed[:]`
//	    -- the 4fde7ad scar, one character, an *ast.SliceExpr where the census used to want an
//	    *ast.Ident
//	    -> "NewDevice|literal Device.identityPub" carries "wrapSeed" and its entry does not list it
//	    -> AND the entry says it carries "signerPub" and the census finds only [wrapSeed] there
//	M6  the BINDING FORM: `var parked = self.wrapSeed` before the erase and `self.wrapSeed = parked`
//	    after it -- the erase performed and then undone, bound with the keyword that bound nothing
//	    when the fixpoint read *ast.AssignStmt alone
//	    -> sink site "Close|assign self.wrapSeed" has no entry in the disposition
//	M7  A CHANGE OF MECHANISM RATHER THAN AN ATTACK: `xwing.Seed()` moved behind a helper
//	    `wrapSeedOf`, which is how a gate is AVOIDED. Both directions of the producer hold fire:
//	    -> producer site "wrapSeedOf|key.Seed" has no entry in the disposition
//	    -> AND the disposition says producer site "deviceIdentity|xwing.Seed" is allowed and the
//	       census does not find it  -- the gate reporting that it has gone blind
//	    -> AND sink site "wrapSeedOf|return" has no entry in the disposition
//	M8  the NARROWING'S OWN GUARD: a local `len` declared in DecapsulateToOwnLeaf, shadowing the
//	    builtin from inside the source this gate inspects
//	    -> sink site "DecapsulateToOwnLeaf|call len" has no entry in the disposition
//	    -> AND the disposition says counted-not-carried site "DecapsulateToOwnLeaf|len
//	       self.wrapSeed" is allowed and the census does not find it
//	M9  the COUNTED CENSUS's second direction: `_ = len(wrapSeed)` added to NewDevice, a function
//	    that counts the seed nowhere today
//	    -> counted-not-carried site "NewDevice|len wrapSeed" has no entry in the disposition
//
// AND THE ONE MEASUREMENT THAT IS THE POINT OF THE FILE. M1 and M2 applied TOGETHER, which is the
// finding exactly as it was reproduced, under the whole package rather than this gate by name:
//
//	before this file:  go test ./urmessage/ -run '.*' -timeout 1800s  ->  ok   … 6.147s
//	after  this file:  go test ./urmessage/ -run '.*' -timeout 1800s  ->  FAIL … 6.118s
//	                   naming both sites, "deviceIdentity|call fmt.Errorf" and
//	                   "DecapsulateToOwnLeaf|call fmt.Errorf"
//
// THERE IS NO LEAK IN THE TREE THIS FILE LANDS ON and this file does not claim to have found one.
// What it claims is the narrower and checkable thing: the leak was possible, it was measured
// possible, and it is now refused.
