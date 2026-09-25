package urmessage

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// ══════════════════════════════════════════════════════════════════════════════════════════════
// EVERY TEST THIS REPOSITORY'S PRODUCTION PROSE CITES EXISTS, AND EXISTS EXACTLY ONCE
// ══════════════════════════════════════════════════════════════════════════════════════════════
//
// WHY THIS IS A GATE AND NOT A CONVENTION. This corpus writes its arguments in production comments
// and discharges them by naming the case that holds each one -- "an arm that forgot would be caught
// by the property rather than by this sentence: <Test...>". A name that resolves to nothing turns
// that discharge into decoration: the sentence still reads as though something holds it, and the
// next reader has no way to find out that nothing does without running the query. Ledger item 257
// recorded exactly that, found by hand: `publishCommitLocked`'s header cited
// TestAMemberRemovedByACommitCannotDeriveTheEpochThatCommitOpens, a name with one hit in either
// repository -- the comment citing it. Driven here at the commit that consumed ruling 51, the same
// query over the whole repository found FOUR more (an eph-wrap twin misnamed by two words, a
// ladder gate that had been renamed, a .def gate that had been renamed, and a stream-store
// exclusion named for a property rather than for the case that holds it) and TWO short forms that
// named a family rather than a case. All six are repaired in that commit; this is what stops the
// seventh.
//
// IT IS A STRUCTURAL PROPERTY AND THE INSTRUMENT IS STRUCTURAL, which is why ruling 46 does not
// apply to it. Ruling 46 refuses an AST reading that stands in for a RUNTIME question -- "does this
// refusal fire for every input it should" -- because each reading it adds is a fresh surface to
// route around. The question here is not about any run: it is *does this identifier name a
// declaration in this corpus*, a fact about the text, decided by reading the text. There is nothing
// behavioural underneath it to be approximated and nothing an indirection can hide, because a
// citation is prose and prose has no indirections.
//
// THE NARROWING IS ASSERTED IN BOTH DIRECTIONS AND NOT MERELY PRINTED. Two dispositions below
// carve names out of the refusal, and each is held both ways: an entry whose name this repository
// declares after all is a FAILURE (the carve-out has gone stale and is now excusing a name the
// plain rule would pass), and an entry no production comment cites any more is a FAILURE (the
// carve-out is excusing nothing and is the shape a disposition rots into). So a rename in connect,
// or the deletion of the one comment that needed an entry, reports here rather than going quiet.
//
// AND THE CONTROLS ARE INLINE AND FIRE FOR THEIR OWN REASONS. The absent literal is the very name
// item 257 found dangling -- it is not declared anywhere in this corpus and must resolve to zero,
// or this query is looking in the wrong place. The present literal is the case that holds the
// removal property one file away, and must resolve to exactly one. A build in which the walk found
// no files at all would answer zero for BOTH, which the second control refuses.

// citationDeclaredElsewhere is every cited name that lives in a SIBLING repository rather than in
// this one, with where it lives and why this file cannot simply look.
//
// WHY A TABLE AND NOT A WALK OF ../connect. connect's own cross-repo gate reads ../../sdk, so the
// precedent for reaching across exists -- and the cost is what decides against it here: a walk of
// a sibling checkout makes THIS repository's suite depend on that checkout being present and at a
// compatible commit, so a developer with only `sdk` cloned gets a red suite about somebody else's
// file layout. A table costs one line per citation, needs no second checkout, and -- because it is
// held both ways below -- reports a connect rename as loudly as a walk would. What it cannot do is
// notice that the named test has been DELETED in connect while its name stays in this table; that
// residual is stated here rather than left to be found, and the reading that closes it is connect's
// own suite going red on the deletion.
var citationDeclaredElsewhere = map[string]string{
	"TestABodyNoRungCouldHoldCostsNeitherAnIndexNorAGeneration": "connect/messagegroup/mlsframe_test.go -- " +
		"the frame-size ladder is connect's and the cost it prices is read from this side",
	"TestARemovalWhoseLeafIsRefilledInTheSameCommitIsStillNamedByTheStagedCommit": "connect/messagegroup/" +
		"engineremovewithextensions_test.go -- ledger ruling 51's derivation held one layer down, " +
		"on the seam's own PendingEpoch.RemovedLeaves",
	"TestAnyMemberCanStillSquatAnotherLeafsStreamIndex": "connect/messagegroup/m1w1repairs_test.go -- " +
		"the squat is a property of the server's index space, which connect owns",
	"TestClassBucketJoinIsConfinedToRecordGo": "connect/message/record_test.go -- the class bucket's " +
		"join is connect's, and this repository is the caller it is confined against",
	"TestTheCommittersOwnPathCanSwapItsLeafIdentityAndOnlyThePreCommitTreeStillNamesIt": "connect/mls/" +
		"staged_after_test.go -- the staged tree's own behaviour, below the seam",
	"TestTheSizeLadderCostOfTheInnerFrameIsMeasuredHere": "connect/messagegroup/mlsframe_test.go -- " +
		"the same ladder as the first entry, measured rather than reasoned",
}

// citationIsNotACase is a name the language reserves, cited as a mechanism rather than as a case.
//
// TestMain IS GO'S OWN ENTRY POINT and a package may declare at most one, so "exactly one
// declaration in this repository" is the wrong question about it: this repository has one and every
// sibling module may have its own, and a comment that says "TestMain installs X" is naming the
// hook and not a property somebody holds. It is carved out BY NAME and held both ways like the
// table above, so the day nothing cites it this entry reports rather than sitting here.
var citationIsNotACase = map[string]string{
	"TestMain": "go's own per-package entry point, named as a mechanism rather than as a case; " +
		"a repository has one per package and the count is meaningless",
}

func TestEveryTestNameCitedInThisRepositorysProductionProseResolvesToOneDeclaration(t *testing.T) {
	root := moduleRoot(t)
	// a Go test function's declaration, and the citation net that has to find the same spelling.
	declaration := regexp.MustCompile(`(?m)^func\s+(Test[A-Z][A-Za-z0-9_]*)\s*\(`)
	citation := regexp.MustCompile(`\bTest[A-Z][A-Za-z0-9_]*`)

	declared := map[string][]string{}
	cited := map[string][]string{}
	production, total := 0, 0
	err := filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if info.IsDir() {
			if name := info.Name(); name == ".git" || name == "testdata" || name == "vendor" || name == "build" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		source, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		total += 1
		rel := filepath.ToSlash(func() string {
			at, _ := filepath.Rel(root, path)
			return at
		}())
		for _, one := range declaration.FindAllStringSubmatch(string(source), -1) {
			declared[one[1]] = append(declared[one[1]], rel)
		}
		if strings.HasSuffix(path, "_test.go") {
			return nil
		}
		production += 1
		// THE CITATION IS IN A COMMENT AND NOWHERE ELSE. A production file cannot call a test, so
		// a Test... spelling outside a comment would be a different finding; reading only the
		// comment half keeps this gate's subject the PROSE, which is what rots.
		for at, line := range strings.Split(string(source), "\n") {
			cut := strings.Index(line, "//")
			if cut < 0 {
				continue
			}
			for _, name := range citation.FindAllString(line[cut:], -1) {
				cited[name] = append(cited[name], fmt.Sprintf("%s:%d", rel, at+1))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking %s: %v", root, err)
	}

	// ── THE CONTROLS, IN THE SAME QUERY AND OVER THE SAME MAPS ─────────────────────────────────
	const absent = "TestAMemberRemovedByACommitCannotDeriveTheEpochThatCommitOpens"
	const present = "TestThreeMembersRotateAcrossTwoEpochsAndAMemberRemovedByThatCommitCannotFollow"
	if found := len(declared[absent]); found != 0 {
		t.Fatalf("CONTROL FAILED: %s resolves to %d declaration(s). It is ledger item 257's own "+
			"dangling citation and this query is supposed to answer zero for it; a non-zero answer "+
			"means the net is matching something that is not a declaration", absent, found)
	}
	if found := len(declared[present]); found != 1 {
		t.Fatalf("CONTROL FAILED: %s resolves to %d declaration(s), want 1. Without this the zero "+
			"above is satisfied by a walk that read no files at all", present, found)
	}
	if production == 0 || total == production {
		t.Fatalf("CONTROL FAILED: the walk saw %d .go files of which %d are production; a run with "+
			"no production files or no test files is measuring nothing", total, production)
	}

	// ── THE DISPOSITIONS, HELD BOTH WAYS ───────────────────────────────────────────────────────
	for name, why := range citationDeclaredElsewhere {
		if here := declared[name]; 0 < len(here) {
			t.Errorf("%s is carved out as living in a sibling repository (%s) and THIS repository "+
				"declares it at %s. The entry is excusing a name the plain rule would pass; delete it",
				name, why, strings.Join(here, ", "))
		}
		if len(cited[name]) == 0 {
			t.Errorf("%s is carved out as living in a sibling repository (%s) and no production "+
				"comment cites it any more. An entry nothing needs is how a disposition rots; delete it",
				name, why)
		}
	}
	for name, why := range citationIsNotACase {
		if len(cited[name]) == 0 {
			t.Errorf("%s is carved out as not-a-case (%s) and no production comment names it any "+
				"more; delete the entry", name, why)
		}
	}

	// ── THE PROPERTY ───────────────────────────────────────────────────────────────────────────
	names := []string{}
	for name := range cited {
		names = append(names, name)
	}
	sort.Strings(names)
	here, elsewhere, exempt := 0, 0, 0
	for _, name := range names {
		if _, carved := citationIsNotACase[name]; carved {
			exempt += 1
			continue
		}
		if _, carved := citationDeclaredElsewhere[name]; carved {
			elsewhere += 1
			continue
		}
		found := declared[name]
		if len(found) == 1 {
			here += 1
			continue
		}
		if len(found) == 0 {
			// the nearest declared name, so a rename or a typo says so rather than making the
			// reader run the query by hand. It is a REPORT and not a suggestion: naming the wrong
			// case is worse than naming none, so what follows the colon has to be read before it
			// is written in.
			t.Errorf("%s is cited at %s and NOTHING in this repository declares it. A sentence that "+
				"names a case which does not exist reads as though something holds it and nothing "+
				"does. Either the case is in a sibling repository -- add it to "+
				"citationDeclaredElsewhere, having READ what it holds -- or the citation is stale "+
				"and the right name goes here.%s",
				name, strings.Join(cited[name], ", "), citationNearest(name, declared))
			continue
		}
		t.Errorf("%s is cited at %s and this repository declares it %d times (%s), so the citation "+
			"does not say which one", name, strings.Join(cited[name], ", "), len(found),
			strings.Join(found, ", "))
	}

	// ── THE COMPLEMENT, PRINTED BESIDE WHAT WAS ASSERTED ───────────────────────────────────────
	t.Logf("%d .go files walked, %d of them production; %d distinct Test... names declared here",
		total, production, len(declared))
	t.Logf("%d distinct names cited in production prose: %d declared here exactly once, %d carved "+
		"out to a sibling repository, %d carved out as not-a-case", len(names), here, elsewhere, exempt)
	if here == 0 {
		t.Errorf("no cited name resolves inside this repository at all, so the rule above is " +
			"vacuous and only the carve-outs are being exercised")
	}
}

// citationNearest is the declared name that shares the longest prefix with a dangling one, as a
// suffix for the failure above, or the empty string when nothing is close. It exists so a two-word
// rename says so in the failure rather than in a reader's next hour.
func citationNearest(name string, declared map[string][]string) string {
	best, longest := "", 0
	for candidate := range declared {
		shared := 0
		for shared < len(name) && shared < len(candidate) && name[shared] == candidate[shared] {
			shared += 1
		}
		if longest < shared {
			best, longest = candidate, shared
		}
	}
	if best == "" || longest < 12 {
		return ""
	}
	return fmt.Sprintf(" The declared name sharing the longest prefix (%d characters) is %s -- READ "+
		"WHAT IT HOLDS before writing it in.", longest, best)
}
