package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/urnetwork/sdk/urmessage"
)

// THE GO-LEVEL HALF, AND IT IS THE SMALLER HALF ON PURPOSE.
//
// ctest/message_abi_test.c is the real test of this binding: it drives the abi from C, through a
// real message server, with real handles, real malloc'd strings and a real second OS thread, and
// it is where "a C program can send a message and read it back" is answered. What is HERE is the
// part that C test cannot reach on this host:
//
//   - THE RACE DETECTOR. `go build -race -buildmode=c-shared` produces a dll, and on Windows
//     ThreadSanitizer cannot map its shadow memory when that dll is loaded into an already
//     running process: the C consumer dies before main with "ThreadSanitizer failed to allocate
//     0x6920000 bytes ... (error code: 87)". So `go test -race` over the same registry and the
//     same context handles is what holds the concurrency property on this host, and
//     ctest/run.sh prints that where it tries.
//   - THE COMPLEMENT OF THE BODY DECISION. The C test shows octets surviving. This shows what
//     they would NOT have survived, which is the half that says the decision is load bearing
//     rather than decorative.
//
// NOTE FOR ANYONE EXTENDING THIS FILE: it must not `import "C"`. Go does not support cgo in a
// _test.go file ("use of cgo in test ... not supported"), so nothing here may NAME a C type. The
// exported functions are still callable -- their results carry the C types without being spelled.

// urnet_message_context_new and urnet_release are the two halves of a handle's life, and a ui
// that polls a conversation on one thread while another closes the app runs them at once.
//
// THE ASSERTION IS THE COUNT, NOT THE ABSENCE OF A CRASH. A registry that lost an entry under a
// race leaves the count low and one that double-inserted leaves it high; both are silent without
// this, and both would show up in a real app as handles that outlive their objects.
func TestTheHandleCountComesBackUnderConcurrentCreateCancelAndRelease(t *testing.T) {
	before := handleCount()
	const writers = 16
	const each = 250
	var wait sync.WaitGroup
	wait.Add(writers)
	for at := 0; at < writers; at += 1 {
		go func() {
			defer wait.Done()
			for n := 0; n < each; n += 1 {
				handle := urnet_message_context_new()
				if handle == 0 {
					t.Error("context_new answered 0")
					return
				}
				urnet_message_context_cancel(handle)
				// cancel is idempotent: a ui that closes twice must not be a panic
				urnet_message_context_cancel(handle)
				if !urnet_release(handle) {
					t.Error("releasing a live handle answered false")
					return
				}
				if urnet_release(handle) {
					t.Errorf("releasing handle %d twice answered true both times", uint64(handle))
					return
				}
			}
		}()
	}
	wait.Wait()
	if after := handleCount(); after != before {
		t.Errorf("%d handles leaked across %d create/cancel/release cycles (%d -> %d)",
			after-before, writers*each, before, after)
	}
}

// A handle id is never reused, so a stale handle a C caller kept can never resolve to a NEW
// object. It is the property that makes a bare uint64_t safe to hold: without it, releasing a
// group and then calling _group_send on the old value could reach some other group entirely.
func TestAReleasedHandleIsNeverHandedOutAgain(t *testing.T) {
	seen := map[uint64]bool{}
	var last uint64
	for n := 0; n < 2000; n += 1 {
		handle := urnet_message_context_new()
		if seen[uint64(handle)] {
			t.Fatalf("handle %d was issued twice", uint64(handle))
		}
		seen[uint64(handle)] = true
		last = uint64(handle)
		urnet_message_context_cancel(handle)
		urnet_release(handle)
	}
	if _, ok := handleValue(last); ok {
		t.Fatalf("released handle %d still resolves to an object", last)
	}
}

// messageCtx is what every blocking export calls, and the two answers it must keep apart are
// "the caller passed nothing, so this call is uncancellable" and "the caller passed a handle
// that is not one of ours". The second must be REFUSED: a call that silently ran on
// context.Background() while its caller believed it held a cancel handle is a call that cannot
// be stopped, which is the whole failure the handle exists to prevent.
func TestAnUnknownContextHandleIsRefusedRatherThanDowngradedToBackground(t *testing.T) {
	ctx, ok := messageCtx(0, "test")
	if !ok || ctx == nil {
		t.Error("a zero context handle was refused; it is the documented uncancellable call")
	} else if ctx != context.Background() {
		t.Error("a zero context handle did not answer context.Background()")
	}
	// an id the registry has never issued. 1<<63 is far above any id this process allocates.
	if _, ok := messageCtx(1<<63, "test"); ok {
		t.Error("an unknown context handle was accepted, and the call it came from would have run " +
			"uncancellable while its caller believed it could be stopped")
	}
	// an id that WAS ours and has been released
	handle := urnet_message_context_new()
	urnet_release(handle)
	if _, ok := messageCtx(handle, "test"); ok {
		t.Error("a released context handle was accepted")
	}
}

// Cancelling from one goroutine while others hold the context is the shape of "the app is
// closing while a poll is in flight", which is what the C test does across an OS thread.
func TestCancelIsSeenByEveryHolderOfTheContext(t *testing.T) {
	handle := urnet_message_context_new()
	defer urnet_release(handle)
	ctx, ok := messageCtx(handle, "test")
	if !ok {
		t.Fatal("a context this test just created did not resolve")
	}
	const holders = 32
	var wait sync.WaitGroup
	wait.Add(holders)
	for at := 0; at < holders; at += 1 {
		go func() {
			defer wait.Done()
			<-ctx.Done()
		}()
	}
	go urnet_message_context_cancel(handle)
	// a holder that is never woken hangs here rather than failing, and the panic the test
	// timeout prints names every stuck goroutine, which is the more useful report
	wait.Wait()
	if ctx.Err() == nil {
		t.Error("the context reports no error after being cancelled")
	}
}

// ── the complement of the body decision ─────────────────────────────────────────────────────

// THE BODY THAT WOULD NOT HAVE SURVIVED. exports_message.go decides that a body crosses as
// counted octets and never as a char* and never inside json. This measures what each REJECTED
// alternative would have done to these octets, so that the decision is defended by a number rather
// than by the paragraph above it.
//
// THESE 21 OCTETS USED TO BE ctest/message_abi_test.c's kBody, CHARACTER FOR CHARACTER, AND THEY
// ARE NO LONGER. Since the content envelope a TEXT tail is checked for valid UTF-8 before it is
// sealed, so the C test cannot SEND 0xFF 0xFE or the ill-formed 0xC3 0x28 -- Group.Send refuses
// them, and that is what had made ctest red at sdk bd4672d, at its first send. kBody there is now
// valid UTF-8 with the two NULs kept, because the NUL is the half a real seal can still carry.
//
// SO THE JSON HALF LIVES HERE, AND ONLY HERE. This case seals nothing and can therefore still hold
// the octets that would be corrupted, which is the whole reason it is not deleted along with them:
// a body from a kind this build does not know is not checked for UTF-8 by anything (it is not
// text, and there is no tail to check), so json remains the wrong carrier for a body even though
// no send path can now produce an ill-formed one.
func TestTheRejectedBodyEncodingsWouldHaveChangedTheseOctets(t *testing.T) {
	body := []byte("hello from C\x00\xff\xfex\xc3\x28\n\x00z")
	if len(body) != 21 {
		t.Fatalf("this case's body is %d octets and both halves of it are written for 21", len(body))
	}

	// (1) as a char*, which is NUL terminated: a C caller reading it stops at the first 0x00.
	truncated := body
	for at, octet := range body {
		if octet == 0 {
			truncated = body[:at]
			break
		}
	}
	if len(truncated) == len(body) {
		t.Fatal("this body has no NUL in it, so the char* case proves nothing")
	}
	t.Logf("as a char*: %d octets of %d, losing %d", len(truncated), len(body), len(body)-len(truncated))

	// (2) inside json, which is how every other data type in this abi crosses.
	encoded, err := json.Marshal(map[string]string{"text": string(body)})
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	var back map[string]string
	if err := json.Unmarshal(encoded, &back); err != nil {
		t.Fatalf("unmarshalling: %v", err)
	}
	if back["text"] == string(body) {
		t.Error("json round-tripped these octets unchanged, so the no-json rule defends nothing " +
			"and this body needs ill-formed utf-8 in it")
	}
	t.Logf("through json: %d octets of %d, carrying %d replacement characters",
		len(back["text"]), len(body), strings.Count(back["text"], "�"))

	// The abi's own answer -- copyOut over these same octets -- is measured in C, where the
	// pointer and the length are real: ctest/message_abi_test.c compares all 21 one at a time.
}

// The metadata projection carries no body at all, which is what keeps (2) above from happening
// by accident the day somebody adds a field to it.
func TestTheMessageMetadataProjectionCarriesNoBody(t *testing.T) {
	message := &urmessage.Message{
		RecordId:     7,
		SenderHandle: []byte{0x00, 0x11, 0xAB, 0xFF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		Mine:         true,
		Text:         "a body that must not appear anywhere in this json \x00\xff",
		SentAtMs:     1234,
	}
	encoded, err := json.Marshal(messageInfoOf(messageEntryOf(message)))
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	if strings.Contains(string(encoded), "a body that must not appear") {
		t.Errorf("the metadata json carries the body: %s", encoded)
	}
	for _, want := range []string{
		`"record_id":7`,
		`"sender_handle":"0011abff0102030405060708090a0b0c"`,
		`"mine":true`,
		`"sent_at_ms":1234`,
		`"body_len":52`,
	} {
		if !strings.Contains(string(encoded), want) {
			t.Errorf("the metadata json is missing %s: %s", want, encoded)
		}
	}
	if messageInfoOf(messageEntryOf(nil)) != nil {
		t.Error("a nil message projected to something")
	}
}

// ── the projection that lost five fields, and the gate that makes the next one loud ─────────

// messageInfoExempt is every field of urmessage.Message that the metadata json deliberately does
// NOT carry, with the reason and with where it crosses instead. It is the gate's exemption list and
// it is printed on every run: an exemption nobody reads is an exemption that outlives its reason.
var messageInfoExempt = map[string]string{
	"Text": "the BODY. it is arbitrary octets from another device and json would replace every " +
		"ill-formed one with U+FFFD, so it crosses through urnet_message_list_body and never " +
		"here. body_len is what the json says about it.",
	"Reactions": "a per-message COLLECTION with no cap on it, so it crosses through " +
		"urnet_message_list_reaction_count and _reaction_info rather than as an array that " +
		"would make one row's metadata unbounded. reaction_count is what the json says about it.",
}

// EVERY FIELD urmessage.Message CARRIES REACHES A C CALLER, OR IS EXEMPT BY NAME WITH A REASON.
//
// THIS IS THE GATE FOR THE DEFECT ITSELF AND NOT FOR ONE INSTANCE OF IT. messageInfo is a HAND
// projection -- exports_message.go says why -- so a field added to urmessage.Message arrives at a C
// caller as NOTHING AT ALL unless somebody remembers to add it here. Kind, ReplyToId, Deleted,
// Reactions and then Gap all landed that way and all reached C as nothing, with every test in this
// package green (msgrepo ledger item 236). This is what makes the next one red.
//
// IT IS TWO CHECKS AND THE SECOND IS THE ONE THAT MATTERS. A field that exists on messageInfo and
// is never ASSIGNED is exactly as invisible as one that does not exist, so the fixture below sets
// every field of urmessage.Message to a non-zero value and every field of the projection must come
// out non-zero. Declaring the field is not enough; filling it is the property.
//
// WHAT WOULD GO RED: add a field to urmessage.Message and not to messageInfo; declare one in
// messageInfo and forget to assign it in messageInfoOf; exempt a field that no longer exists.
func TestTheMessageInfoCarriesEveryFieldUrmessageKeeps(t *testing.T) {
	// the fixture: every field of urmessage.Message non-zero, so that "carried" can mean
	// "arrived with a value" rather than "was declared"
	message := &urmessage.Message{
		RecordId:     7,
		SenderHandle: []byte{0x00, 0x11, 0xAB, 0xFF, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12},
		Mine:         true,
		Text:         "a body",
		SentAtMs:     1234,
		MessageId:    bytes.Repeat([]byte{0x5A}, 32),
		Kind:         urmessage.KindReply,
		Gap:          urmessage.GapUnsupported,
		ReplyToId:    bytes.Repeat([]byte{0xC3}, 32),
		Deleted:      true,
		Reactions:    []urmessage.Reaction{{SenderHandle: []byte{0x01}, Emoji: "x", Mine: true}},
	}

	kept := reflect.TypeOf(urmessage.Message{})
	fixture := reflect.ValueOf(*message)
	for at := 0; at < kept.NumField(); at += 1 {
		if fixture.Field(at).IsZero() {
			t.Fatalf("this case's fixture leaves urmessage.Message.%s at its zero value, so "+
				"nothing below can tell a field that is carried from one that is dropped",
				kept.Field(at).Name)
		}
	}

	// every field of the projection arrived with a value
	info := messageInfoOf(messageEntryOf(message))
	if info == nil {
		t.Fatal("the projection answered nil for a message")
	}
	carried := reflect.TypeOf(messageInfo{})
	projected := reflect.ValueOf(*info)
	for at := 0; at < carried.NumField(); at += 1 {
		if projected.Field(at).IsZero() {
			t.Errorf("messageInfo.%s (json %q) is declared and never assigned, which reaches a C "+
				"caller as exactly the same nothing as not existing",
				carried.Field(at).Name, carried.Field(at).Tag.Get("json"))
		}
	}

	// and every field urmessage keeps is either one of those or exempt by name
	names := map[string]bool{}
	for at := 0; at < carried.NumField(); at += 1 {
		names[carried.Field(at).Name] = true
	}
	exempted := 0
	for at := 0; at < kept.NumField(); at += 1 {
		name := kept.Field(at).Name
		if names[name] {
			continue
		}
		why, allowed := messageInfoExempt[name]
		if !allowed {
			t.Errorf("urmessage.Message keeps %s and urnet_message_list_info does not carry it; "+
				"a C caller cannot see it at all", name)
			continue
		}
		exempted += 1
		t.Logf("EXEMPT %s: %s", name, why)
	}
	// AND AN EXEMPTION THAT OUTLIVED ITS USE IS A FAILURE. An exemption for a field urmessage no
	// longer has, or for one the projection has since started carrying, is a hole standing open
	// over nothing -- and it is silent, because an exemption reports nothing by construction.
	for name := range messageInfoExempt {
		if _, kept := kept.FieldByName(name); !kept {
			t.Errorf("%s is exempt from this gate and urmessage.Message no longer has a field by "+
				"that name; the exemption has outlived what it was for", name)
		}
		if names[name] {
			t.Errorf("%s is exempt from this gate and messageInfo carries it anyway; the "+
				"exemption is stale and hides the next field that goes missing", name)
		}
	}
	if exempted != len(messageInfoExempt) {
		t.Errorf("the gate used %d exemptions of the %d declared", exempted, len(messageInfoExempt))
	}
	t.Logf("%d of urmessage.Message's %d fields cross in the info json, %d by other exports",
		kept.NumField()-exempted, kept.NumField(), exempted)
}

// A GAP IS NOT A MESSAGE WITH NO TEXT, AND THAT IS THE WHOLE OF LEDGER ITEM 236.
//
// Both are body_len 0. Before the gap field a C caller had no other difference to read: an
// unsupported record and a line somebody sent nothing on projected to the same json, and a UI that
// drew a blank line for the first was telling a user that a member had said nothing when in fact
// something was there that this build could not show.
//
// WHAT WOULD GO RED: drop Gap from messageInfo, or project it as "" -- a gap reported as a normal
// message, which is the mutation this case exists for.
func TestAGapIsDistinguishableFromAMessageWithNoText(t *testing.T) {
	blank := &urmessage.Message{RecordId: 4, Kind: urmessage.KindText}
	// A MALFORMED REPLY IS THE HARD CASE AND THAT IS WHY IT IS THE ONE HERE: Kind is the code the
	// record ARRIVED under and not what the record is, so this gap carries KindReply. A caller
	// that branched on kind would render it as a reply with nothing in it.
	gap := &urmessage.Message{RecordId: 5, Kind: urmessage.KindReply, Gap: urmessage.GapMalformed}

	blankInfo := messageInfoOf(messageEntryOf(blank))
	gapInfo := messageInfoOf(messageEntryOf(gap))
	if blankInfo.BodyLen != gapInfo.BodyLen {
		t.Fatalf("the two differ by body_len alone (%d and %d), so this case is not measuring what "+
			"it says it is", blankInfo.BodyLen, gapInfo.BodyLen)
	}
	if blankInfo.Gap != "" {
		t.Errorf("a message that is a message reports gap %q", blankInfo.Gap)
	}
	if gapInfo.Gap != string(urmessage.GapMalformed) {
		t.Errorf("a malformed record reports gap %q, want %q", gapInfo.Gap, urmessage.GapMalformed)
	}
	// and the two vocabularies do not collide: "malformed" and "unsupported" are different
	// sentences to a user, and one of them offers an upgrade that the other must not
	unsupported := messageInfoOf(messageEntryOf(&urmessage.Message{Gap: urmessage.GapUnsupported}))
	if unsupported.Gap == gapInfo.Gap {
		t.Errorf("both gap reasons project to %q", unsupported.Gap)
	}
	encoded, err := json.Marshal(gapInfo)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	if !strings.Contains(string(encoded), `"gap":"malformed"`) {
		t.Errorf("the gap json is %s", encoded)
	}
	if !strings.Contains(string(encoded), `"kind":2`) {
		t.Errorf("the gap does not carry the code it arrived under: %s", encoded)
	}
}

// ── a list handle is ONE INSTANT of the conversation ────────────────────────────────────────

// callExport drives an exported function with values this package minted.
//
// IT IS reflect RATHER THAN A CALL because this file must not `import "C"` -- go does not support
// cgo in a _test.go file -- so C.uint64_t and C.int32_t cannot be NAMED here and a plain uint64
// handle cannot be passed to an export that declares one. Converting through the parameter types
// the function itself declares needs no name at all, and it is what lets the cases below drive the
// REAL exports rather than the unexported machinery under them.
func callExport(t *testing.T, fn any, args ...any) []reflect.Value {
	t.Helper()
	value := reflect.ValueOf(fn)
	shape := value.Type()
	if shape.NumIn() != len(args) {
		t.Fatalf("the export takes %d arguments and %d were passed", shape.NumIn(), len(args))
	}
	in := make([]reflect.Value, 0, len(args))
	for at, arg := range args {
		in = append(in, reflect.ValueOf(arg).Convert(shape.In(at)))
	}
	return value.Call(in)
}

func listReactionCount(t *testing.T, list uint64, index int) int {
	t.Helper()
	return int(callExport(t, urnet_message_list_reaction_count, list, index)[0].Int())
}

// A LIST HANDLE ANSWERS FROM ONE INSTANT, AND urmessage REWRITES A MESSAGE AFTER IT IS IN THE LOG.
//
// Group.Messages says "the messages themselves are shared and are not written after they are
// appended" and that sentence is FALSE for two fields: reapplyLocked sets Deleted and rebuilds
// Reactions on a message that is already in the log, every time a reaction or a tombstone for it
// arrives. This abi is polled from one thread and rendered from another -- the threading decision
// at the top of exports_message.go is exactly that -- so a list handle that read those two live
// would answer _reaction_count and _reaction_info from two different instants, and a C caller
// looping `for k in 0..count` would read past the end of a list that had just shrunk.
//
// The mutation below is a later Receive, written as the in-place rewrite it is.
//
// WHAT WOULD GO RED: have newMessageList keep the *Message and have the accessors read
// entry.message.Reactions and entry.message.Deleted.
func TestAListHandleAnswersFromOneInstantOfTheConversation(t *testing.T) {
	message := &urmessage.Message{
		RecordId:     9,
		SenderHandle: bytes.Repeat([]byte{0x11}, 16),
		Text:         "a line two people reacted to",
		MessageId:    bytes.Repeat([]byte{0x22}, 32),
		Kind:         urmessage.KindText,
		Reactions: []urmessage.Reaction{
			{SenderHandle: bytes.Repeat([]byte{0xAA}, 16), Emoji: "👍"},
		},
	}
	list := newMessageList([]*urmessage.Message{message})
	if list == 0 {
		t.Fatal("a one message list answered handle 0")
	}
	defer handleRelease(list)

	if got := listReactionCount(t, list, 0); got != 1 {
		t.Fatalf("the list answered %d reactions, want 1", got)
	}
	before := messageInfoOf(messageEntryOf(message))
	// the array the message held at that instant, kept for the copy check at the end: the append
	// below reallocates, so after it the message no longer points at this one
	original := message.Reactions

	// a later Receive: one more reaction, and the sender's own tombstone, both written IN PLACE
	// onto a message that is already in the log
	message.Reactions = append(message.Reactions, urmessage.Reaction{
		SenderHandle: bytes.Repeat([]byte{0xBB}, 16), Emoji: "🎯", Mine: true,
	})
	message.Deleted = true

	if got := listReactionCount(t, list, 0); got != 1 {
		t.Errorf("a reaction that landed after the list was built changed it to %d; the count and "+
			"the info a caller has already read would disagree with each other", got)
	}
	held, ok := handleValue(list)
	if !ok {
		t.Fatal("the list handle stopped resolving")
	}
	after := messageInfoOf(held.(*messageList).entries[0])
	if after.ReactionCount != before.ReactionCount || after.Deleted != before.Deleted {
		t.Errorf("the list's own info moved under it: reaction_count %d -> %d, deleted %v -> %v",
			before.ReactionCount, after.ReactionCount, before.Deleted, after.Deleted)
	}
	// AND THE SNAPSHOT IS A COPY OF THE ARRAY AND NOT A RESLICE OF IT, which is a guard rather
	// than a repair and is labelled as one. urmessage REBUILDS the whole slice today --
	// reapplyLocked clears Reactions and re-appends, and the REMOVE arm makes a new slice -- so
	// nothing it does now can be seen through a shared array, and the append above cannot see it
	// either, because appending past cap reallocates and leaves the old array alone. The only
	// thing that can observe the difference is a write INTO an element, which is why the line
	// below writes into the array the message held when the snapshot was taken. Without it,
	// dropping the copy has no killer at all.
	standing := held.(*messageList).entries[0].reactions
	original[0].Emoji = "a rebuild that wrote in place"
	if standing[0].Emoji != "👍" {
		t.Errorf("the snapshot shares its array with the message: reaction 0 is now %q", standing[0].Emoji)
	}

	// the bounds, which C cannot tell apart from a refusal because cgoGuard recovers a panic
	for _, one := range []struct{ index, reaction int }{{-1, 0}, {1, 0}, {0, -1}, {0, 5}} {
		if got := callExport(t, urnet_message_list_reaction_info, list, one.index, one.reaction)[0]; !got.IsNil() {
			t.Errorf("message %d reaction %d answered something", one.index, one.reaction)
		}
	}
	if got := listReactionCount(t, list, 3); got != 0 {
		t.Errorf("reaction_count at index 3 of a 1 message list answered %d", got)
	}
	if got := listReactionCount(t, 0, 0); got != 0 {
		t.Errorf("reaction_count on handle 0 answered %d", got)
	}
}

// THE EMOJI MAY CROSS INSIDE JSON AND A BODY MAY NOT, AND THE DIFFERENCE IS ONE VALIDATION.
//
// The body decision at the top of exports_message.go bans json for octets that arrive from another
// device, because encoding/json replaces every ill-formed byte with U+FFFD in silence. A reaction's
// emoji arrives from another device too, and it rides inside json anyway -- the premise being that
// urmessage's checkEmoji requires valid UTF-8 of 1..MaxEmojiOctets octets on BOTH paths into a
// Reaction. This measures both halves of that premise so it is a number rather than a sentence: what
// a valid emoji does through the projection, and what one checkEmoji would have refused would have
// done. The second half is the one that says the validation is load-bearing.
//
// WHAT WOULD GO RED: nothing here, if checkEmoji stops requiring valid UTF-8 -- that is urmessage's
// gate to keep. What goes red here is the emoji being carried as anything other than its own octets.
func TestTheEmojiSurvivesJsonAndAnIllFormedOneWouldNot(t *testing.T) {
	// the last of these is the one a char* would have lost: U+0000 IS valid utf-8, so checkEmoji
	// accepts it, and json carries it as an escape while a NUL-terminated string would have handed
	// back one octet of a three octet emoji with no error raised anywhere
	for _, emoji := range []string{"👍", "👨‍👩‍👧", "❤️", "a\x00b"} {
		encoded, err := json.Marshal(reactionInfoOf(urmessage.Reaction{
			SenderHandle: bytes.Repeat([]byte{0x7F}, 16), Emoji: emoji, Mine: true,
		}))
		if err != nil {
			t.Fatalf("marshalling %q: %v", emoji, err)
		}
		var back messageReactionInfo
		if err := json.Unmarshal(encoded, &back); err != nil {
			t.Fatalf("unmarshalling %q: %v", emoji, err)
		}
		if back.Emoji != emoji {
			t.Errorf("the emoji %q came back as %q", emoji, back.Emoji)
		}
		if !back.Mine || back.SenderHandle != strings.Repeat("7f", 16) {
			t.Errorf("the rest of the reaction came back as %+v", back)
		}
		if len(emoji) > urmessage.MaxEmojiOctets {
			t.Errorf("this case's emoji %q is %d octets and checkEmoji caps one at %d",
				emoji, len(emoji), urmessage.MaxEmojiOctets)
		}
	}

	// THE COMPLEMENT. An emoji checkEmoji would have refused does NOT survive, which is what makes
	// the validation the reason this field may be json at all rather than a coincidence.
	illFormed := "\xff\xfe\xc3\x28"
	encoded, err := json.Marshal(reactionInfoOf(urmessage.Reaction{Emoji: illFormed}))
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	var back messageReactionInfo
	if err := json.Unmarshal(encoded, &back); err != nil {
		t.Fatalf("unmarshalling: %v", err)
	}
	if back.Emoji == illFormed {
		t.Error("json round-tripped ill-formed utf-8 unchanged, so the checkEmoji premise defends " +
			"nothing and this case measures nothing")
	}
	t.Logf("ill-formed: %d octets in, %d out, %d replacement characters -- which is what the emoji "+
		"would do here if checkEmoji ever stopped requiring valid utf-8",
		len(illFormed), len(back.Emoji), strings.Count(back.Emoji, "�"))
}

// PROTOCOL_VERSION: 0 IS THIS BUILD'S VERSION, THE BUILD'S VERSION IS ITSELF, AND NOTHING ELSE IS
// ACCEPTED.
//
// The review that found this passed 0 by analogy with every other 0 in this abi and lost a whole
// conversation to a Hello the server refused two calls later. The C consumer holds the export end to
// end (2 and 3 refused at transport_new, 0 connecting); this holds the whole range of the rule at
// its edges, which C would need a server per value to reach.
//
// WHAT WOULD GO RED: pass protocol_version straight through again, or map 0 to itself.
func TestProtocolVersionZeroIsThisBuildsAndEveryOtherValueIsRefused(t *testing.T) {
	for _, one := range []struct {
		in   uint32
		want uint32
		ok   bool
	}{
		{0, messageProtocolVersion, true},
		{messageProtocolVersion, messageProtocolVersion, true},
		{messageProtocolVersion + 1, 0, false},
		{messageProtocolVersion + 2, 0, false},
		{^uint32(0), 0, false},
	} {
		got, err := messageProtocolVersionOf(one.in)
		if (err == nil) != one.ok || got != one.want {
			t.Errorf("protocol_version %d answered %d, %v; want %d and ok=%v", one.in, got, err, one.want, one.ok)
		}
		if err != nil && !strings.Contains(err.Error(), "URNET_MESSAGE_PROTOCOL_VERSION") {
			t.Errorf("the refusal of %d does not name the constant that works: %v", one.in, err)
		}
	}
}

// THE STATS JSON CARRIES EVERY COUNTER urmessage KEEPS, BY NAME.
//
// urnet_message_group_stats's own comment says "every counter urmessage keeps is carried", and until
// this case that sentence was held by nobody: a counter added to urmessage.Stats and not to the json
// projection would leave a C caller unable to see it with every test green. OwnWithoutCopy is the
// counter that made it matter -- the number of this device's own lines it cannot show.
//
// WHAT WOULD GO RED: add a field to urmessage.Stats and not to messageGroupStats.
func TestTheStatsJsonCarriesEveryCounterUrmessageKeeps(t *testing.T) {
	kept := reflect.TypeOf(urmessage.Stats{})
	carried := reflect.TypeOf(messageGroupStats{})
	names := map[string]bool{}
	for at := 0; at < carried.NumField(); at += 1 {
		names[carried.Field(at).Name] = true
	}
	for at := 0; at < kept.NumField(); at += 1 {
		if name := kept.Field(at).Name; !names[name] {
			t.Errorf("urmessage.Stats keeps %s and urnet_message_group_stats does not carry it", name)
		}
	}
	if kept.NumField() != carried.NumField() {
		t.Errorf("urmessage.Stats has %d counters and the json carries %d", kept.NumField(), carried.NumField())
	}
}

// THE HEADER'S DOCUMENTED STATS KEY LIST IS THE JSON'S OWN, IN ITS ORDER.
//
// include/urnetwork_message.h documents urnet_message_group_stats's keys in the comment above its
// declaration, and that list is what a C caller reads before it reads anything else; the case
// above holds the json against urmessage.Stats and nothing held the header against the json. It
// drifted: four counters (gap_out_of_window, opened_past_epoch, ingested, commit_refused) reached
// the json with every test green and the header never named them. So the list is READ OFF THE
// HEADER FILE -- the text after "as json:" up to its full stop, split on commas -- and held equal,
// entry for entry and in order, to the keys the json actually carries: the marshalled
// messageGroupStats, walked with a decoder so the keys are the output's and not a tag's.
//
// THE POSITIVE CONTROL is that the header's list is found and non-trivial: a header that lost
// the "as json:" phrase, or whose list came back empty, fails here rather than passing on two
// empty lists.
//
// WHAT WOULD GO RED: add a counter to messageGroupStats and not to the header's list, drop one
// from the header, misspell one, or reorder the header against the struct.
func TestTheHeaderDocumentsExactlyTheStatsJsonKeys(t *testing.T) {
	header, err := os.ReadFile("include/urnetwork_message.h")
	if err != nil {
		t.Fatalf("reading the header: %v", err)
	}
	text := strings.ReplaceAll(string(header), "\r\n", "\n")
	declaration := "char* urnet_message_group_stats("
	at := strings.Index(text, declaration)
	if at < 0 {
		t.Fatalf("the header declares no %s", declaration)
	}
	comment := strings.LastIndex(text[:at], "/*")
	if comment < 0 {
		t.Fatal("the stats declaration has no comment block above it")
	}
	block := text[comment:at]
	phrase := "as json:"
	start := strings.Index(block, phrase)
	if start < 0 {
		t.Fatalf("the stats comment does not say %q; the documented key list is found by that phrase", phrase)
	}
	rest := block[start+len(phrase):]
	end := strings.Index(rest, ".")
	if end < 0 {
		t.Fatal("the documented key list has no full stop ending it")
	}
	documented := []string{}
	for _, entry := range strings.Split(rest[:end], ",") {
		entry = strings.TrimSpace(entry)
		entry = strings.TrimSpace(strings.TrimPrefix(entry, "*"))
		if entry != "" {
			documented = append(documented, entry)
		}
	}
	if len(documented) < 2 {
		t.Fatalf("the documented key list is %v; the positive control that the header carries a list is not met", documented)
	}

	encoded, err := json.Marshal(&messageGroupStats{})
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	carried := []string{}
	if open, err := decoder.Token(); err != nil || open != json.Delim('{') {
		t.Fatalf("the stats json does not open an object: %v %v", open, err)
	}
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			t.Fatal(err)
		}
		name, isString := key.(string)
		if !isString {
			t.Fatalf("a key of the stats json is %T, not a string", key)
		}
		carried = append(carried, name)
		if _, err := decoder.Token(); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(documented, carried) {
		t.Fatalf("the header documents the stats keys as\n  %v\nand the json carries\n  %v", documented, carried)
	}
}
