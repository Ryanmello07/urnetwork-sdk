package main

import (
	"context"
	"encoding/json"
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
// alternative would have done to the same octets the C test round-trips, so that the decision is
// defended by a number rather than by the paragraph above it.
func TestTheRejectedBodyEncodingsWouldHaveChangedTheseOctets(t *testing.T) {
	// the C test's body, octet for octet (ctest/message_abi_test.c, kBody)
	body := []byte("hello from C\x00\xff\xfex\xc3\x28\n\x00z")
	if len(body) != 21 {
		t.Fatalf("this test's body is %d octets and the C test's is 21", len(body))
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
	encoded, err := json.Marshal(messageInfoOf(message))
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
	if messageInfoOf(nil) != nil {
		t.Error("a nil message projected to something")
	}
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
