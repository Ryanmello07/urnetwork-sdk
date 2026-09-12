package sdk

// Task 5's four properties, driven without a message server.
//
// ── WHAT THIS FILE CANNOT SEE, stated first because it bounds every number
//    below ────────────────────────────────────────────────────────────────────
//
// `sdk` cannot import `github.com/urnetwork/message-server`: it is a different
// module, `sdk/go.mod` neither requires nor replaces it, and adding a replace is
// out of scope for this task. So nothing here runs against the real server, and
// nothing here runs over a real `connect.Client` either — the client is injected
// through `messageTransportConfig` (S2-7 is open: how a client actually REACHES
// the message server is specified nowhere, and this task does not resolve it),
// and every test below injects [messageTransportFake] in its place.
//
// Concretely, this file establishes NOTHING about:
//
//   - whether the frames this binding emits are the frames the server accepts.
//     `msgrepo/cmd/message-server/twoclient_test.go` is CP3c and is the only
//     place that is asserted; it was read for shape and deliberately not
//     imported.
//   - whether `connect` really delivers responses on the callback this binding
//     registers, or in what order, or on which goroutine.
//   - whether the borrow rule is OBEYED AT RUN TIME under real pool reuse. The
//     `-race` detector cannot run in this sandbox (CGO_ENABLED=0, no C
//     compiler), so Property 1 below is a gate over the CODE and not a
//     behaviour test. That is not a workaround for the missing detector: a
//     borrowed slice handed to a goroutine that copies it promptly is a race a
//     behaviour test WINS most of the time, and a gate that passes there has
//     measured luck. The code gate refuses the construction instead of timing
//     it.
//   - §4.6 fragmentation in either direction. Task 6 owns the cut and the
//     reassembler; this binding sends every request as one frame and reads only
//     the §10.1 response code point.
//   - Hello, `server_nonce`, and `Capabilities`. Task 7.
//
// What it does establish is correlation, copying, refusal typing and
// non-blocking delivery, and every one of those is observable by driving the
// receive callback directly, which is what these tests do.

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/protocol"
	"google.golang.org/protobuf/proto"
)

// ─────────────────────────────────────────────────────────────────────────────
// The injected client
// ─────────────────────────────────────────────────────────────────────────────

// A stand-in for the one method pair this binding uses of a `*connect.Client`.
//
// It decodes each frame it is handed and keeps the DECODED request, never the
// frame: a fake that retained the frame would be the one place in this file
// allowed to break the rule the file is about.
type messageTransportFake struct {
	mutex      sync.Mutex
	receive    connect.ReceiveFunction
	subscribed int
	requests   []*protocol.MessageServerRequest
	refuse     bool

	// Called inline from inside SendWithTimeout, with the transport's own
	// goroutine still inside `send` and not yet in its select. Property 4's
	// whole construction.
	onSend func(request *protocol.MessageServerRequest)
}

func (self *messageTransportFake) AddReceiveCallback(receiveCallback connect.ReceiveFunction) func() {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.receive = receiveCallback
	self.subscribed += 1
	return func() {
		self.mutex.Lock()
		defer self.mutex.Unlock()
		self.subscribed -= 1
	}
}

func (self *messageTransportFake) SendWithTimeout(
	frame *protocol.Frame,
	destination connect.TransferPath,
	ackCallback connect.AckFunction,
	timeout time.Duration,
	opts ...any,
) bool {
	if frame.GetMessageType() != protocol.MessageType_MessageMessageServerRequest {
		return false
	}
	request := &protocol.MessageServerRequest{}
	if proto.Unmarshal(frame.GetMessageBytes(), request) != nil {
		return false
	}
	self.mutex.Lock()
	self.requests = append(self.requests, request)
	refuse := self.refuse
	onSend := self.onSend
	self.mutex.Unlock()
	if refuse {
		return false
	}
	if onSend != nil {
		onSend(request)
	}
	return true
}

func (self *messageTransportFake) requestCount() int {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return len(self.requests)
}

func (self *messageTransportFake) requestAt(index int) *protocol.MessageServerRequest {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	return self.requests[index]
}

// Drive the binding's receive callback the way connect does: inline, with
// borrowed frames.
func (self *messageTransportFake) answer(t *testing.T, response *protocol.MessageServerResponse) {
	t.Helper()
	encoded, err := proto.Marshal(response)
	if err != nil {
		t.Fatalf("could not encode the response: %v", err)
	}
	self.mutex.Lock()
	receive := self.receive
	self.mutex.Unlock()
	if receive == nil {
		t.Fatal("the transport registered no receive callback, so no response can reach it")
	}
	receive(
		connect.TransferPath{},
		[]*protocol.Frame{{
			MessageType:  protocol.MessageType_MessageMessageServerResponse,
			MessageBytes: encoded,
		}},
		connect.Peer{},
	)
}

func helloResponse(requestId uint64, nonce string) *protocol.MessageServerResponse {
	return &protocol.MessageServerResponse{
		RequestId: requestId,
		Reason:    protocol.Reason_REASON_OK,
		Body: &protocol.MessageServerResponse_Hello{
			Hello: &protocol.HelloResponse{ServerNonce: []byte(nonce)},
		},
	}
}

type messageTransportResult struct {
	response *protocol.MessageServerResponse
	err      error
}

// Start a Call and hand back the channel its answer will arrive on.
func callInBackground(
	transport *messageTransport,
	ctx context.Context,
	body proto.Message,
) chan messageTransportResult {
	results := make(chan messageTransportResult, 1)
	go func() {
		response, err := transport.Call(ctx, body)
		results <- messageTransportResult{response: response, err: err}
	}()
	return results
}

// Wait for the fake to have taken `count` requests, so the test knows the
// binding has registered its waiter and is in its select.
func awaitRequests(t *testing.T, fake *messageTransportFake, count int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for fake.requestCount() < count {
		if deadline.Before(time.Now()) {
			t.Fatalf("only %d of %d requests reached the client", fake.requestCount(), count)
		}
		time.Sleep(time.Millisecond)
	}
}

func newTestMessageTransport(t *testing.T, fake *messageTransportFake, timeout time.Duration) *messageTransport {
	t.Helper()
	transport, err := newMessageTransport(&messageTransportConfig{
		Client:          fake,
		Server:          connect.Id{0xC0, 0xFF, 0xEE},
		ProtocolVersion: 1,
		Timeout:         timeout,
	})
	if err != nil {
		t.Fatalf("the transport would not construct: %v", err)
	}
	t.Cleanup(transport.Close)
	return transport
}

// ─────────────────────────────────────────────────────────────────────────────
// Property 2 — a response is delivered to the waiter that asked for it, or to
// nobody.
// ─────────────────────────────────────────────────────────────────────────────

func TestMessageTransportAnswersEachWaiterWithItsOwnResponse(t *testing.T) {
	fake := &messageTransportFake{}
	transport := newTestMessageTransport(t, fake, 5*time.Second)
	ctx := context.Background()

	first := callInBackground(transport, ctx, &protocol.HelloRequest{SupportedVersions: []uint32{1}})
	awaitRequests(t, fake, 1)
	second := callInBackground(transport, ctx, &protocol.HelloRequest{SupportedVersions: []uint32{2}})
	awaitRequests(t, fake, 2)

	firstId := fake.requestAt(0).GetRequestId()
	secondId := fake.requestAt(1).GetRequestId()
	if firstId == secondId {
		t.Fatalf("two concurrent requests shared request_id %d, so nothing here can correlate", firstId)
	}

	// answered out of order, which is the only interesting order
	fake.answer(t, helloResponse(secondId, "second"))
	fake.answer(t, helloResponse(firstId, "first"))

	for _, each := range []struct {
		name      string
		results   chan messageTransportResult
		requestId uint64
		nonce     string
	}{
		{"first", first, firstId, "first"},
		{"second", second, secondId, "second"},
	} {
		select {
		case result := <-each.results:
			if result.err != nil {
				t.Fatalf("the %s call failed: %v", each.name, result.err)
			}
			if got := result.response.GetRequestId(); got != each.requestId {
				t.Fatalf("the %s call asked under request_id %d and was answered under %d",
					each.name, each.requestId, got)
			}
			if got := string(result.response.GetHello().GetServerNonce()); got != each.nonce {
				t.Fatalf("the %s call was handed the body %q, want %q — the correlator delivered another request's answer",
					each.name, got, each.nonce)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("the %s call was never answered, though a response carrying request_id %d was delivered",
				each.name, each.requestId)
		}
	}

	counts := transport.Counts()
	if counts.Responses != 2 {
		t.Fatalf("Counts().Responses is %d, want 2", counts.Responses)
	}
	if counts.Unmatched != 0 {
		t.Fatalf("Counts().Unmatched is %d, want 0 — both responses had a waiter", counts.Unmatched)
	}
	if counts.Waiting != 0 {
		t.Fatalf("Counts().Waiting is %d, want 0 — both waiters were answered", counts.Waiting)
	}
}

func TestMessageTransportCountsAndDropsAResponseNobodyAskedFor(t *testing.T) {
	fake := &messageTransportFake{}
	transport := newTestMessageTransport(t, fake, 5*time.Second)

	results := callInBackground(transport, context.Background(), &protocol.HelloRequest{SupportedVersions: []uint32{1}})
	awaitRequests(t, fake, 1)
	requestId := fake.requestAt(0).GetRequestId()

	fake.answer(t, helloResponse(requestId+9999, "stranger"))

	counts := transport.Counts()
	if counts.Unmatched != 1 {
		t.Fatalf("Counts().Unmatched is %d after a response nobody asked for, want 1 — "+
			"an unmatched response has to be COUNTED, so that \"nothing arrived\" and "+
			"\"something arrived for nobody\" are two readings", counts.Unmatched)
	}
	if counts.Responses != 0 {
		t.Fatalf("Counts().Responses is %d, want 0 — no waiter asked under that request_id", counts.Responses)
	}
	if counts.Waiting != 1 {
		t.Fatalf("Counts().Waiting is %d, want 1 — the outstanding waiter must still be outstanding", counts.Waiting)
	}

	select {
	case result := <-results:
		t.Fatalf("the waiter for request_id %d was handed an answer to request_id %d "+
			"(err %v, body %q): an unmatched response must go to NOBODY, never to the oldest waiter",
			requestId, result.response.GetRequestId(), result.err,
			string(result.response.GetHello().GetServerNonce()))
	case <-time.After(500 * time.Millisecond):
	}

	fake.answer(t, helloResponse(requestId, "mine"))
	select {
	case result := <-results:
		if result.err != nil {
			t.Fatalf("the call failed after its own response arrived: %v", result.err)
		}
		if got := string(result.response.GetHello().GetServerNonce()); got != "mine" {
			t.Fatalf("the call was handed the body %q, want \"mine\"", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the call was never answered, though its own response was delivered")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Property 3 — a response arriving after its waiter timed out leaks nothing.
// ─────────────────────────────────────────────────────────────────────────────

func TestMessageTransportTimeoutIsTypedAndLeavesNoMapEntry(t *testing.T) {
	fake := &messageTransportFake{}
	transport := newTestMessageTransport(t, fake, 150*time.Millisecond)

	response, err := transport.Call(context.Background(), &protocol.HelloRequest{SupportedVersions: []uint32{1}})
	if err == nil {
		t.Fatal("a Call that was never answered returned a nil error: " +
			"(nil, nil) is the one answer a caller cannot tell from success")
	}
	if response != nil {
		t.Fatalf("a timed-out Call returned a response as well as an error: %v", response)
	}
	if !errors.Is(err, errMessageTransportTimeout) {
		t.Fatalf("a timed-out Call returned %v, which is not errMessageTransportTimeout — "+
			"the refusal Property 3 owes is TYPED", err)
	}

	counts := transport.Counts()
	if counts.Timeouts != 1 {
		t.Fatalf("Counts().Timeouts is %d after one timeout, want 1", counts.Timeouts)
	}
	if counts.Waiting != 0 {
		t.Fatalf("Counts().Waiting is %d after the only Call timed out, want 0 — "+
			"the correlation map entry outlived its waiter", counts.Waiting)
	}

	// the late response: it leaks nothing, and it is counted rather than
	// silently discarded
	requestId := fake.requestAt(0).GetRequestId()
	answered := make(chan struct{})
	go func() {
		fake.answer(t, helloResponse(requestId, "late"))
		close(answered)
	}()
	select {
	case <-answered:
	case <-time.After(5 * time.Second):
		t.Fatal("delivering a response whose waiter had already timed out blocked the receive path")
	}

	counts = transport.Counts()
	if counts.Unmatched != 1 {
		t.Fatalf("Counts().Unmatched is %d after a late response, want 1", counts.Unmatched)
	}
	if counts.Responses != 0 {
		t.Fatalf("Counts().Responses is %d, want 0 — the waiter that asked was gone", counts.Responses)
	}
	if counts.Waiting != 0 {
		t.Fatalf("Counts().Waiting is %d after the late response, want 0", counts.Waiting)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Property 4 — the callback never blocks on a waiter.
// ─────────────────────────────────────────────────────────────────────────────

// The response is delivered from INSIDE the send, so the calling goroutine is
// still in `send` and has not reached its select. A delivery that needs the
// waiter to be reading — an unbuffered channel with no default — has nobody to
// hand the value to and stops the receive path dead. A delivery that is
// non-blocking by construction hands the value to the buffer and returns.
//
// This is the shape connect can actually produce: `ReceiveFunction` is invoked
// inline by the receive path, on whatever goroutine that path runs on, and
// nothing sequences it after the sender's select.
func TestMessageTransportReceiveCallbackDoesNotWaitForTheWaiter(t *testing.T) {
	fake := &messageTransportFake{}
	transport := newTestMessageTransport(t, fake, 5*time.Second)
	fake.onSend = func(request *protocol.MessageServerRequest) {
		fake.answer(t, helloResponse(request.GetRequestId(), "inline"))
	}

	results := callInBackground(transport, context.Background(), &protocol.HelloRequest{SupportedVersions: []uint32{1}})
	select {
	case result := <-results:
		if result.err != nil {
			t.Fatalf("the call failed: %v", result.err)
		}
		if got := string(result.response.GetHello().GetServerNonce()); got != "inline" {
			t.Fatalf("the call was handed the body %q, want \"inline\"", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the receive callback blocked on a waiter that was not yet reading: " +
			"delivery has to be non-blocking BY CONSTRUCTION, because connect invokes the " +
			"callback inline and a blocked callback backpressures every other client's frames")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// The refusals construction and the send path owe.
// ─────────────────────────────────────────────────────────────────────────────

func TestMessageTransportRefusesWhatItCannotDo(t *testing.T) {
	if _, err := newMessageTransport(&messageTransportConfig{Server: connect.Id{1}}); !errors.Is(err, errMessageTransportNoClient) {
		t.Fatalf("a config with no client was accepted, or refused with %v", err)
	}
	if _, err := newMessageTransport(&messageTransportConfig{Client: &messageTransportFake{}}); !errors.Is(err, errMessageTransportNoServer) {
		t.Fatalf("a config naming no server was accepted, or refused with %v", err)
	}

	fake := &messageTransportFake{}
	transport := newTestMessageTransport(t, fake, 5*time.Second)

	// a body that is not an arm of the request oneof
	if _, err := transport.Call(context.Background(), &protocol.HelloResponse{}); !errors.Is(err, errMessageTransportNoArm) {
		t.Fatalf("a HelloResponse was accepted as a request body, or refused with %v", err)
	}
	if waiting := transport.Counts().Waiting; waiting != 0 {
		t.Fatalf("Counts().Waiting is %d after a refused body, want 0", waiting)
	}

	fake.refuse = true
	if _, err := transport.Call(context.Background(), &protocol.HelloRequest{}); !errors.Is(err, errMessageTransportRefused) {
		t.Fatalf("a refused send was reported as %v, want errMessageTransportRefused", err)
	}
	if waiting := transport.Counts().Waiting; waiting != 0 {
		t.Fatalf("Counts().Waiting is %d after a refused send, want 0 — "+
			"the waiter registered before the send outlived it", waiting)
	}
}

// ═════════════════════════════════════════════════════════════════════════════
// Property 1 — nothing borrowed outlives the receive callback.
// ═════════════════════════════════════════════════════════════════════════════
//
// GATE CLASS, derived and stated separately from the scope (R3):
//
//	every value that reaches this binding through the receive callback's
//	PARAMETERS. The class is read off `connect.ReceiveFunction`'s own
//	declaration at run time — go/parser over connect's source, located through
//	`go list` — and is never listed here. The gate REPORTS the number it read,
//	and asserts the binding's callback binds exactly that many parameters, so a
//	parameter added to `ReceiveFunction` upstream fails here rather than
//	silently widening the class. It is three today; the gate does not know that
//	in advance and neither does this comment.
//
// GATE SCOPE, derived separately from the class (R3):
//
//	the callback's whole DYNAMIC EXTENT — the registered callback function plus
//	every function and method in `package sdk` that it transitively calls,
//	computed from the parsed call graph. It is NOT the callback's lexical body
//	and it is NOT one file: a callee declared in another file of the package is
//	in scope. "A gate that checks the body and not what the body calls has read
//	half of it."
//
// WHAT IT REFUSES, which is a construction and not a timing:
//
//	a borrowed value stored anywhere but a local of the extent (a field, a map,
//	an index, a dereference), sent on a channel, referenced inside a `go`
//	statement, or passed to a function outside the package that this gate cannot
//	see inside. A `go` statement is refused whatever it does with the value —
//	promptness is not the rule, and `-race` is unavailable here anyway, so a
//	behaviour test would be measuring a race it happened to win.
//
// THE COMPLEMENTS IT PRINTS. Every narrowing below names, at run time, what it
// removed:
//
//	C1 the package-level declarations in the binding's own production files that
//	   are NOT in the extent. Asserted to partition those files' declarations
//	   with the extent, and asserted NON-EMPTY: an extent that swallowed the
//	   whole file is a call-graph walk that lost its bearings, so the gate fails
//	   closed rather than continuing past it.
//	C2 the receive-callback registrations in `package sdk` that are NOT this
//	   binding's. Printed with its count and members. NOT failed on empty, and
//	   the reason is stated rather than assumed: `sdk` is entitled to contain
//	   exactly one registration, and today it contains two.
//	C3 the borrowed expressions the gate examined and CLEARED, each with the
//	   reason it was cleared. Asserted non-empty — an empty clearance set means
//	   the gate located the callback and then looked at nothing — and asserted
//	   to COVER every source line on which a borrowed identifier appears, which
//	   is the assertion that catches twelve readings where there are thirteen.
func TestNothingBorrowedOutlivesTheReceiveCallback(t *testing.T) {
	gate := newBorrowGate(t)

	// ── the class, read off connect rather than listed here ──────────────────
	classPos, class := gate.receiveFunctionClass()
	t.Logf("Property 1 class: connect.ReceiveFunction at %s declares %d parameters: %s",
		classPos, len(class), strings.Join(class, ", "))

	// ── C2: which registration is this binding's, and which are not ──────────
	mine, others := gate.receiveRegistrations()
	t.Logf("C2 complement — receive-callback registrations in package sdk that are NOT this binding's: %d %v",
		len(others), others)
	if len(mine) != 1 {
		t.Fatalf("package sdk has %d receive-callback registrations on messageTransport %v, want exactly 1",
			len(mine), mine)
	}
	root := mine[0]

	rootDecl := gate.decls[root.callee]
	if rootDecl == nil {
		t.Fatalf("the callback registered at %s resolves to %q, which is not a declaration in package sdk",
			root.pos, root.callee)
	}
	bound := fieldNames(rootDecl.Type.Params)
	t.Logf("Property 1 class as this binding binds it: %s binds %d parameters: %s",
		root.callee, len(bound), strings.Join(bound, ", "))
	if len(bound) != len(class) {
		t.Fatalf("connect.ReceiveFunction declares %d parameters (%s) and %s binds %d (%s): "+
			"the class this gate tracks is read off the signature, so a parameter added upstream "+
			"has to fail here",
			len(class), strings.Join(class, ", "), root.callee, len(bound), strings.Join(bound, ", "))
	}

	// ── the scope: the dynamic extent ────────────────────────────────────────
	gate.walkExtent(root.callee)
	t.Logf("Property 1 scope: the dynamic extent of %s is %d functions: %s",
		root.callee, len(gate.order), strings.Join(gate.order, ", "))
	if len(gate.duplicates) != 0 {
		t.Logf("note: %d declaration names appear more than once across the package's production files "+
			"(build-tagged variants): %v", len(gate.duplicates), gate.duplicates)
	}

	// ── C1: what the scope removed ───────────────────────────────────────────
	bindingFiles := gate.bindingFiles()
	inside, outside := gate.partition(bindingFiles)
	t.Logf("C1 complement — declarations in the binding's production files %v that are NOT in the extent: %d %v",
		bindingFiles, len(outside), outside)
	declared := gate.declarationsIn(bindingFiles)
	if len(inside)+len(outside) != len(declared) {
		t.Fatalf("the extent and its complement are %d + %d over %d declarations in %v: the partition does not close",
			len(inside), len(outside), len(declared), bindingFiles)
	}
	if len(outside) == 0 {
		t.Fatalf("the C1 complement is EMPTY: the extent claims all %d declarations in %v, "+
			"which means the call-graph walk lost its bearings rather than that the binding is all callback",
			len(declared), bindingFiles)
	}

	// ── the taint walk ───────────────────────────────────────────────────────
	gate.analyze(root.callee, setOf(bound...))

	// ── C3: what was examined and cleared ────────────────────────────────────
	t.Logf("C3 complement — borrowed expressions examined and CLEARED: %d", len(gate.cleared))
	for _, site := range gate.cleared {
		t.Logf("    cleared  %s  %s  — %s", site.pos, site.what, site.reason)
	}
	if len(gate.cleared) == 0 {
		t.Fatal("the C3 complement is EMPTY: the gate located the callback, walked its extent, " +
			"and classified not one borrowed expression. A gate that removes nothing has not looked.")
	}

	uncovered := gate.uncoveredBorrowLines()
	t.Logf("borrowed-identifier occurrences in the extent: %d, every one on a line a clearance or a flag covers: %v",
		gate.borrowLineCount(), len(uncovered) == 0)
	if len(uncovered) != 0 {
		t.Fatalf("%d borrowed identifier(s) sit on a source line this gate classified neither way: %v — "+
			"the classifier is silent on a construction it walked past", len(uncovered), uncovered)
	}

	// ── the verdict ──────────────────────────────────────────────────────────
	if len(gate.flagged) != 0 {
		for _, site := range gate.flagged {
			t.Errorf("a borrowed value outlives the receive callback: %s  %s  — %s",
				site.pos, site.what, site.reason)
		}
		t.Fatalf("%d borrowed value(s) escape the callback. connect: \"the frames, frame objects, "+
			"and their message bytes are borrowed and valid only until the callback returns ... never "+
			"hand a borrowed Frame to an asynchronous send, goroutine, or channel.\"", len(gate.flagged))
	}
}

// Property 3's other half, and it is a code check for the same reason Property 1
// is: "no goroutine leaks" is not observable in a suite that cannot run -race
// and whose other tests run concurrently with this one, so `runtime.NumGoroutine`
// would be measuring the package and not this binding.
//
// GATE CLASS:  every `go` statement in the binding's production files.
// GATE SCOPE:  the binding's production files WHOLE — derived as the production
//
//	files of package sdk that declare a method on `messageTransport`
//	— and not `Call` alone, because a goroutine started anywhere in
//	this file outlives the request that started it just as well.
//
// Complement printed: the statements scanned that are NOT `go` statements, with
// its count. An empty complement means the gate parsed nothing, and it fails
// closed on that.
func TestTheMessageTransportStartsNoGoroutine(t *testing.T) {
	gate := newBorrowGate(t)
	files := gate.bindingFiles()
	if len(files) == 0 {
		t.Fatal("no production file of package sdk declares a method on messageTransport")
	}

	statements := 0
	found := []string{}
	for _, name := range files {
		ast.Inspect(gate.prodFiles[name], func(node ast.Node) bool {
			statement, ok := node.(ast.Stmt)
			if !ok {
				return true
			}
			statements += 1
			if _, isGo := statement.(*ast.GoStmt); isGo {
				found = append(found, gate.fset.Position(statement.Pos()).String())
			}
			return true
		})
	}
	t.Logf("class: `go` statements in %v; complement — statements scanned that are not `go` statements: %d",
		files, statements-len(found))
	if statements-len(found) == 0 {
		t.Fatalf("the complement is EMPTY: %d statements scanned across %v, so the gate parsed nothing",
			statements, files)
	}
	if len(found) != 0 {
		t.Fatalf("the binding starts %d goroutine(s), at %v: a request that timed out has to leave "+
			"no goroutine behind, and a goroutine here is also the construction Property 1 refuses",
			len(found), found)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// the gate's machinery
// ─────────────────────────────────────────────────────────────────────────────

type borrowSite struct {
	pos    string
	what   string
	reason string
}

type registration struct {
	pos    string
	callee string
	owner  string
}

type borrowGate struct {
	t          *testing.T
	fset       *token.FileSet
	prodFiles  map[string]*ast.File
	fileNames  []string
	decls      map[string]*ast.FuncDecl
	declFile   map[string]string
	declOrder  []string
	duplicates []string

	extent   map[string]bool
	order    []string
	analyzed map[string]bool

	cleared     []borrowSite
	flagged     []borrowSite
	borrowLines map[string]bool
	coveredLine map[string]bool
}

// The functions this gate treats as copying their borrowed argument, and the
// only way a borrowed value is cleared out of the class once it is in it. Each
// one either copies the bytes or reads a scalar out of them; connect's own rule
// names `MessagePoolShareReadOnly` as the third way, so it is here too.
var borrowSanitizers = map[string]string{
	"len":                              "len reads a length, not the bytes",
	"cap":                              "cap reads a capacity, not the bytes",
	"copy":                             "copy writes the borrowed bytes into a buffer of our own",
	"string":                           "a string conversion copies",
	"proto.Unmarshal":                  "Unmarshal decodes into a message of our own, which copies every byte it keeps",
	"connect.MessagePoolShareReadOnly": "connect's own rule names this as a way to outlive the callback",
}

func newBorrowGate(t *testing.T) *borrowGate {
	t.Helper()
	gate := &borrowGate{
		t:           t,
		fset:        token.NewFileSet(),
		prodFiles:   map[string]*ast.File{},
		decls:       map[string]*ast.FuncDecl{},
		declFile:    map[string]string{},
		extent:      map[string]bool{},
		analyzed:    map[string]bool{},
		borrowLines: map[string]bool{},
		coveredLine: map[string]bool{},
	}
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("could not list the package's files: %v", err)
	}
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(gate.fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatalf("could not parse %s: %v", path, err)
		}
		gate.prodFiles[path] = file
		gate.fileNames = append(gate.fileNames, path)
		for _, decl := range file.Decls {
			funcDecl, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			key := declKey(funcDecl)
			if _, already := gate.decls[key]; already {
				gate.duplicates = append(gate.duplicates, key)
				continue
			}
			gate.decls[key] = funcDecl
			gate.declFile[key] = path
			gate.declOrder = append(gate.declOrder, key)
		}
	}
	if len(gate.prodFiles) == 0 {
		t.Fatal("no production file of package sdk was parsed, so this gate has read nothing")
	}
	sort.Strings(gate.fileNames)
	return gate
}

// The class, read off connect's own declaration.
func (self *borrowGate) receiveFunctionClass() (string, []string) {
	self.t.Helper()
	out, err := exec.Command("go", "list", "-f", "{{.Dir}}", "github.com/urnetwork/connect").Output()
	if err != nil {
		self.t.Fatalf("could not locate connect's source, so the class cannot be read off its signature: %v", err)
	}
	dir := strings.TrimSpace(string(out))
	if dir == "" {
		self.t.Fatal("go list named no directory for github.com/urnetwork/connect")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		self.t.Fatalf("could not read %s: %v", dir, err)
	}
	fset := token.NewFileSet()
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			continue
		}
		for _, decl := range file.Decls {
			genDecl, ok := decl.(*ast.GenDecl)
			if !ok || genDecl.Tok != token.TYPE {
				continue
			}
			for _, spec := range genDecl.Specs {
				typeSpec, ok := spec.(*ast.TypeSpec)
				if !ok || typeSpec.Name.Name != "ReceiveFunction" {
					continue
				}
				funcType, ok := typeSpec.Type.(*ast.FuncType)
				if !ok {
					self.t.Fatalf("connect.ReceiveFunction at %s is not a func type",
						fset.Position(typeSpec.Pos()))
				}
				return fset.Position(typeSpec.Pos()).String(), fieldNames(funcType.Params)
			}
		}
	}
	self.t.Fatalf("connect.ReceiveFunction was not found in %s, so the class has no source to be read from", dir)
	return "", nil
}

// Every receive-callback registration in the package, split into this binding's
// and the complement.
func (self *borrowGate) receiveRegistrations() (mine []registration, others []string) {
	for _, key := range self.declOrder {
		decl := self.decls[key]
		ast.Inspect(decl, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != "AddReceiveCallback" || len(call.Args) != 1 {
				return true
			}
			pos := self.fset.Position(call.Pos()).String()
			callee, receiverType := self.resolveCallback(decl, call.Args[0])
			if receiverType == "messageTransport" {
				mine = append(mine, registration{pos: pos, callee: callee, owner: receiverType})
			} else {
				others = append(others, fmt.Sprintf("%s registers %s (on %s) at %s",
					key, types.ExprString(call.Args[0]), orUnknown(receiverType), pos))
			}
			return true
		})
	}
	return mine, others
}

// `x.receive` resolves to the decl key `<the type of x>.receive`.
//
// The type of `x` is derived rather than assumed: it is the enclosing method's
// receiver type when `x` is the receiver, and otherwise the composite-literal
// type `x` was built from inside the enclosing function. That is what makes this
// gate find its own registration in [newMessageTransport], where the transport
// is a LOCAL and not a receiver — the earlier draft keyed on the enclosing
// function's receiver, found none, and would have reported zero registrations
// for a binding that plainly has one.
func (self *borrowGate) resolveCallback(enclosing *ast.FuncDecl, arg ast.Expr) (string, string) {
	selector, ok := arg.(*ast.SelectorExpr)
	if !ok {
		return types.ExprString(arg), ""
	}
	base, ok := selector.X.(*ast.Ident)
	if !ok {
		return types.ExprString(arg), ""
	}
	receiverType := localTypeOf(enclosing, base.Name)
	if receiverType == "" {
		return types.ExprString(arg), ""
	}
	return receiverType + "." + selector.Sel.Name, receiverType
}

// The named type a local or receiver was built from, read syntactically: the
// enclosing method's receiver type, or the composite literal the local was
// assigned. Nothing here type-checks, so a local built any other way reads as
// unknown and its registration lands in the complement, where it is PRINTED
// rather than silently dropped.
func localTypeOf(enclosing *ast.FuncDecl, name string) string {
	if name == recvName(enclosing) {
		return recvTypeName(enclosing)
	}
	found := ""
	ast.Inspect(enclosing, func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for index, lhs := range assign.Lhs {
			ident, ok := lhs.(*ast.Ident)
			if !ok || ident.Name != name || len(assign.Rhs) <= index {
				continue
			}
			if spelled := compositeTypeName(assign.Rhs[index]); spelled != "" {
				found = spelled
			}
		}
		return true
	})
	return found
}

func compositeTypeName(expr ast.Expr) string {
	if unary, ok := expr.(*ast.UnaryExpr); ok && unary.Op == token.AND {
		expr = unary.X
	}
	composite, ok := expr.(*ast.CompositeLit)
	if !ok {
		return ""
	}
	if ident, ok := composite.Type.(*ast.Ident); ok {
		return ident.Name
	}
	return ""
}

func orUnknown(name string) string {
	if name == "" {
		return "an unresolved type"
	}
	return name
}

// The dynamic extent: the root plus every package function it transitively
// calls.
func (self *borrowGate) walkExtent(root string) {
	queue := []string{root}
	for 0 < len(queue) {
		key := queue[0]
		queue = queue[1:]
		if self.extent[key] {
			continue
		}
		decl := self.decls[key]
		if decl == nil {
			continue
		}
		self.extent[key] = true
		self.order = append(self.order, key)
		ast.Inspect(decl, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			if callee := self.resolveCallee(decl, call); callee != "" {
				queue = append(queue, callee)
			}
			return true
		})
	}
}

func (self *borrowGate) resolveCallee(enclosing *ast.FuncDecl, call *ast.CallExpr) string {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		if _, found := self.decls[fun.Name]; found {
			return fun.Name
		}
	case *ast.SelectorExpr:
		receiver, ok := fun.X.(*ast.Ident)
		if !ok {
			return ""
		}
		if receiver.Name != recvName(enclosing) {
			return ""
		}
		key := recvTypeName(enclosing) + "." + fun.Sel.Name
		if _, found := self.decls[key]; found {
			return key
		}
	}
	return ""
}

// The production files that declare a method on messageTransport. Derived, so
// that Tasks 6 and 7's files join the scope on the commit that adds them.
func (self *borrowGate) bindingFiles() []string {
	seen := map[string]bool{}
	names := []string{}
	for _, key := range self.declOrder {
		if recvTypeName(self.decls[key]) != "messageTransport" {
			continue
		}
		name := self.declFile[key]
		if seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (self *borrowGate) declarationsIn(files []string) []string {
	within := map[string]bool{}
	for _, name := range files {
		within[name] = true
	}
	keys := []string{}
	for _, key := range self.declOrder {
		if within[self.declFile[key]] {
			keys = append(keys, key)
		}
	}
	return keys
}

func (self *borrowGate) partition(files []string) (inside []string, outside []string) {
	for _, key := range self.declarationsIn(files) {
		if self.extent[key] {
			inside = append(inside, key)
		} else {
			outside = append(outside, key)
		}
	}
	return inside, outside
}

// ── the taint walk ───────────────────────────────────────────────────────────

func (self *borrowGate) analyze(key string, roots map[string]bool) {
	decl := self.decls[key]
	if decl == nil || decl.Body == nil || len(roots) == 0 {
		return
	}
	memo := key + "|" + strings.Join(sortedKeys(roots), ",")
	if self.analyzed[memo] {
		return
	}
	self.analyzed[memo] = true

	tainted := map[string]bool{}
	for name := range roots {
		tainted[name] = true
	}

	// fixpoint: a borrowed value bound to a local makes that local borrowed too
	for round := 0; round < 32; round += 1 {
		grew := false
		ast.Inspect(decl.Body, func(node ast.Node) bool {
			switch statement := node.(type) {
			case *ast.AssignStmt:
				for index, rhs := range statement.Rhs {
					if !isBorrowed(rhs, tainted) {
						continue
					}
					for _, lhs := range lhsFor(statement, index) {
						if ident, ok := lhs.(*ast.Ident); ok && ident.Name != "_" && !tainted[ident.Name] {
							tainted[ident.Name] = true
							grew = true
						}
					}
				}
			case *ast.RangeStmt:
				if !isBorrowed(statement.X, tainted) {
					return true
				}
				for _, each := range []ast.Expr{statement.Key, statement.Value} {
					if ident, ok := each.(*ast.Ident); ok && ident.Name != "_" && !tainted[ident.Name] {
						tainted[ident.Name] = true
						grew = true
					}
				}
			case *ast.ValueSpec:
				for index, value := range statement.Values {
					if !isBorrowed(value, tainted) || len(statement.Names) <= index {
						continue
					}
					if name := statement.Names[index].Name; name != "_" && !tainted[name] {
						tainted[name] = true
						grew = true
					}
				}
			}
			return true
		})
		if !grew {
			break
		}
	}

	// every occurrence of a borrowed identifier, so that a classifier which
	// walks past a construction is caught by the coverage assertion rather than
	// by nobody
	ast.Inspect(decl.Body, func(node ast.Node) bool {
		ident, ok := node.(*ast.Ident)
		if !ok || !tainted[ident.Name] {
			return true
		}
		self.borrowLines[self.fset.Position(ident.Pos()).String()] = true
		return true
	})

	// classification
	ast.Inspect(decl.Body, func(node ast.Node) bool {
		switch statement := node.(type) {

		case *ast.AssignStmt:
			for index, rhs := range statement.Rhs {
				if !isBorrowed(rhs, tainted) {
					continue
				}
				for _, lhs := range lhsFor(statement, index) {
					if ident, ok := lhs.(*ast.Ident); ok {
						self.clear(statement, types.ExprString(rhs),
							fmt.Sprintf("bound to the local %s, which dies with the callback", ident.Name))
						continue
					}
					self.flag(statement, types.ExprString(rhs),
						fmt.Sprintf("stored into %s, which outlives the callback", types.ExprString(lhs)))
				}
			}

		case *ast.SendStmt:
			if isBorrowed(statement.Value, tainted) || isBorrowed(statement.Chan, tainted) {
				self.flag(statement, types.ExprString(statement.Value),
					fmt.Sprintf("sent on the channel %s", types.ExprString(statement.Chan)))
			}

		case *ast.GoStmt:
			if names := borrowedNames(statement, tainted); 0 < len(names) {
				self.flag(statement, strings.Join(names, ", "),
					"referenced inside a `go` statement. Promptness is not the rule: a goroutine "+
						"that copies immediately is still a goroutine the callback does not wait for")
			}

		case *ast.DeferStmt:
			if names := borrowedNames(statement, tainted); 0 < len(names) {
				self.clear(statement, strings.Join(names, ", "),
					"deferred, which runs before the callback returns")
			}

		case *ast.RangeStmt:
			if isBorrowed(statement.X, tainted) {
				self.clear(statement, types.ExprString(statement.X), "ranged over, and read element by element")
			}

		case *ast.IfStmt:
			if statement.Cond != nil && isBorrowed(statement.Cond, tainted) {
				self.clear(statement, types.ExprString(statement.Cond), "read in a condition; a comparison keeps nothing")
			}

		case *ast.SwitchStmt:
			if statement.Tag != nil && isBorrowed(statement.Tag, tainted) {
				self.clear(statement, types.ExprString(statement.Tag), "read as a switch tag; a comparison keeps nothing")
			}

		case *ast.CaseClause:
			for _, each := range statement.List {
				if isBorrowed(each, tainted) {
					self.clear(statement, types.ExprString(each), "compared in a case clause")
				}
			}

		case *ast.ReturnStmt:
			for _, each := range statement.Results {
				if isBorrowed(each, tainted) {
					self.clear(statement, types.ExprString(each),
						"returned to a caller that is itself inside the callback")
				}
			}

		case *ast.ExprStmt:
			if isBorrowed(statement.X, tainted) {
				self.clear(statement, types.ExprString(statement.X), "evaluated and discarded")
			}

		case *ast.CallExpr:
			self.classifyCall(decl, statement, tainted)
		}
		return true
	})
}

func (self *borrowGate) classifyCall(enclosing *ast.FuncDecl, call *ast.CallExpr, tainted map[string]bool) {
	name := calleeName(call)

	borrowedArgs := []ast.Expr{}
	for _, arg := range call.Args {
		if isBorrowed(arg, tainted) {
			borrowedArgs = append(borrowedArgs, arg)
		}
	}

	if len(borrowedArgs) == 0 {
		// a method on a borrowed value: reading it is the whole point of the
		// callback, and the RESULT stays in the class
		if selector, ok := call.Fun.(*ast.SelectorExpr); ok && isBorrowed(selector.X, tainted) {
			self.clear(call, types.ExprString(call),
				"a method called on a borrowed value; its result is treated as borrowed too")
		}
		return
	}

	if callee := self.resolveCallee(enclosing, call); callee != "" {
		// in-package: the class travels into the callee and this gate walks it
		roots := map[string]bool{}
		target := self.decls[callee]
		for index, arg := range call.Args {
			if !isBorrowed(arg, tainted) {
				continue
			}
			if param := paramNameAt(target, index); param != "" {
				roots[param] = true
			}
		}
		self.clear(call, types.ExprString(call),
			fmt.Sprintf("passed to %s, which is inside the extent and walked by this gate", callee))
		self.analyze(callee, roots)
		return
	}

	if reason, sanitizes := borrowSanitizers[name]; sanitizes {
		self.clear(call, types.ExprString(call), fmt.Sprintf("passed to %s: %s", name, reason))
		return
	}

	shown := []string{}
	for _, arg := range borrowedArgs {
		shown = append(shown, types.ExprString(arg))
	}
	self.flag(call, strings.Join(shown, ", "),
		fmt.Sprintf("handed to %s, which is outside package sdk and outside this gate's sanitizer set, "+
			"so nothing here establishes that it does not retain the value", name))
}

func (self *borrowGate) clear(node ast.Node, what string, reason string) {
	pos := self.fset.Position(node.Pos()).String()
	self.cleared = append(self.cleared, borrowSite{pos: pos, what: what, reason: reason})
	self.coverLine(node)
}

func (self *borrowGate) flag(node ast.Node, what string, reason string) {
	pos := self.fset.Position(node.Pos()).String()
	self.flagged = append(self.flagged, borrowSite{pos: pos, what: what, reason: reason})
	self.coverLine(node)
}

// A classification covers every line of the construction it classified, because
// a `go` statement or a call can span several.
func (self *borrowGate) coverLine(node ast.Node) {
	start := self.fset.Position(node.Pos())
	end := self.fset.Position(node.End())
	for line := start.Line; line <= end.Line; line += 1 {
		self.coveredLine[fmt.Sprintf("%s:%d:", start.Filename, line)] = true
	}
}

func (self *borrowGate) borrowLineCount() int {
	return len(self.borrowLines)
}

func (self *borrowGate) uncoveredBorrowLines() []string {
	uncovered := []string{}
	for position := range self.borrowLines {
		parts := strings.Split(position, ":")
		if len(parts) < 3 {
			continue
		}
		prefix := strings.Join(parts[:len(parts)-2], ":") + ":" + parts[len(parts)-2] + ":"
		if !self.coveredLine[prefix] {
			uncovered = append(uncovered, position)
		}
	}
	sort.Strings(uncovered)
	return uncovered
}

// ── expression helpers ───────────────────────────────────────────────────────

// Conservative by construction: anything derived from a borrowed value is
// borrowed until a sanitizer copies it.
func isBorrowed(expr ast.Expr, tainted map[string]bool) bool {
	switch each := expr.(type) {
	case nil:
		return false
	case *ast.Ident:
		return tainted[each.Name]
	case *ast.SelectorExpr:
		return isBorrowed(each.X, tainted)
	case *ast.IndexExpr:
		return isBorrowed(each.X, tainted) || isBorrowed(each.Index, tainted)
	case *ast.SliceExpr:
		return isBorrowed(each.X, tainted)
	case *ast.StarExpr:
		return isBorrowed(each.X, tainted)
	case *ast.ParenExpr:
		return isBorrowed(each.X, tainted)
	case *ast.UnaryExpr:
		return isBorrowed(each.X, tainted)
	case *ast.BinaryExpr:
		return isBorrowed(each.X, tainted) || isBorrowed(each.Y, tainted)
	case *ast.TypeAssertExpr:
		return isBorrowed(each.X, tainted)
	case *ast.KeyValueExpr:
		return isBorrowed(each.Value, tainted)
	case *ast.CompositeLit:
		for _, element := range each.Elts {
			if isBorrowed(element, tainted) {
				return true
			}
		}
		return false
	case *ast.CallExpr:
		if _, sanitizes := borrowSanitizers[calleeName(each)]; sanitizes {
			return false
		}
		if isBorrowed(each.Fun, tainted) {
			return true
		}
		for _, arg := range each.Args {
			if isBorrowed(arg, tainted) {
				return true
			}
		}
		return false
	}
	return false
}

func borrowedNames(node ast.Node, tainted map[string]bool) []string {
	seen := map[string]bool{}
	names := []string{}
	ast.Inspect(node, func(each ast.Node) bool {
		ident, ok := each.(*ast.Ident)
		if !ok || !tainted[ident.Name] || seen[ident.Name] {
			return true
		}
		seen[ident.Name] = true
		names = append(names, ident.Name)
		return true
	})
	sort.Strings(names)
	return names
}

func calleeName(call *ast.CallExpr) string {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name
	case *ast.SelectorExpr:
		if pkg, ok := fun.X.(*ast.Ident); ok {
			return pkg.Name + "." + fun.Sel.Name
		}
		return fun.Sel.Name
	}
	return types.ExprString(call.Fun)
}

func lhsFor(statement *ast.AssignStmt, index int) []ast.Expr {
	if len(statement.Lhs) == len(statement.Rhs) {
		return []ast.Expr{statement.Lhs[index]}
	}
	return statement.Lhs
}

func paramNameAt(decl *ast.FuncDecl, index int) string {
	if decl == nil || decl.Type.Params == nil {
		return ""
	}
	position := 0
	for _, field := range decl.Type.Params.List {
		if len(field.Names) == 0 {
			if position == index {
				return ""
			}
			position += 1
			continue
		}
		for _, name := range field.Names {
			if position == index {
				return name.Name
			}
			position += 1
		}
	}
	return ""
}

func fieldNames(fields *ast.FieldList) []string {
	names := []string{}
	if fields == nil {
		return names
	}
	for _, field := range fields.List {
		spelled := types.ExprString(field.Type)
		if len(field.Names) == 0 {
			names = append(names, "_ "+spelled)
			continue
		}
		for _, name := range field.Names {
			names = append(names, name.Name+" "+spelled)
		}
	}
	return names
}

func declKey(decl *ast.FuncDecl) string {
	if recv := recvTypeName(decl); recv != "" {
		return recv + "." + decl.Name.Name
	}
	return decl.Name.Name
}

func recvTypeName(decl *ast.FuncDecl) string {
	if decl == nil || decl.Recv == nil || len(decl.Recv.List) == 0 {
		return ""
	}
	expr := decl.Recv.List[0].Type
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if index, ok := expr.(*ast.IndexExpr); ok {
		expr = index.X
	}
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name
	}
	return ""
}

func recvName(decl *ast.FuncDecl) string {
	if decl == nil || decl.Recv == nil || len(decl.Recv.List) == 0 || len(decl.Recv.List[0].Names) == 0 {
		return ""
	}
	return decl.Recv.List[0].Names[0].Name
}

func setOf(entries ...string) map[string]bool {
	set := map[string]bool{}
	for _, entry := range entries {
		// fieldNames spells "name type"; the root set is the names
		set[strings.SplitN(entry, " ", 2)[0]] = true
	}
	delete(set, "_")
	return set
}

func sortedKeys(set map[string]bool) []string {
	keys := []string{}
	for key := range set {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
