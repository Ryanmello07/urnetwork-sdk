package main

/*
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include "callbacks_message.h"
*/
import "C"

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"
	"unsafe"

	"github.com/urnetwork/connect"
	"github.com/urnetwork/connect/messagegroup"
	"github.com/urnetwork/sdk"
	"github.com/urnetwork/sdk/urmessage"
)

// THE MESSAGING C ABI, AND IT IS HAND-WRITTEN ON PURPOSE.
//
// exports_gen.go is produced by gen/gen.go from package sdk's own surface, under curated
// classification lists that say which types are behavioural and which are data. The messaging
// surface is NOT in package sdk: it is sdk/urmessage, plus three constructors in sdk that the
// generator's walk does not reach, plus one interface that belongs to connect/messagegroup.
// Widening the generator to a second and third package is a change to the classification model
// and would reflow every one of the 620 existing declarations in the same commit. That is a
// separate, larger job. So this file is the messaging surface written by hand, in the
// generator's own style, ALONGSIDE the generated file rather than inside it -- the same reason
// exports_manual.go gives for the byte-buffer exports, and it is not repeated there.
//
// TWO CONSEQUENCES OF BEING HAND-WRITTEN, NAMED RATHER THAN LEFT TO BE DISCOVERED:
//   - include/urnetwork_message.h is the header for this file and is hand-written too. The
//     generated include/urnetwork_sdk.h does not declare these; the two headers are independent
//     and both ship. The cgo-generated header emitted next to the library declares both.
//   - include/urnetwork_sdk.def names every export in this file because gen.go's manualExports()
//     picks them up. It used to be STALE -- 0 of 34 names, so an MSVC consumer linking through the
//     import library found none of the messaging surface -- and it is now held by
//     gen.TestTheDefNamesEveryHandWrittenMessagingExport rather than by this sentence.
//
// ── WHAT IS EXPOSED IS WHAT IS PROVEN, AND THE SILENCES ARE DELIBERATE ───────────────────────
//
// The content envelope is the owner's ruling and is not made here. A body is opaque octets, in
// and out, and nothing in this file knows what is inside one. There is no receipt, no reaction,
// no reply, no edit, no delete and no media -- not as a stub, not as an export that answers a
// plausible empty result. urmessage does not carry them and neither does this.
//
// ── DECISION: BLOCKING, ON THE CALLER'S OWN THREAD, WITH A CANCEL HANDLE ─────────────────────
//
// Connect, Open, Send and Receive block and take a context. They are exported as BLOCKING calls
// the caller runs on a thread of its own, NOT as callback-completions, and the argument has four
// parts:
//
//  1. There is no completion model to map onto. urmessage has no queue, no dispatcher and no
//     receive push -- sdk/message_transport.go says it in its own voice: "there is no server
//     push, and the receive path is a poll". An async ABI would have to INVENT the completion
//     machinery, which would put the concurrency model in the binding rather than in the code
//     that is measured.
//  2. The caller already has threads and its own idea of where work belongs. A WinUI3 app awaits
//     on winrt::resume_background(); a blocking call is exactly what such a coroutine wants, and
//     a completion delivered on a Go-owned thread is exactly what it does not -- it would arrive
//     with no apartment and have to be marshalled back across.
//  3. It is what the Windows app's own shape needs. urmsg::demo::GetWorld() is called from
//     CollectDiagnostics() at main.cpp:168, BEFORE winrt::init_apartment() at main.cpp:183, and
//     DemoWorld.h states that a winrt type there would be constructed without an apartment.
//     Every function in this file is plain C over uint64_t handles and touches no COM, so a
//     world can be constructed on that thread for nothing and the network work happens later,
//     elsewhere.
//  4. A blocking call needs a way to be woken, and that is the part a "just block" ABI forgets.
//     Device.Connect rides out a MEASURED ~60s operator window on a budget that defaults to 90
//     SECONDS. An app that is closing cannot wait that out. So every blocking export takes a
//     urnet_message_context handle: urnet_message_context_cancel wakes it from any thread and
//     the call returns with the context's error instead of spending its budget. Pass 0 for an
//     uncancellable call.
//
// WHAT THIS DOES NOT DO: it does not make a receive arrive on its own. A caller polls
// urnet_message_group_receive on its own schedule, because a poll is what the transport is.
//
// ── DECISION: A BODY CROSSES AS COUNTED OCTETS, NEVER AS char* AND NEVER INSIDE JSON ─────────
//
// urmessage.Group.Send takes a Go string and Message.Text is a Go string, and A GO STRING IS NOT
// TEXT: group.go seals []byte(text) and fills Text with string(bodyPlain) straight out of the
// AEAD. Neither is validated as UTF-8 and neither is NUL-free. So:
//
//   - A body is (const uint8_t*, int32_t) going in and the buffer-out pattern coming back. It is
//     never a char*: a char* would truncate a body at its first 0x00 octet and hand back a
//     SHORTER message with no error raised anywhere.
//   - A body is never a field of a json result. encoding/json replaces every invalid UTF-8 byte
//     with U+FFFD SILENTLY, so a json-carried body is a body the binding corrupted. That is the
//     whole reason urnet_message_list_info and urnet_message_list_body are two calls: the
//     metadata is json, the body is octets, and they do not mix.
//
// The caller decides whether its bodies are UTF-8. This ABI does not and cannot, because the
// envelope is unruled.
//
// ── LIFETIME ────────────────────────────────────────────────────────────────────────────────
//
// Every uint64_t this file returns is a handle in handles.go's registry and keeps its Go object
// reachable until urnet_release. Releasing does not close: call the object's own close first
// where one exists (a context, a store, a transport, a device, a group). Zero is never a handle
// -- it is "none" on the way in and "failure" or "empty" on the way out.
//
// urnet_live_handle_count is the measurement, and ctest/message_abi_test.c holds it across a
// whole conversation.

// ── the cancel handle ───────────────────────────────────────────────────────────────────────

// messageContext is a context.Context a C caller can hold and cancel from another thread. It is
// the piece that makes a blocking ABI closeable; see the threading decision above.
type messageContext struct {
	ctx    context.Context
	cancel context.CancelFunc
}

//export urnet_message_context_new
func urnet_message_context_new() C.uint64_t {
	defer cgoGuard("urnet_message_context_new")
	ctx, cancel := context.WithCancel(context.Background())
	return C.uint64_t(newHandle(&messageContext{ctx: ctx, cancel: cancel}))
}

// urnet_message_context_cancel wakes every blocking call holding this context. It is safe from
// any thread and it is idempotent. It is the "stop" half of the abi contract's
// stop-then-release: urnet_release alone leaves the context uncancelled.
//
//export urnet_message_context_cancel
func urnet_message_context_cancel(self C.uint64_t) {
	defer cgoGuard("urnet_message_context_cancel")
	self_, ok := resolveHandle[*messageContext](uint64(self), "urnet_message_context_cancel")
	if !ok || self_ == nil {
		return
	}
	self_.cancel()
}

// messageCtx resolves a context handle. A zero handle is context.Background(), which is an
// UNCANCELLABLE call and is what a caller that passes nothing asked for; an unknown handle is
// REFUSED rather than quietly downgraded to Background, because a call that cannot be cancelled
// while its caller believes it can is the exact failure this handle exists to prevent.
func messageCtx(id C.uint64_t, name string) (context.Context, bool) {
	if id == 0 {
		return context.Background(), true
	}
	self_, ok := resolveHandle[*messageContext](uint64(id), name)
	if !ok || self_ == nil {
		return nil, false
	}
	return self_.ctx, true
}

// ── the two durable stores, and the stream index reserver over one of them ──────────────────

//export urnet_message_stream_store_open
func urnet_message_stream_store_open(dir *C.char, outError **C.char) C.uint64_t {
	defer cgoGuard("urnet_message_stream_store_open")
	store, err := sdk.OpenStreamStore(goString(dir))
	if err != nil {
		setErrorOut(outError, err)
		return 0
	}
	return C.uint64_t(newHandle(store))
}

//export urnet_message_stream_store_close
func urnet_message_stream_store_close(self C.uint64_t, outError **C.char) C.bool {
	defer cgoGuard("urnet_message_stream_store_close")
	self_, ok := resolveHandle[*sdk.StreamStore](uint64(self), "urnet_message_stream_store_close")
	if !ok || self_ == nil {
		return C.bool(false)
	}
	if err := self_.Close(); err != nil {
		setErrorOut(outError, err)
		return C.bool(false)
	}
	return C.bool(true)
}

//export urnet_message_stream_index_reserver_new
func urnet_message_stream_index_reserver_new(streamStore C.uint64_t) C.uint64_t {
	defer cgoGuard("urnet_message_stream_index_reserver_new")
	store, ok := resolveHandle[*sdk.StreamStore](uint64(streamStore), "urnet_message_stream_index_reserver_new")
	if !ok || store == nil {
		return 0
	}
	return C.uint64_t(newHandle(sdk.NewStreamIndexReserver(store)))
}

//export urnet_message_durable_state_store_open
func urnet_message_durable_state_store_open(dir *C.char, outError **C.char) C.uint64_t {
	defer cgoGuard("urnet_message_durable_state_store_open")
	store, err := urmessage.OpenDurableStateStore(goString(dir))
	if err != nil {
		setErrorOut(outError, err)
		return 0
	}
	return C.uint64_t(newHandle(store))
}

//export urnet_message_durable_state_store_close
func urnet_message_durable_state_store_close(self C.uint64_t, outError **C.char) C.bool {
	defer cgoGuard("urnet_message_durable_state_store_close")
	self_, ok := resolveHandle[*urmessage.DurableStateStore](uint64(self), "urnet_message_durable_state_store_close")
	if !ok || self_ == nil {
		return C.bool(false)
	}
	if err := self_.Close(); err != nil {
		setErrorOut(outError, err)
		return C.bool(false)
	}
	return C.bool(true)
}

// ── the transport, over a connect client this abi does not produce ──────────────────────────

// urnet_message_transport_new binds §10.1 to one message server over a connect client the CALLER
// owns: nothing here dials, authenticates or closes that client.
//
// PROTOCOL_VERSION IS URNET_MESSAGE_PROTOCOL_VERSION, OR 0 FOR IT, AND NOTHING ELSE. It used to be
// passed straight through with no value documented anywhere, and 0 was the trap: every other
// numeric parameter in this abi uses 0 for "the default", and a caller who passed 0 by that analogy
// got a transport that offered no version at all, which the server answers two calls later, at
// Hello, as REASON_UNSUPPORTED_VERSION. A review built a whole conversation that way and lost every
// check after it. So 0 now takes the version this build speaks, like every other 0 here, and any
// other value is refused HERE, by name, before it can become a Hello the server refuses.
//
// THE CLIENT HANDLE HAS NO SOURCE IN THIS ABI TODAY AND THAT IS NOT AN OVERSIGHT. A
// connect.Client receives a frame in exactly two ways -- an in-process connect.Route, or a
// connect.PlatformTransport that dials wss://connect.<host> with an operator-minted ByJwt for a
// network_client (spec B §9.1) -- and neither is something sdk, connect or this binding can
// perform for itself. It is S2-7, it is open, and a client factory invented here would be an
// invented answer to it. What this export fixes is the SHAPE: the day a credential exists the
// client goes in this hole and nothing above it moves.
//
//export urnet_message_transport_new
func urnet_message_transport_new(client C.uint64_t, serverClientId *C.char, protocolVersion C.uint32_t, timeoutMs C.int64_t, outError **C.char) C.uint64_t {
	defer cgoGuard("urnet_message_transport_new")
	client_, ok := resolveHandle[sdk.MessageTransportClient](uint64(client), "urnet_message_transport_new")
	if !ok {
		return 0
	}
	version, err := messageProtocolVersionOf(uint32(protocolVersion))
	if err != nil {
		setErrorOut(outError, err)
		return 0
	}
	server, err := connect.ParseId(goString(serverClientId))
	if err != nil {
		setErrorOut(outError, err)
		return 0
	}
	transport, err := sdk.NewMessageTransport(&sdk.MessageTransportConfig{
		Client:          client_,
		Server:          server,
		ProtocolVersion: version,
		Timeout:         time.Duration(timeoutMs) * time.Millisecond,
	})
	if err != nil {
		setErrorOut(outError, err)
		return 0
	}
	return C.uint64_t(newHandle(transport))
}

// messageProtocolVersion is the one §4.3.1 protocol version this build speaks, and it is
// URNET_MESSAGE_PROTOCOL_VERSION in include/urnetwork_message.h. The server this alpha is deployed
// from declares the same number, as `const protocolVersion = 1` in msgrepo
// cmd/message-server/server.go, and answers anything else REASON_UNSUPPORTED_VERSION.
const messageProtocolVersion uint32 = 1

// messageProtocolVersionOf is protocol_version as the abi takes it: 0 is this build's version, the
// build's version is itself, and every other value is refused with a sentence naming the one that
// works.
func messageProtocolVersionOf(protocolVersion uint32) (uint32, error) {
	switch protocolVersion {
	case 0, messageProtocolVersion:
		return messageProtocolVersion, nil
	}
	return 0, fmt.Errorf("urnet_message_transport_new: protocol_version %d is not a version this build speaks; pass %d (URNET_MESSAGE_PROTOCOL_VERSION), or 0 for it",
		protocolVersion, messageProtocolVersion)
}

// urnet_message_transport_close stops receiving. The connect client under it is the caller's and
// is NOT closed.
//
//export urnet_message_transport_close
func urnet_message_transport_close(self C.uint64_t) {
	defer cgoGuard("urnet_message_transport_close")
	self_, ok := resolveHandle[*sdk.MessageTransport](uint64(self), "urnet_message_transport_close")
	if !ok || self_ == nil {
		return
	}
	self_.Close()
}

// ── the device ──────────────────────────────────────────────────────────────────────────────

// cAdapterMessageConnectAttempt carries ConnectPolicy.OnAttempt across to C. It holds a C
// function pointer and a C user_data and no Go pointer, which is what cgo's pointer rules
// require of a value a Go struct keeps; the generated adapters in exports_gen.go have the same
// shape and this one follows them.
type cAdapterMessageConnectAttempt struct {
	cb       C.urnet_message_connect_attempt_cb
	userData unsafe.Pointer
}

func (self *cAdapterMessageConnectAttempt) onAttempt(attempt urmessage.ConnectAttempt) {
	defer cgoGuard("urnet_message_connect_attempt_cb")
	var err *C.char
	if attempt.Err != nil {
		err = cString(attempt.Err.Error())
	}
	C.urnet_invoke_message_connect_attempt(self.cb, self.userData,
		C.int32_t(attempt.Attempt),
		C.int64_t(attempt.Elapsed.Milliseconds()),
		C.int64_t(attempt.Backoff.Milliseconds()),
		err)
	if err != nil {
		cStringFree(err)
	}
}

// urnet_message_device_new builds one device over a transport, a reserver and, optionally, a
// durable state store.
//
// state_store may be 0, which takes urmessage's in-memory store: it persists NOTHING and every
// group is gone when the process ends. That is urmessage's own default and its reason is that a
// device which silently wrote private keys into a directory the caller did not choose would be
// the worse surprise. Pass a urnet_message_durable_state_store_open handle to persist.
//
// connect_budget_ms and connect_attempt_timeout_ms are 0 for urmessage's defaults (90s and 10s).
// THE BUDGET IS THE BOUND ON HOW LONG urnet_message_device_connect BLOCKS, whatever the attempt
// timeout: an attempt is cut to what is left of the budget, so a budget under one attempt is one
// attempt of the budget's length. It used to be checked only after an attempt returned, and a
// 500 ms budget blocked for the whole 10 s default attempt.
// connect_attempt_cb may be NULL; when it is not it fires for every Hello that did not connect,
// on the thread inside urnet_message_device_connect, which is how a caller says "Reconnecting..."
// DURING the ~60s operator window rather than after it.
//
//export urnet_message_device_new
func urnet_message_device_new(transport C.uint64_t, reserver C.uint64_t, stateStore C.uint64_t, connectBudgetMs C.int64_t, connectAttemptTimeoutMs C.int64_t, connectAttemptCb C.urnet_message_connect_attempt_cb, connectAttemptUserData unsafe.Pointer, outError **C.char) C.uint64_t {
	defer cgoGuard("urnet_message_device_new")
	transport_, ok := resolveHandle[*sdk.MessageTransport](uint64(transport), "urnet_message_device_new")
	if !ok {
		return 0
	}
	reserver_, ok := resolveHandle[messagegroup.StreamIndexReserver](uint64(reserver), "urnet_message_device_new")
	if !ok {
		return 0
	}
	config := urmessage.DeviceConfig{
		Transport: transport_,
		Reserver:  reserver_,
		Connect: urmessage.ConnectPolicy{
			Budget:         time.Duration(connectBudgetMs) * time.Millisecond,
			AttemptTimeout: time.Duration(connectAttemptTimeoutMs) * time.Millisecond,
		},
	}
	// NOT an unconditional `config.StateStore = stateStore_`. StateStore is an INTERFACE field,
	// and a nil *DurableStateStore assigned into it is a NON-NIL interface holding a nil
	// pointer -- which is not the nil that urmessage tests for when it decides to take the
	// memory store, and which panics on the first call to it instead.
	if stateStore != 0 {
		stateStore_, ok := resolveHandle[*urmessage.DurableStateStore](uint64(stateStore), "urnet_message_device_new")
		if !ok || stateStore_ == nil {
			return 0
		}
		config.StateStore = stateStore_
	}
	if connectAttemptCb != nil {
		adapter := &cAdapterMessageConnectAttempt{cb: connectAttemptCb, userData: connectAttemptUserData}
		config.Connect.OnAttempt = adapter.onAttempt
	}
	device, err := urmessage.NewDevice(config)
	if err != nil {
		setErrorOut(outError, err)
		return 0
	}
	return C.uint64_t(newHandle(device))
}

// urnet_message_device_connect says §4.3.1's Hello and BLOCKS until it is answered, until the
// budget is spent, or until ctx is cancelled. See the threading decision at the top of this
// file: the budget defaults to 90 seconds and a ui thread must not be what waits it out.
//
// A budget spent on silence is urmessage's ErrReconnecting, which means "not yet, ask again" and
// NOT "failed": on the deployed server a reconnecting client_id is not routed to for about sixty
// seconds. A caller that shows a user "could not connect" here is telling them something false.
//
//export urnet_message_device_connect
func urnet_message_device_connect(self C.uint64_t, ctx C.uint64_t, outError **C.char) C.bool {
	defer cgoGuard("urnet_message_device_connect")
	self_, ok := resolveHandle[*urmessage.Device](uint64(self), "urnet_message_device_connect")
	if !ok || self_ == nil {
		return C.bool(false)
	}
	ctx_, ok := messageCtx(ctx, "urnet_message_device_connect")
	if !ok {
		return C.bool(false)
	}
	if err := self_.Connect(ctx_); err != nil {
		setErrorOut(outError, err)
		return C.bool(false)
	}
	return C.bool(true)
}

//export urnet_message_device_close
func urnet_message_device_close(self C.uint64_t, outError **C.char) C.bool {
	defer cgoGuard("urnet_message_device_close")
	self_, ok := resolveHandle[*urmessage.Device](uint64(self), "urnet_message_device_close")
	if !ok || self_ == nil {
		return C.bool(false)
	}
	if err := self_.Close(); err != nil {
		setErrorOut(outError, err)
		return C.bool(false)
	}
	return C.bool(true)
}

// urnet_message_device_key_package is the buffer-out pattern (see copyOut in exports_manual.go):
// call once with out == NULL to learn the size, again with a buffer that large to fill it.
//
//export urnet_message_device_key_package
func urnet_message_device_key_package(self C.uint64_t, out *C.uint8_t, inoutLen *C.int32_t, outError **C.char) C.bool {
	defer cgoGuard("urnet_message_device_key_package")
	self_, ok := resolveHandle[*urmessage.Device](uint64(self), "urnet_message_device_key_package")
	if !ok || self_ == nil {
		return C.bool(false)
	}
	keyPackage, err := self_.KeyPackage()
	if err != nil {
		setErrorOut(outError, err)
		if inoutLen != nil {
			*inoutLen = 0
		}
		return C.bool(false)
	}
	return copyOut(out, inoutLen, keyPackage)
}

//export urnet_message_device_groups
func urnet_message_device_groups(self C.uint64_t) C.uint64_t {
	defer cgoGuard("urnet_message_device_groups")
	self_, ok := resolveHandle[*urmessage.Device](uint64(self), "urnet_message_device_groups")
	if !ok || self_ == nil {
		return 0
	}
	return C.uint64_t(newGroupList(self_.Groups()))
}

// urnet_message_device_restore rebuilds every group a DURABLE state store holds. A restored
// group will not seal until urnet_message_group_receive has run once over it -- that is
// urmessage's ErrNotReconciled, and it is what bounds a copied app-data folder.
//
// Like receive, a non-zero list and a non-NULL out_error can both come back: a restore that
// rebuilt some groups and failed on others carries both halves.
//
//export urnet_message_device_restore
func urnet_message_device_restore(self C.uint64_t, ctx C.uint64_t, outError **C.char) C.uint64_t {
	defer cgoGuard("urnet_message_device_restore")
	self_, ok := resolveHandle[*urmessage.Device](uint64(self), "urnet_message_device_restore")
	if !ok || self_ == nil {
		return 0
	}
	ctx_, ok := messageCtx(ctx, "urnet_message_device_restore")
	if !ok {
		return 0
	}
	groups, err := self_.Restore(ctx_)
	if err != nil {
		setErrorOut(outError, err)
	}
	return C.uint64_t(newGroupList(groups))
}

//export urnet_message_device_create_group
func urnet_message_device_create_group(self C.uint64_t, ctx C.uint64_t, groupId *C.uint8_t, groupIdLen C.int32_t, outError **C.char) C.uint64_t {
	defer cgoGuard("urnet_message_device_create_group")
	self_, ok := resolveHandle[*urmessage.Device](uint64(self), "urnet_message_device_create_group")
	if !ok || self_ == nil {
		return 0
	}
	ctx_, ok := messageCtx(ctx, "urnet_message_device_create_group")
	if !ok {
		return 0
	}
	group, err := self_.CreateGroup(ctx_, goBytes(groupId, groupIdLen))
	if err != nil {
		setErrorOut(outError, err)
		return 0
	}
	return C.uint64_t(newHandle(group))
}

//export urnet_message_device_join
func urnet_message_device_join(self C.uint64_t, ctx C.uint64_t, invite C.uint64_t, outError **C.char) C.uint64_t {
	defer cgoGuard("urnet_message_device_join")
	self_, ok := resolveHandle[*urmessage.Device](uint64(self), "urnet_message_device_join")
	if !ok || self_ == nil {
		return 0
	}
	ctx_, ok := messageCtx(ctx, "urnet_message_device_join")
	if !ok {
		return 0
	}
	invite_, ok := resolveHandle[*urmessage.Invite](uint64(invite), "urnet_message_device_join")
	if !ok || invite_ == nil {
		return 0
	}
	group, err := self_.Join(ctx_, invite_)
	if err != nil {
		setErrorOut(outError, err)
		return 0
	}
	return C.uint64_t(newHandle(group))
}

// ── the invite, which is secret in full ─────────────────────────────────────────────────────

//export urnet_message_group_add_member
func urnet_message_group_add_member(self C.uint64_t, keyPackage *C.uint8_t, keyPackageLen C.int32_t, outError **C.char) C.uint64_t {
	defer cgoGuard("urnet_message_group_add_member")
	self_, ok := resolveHandle[*urmessage.Group](uint64(self), "urnet_message_group_add_member")
	if !ok || self_ == nil {
		return 0
	}
	invite, err := self_.AddMember(goBytes(keyPackage, keyPackageLen))
	if err != nil {
		setErrorOut(outError, err)
		return 0
	}
	return C.uint64_t(newHandle(invite))
}

// urnet_message_invite_encode is the buffer-out pattern. WHAT COMES OUT IS KEY MATERIAL: two of
// an invite's four fields are secret (pq_secret, and the MLS init secret inside the Welcome), so
// an invite that reaches a third party is a group that third party is in. Move it the way you
// would move a private key, once, over a channel that is already authenticated and already
// confidential, and destroy it afterwards.
//
//export urnet_message_invite_encode
func urnet_message_invite_encode(self C.uint64_t, out *C.uint8_t, inoutLen *C.int32_t, outError **C.char) C.bool {
	defer cgoGuard("urnet_message_invite_encode")
	self_, ok := resolveHandle[*urmessage.Invite](uint64(self), "urnet_message_invite_encode")
	if !ok || self_ == nil {
		return C.bool(false)
	}
	encoded, err := self_.Encode()
	if err != nil {
		setErrorOut(outError, err)
		if inoutLen != nil {
			*inoutLen = 0
		}
		return C.bool(false)
	}
	return copyOut(out, inoutLen, encoded)
}

//export urnet_message_parse_invite
func urnet_message_parse_invite(encoded *C.uint8_t, encodedLen C.int32_t, outError **C.char) C.uint64_t {
	defer cgoGuard("urnet_message_parse_invite")
	invite, err := urmessage.ParseInvite(goBytes(encoded, encodedLen))
	if err != nil {
		setErrorOut(outError, err)
		return 0
	}
	return C.uint64_t(newHandle(invite))
}

// ── the group ───────────────────────────────────────────────────────────────────────────────

//export urnet_message_group_open
func urnet_message_group_open(self C.uint64_t, ctx C.uint64_t, outError **C.char) C.bool {
	defer cgoGuard("urnet_message_group_open")
	self_, ok := resolveHandle[*urmessage.Group](uint64(self), "urnet_message_group_open")
	if !ok || self_ == nil {
		return C.bool(false)
	}
	ctx_, ok := messageCtx(ctx, "urnet_message_group_open")
	if !ok {
		return C.bool(false)
	}
	if err := self_.Open(ctx_); err != nil {
		setErrorOut(outError, err)
		return C.bool(false)
	}
	return C.bool(true)
}

// urnet_message_group_send seals one body and BLOCKS on its submit. The body is counted octets
// and crosses byte for byte: it is not a char*, it is not read as UTF-8, and it may contain
// 0x00. See the body decision at the top of this file.
//
// The returned string is this message's metadata as json and DOES NOT CARRY THE BODY -- the
// caller already has the body, and a json-carried body would be silently mangled wherever it is
// not valid UTF-8. Free it with urnet_free_string.
//
//export urnet_message_group_send
func urnet_message_group_send(self C.uint64_t, ctx C.uint64_t, body *C.uint8_t, bodyLen C.int32_t, outError **C.char) *C.char {
	defer cgoGuard("urnet_message_group_send")
	self_, ok := resolveHandle[*urmessage.Group](uint64(self), "urnet_message_group_send")
	if !ok || self_ == nil {
		return nil
	}
	ctx_, ok := messageCtx(ctx, "urnet_message_group_send")
	if !ok {
		return nil
	}
	sent, err := self_.Send(ctx_, string(goBytes(body, bodyLen)))
	if err != nil {
		setErrorOut(outError, err)
		return nil
	}
	return cJson(messageInfoOf(sent), "urnet_message_group_send")
}

// urnet_message_group_receive fetches §4.3.4's pages and BLOCKS while it does.
//
// A NON-ZERO RESULT AND A NON-NULL out_error CAN BOTH COME BACK, and a caller that reads an
// error as "nothing arrived" will drop real messages. urmessage returns its partial answers WITH
// the reason -- a page bound reached with more to come (ErrFetchIncomplete), a server that named
// a high water above everything it handed over (ErrFetchOmitted), a record given up on after
// every retry (ErrRecordAbandoned) -- and this export carries both halves rather than collapsing
// one into the other.
//
// Zero with no error is the ordinary polling answer: nothing new. Zero with an error is a fetch
// that returned nothing at all.
//
// AND ZERO WITH NO ERROR IS ALSO WHAT AN UNKNOWN self OR ctx HANDLE ANSWERS, which makes a dead
// handle look like a quiet conversation. That is this abi's convention everywhere -- a handle
// that does not resolve is a programming error, it is logged by name through glog and it is not
// an out_error -- and it is stated here rather than only inherited, because receive is the one
// export where the ambiguous answer is also the common one.
//
//export urnet_message_group_receive
func urnet_message_group_receive(self C.uint64_t, ctx C.uint64_t, outError **C.char) C.uint64_t {
	defer cgoGuard("urnet_message_group_receive")
	self_, ok := resolveHandle[*urmessage.Group](uint64(self), "urnet_message_group_receive")
	if !ok || self_ == nil {
		return 0
	}
	ctx_, ok := messageCtx(ctx, "urnet_message_group_receive")
	if !ok {
		return 0
	}
	messages, err := self_.Receive(ctx_)
	if err != nil {
		setErrorOut(outError, err)
	}
	return C.uint64_t(newMessageList(messages))
}

// urnet_message_group_messages is every message this group has sent or received, in the order it
// learned them.
//
//export urnet_message_group_messages
func urnet_message_group_messages(self C.uint64_t) C.uint64_t {
	defer cgoGuard("urnet_message_group_messages")
	self_, ok := resolveHandle[*urmessage.Group](uint64(self), "urnet_message_group_messages")
	if !ok || self_ == nil {
		return 0
	}
	return C.uint64_t(newMessageList(self_.Messages()))
}

//export urnet_message_group_id
func urnet_message_group_id(self C.uint64_t, out *C.uint8_t, inoutLen *C.int32_t) C.bool {
	defer cgoGuard("urnet_message_group_id")
	self_, ok := resolveHandle[*urmessage.Group](uint64(self), "urnet_message_group_id")
	if !ok || self_ == nil {
		return C.bool(false)
	}
	return copyOut(out, inoutLen, self_.Id())
}

//export urnet_message_group_epoch
func urnet_message_group_epoch(self C.uint64_t) C.uint64_t {
	defer cgoGuard("urnet_message_group_epoch")
	self_, ok := resolveHandle[*urmessage.Group](uint64(self), "urnet_message_group_epoch")
	if !ok || self_ == nil {
		return 0
	}
	return C.uint64_t(self_.Epoch())
}

//export urnet_message_group_is_open
func urnet_message_group_is_open(self C.uint64_t) C.bool {
	defer cgoGuard("urnet_message_group_is_open")
	self_, ok := resolveHandle[*urmessage.Group](uint64(self), "urnet_message_group_is_open")
	if !ok || self_ == nil {
		return C.bool(false)
	}
	return C.bool(self_.IsOpen())
}

// urnet_message_group_stats is what this group has SEEN, as json. Free with urnet_free_string.
// It exists so that "nothing arrived" and "something arrived and this build would not open it"
// are two readings rather than one silence; every counter urmessage keeps is carried.
//
//export urnet_message_group_stats
func urnet_message_group_stats(self C.uint64_t) *C.char {
	defer cgoGuard("urnet_message_group_stats")
	self_, ok := resolveHandle[*urmessage.Group](uint64(self), "urnet_message_group_stats")
	if !ok || self_ == nil {
		return nil
	}
	stats := self_.Stats()
	return cJson(&messageGroupStats{
		Fetched:         stats.Fetched,
		Opened:          stats.Opened,
		SkippedCeremony: stats.SkippedCeremony,
		SkippedOwn:      stats.SkippedOwn,
		OpenedOwn:       stats.OpenedOwn,
		OwnWithoutCopy:  stats.OwnWithoutCopy,
		SkippedSeen:     stats.SkippedSeen,
		Unopened:        stats.Unopened,
		Omitted:         stats.Omitted,
		SkippedClass:    stats.SkippedClass,
		FailedOpen:      stats.FailedOpen,
		Submitted:       stats.Submitted,
		Rebound:         stats.Rebound,
		Pages:           stats.Pages,
		Unattested:      stats.Unattested,
	}, "urnet_message_group_stats")
}

//export urnet_message_group_close
func urnet_message_group_close(self C.uint64_t, outError **C.char) C.bool {
	defer cgoGuard("urnet_message_group_close")
	self_, ok := resolveHandle[*urmessage.Group](uint64(self), "urnet_message_group_close")
	if !ok || self_ == nil {
		return C.bool(false)
	}
	if err := self_.Close(); err != nil {
		setErrorOut(outError, err)
		return C.bool(false)
	}
	return C.bool(true)
}

// ── the two list handles ────────────────────────────────────────────────────────────────────
//
// A []*Group and a []*Message cross as ONE handle with indexed accessors rather than as N
// handles or as one json blob. N handles would make a 600 message page 600 things for a caller
// to release; one json blob cannot carry a body (see the body decision). An EMPTY slice is
// handle 0, so the ordinary "nothing new" poll costs the caller no release at all, and every
// accessor answers 0/NULL/false on handle 0 rather than failing.

type groupList struct {
	groups []*urmessage.Group
}

func newGroupList(groups []*urmessage.Group) uint64 {
	if len(groups) == 0 {
		return 0
	}
	return newHandle(&groupList{groups: groups})
}

//export urnet_message_group_list_count
func urnet_message_group_list_count(self C.uint64_t) C.int32_t {
	defer cgoGuard("urnet_message_group_list_count")
	self_, ok := resolveHandle[*groupList](uint64(self), "urnet_message_group_list_count")
	if !ok || self_ == nil {
		return 0
	}
	return C.int32_t(len(self_.groups))
}

// urnet_message_group_list_at hands out a NEW handle onto the group at index, which the caller
// releases. Two calls at one index are two handles onto one group; releasing either leaves the
// group alive under the other.
//
//export urnet_message_group_list_at
func urnet_message_group_list_at(self C.uint64_t, index C.int32_t) C.uint64_t {
	defer cgoGuard("urnet_message_group_list_at")
	self_, ok := resolveHandle[*groupList](uint64(self), "urnet_message_group_list_at")
	if !ok || self_ == nil {
		return 0
	}
	if index < 0 || int(index) >= len(self_.groups) {
		return 0
	}
	return C.uint64_t(newHandle(self_.groups[index]))
}

type messageList struct {
	messages []*urmessage.Message
}

func newMessageList(messages []*urmessage.Message) uint64 {
	if len(messages) == 0 {
		return 0
	}
	return newHandle(&messageList{messages: messages})
}

// messageInfo is one message WITHOUT its body. The field names are snake_case to match the json
// every other data type in this abi crosses as; urmessage's own structs carry no json tags, so
// this is a projection rather than a marshal of the type -- and the projection is also what
// keeps the body out of json, which is the point.
type messageInfo struct {
	RecordId uint64 `json:"record_id"`
	// 3.1's sender_handle, 16 octets, lower case hex. It is the routing identity of the member
	// that sealed the record and IT IS NOT A NAME: the alpha has no identity system.
	SenderHandle string `json:"sender_handle"`
	Mine         bool   `json:"mine"`
	SentAtMs     int64  `json:"sent_at_ms"`
	// The body's length in octets, which is what urnet_message_list_body will ask for.
	BodyLen int32 `json:"body_len"`
}

// messageGroupStats is urmessage.Stats under the same snake_case rule.
type messageGroupStats struct {
	Fetched         uint64 `json:"fetched"`
	Opened          uint64 `json:"opened"`
	SkippedCeremony uint64 `json:"skipped_ceremony"`
	SkippedOwn      uint64 `json:"skipped_own"`
	OpenedOwn       uint64 `json:"opened_own"`
	OwnWithoutCopy  uint64 `json:"own_without_copy"`
	SkippedSeen     uint64 `json:"skipped_seen"`
	Unopened        uint64 `json:"unopened"`
	Omitted         uint64 `json:"omitted"`
	SkippedClass    uint64 `json:"skipped_class"`
	FailedOpen      uint64 `json:"failed_open"`
	Submitted       uint64 `json:"submitted"`
	Rebound         uint64 `json:"rebound"`
	Pages           uint64 `json:"pages"`
	Unattested      uint64 `json:"unattested"`
}

func messageInfoOf(message *urmessage.Message) *messageInfo {
	if message == nil {
		return nil
	}
	// encoding/hex rather than hand-rolled nibbles. The hand-rolled form was correct, and it
	// tripped connect/message TestClassBucketJoinIsConfinedToRecordGo -- a gate that scans this
	// repository too and forbids splitting a byte as >>4 / &0x0F outside record.go, because that
	// is how a retention-class wire byte is split into its class and its eph bucket. This code
	// was splitting a byte into hex digits: the same SHAPE, an unrelated PROPERTY. Filed against
	// the gate as a false-positive class; the standard library is the better answer either way.
	handle := []byte(hex.EncodeToString(message.SenderHandle))
	return &messageInfo{
		RecordId:     message.RecordId,
		SenderHandle: string(handle),
		Mine:         message.Mine,
		SentAtMs:     message.SentAtMs,
		BodyLen:      int32(len(message.Text)),
	}
}

//export urnet_message_list_count
func urnet_message_list_count(self C.uint64_t) C.int32_t {
	defer cgoGuard("urnet_message_list_count")
	self_, ok := resolveHandle[*messageList](uint64(self), "urnet_message_list_count")
	if !ok || self_ == nil {
		return 0
	}
	return C.int32_t(len(self_.messages))
}

// urnet_message_list_info is one message's metadata as json, WITHOUT the body. Free with
// urnet_free_string.
//
//export urnet_message_list_info
func urnet_message_list_info(self C.uint64_t, index C.int32_t) *C.char {
	defer cgoGuard("urnet_message_list_info")
	self_, ok := resolveHandle[*messageList](uint64(self), "urnet_message_list_info")
	if !ok || self_ == nil {
		return nil
	}
	if index < 0 || int(index) >= len(self_.messages) {
		return nil
	}
	return cJson(messageInfoOf(self_.messages[index]), "urnet_message_list_info")
}

// urnet_message_list_body is one message's body, byte for byte, through the buffer-out pattern:
// call once with out == NULL to size it, again to fill it. It is the ONLY way a body leaves this
// abi, for the reason the body decision at the top of this file gives.
//
//export urnet_message_list_body
func urnet_message_list_body(self C.uint64_t, index C.int32_t, out *C.uint8_t, inoutLen *C.int32_t) C.bool {
	defer cgoGuard("urnet_message_list_body")
	self_, ok := resolveHandle[*messageList](uint64(self), "urnet_message_list_body")
	if !ok || self_ == nil {
		return C.bool(false)
	}
	if index < 0 || int(index) >= len(self_.messages) {
		return C.bool(false)
	}
	return copyOut(out, inoutLen, []byte(self_.messages[index].Text))
}
