/* HAND-WRITTEN. This is the header for exports_message.go, which is hand-written for the reason
 * stated at the top of that file: the messaging surface lives in sdk/urmessage rather than in
 * package sdk, and gen/gen.go walks package sdk. urnetwork_sdk.h next to this file is generated
 * and carries "DO NOT EDIT"; these declarations are not in it. Both headers ship and they are
 * independent -- include whichever you need, or both.
 *
 * THE MESSAGING C ABI.
 *
 * Contract, the same one urnetwork_sdk.h states, plus what is particular to messaging:
 *
 * - objects are opaque uint64_t handles. release every returned handle with urnet_release
 *   (declared in urnetwork_sdk.h). releasing a handle does not close or stop the object; call
 *   the object's close/cancel function first where one exists. zero is never a handle: it is
 *   "none" going in and "failure" or "empty" coming out.
 * - returned char* strings are owned by the caller: free with urnet_free_string.
 * - functions with a char** out_error set a malloc'd message on failure (free with
 *   urnet_free_string). pass NULL to ignore the text.
 * - the buffer-out pattern for octets: *inout_len is ALWAYS set to the needed size; the copy
 *   happens and true is returned only when out is non-NULL and the capacity passed in was
 *   sufficient. so: call once with out == NULL to size, allocate, call again.
 * - urnet_live_handle_count (urnetwork_sdk.h) counts live handles, for leak checks.
 *
 * A MESSAGE BODY IS OCTETS AND NOT TEXT, AND THE ABI TREATS IT THAT WAY. The seal path takes
 * []byte and the open path hands []byte back; neither is validated as UTF-8 and neither is
 * NUL-free. So a body crosses as (const uint8_t*, int32_t) going in and through the buffer-out
 * pattern coming back, and a body is NEVER a field of a json result -- a char* would truncate at
 * the first 0x00 and a json string would silently replace every invalid byte with U+FFFD. That
 * is why message metadata (urnet_message_list_info) and a message body
 * (urnet_message_list_body) are two calls. Whether your bodies are text is your decision; this
 * abi does not make it, because the content envelope is not ruled.
 *
 * THESE CALLS BLOCK AND YOU SHOULD NOT BE ON A UI THREAD. urnet_message_device_connect,
 * _group_open, _group_send, _group_receive, _device_restore and _device_create_group/_join all
 * wait on the network. connect's budget DEFAULTS TO 90 SECONDS, because a reconnecting client is
 * not routed to by the operator for about sixty (measured). run them on a thread of your own and
 * pass a urnet_message_context handle so you can cancel them: urnet_message_context_cancel wakes
 * every call holding that context, from any thread. pass ctx 0 for an uncancellable call.
 *
 * THERE IS NO RECEIVE PUSH. urnet_message_group_receive is a poll and that is what the transport
 * is. nothing arrives on its own.
 *
 * WHAT IS NOT HERE: receipts, reactions, replies, edit, delete, media, group names, contact
 * discovery, a third member. They are not built underneath this and they are not stubbed here.
 *
 * SPDX-License-Identifier: MPL-2.0 */
#ifndef URNETWORK_MESSAGE_H
#define URNETWORK_MESSAGE_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ----- constants ----- */

/* the one message server protocol version this build speaks, which is what
 * urnet_message_transport_new's protocol_version takes. 0 takes it too, as every other 0 in this
 * abi takes a default; any other value is refused at transport_new, by name. */
#define URNET_MESSAGE_PROTOCOL_VERSION 1

/* ----- callback types ----- */

/* one Hello that did not connect. fires on the thread inside urnet_message_device_connect --
 * this is a progress report from a blocking call, not an async completion. it must not call back
 * into the device it came from. err is only valid during the call.
 *
 * the typedef is repeated here rather than included from callbacks_message.h so that this header
 * stands alone, which is what urnetwork_sdk.h does with the generated callbacks.h. */
#ifndef URNETWORK_MESSAGE_CALLBACKS_H
typedef void (*urnet_message_connect_attempt_cb)(void* user_data, int32_t attempt, int64_t elapsed_ms, int64_t backoff_ms, const char* err);
#endif

/* ----- cancellation ----- */

/* a context a blocking call can be woken from. release with urnet_release AFTER cancelling. */
uint64_t urnet_message_context_new(void);
/* wake every call holding this context. safe from any thread, idempotent. */
void urnet_message_context_cancel(uint64_t self);

/* ----- the durable stores ----- */

/* the stream index allocator's backing store. one directory per device, held under a
 * single-writer exclusion, fsync'd before an index is handed out -- a reused stream index is a
 * reused nonce under a reused record key. */
uint64_t urnet_message_stream_store_open(const char* dir, char** out_error);
bool urnet_message_stream_store_close(uint64_t self, char** out_error);
uint64_t urnet_message_stream_index_reserver_new(uint64_t stream_store);

/* where MLS keeps group state and private keys, so that a restart is a restore. EVERY OCTET IS
 * WRITTEN IN THE CLEAR and the only thing protecting it is file permissions, which is a real
 * bound on POSIX and is not a bound this code sets on Windows. a COPY of this directory is a
 * second device on one identity; see urnet_message_device_restore. */
uint64_t urnet_message_durable_state_store_open(const char* dir, char** out_error);
bool urnet_message_durable_state_store_close(uint64_t self, char** out_error);

/* ----- the platform-attached client ----- */

/* build a connect client ATTACHED TO THE PLATFORM and dial it: this is the `client` handle
 * urnet_message_transport_new takes, and it is what lets this abi reach a message server that is
 * not in your own process.
 *
 * by_client_jwt is an operator-minted ByJwt for a network_client. NOTHING HERE MINTS ONE: that is
 * an admin action against a running URnetwork operator, it is the half of S2-7 that is still open,
 * and this call takes the credential you already hold. IT IS A SECRET -- do not log it.
 *
 * host is the operator host name, e.g. "ur.io". the platform and api urls are DERIVED from it:
 * env "" or "main" gives wss://connect.<host>, any other env gives wss://<env>-connect.<host>.
 * env, instance_id and app_version may each be NULL. instance_id is a uuid identifying THIS
 * installation -- pass NULL or "" to draw a fresh one, or the uuid you kept to reconnect as the
 * same one; a malformed uuid is refused rather than silently replaced. every refusal answers 0
 * AND sets out_error.
 *
 * IT DOES NOT BLOCK AND IT DOES NOT TELL YOU WHETHER THE CREDENTIAL WAS ACCEPTED. the dial runs on
 * its own thread and reconnects by itself; urnet_message_device_connect is what finds out.
 *
 * THIS PATH HAS NOT BEEN RUN AGAINST A REAL OPERATOR FROM THIS ABI. what is under test is the
 * shape -- refusals, the derived url, the client_id, the provide modes -- and not that a frame
 * crossed.
 *
 * CLOSE IT WITH urnet_message_client_close BEFORE urnet_release. release alone leaves the
 * websocket and its reconnect loop running. close the device and the transport first: they are
 * built over this and neither closes it. */
uint64_t urnet_message_client_new(const char* by_client_jwt, const char* host, const char* env, const char* instance_id, const char* app_version, char** out_error);
/* the client_id the credential names, as a uuid string, which is the identity the platform routes
 * to. free with urnet_free_string. */
char* urnet_message_client_id(uint64_t self);
/* the url this client actually dialled. the derivation from host and env happens inside the
 * library, and dialling the production authority from a staging env looks exactly like working.
 * free with urnet_free_string. */
char* urnet_message_client_platform_url(uint64_t self);
/* stop the platform transport, the client and everything under them. idempotent. */
void urnet_message_client_close(uint64_t self);

/* ----- the transport ----- */

/* bind to one message server over a connect client YOU own: nothing here dials, authenticates or
 * closes it. server_client_id is a uuid string. protocol_version is URNET_MESSAGE_PROTOCOL_VERSION,
 * or 0 for it; any other value answers 0 and out_error here, rather than a Hello the server refuses
 * later. timeout_ms 0 takes the binding's default.
 *
 * WHERE THE client HANDLE COMES FROM: urnet_message_client_new, above -- a connect.Client receives
 * a frame only through an in-process route or through a platform transport dialling an operator
 * with a minted ByJwt, and that export is the second. what is still open of S2-7 is the CREDENTIAL
 * and only the credential. */
uint64_t urnet_message_transport_new(uint64_t client, const char* server_client_id, uint32_t protocol_version, int64_t timeout_ms, char** out_error);
/* stop receiving. the connect client under it is yours and is NOT closed. */
void urnet_message_transport_close(uint64_t self);

/* ----- the device ----- */

/* state_store may be 0, which takes an IN-MEMORY store: it persists nothing and every group is
 * gone when the process ends. connect_budget_ms and connect_attempt_timeout_ms 0 take 90s and
 * 10s. THE BUDGET BOUNDS HOW LONG urnet_message_device_connect BLOCKS whatever the attempt timeout
 * says: every attempt is cut to what is left of it, so a 500ms budget returns at about 500ms even
 * with the 10s default attempt. connect_attempt_cb may be NULL; when it is not it fires for every Hello that did not
 * connect, on the thread inside urnet_message_device_connect -- it is how you say
 * "Reconnecting..." DURING the window rather than after it. */
uint64_t urnet_message_device_new(uint64_t transport, uint64_t reserver, uint64_t state_store, int64_t connect_budget_ms, int64_t connect_attempt_timeout_ms, urnet_message_connect_attempt_cb connect_attempt_cb, void* connect_attempt_user_data, char** out_error);
/* say Hello. BLOCKS for up to the budget, and not an attempt past it. a budget spent on silence is "not yet, ask again" and
 * is NOT a failure: on the deployed server a reconnecting client_id is not routed to for about
 * sixty seconds. showing a user "could not connect" here tells them something false. */
bool urnet_message_device_connect(uint64_t self, uint64_t ctx, char** out_error);
bool urnet_message_device_close(uint64_t self, char** out_error);
/* buffer-out. the key package another device's urnet_message_group_add_member takes. */
bool urnet_message_device_key_package(uint64_t self, uint8_t* out, int32_t* inout_len, char** out_error);
/* a group list handle, or 0 when there are none. */
uint64_t urnet_message_device_groups(uint64_t self);
/* rebuild every group a DURABLE state store holds. a restored group will not seal until
 * urnet_message_group_receive has run once over it. a non-zero list and a non-NULL out_error can
 * both come back. */
uint64_t urnet_message_device_restore(uint64_t self, uint64_t ctx, char** out_error);
/* group_id is 32 octets. */
uint64_t urnet_message_device_create_group(uint64_t self, uint64_t ctx, const uint8_t* group_id, int32_t group_id_len, char** out_error);
uint64_t urnet_message_device_join(uint64_t self, uint64_t ctx, uint64_t invite, char** out_error);

/* ----- the invite, which is secret in full ----- */

/* the alpha adds exactly ONE member, BEFORE urnet_message_group_open: it is the commit that
 * opens epoch 1. a second add is a second epoch and is refused by name. */
uint64_t urnet_message_group_add_member(uint64_t self, const uint8_t* key_package, int32_t key_package_len, char** out_error);
/* buffer-out. WHAT COMES OUT IS KEY MATERIAL: an invite that reaches a third party is a group
 * that third party is in. move it like a private key and destroy it afterwards. */
bool urnet_message_invite_encode(uint64_t self, uint8_t* out, int32_t* inout_len, char** out_error);
/* an invite ends with a checksum of everything before it, so a damaged one -- truncated, a mangled
 * paste, one octet rewritten -- answers 0 and out_error HERE, where a user pasting it can be told,
 * and never joins. the checksum is not an authentication: move the invite over a channel that is
 * already authenticated. */
uint64_t urnet_message_parse_invite(const uint8_t* encoded, int32_t encoded_len, char** out_error);

/* ----- the group ----- */

/* publish the group on the server: the founding commit, the epoch's wraps, the marker that
 * closes them. comes AFTER add_member. */
bool urnet_message_group_open(uint64_t self, uint64_t ctx, char** out_error);
/* seal one body and submit it. the body is counted octets and crosses byte for byte. the result
 * is this message's metadata as json WITHOUT the body -- you already have the body -- or NULL on
 * failure. free with urnet_free_string. */
char* urnet_message_group_send(uint64_t self, uint64_t ctx, const uint8_t* body, int32_t body_len, char** out_error);
/* fetch. returns a message list handle, or 0 when nothing new arrived.
 *
 * A NON-ZERO RESULT AND A NON-NULL out_error CAN BOTH COME BACK, and code that reads an error as
 * "nothing arrived" will drop real messages: a page bound reached with more to come, a server
 * that named a high water above what it handed over, and a record given up on after every retry
 * are all answers that carry messages AND a reason.
 *
 * 0 with no error is also what an unknown self or ctx handle answers -- a handle that does not
 * resolve is a programming error, logged by name rather than returned as out_error, which is
 * this abi's convention everywhere. It is worth knowing here because "nothing new" is the
 * common answer this one shares with it. */
uint64_t urnet_message_group_receive(uint64_t self, uint64_t ctx, char** out_error);
/* every message this group has sent or received, in the order it learned them. */
uint64_t urnet_message_group_messages(uint64_t self);
/* buffer-out, 32 octets. */
bool urnet_message_group_id(uint64_t self, uint8_t* out, int32_t* inout_len);
uint64_t urnet_message_group_epoch(uint64_t self);
bool urnet_message_group_is_open(uint64_t self);
/* what this group has SEEN, as json: fetched, opened, skipped_ceremony, skipped_own, opened_own,
 * own_without_copy, skipped_seen, unopened, omitted, skipped_class, failed_open, submitted,
 * rebound, pages, unattested. opened_own counts this device's own records shown from the copy it
 * persisted when it sent them -- a member cannot decrypt its own records -- and own_without_copy
 * counts its own records it has no copy of and cannot show. it exists so that "nothing arrived" and "something arrived and this build would
 * not open it" are two readings rather than one silence. free with urnet_free_string. */
char* urnet_message_group_stats(uint64_t self);
bool urnet_message_group_close(uint64_t self, char** out_error);

/* ----- the list handles ----- */

/* a list of groups or messages is ONE handle with indexed accessors, not N handles and not one
 * json blob (a blob cannot carry a body). an empty list is handle 0, and every accessor answers
 * 0/NULL/false on handle 0 rather than failing. */

int32_t urnet_message_group_list_count(uint64_t self);
/* a NEW handle onto the group at index, which you release. two calls at one index are two
 * handles onto one group. */
uint64_t urnet_message_group_list_at(uint64_t self, int32_t index);

int32_t urnet_message_list_count(uint64_t self);
/* one message's metadata as json, WITHOUT the body:
 *   {"record_id":u64,"sender_handle":"<32 hex>","mine":bool,"sent_at_ms":i64,"body_len":i32,
 *    "message_id":"<64 hex>"}
 * sender_handle is 16 opaque octets and IS NOT A NAME: the alpha has no identity system.
 *
 * message_id is 32 octets and IS the name to quote: a reply, a reaction, a tombstone or a read
 * cursor has to say which message it is about, and record_id cannot -- record_id is the SERVER's
 * per-group counter, so it is zero on a message whose submit response was lost. it is a NAME and
 * not an authentication: the key it is derived under is group-shared, so any member can compute
 * any member's id at any position. what makes an id trustworthy is that the record it names
 * opened.
 * free with urnet_free_string. */
char* urnet_message_list_info(uint64_t self, int32_t index);
/* one message's body, byte for byte, through the buffer-out pattern. the ONLY way a body leaves
 * this abi. */
bool urnet_message_list_body(uint64_t self, int32_t index, uint8_t* out, int32_t* inout_len);

#ifdef __cplusplus
}
#endif

#endif
