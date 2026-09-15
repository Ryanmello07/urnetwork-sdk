/* A C PROGRAM THAT OPENS TWO DEVICES, FOUNDS A GROUP, JOINS IT, SENDS OCTETS AND READS THEM
 * BACK, THROUGH THE SHIPPING C ABI AND NOTHING ELSE.
 *
 * It exists because the boundary is the whole point of the binding: a Go test of exports_message.go
 * would call Go functions with Go types and would never once exercise a uint64_t handle, a
 * malloc'd char*, a buffer-out length negotiation or a C function pointer. Every line below is on
 * the C side of the cgo wall.
 *
 * WHAT IS REAL HERE AND WHAT IS THE HARNESS. The server is real: peer.Peer dispatching frames,
 * api.Handler running the §5.1 pipeline, store.MemoryStore holding rows, wired exactly as
 * sdk/cp3b's world_test.go wires it. The five urnet_message_loopback_* functions are the harness
 * and they are NOT in the shipping library -- they are behind a Go build tag, run.sh proves the
 * shipping header has none of them, and the reason a harness is needed at all is that
 * urnet_message_transport_new takes a connect client handle that no shipping export produces
 * (S2-7, open, stated at that function). EVERYTHING ELSE below -- every store, every device,
 * every group, every octet -- goes through the abi that ships.
 *
 * SPDX-License-Identifier: MPL-2.0 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <windows.h>

#include "urnetwork_message.h"

/* from urnetwork_sdk.h, which is 122 KB of the VPN surface this test does not use. Declared here
 * rather than included so that a reader can see the whole of what this test depends on. */
extern void urnet_free_string(char* s);
extern bool urnet_release(uint64_t handle);
extern int64_t urnet_live_handle_count(void);

/* the harness. NOT IN THE SHIPPING LIBRARY -- see the file header. */
extern uint64_t urnet_message_loopback_world_new(char** out_error);
extern char* urnet_message_loopback_world_server_id(uint64_t self);
extern uint64_t urnet_message_loopback_world_client(uint64_t self);
extern uint64_t urnet_message_loopback_world_unrouted_client(uint64_t self);
extern void urnet_message_loopback_world_omit_highest(uint64_t self, bool on);
extern void urnet_message_loopback_world_close(uint64_t self);

/* ── assertions ──────────────────────────────────────────────────────────────────────────── */

static int checks = 0;
static int failures = 0;
static int steps = 0;

#define CHECK(cond, ...)                                                    \
  do {                                                                      \
    checks += 1;                                                            \
    if (!(cond)) {                                                          \
      failures += 1;                                                        \
      fprintf(stderr, "  FAIL %s:%d: ", __FILE__, __LINE__);                \
      fprintf(stderr, __VA_ARGS__);                                         \
      fprintf(stderr, "\n");                                                \
    }                                                                       \
  } while (0)

/* REQUIRE is CHECK plus "everything after this is meaningless": a run that lost its group cannot
 * go on to say anything about a message. It returns from main rather than continuing to print
 * passes that mean nothing.
 *
 * THE CONDITION IS EVALUATED EXACTLY ONCE, into urnet_ok_. It used to expand to
 * `CHECK(cond); if (!(cond))`, which ran REQUIRE(party_open(...)) twice and stood up every device
 * twice -- and the handle-count assertion at the end of this file is what caught it, at 18
 * handles leaked, which is exactly three parties' worth of the second copy. */
#define REQUIRE(cond, ...)                                                  \
  do {                                                                      \
    bool urnet_ok_ = (cond);                                                \
    CHECK(urnet_ok_, __VA_ARGS__);                                          \
    if (!urnet_ok_) {                                                       \
      report();                                                             \
      return 1;                                                             \
    }                                                                       \
  } while (0)

static void report(void);

/* Every step prints the live handle count, so that a leak is located at the step that made it
 * rather than only totalled at the end. */
static void step(const char* what) {
  steps += 1;
  printf("[%d] (%lld live) %s\n", steps, (long long)urnet_live_handle_count(), what);
  fflush(stdout);
}

/* err_of prints and frees an out_error, and answers a stable string for the message. */
static void show_error(const char* what, char* err) {
  if (err != NULL) {
    fprintf(stderr, "  %s: %s\n", what, err);
    urnet_free_string(err);
  } else {
    fprintf(stderr, "  %s: (no error text)\n", what);
  }
}

/* ── a temp directory per store ──────────────────────────────────────────────────────────── */

static char temp_root[MAX_PATH];
static int temp_n = 0;

/* into a buffer the CALLER owns. It used to answer a pointer into a static, which made two calls
 * one directory -- and the durable state store's single-writer exclusion is what caught it, which
 * is that store working exactly as its document says it does. */
static bool temp_dir(char* path, size_t cap) {
  temp_n += 1;
  snprintf(path, cap, "%surnet_ctest_%lu_%d", temp_root,
           (unsigned long)GetCurrentProcessId(), temp_n);
  if (!CreateDirectoryA(path, NULL)) {
    fprintf(stderr, "  could not create %s (%lu)\n", path, GetLastError());
    return false;
  }
  return true;
}

/* ── the body. IT IS NOT TEXT, ON PURPOSE. ───────────────────────────────────────────────────
 *
 * 0x00 at offsets 12 and 19 would truncate a char*-carried body to 12 octets with no error
 * raised. 0xFF 0xFE and the ill-formed 0xC3 0x28 would each become U+FFFD in a json-carried one,
 * changing both the bytes and the length. A byte-identical round trip is the measurement that
 * says neither happened. */
static const unsigned char kBody[] = {
  'h', 'e', 'l', 'l', 'o', ' ', 'f', 'r', 'o', 'm', ' ', 'C',
  0x00, 0xFF, 0xFE, 'x', 0xC3, 0x28, '\n', 0x00, 'z'
};
static const int32_t kBodyLen = (int32_t)sizeof(kBody);

static const unsigned char kReply[] = { 'r', 'e', 'p', 'l', 'y', 0x00, 0x80, '!' };
static const int32_t kReplyLen = (int32_t)sizeof(kReply);

/* ── the connect-attempt callback, which is the listener convention ──────────────────────── */

typedef struct {
  volatile LONG calls;
  int32_t last_attempt;
} attempt_counter;

static void on_connect_attempt(void* user_data, int32_t attempt, int64_t elapsed_ms,
                               int64_t backoff_ms, const char* err) {
  attempt_counter* counter = (attempt_counter*)user_data;
  if (counter == NULL) {
    return;
  }
  InterlockedIncrement(&counter->calls);
  counter->last_attempt = attempt;
  printf("      reconnecting: attempt %d, %lldms elapsed, %lldms backoff, %s\n",
         (int)attempt, (long long)elapsed_ms, (long long)backoff_ms,
         err != NULL ? err : "(no error)");
  fflush(stdout);
}

/* ── one device, built entirely through the shipping abi ─────────────────────────────────── */

typedef struct {
  const char* name;
  uint64_t client;
  uint64_t transport;
  uint64_t stream_store;
  uint64_t reserver;
  uint64_t state_store;
  uint64_t device;
} party;

static bool party_open(party* self, const char* name, uint64_t client, const char* server_id,
                       attempt_counter* counter, int64_t budget_ms, int64_t attempt_ms) {
  char* err = NULL;
  self->name = name;
  self->client = client;
  self->transport = urnet_message_transport_new(client, server_id, 1, 30000, &err);
  if (self->transport == 0) {
    show_error("transport_new", err);
    return false;
  }
  char stream[MAX_PATH + 64];
  char state[MAX_PATH + 64];
  if (!temp_dir(stream, sizeof(stream)) || !temp_dir(state, sizeof(state))) {
    return false;
  }
  self->stream_store = urnet_message_stream_store_open(stream, &err);
  if (self->stream_store == 0) {
    show_error("stream_store_open", err);
    return false;
  }
  self->reserver = urnet_message_stream_index_reserver_new(self->stream_store);
  if (self->reserver == 0) {
    fprintf(stderr, "  reserver_new answered 0\n");
    return false;
  }
  /* the DURABLE state store, not the in-memory default: a real caller persists, and the nil
   * interface trap in urnet_message_device_new is only exercised by passing a real one. */
  self->state_store = urnet_message_durable_state_store_open(state, &err);
  if (self->state_store == 0) {
    show_error("durable_state_store_open", err);
    return false;
  }
  self->device = urnet_message_device_new(self->transport, self->reserver, self->state_store,
                                          budget_ms, attempt_ms, on_connect_attempt, counter, &err);
  if (self->device == 0) {
    show_error("device_new", err);
    return false;
  }
  return true;
}

/* party_close is stop-then-release, in that order, for every handle this party owns. It is what
 * the handle-count measurement at the end is measuring. */
static void party_close(party* self) {
  char* err = NULL;
  if (self->device != 0) {
    if (!urnet_message_device_close(self->device, &err)) {
      show_error("device_close", err);
    }
    CHECK(urnet_release(self->device), "%s: releasing the device answered false", self->name);
  }
  if (self->state_store != 0) {
    err = NULL;
    if (!urnet_message_durable_state_store_close(self->state_store, &err)) {
      show_error("state_store_close", err);
    }
    CHECK(urnet_release(self->state_store), "%s: releasing the state store answered false", self->name);
  }
  if (self->reserver != 0) {
    CHECK(urnet_release(self->reserver), "%s: releasing the reserver answered false", self->name);
  }
  if (self->stream_store != 0) {
    err = NULL;
    if (!urnet_message_stream_store_close(self->stream_store, &err)) {
      show_error("stream_store_close", err);
    }
    CHECK(urnet_release(self->stream_store), "%s: releasing the stream store answered false", self->name);
  }
  if (self->transport != 0) {
    urnet_message_transport_close(self->transport);
    CHECK(urnet_release(self->transport), "%s: releasing the transport answered false", self->name);
  }
  if (self->client != 0) {
    CHECK(urnet_release(self->client), "%s: releasing the client answered false", self->name);
  }
  memset(self, 0, sizeof(*self));
}

/* ── the cancellation thread ─────────────────────────────────────────────────────────────── */

typedef struct {
  uint64_t ctx;
  DWORD after_ms;
} canceller;

static DWORD WINAPI cancel_after(LPVOID arg) {
  canceller* self = (canceller*)arg;
  Sleep(self->after_ms);
  urnet_message_context_cancel(self->ctx);
  return 0;
}

/* ── the run ─────────────────────────────────────────────────────────────────────────────── */

static int64_t baseline_handles = 0;

static void report(void) {
  printf("\n=== %d STEPS, %d ASSERTIONS, %d FAILED ===\n", steps, checks, failures);
  fflush(stdout);
}

int main(void) {
  char* err = NULL;

  if (GetTempPathA(sizeof(temp_root), temp_root) == 0) {
    fprintf(stderr, "GetTempPathA failed\n");
    return 1;
  }

  step("the handle registry, before anything");
  baseline_handles = urnet_live_handle_count();
  printf("      %lld live handles\n", (long long)baseline_handles);

  step("a message server, in process, real");
  uint64_t world = urnet_message_loopback_world_new(&err);
  REQUIRE(world != 0, "the loopback world would not start");
  char* server_id = urnet_message_loopback_world_server_id(world);
  REQUIRE(server_id != NULL, "the world named no server");
  printf("      server %s\n", server_id);

  step("two devices, each with its own durable stream store and durable mls state store");
  attempt_counter counter_a = {0, 0};
  attempt_counter counter_b = {0, 0};
  party a = {0};
  party b = {0};
  REQUIRE(party_open(&a, "A", urnet_message_loopback_world_client(world), server_id, &counter_a, 0, 0),
          "A would not open");
  REQUIRE(party_open(&b, "B", urnet_message_loopback_world_client(world), server_id, &counter_b, 0, 0),
          "B would not open");
  urnet_free_string(server_id);
  server_id = NULL;

  step("a cancellable context, which every blocking call below rides on");
  uint64_t ctx = urnet_message_context_new();
  REQUIRE(ctx != 0, "context_new answered 0");

  step("Hello, on both");
  err = NULL;
  REQUIRE(urnet_message_device_connect(a.device, ctx, &err), "A could not connect");
  err = NULL;
  REQUIRE(urnet_message_device_connect(b.device, ctx, &err), "B could not connect");
  CHECK(counter_a.calls == 0, "A connected first time and the attempt callback fired %ld times",
        (long)counter_a.calls);

  step("B's key package, through the buffer-out pattern");
  int32_t kp_len = 0;
  bool sized = urnet_message_device_key_package(b.device, NULL, &kp_len, &err);
  CHECK(!sized, "a sizing call with out == NULL answered true, which would mean it copied somewhere");
  REQUIRE(kp_len > 0, "B's key package sized to %d octets", (int)kp_len);
  printf("      %d octets\n", (int)kp_len);
  uint8_t* key_package = (uint8_t*)malloc((size_t)kp_len);
  REQUIRE(key_package != NULL, "out of memory");
  int32_t kp_cap = kp_len;
  err = NULL;
  REQUIRE(urnet_message_device_key_package(b.device, key_package, &kp_cap, &err),
          "B's key package would not fill a buffer of exactly its own size");
  CHECK(kp_cap == kp_len, "the fill call reported %d octets and the sizing call said %d",
        (int)kp_cap, (int)kp_len);
  /* and one octet short must REFUSE rather than write past the end */
  int32_t kp_short = kp_len - 1;
  err = NULL;
  CHECK(!urnet_message_device_key_package(b.device, key_package, &kp_short, &err),
        "a buffer one octet short was accepted");
  CHECK(kp_short == kp_len, "the refused call reported %d octets, not the needed %d",
        (int)kp_short, (int)kp_len);

  step("A founds a group and adds B, which is the commit that opens epoch 1");
  uint8_t group_id[32];
  for (int at = 0; at < 32; at += 1) {
    group_id[at] = (uint8_t)(0xA0 + at);
  }
  err = NULL;
  uint64_t group_a = urnet_message_device_create_group(a.device, ctx, group_id, 32, &err);
  if (group_a == 0) {
    show_error("create_group", err);
  }
  REQUIRE(group_a != 0, "A could not found the group");
  err = NULL;
  uint64_t invite = urnet_message_group_add_member(group_a, key_package, kp_len, &err);
  if (invite == 0) {
    show_error("add_member", err);
  }
  REQUIRE(invite != 0, "A could not add B");
  free(key_package);
  key_package = NULL;

  step("the invite crosses as octets, and is parsed back on the other side");
  int32_t invite_len = 0;
  err = NULL;
  urnet_message_invite_encode(invite, NULL, &invite_len, &err);
  REQUIRE(invite_len > 0, "the invite sized to %d octets", (int)invite_len);
  uint8_t* encoded = (uint8_t*)malloc((size_t)invite_len);
  REQUIRE(encoded != NULL, "out of memory");
  int32_t invite_cap = invite_len;
  err = NULL;
  REQUIRE(urnet_message_invite_encode(invite, encoded, &invite_cap, &err),
          "the invite would not encode");
  printf("      %d octets of key material\n", (int)invite_len);
  err = NULL;
  uint64_t carried = urnet_message_parse_invite(encoded, invite_len, &err);
  if (carried == 0) {
    show_error("parse_invite", err);
  }
  REQUIRE(carried != 0, "the encoded invite would not parse back");
  /* A BLOB FROM ANOTHER BUILD IS REFUSED RATHER THAN READ AS THIS ONE: the first two octets are
   * the invite version, and ParseInvite refuses a version it did not write.
   *
   * WHAT IT DOES NOT CHECK, MEASURED HERE AND NOT ASSUMED: an invite is length-prefixed fields
   * and NOT an integrity-checked container, so a bit flipped INSIDE the welcome or the ratchet
   * tree parses cleanly and fails later, in MLS, at Join. This test asserted the opposite at
   * first and was wrong; the assertion below is what the code actually promises. */
  encoded[0] ^= 0xFF;
  err = NULL;
  uint64_t wrong_version = urnet_message_parse_invite(encoded, invite_len, &err);
  CHECK(wrong_version == 0, "an invite at a version this build does not write was parsed anyway");
  if (wrong_version != 0) {
    urnet_release(wrong_version);
  }
  CHECK(err != NULL, "the refused invite came back with no error text");
  if (err != NULL) {
    urnet_free_string(err);
    err = NULL;
  }
  free(encoded);
  encoded = NULL;

  step("A opens the group on the server");
  err = NULL;
  if (!urnet_message_group_open(group_a, ctx, &err)) {
    show_error("group_open", err);
    REQUIRE(false, "A could not open the group");
  }
  CHECK(urnet_message_group_is_open(group_a), "A's group says it is not open after open");
  CHECK(urnet_message_group_epoch(group_a) == 1, "A's group is at epoch %llu, want 1",
        (unsigned long long)urnet_message_group_epoch(group_a));
  int32_t id_len = 0;
  urnet_message_group_id(group_a, NULL, &id_len);
  CHECK(id_len == 32, "the group id is %d octets, want 32", (int)id_len);
  uint8_t id_out[32];
  int32_t id_cap = 32;
  CHECK(urnet_message_group_id(group_a, id_out, &id_cap), "the group id would not copy out");
  CHECK(memcmp(id_out, group_id, 32) == 0, "the group id came back different from the one founded");

  step("B joins");
  err = NULL;
  uint64_t group_b = urnet_message_device_join(b.device, ctx, carried, &err);
  if (group_b == 0) {
    show_error("join", err);
  }
  REQUIRE(group_b != 0, "B could not join");
  CHECK(urnet_release(carried), "releasing the parsed invite answered false");
  CHECK(urnet_release(invite), "releasing A's invite answered false");
  invite = 0;
  carried = 0;

  step("A sends 21 octets that are NOT text: two NULs, and two ill-formed utf-8 sequences");
  err = NULL;
  char* sent_info = urnet_message_group_send(group_a, ctx, kBody, kBodyLen, &err);
  if (sent_info == NULL) {
    show_error("send", err);
  }
  REQUIRE(sent_info != NULL, "A's send failed");
  printf("      %s\n", sent_info);
  CHECK(strstr(sent_info, "\"mine\":true") != NULL, "A's own message did not say mine:true");
  CHECK(strstr(sent_info, "\"body_len\":21") != NULL, "A's send reported a body_len that is not 21");
  urnet_free_string(sent_info);

  step("B reads it back, and the octets are compared one at a time");
  err = NULL;
  uint64_t got = urnet_message_group_receive(group_b, ctx, &err);
  if (err != NULL) {
    show_error("receive (carried alongside whatever arrived)", err);
    err = NULL;
  }
  REQUIRE(got != 0, "B's receive answered no messages at all");
  CHECK(urnet_message_list_count(got) == 1, "B received %d messages, want 1",
        (int)urnet_message_list_count(got));
  char* info = urnet_message_list_info(got, 0);
  REQUIRE(info != NULL, "the received message had no metadata");
  printf("      %s\n", info);
  CHECK(strstr(info, "\"mine\":false") != NULL, "B read A's message as its own");
  CHECK(strstr(info, "\"body_len\":21") != NULL, "B's copy is not 21 octets");
  urnet_free_string(info);

  int32_t body_len = 0;
  urnet_message_list_body(got, 0, NULL, &body_len);
  CHECK(body_len == kBodyLen, "the body sized to %d octets, want %d", (int)body_len, (int)kBodyLen);
  uint8_t* body = (uint8_t*)malloc((size_t)(body_len > 0 ? body_len : 1));
  REQUIRE(body != NULL, "out of memory");
  memset(body, 0xCC, (size_t)body_len);
  int32_t body_cap = body_len;
  REQUIRE(urnet_message_list_body(got, 0, body, &body_cap), "the body would not copy out");
  int different = 0;
  for (int32_t at = 0; at < kBodyLen; at += 1) {
    if (body[at] != kBody[at]) {
      different += 1;
      fprintf(stderr, "  octet %d: got 0x%02X, sealed 0x%02X\n", (int)at, body[at], kBody[at]);
    }
  }
  CHECK(different == 0, "%d of %d octets came back different", different, (int)kBodyLen);
  CHECK(body_len == kBodyLen && different == 0,
        "the body did NOT survive the boundary byte for byte");
  free(body);
  CHECK(urnet_release(got), "releasing the message list answered false");

  step("a second receive, with nothing new: 0 handles and no error, which is the polling case");
  err = NULL;
  uint64_t nothing = urnet_message_group_receive(group_b, ctx, &err);
  CHECK(nothing == 0,
        "a receive that found nothing answered handle %llu; the ordinary poll must cost the "
        "caller no release at all",
        (unsigned long long)nothing);
  CHECK(err == NULL, "a receive that found nothing also reported an error");
  if (nothing != 0) {
    urnet_release(nothing);
  }
  if (err != NULL) {
    urnet_free_string(err);
    err = NULL;
  }
  CHECK(urnet_message_list_count(0) == 0, "counting the empty list handle did not answer 0");
  CHECK(urnet_message_list_info(0, 0) == NULL, "the empty list handle answered metadata");

  step("B answers, and A reads THAT back");
  err = NULL;
  char* reply_info = urnet_message_group_send(group_b, ctx, kReply, kReplyLen, &err);
  if (reply_info == NULL) {
    show_error("B send", err);
  }
  REQUIRE(reply_info != NULL, "B's send failed");
  urnet_free_string(reply_info);
  err = NULL;
  uint64_t back = urnet_message_group_receive(group_a, ctx, &err);
  if (err != NULL) {
    show_error("A receive", err);
    err = NULL;
  }
  REQUIRE(back != 0, "A received nothing");
  CHECK(urnet_message_list_count(back) == 1,
        "A received %d messages, want 1 (its own record is already in its log)",
        (int)urnet_message_list_count(back));
  int32_t reply_len = 0;
  urnet_message_list_body(back, 0, NULL, &reply_len);
  CHECK(reply_len == kReplyLen, "the reply sized to %d, want %d", (int)reply_len, (int)kReplyLen);
  uint8_t reply_out[16];
  int32_t reply_cap = (int32_t)sizeof(reply_out);
  CHECK(urnet_message_list_body(back, 0, reply_out, &reply_cap), "the reply would not copy out");
  CHECK(reply_cap == kReplyLen && memcmp(reply_out, kReply, (size_t)kReplyLen) == 0,
        "the reply did not survive the boundary byte for byte");
  /* an index past the end is a refusal, not a read past the end */
  CHECK(!urnet_message_list_body(back, 7, reply_out, &reply_cap), "index 7 of a 1 message list was read");
  CHECK(urnet_message_list_info(back, -1) == NULL, "index -1 answered metadata");
  CHECK(urnet_release(back), "releasing A's message list answered false");

  step("the logs and the counters");
  uint64_t log_a = urnet_message_group_messages(group_a);
  uint64_t log_b = urnet_message_group_messages(group_b);
  CHECK(urnet_message_list_count(log_a) == 2, "A's log holds %d, want 2",
        (int)urnet_message_list_count(log_a));
  CHECK(urnet_message_list_count(log_b) == 2, "B's log holds %d, want 2",
        (int)urnet_message_list_count(log_b));
  CHECK(urnet_release(log_a) && urnet_release(log_b), "releasing a log answered false");
  char* stats = urnet_message_group_stats(group_b);
  REQUIRE(stats != NULL, "B's group answered no stats");
  printf("      B: %s\n", stats);
  CHECK(strstr(stats, "\"opened\":") != NULL, "the stats carry no opened counter");
  urnet_free_string(stats);

  step("the device's own group list, which is a second handle onto the same group");
  uint64_t groups_b = urnet_message_device_groups(b.device);
  REQUIRE(groups_b != 0, "B's device lists no groups");
  CHECK(urnet_message_group_list_count(groups_b) == 1, "B's device lists %d groups, want 1",
        (int)urnet_message_group_list_count(groups_b));
  uint64_t same = urnet_message_group_list_at(groups_b, 0);
  REQUIRE(same != 0, "index 0 of a 1 group list answered 0");
  CHECK(same != group_b, "the list handed back the SAME handle value, not a new one");
  CHECK(urnet_message_group_epoch(same) == urnet_message_group_epoch(group_b),
        "the two handles onto one group disagree about its epoch");
  CHECK(urnet_message_group_list_at(groups_b, 1) == 0, "index 1 of a 1 group list answered a handle");
  CHECK(urnet_release(same), "releasing the second group handle answered false");
  /* and the group is still alive under the first handle */
  CHECK(urnet_message_group_is_open(group_b), "releasing one handle closed the group under the other");
  CHECK(urnet_release(groups_b), "releasing the group list answered false");

  step("a server that holds a record back: BOTH a list AND an error come back, never one or the other");
  {
    /* three more from A, so that a page with its highest message removed still carries some. */
    for (int at = 0; at < 3; at += 1) {
      unsigned char line[8] = { 'h', 'e', 'l', 'd', ' ', 0x00, (unsigned char)('0' + at), 0x00 };
      err = NULL;
      char* info = urnet_message_group_send(group_a, ctx, line, (int32_t)sizeof(line), &err);
      if (info == NULL) {
        show_error("send during the omission case", err);
      }
      REQUIRE(info != NULL, "A could not send line %d", at);
      urnet_free_string(info);
    }
    /* the server now answers every fetch as COMPLETE while withholding its highest message and
     * still naming that record in high_water_record_id. Nothing about the AEAD can see it. */
    urnet_message_loopback_world_omit_highest(world, true);
    err = NULL;
    uint64_t partial = urnet_message_group_receive(group_b, ctx, &err);
    urnet_message_loopback_world_omit_highest(world, false);
    int32_t partial_count = urnet_message_list_count(partial);
    printf("      %d messages came back with the refusal\n", (int)partial_count);
    if (err != NULL) {
      printf("      %s\n", err);
    }
    CHECK(err != NULL,
          "the server held a record back and answered a page it called complete, and receive "
          "reported no error at all");
    CHECK(partial != 0 && partial_count > 0,
          "receive collapsed a partial answer to nothing: %d messages arrived and a caller that "
          "reads an error as 'nothing arrived' would have dropped every one of them",
          (int)partial_count);
    if (err != NULL) {
      urnet_free_string(err);
      err = NULL;
    }
    if (partial != 0) {
      urnet_release(partial);
    }
    /* and with the shape off, the held-back record is delivered rather than lost for good */
    err = NULL;
    uint64_t rest = urnet_message_group_receive(group_b, ctx, &err);
    CHECK(rest != 0, "the record the server had held back never arrived once it stopped");
    if (err != NULL) {
      show_error("the catch-up fetch", err);
      err = NULL;
    }
    if (rest != 0) {
      urnet_release(rest);
    }
  }

  step("a device with state_store 0, which takes the in-memory store and persists nothing");
  {
    uint64_t volatile_client = urnet_message_loopback_world_client(world);
    char* vs_id = urnet_message_loopback_world_server_id(world);
    REQUIRE(vs_id != NULL, "the world named no server");
    err = NULL;
    uint64_t vt = urnet_message_transport_new(volatile_client, vs_id, 1, 30000, &err);
    urnet_free_string(vs_id);
    REQUIRE(vt != 0, "the transport for the in-memory device would not open");
    char vdir[MAX_PATH + 64];
    REQUIRE(temp_dir(vdir, sizeof(vdir)), "no temp dir");
    err = NULL;
    uint64_t vss = urnet_message_stream_store_open(vdir, &err);
    REQUIRE(vss != 0, "the stream store for the in-memory device would not open");
    uint64_t vr = urnet_message_stream_index_reserver_new(vss);
    REQUIRE(vr != 0, "the reserver for the in-memory device would not open");
    err = NULL;
    /* state_store 0 IS THE POINT. It must take urmessage's in-memory store, not assign a nil
     * pointer into an interface field -- which would be a non-nil interface holding nil and
     * would panic on first use rather than defaulting. */
    uint64_t vd = urnet_message_device_new(vt, vr, 0, 0, 0, NULL, NULL, &err);
    if (vd == 0) {
      show_error("device_new with state_store 0", err);
    }
    CHECK(vd != 0, "a device with state_store 0 was refused; 0 must take the in-memory store");
    if (vd != 0) {
      err = NULL;
      CHECK(urnet_message_device_connect(vd, ctx, &err), "the in-memory device could not connect");
      if (err != NULL) {
        urnet_free_string(err);
        err = NULL;
      }
      /* and it really has no durable store behind it: Restore is refused by name */
      err = NULL;
      uint64_t restored = urnet_message_device_restore(vd, ctx, &err);
      CHECK(restored == 0, "an in-memory device restored %d groups",
            (int)urnet_message_group_list_count(restored));
      CHECK(err != NULL, "an in-memory device answered Restore with no groups AND no error, which "
                         "reads exactly like 'this device was in no groups'");
      if (restored != 0) {
        urnet_release(restored);
      }
      if (err != NULL) {
        urnet_free_string(err);
        err = NULL;
      }
      err = NULL;
      CHECK(urnet_message_device_close(vd, &err), "the in-memory device would not close");
      CHECK(urnet_release(vd), "releasing the in-memory device answered false");
    }
    urnet_message_transport_close(vt);
    CHECK(urnet_release(vt), "releasing the in-memory transport answered false");
    CHECK(urnet_release(vr), "releasing the in-memory reserver answered false");
    err = NULL;
    CHECK(urnet_message_stream_store_close(vss, &err), "the in-memory device's stream store would not close");
    CHECK(urnet_release(vss), "releasing that stream store answered false");
    CHECK(urnet_release(volatile_client), "releasing that client answered false");
  }

  step("a blocking call that is cancelled from another thread, instead of waiting its 90s budget");
  attempt_counter counter_c = {0, 0};
  party c = {0};
  char* lost_server = urnet_message_loopback_world_server_id(world);
  /* a 30s budget and an 800ms per-Hello deadline, so that attempts actually FAIL and the
   * progress callback has something to report before the cancel lands. With urmessage's own 10s
   * per-attempt deadline the cancel arrives inside the first Hello and OnAttempt never runs --
   * which is correct (Connect checks the caller's context BEFORE reporting an attempt, because
   * stop means stop) and is not what this case is measuring. */
  REQUIRE(party_open(&c, "C", urnet_message_loopback_world_unrouted_client(world), lost_server,
                     &counter_c, 30000, 800),
          "C would not open");
  urnet_free_string(lost_server);
  uint64_t doomed = urnet_message_context_new();
  REQUIRE(doomed != 0, "context_new answered 0");
  canceller job = {doomed, 2500};
  HANDLE thread = CreateThread(NULL, 0, cancel_after, &job, 0, NULL);
  REQUIRE(thread != NULL, "could not start the cancelling thread");
  ULONGLONG started = GetTickCount64();
  err = NULL;
  bool connected = urnet_message_device_connect(c.device, doomed, &err);
  ULONGLONG elapsed = GetTickCount64() - started;
  WaitForSingleObject(thread, INFINITE);
  CloseHandle(thread);
  printf("      connect returned after %llums\n", (unsigned long long)elapsed);
  if (err != NULL) {
    printf("      %s\n", err);
    urnet_free_string(err);
    err = NULL;
  }
  CHECK(!connected, "a device with no route to the server reported that it connected");
  /* THE BOUND IS THE POINT. urmessage's default budget is 90,000ms. Anything near that means the
   * cancel did nothing and a closing app would hang for a minute and a half. */
  CHECK(elapsed < 10000, "connect took %llums; the cancel did not cut its 90,000ms budget short",
        (unsigned long long)elapsed);
  CHECK(counter_c.calls > 0,
        "the connect-attempt callback never fired, so a caller has no way to say 'Reconnecting...'");
  urnet_message_context_cancel(doomed);
  CHECK(urnet_release(doomed), "releasing the cancelled context answered false");
  party_close(&c);

  step("everything closes, and the handle registry comes back to where it started");
  err = NULL;
  CHECK(urnet_message_group_close(group_a, &err), "A's group would not close");
  CHECK(urnet_release(group_a), "releasing A's group answered false");
  err = NULL;
  CHECK(urnet_message_group_close(group_b, &err), "B's group would not close");
  CHECK(urnet_release(group_b), "releasing B's group answered false");
  urnet_message_context_cancel(ctx);
  CHECK(urnet_release(ctx), "releasing the context answered false");
  party_close(&a);
  party_close(&b);
  urnet_message_loopback_world_close(world);
  CHECK(urnet_release(world), "releasing the world answered false");

  int64_t after = urnet_live_handle_count();
  printf("      %lld live handles, started at %lld\n", (long long)after, (long long)baseline_handles);
  CHECK(after == baseline_handles,
        "%lld handles leaked across one whole conversation (started %lld, ended %lld)",
        (long long)(after - baseline_handles), (long long)baseline_handles, (long long)after);

  /* a released handle must not resolve to anything afterwards, and releasing twice must say so */
  CHECK(!urnet_release(world), "releasing the world a second time answered true");
  CHECK(urnet_message_group_list_count(world) == 0, "a released handle still answered a count");

  report();
  return failures == 0 ? 0 : 1;
}
