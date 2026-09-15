# liveprobe

Two real URnetwork accounts, two real platform connections, one **deployed** message server — and
the whole of what the alpha can do, scenario by scenario.

Every other transport test in this workspace runs two `connect.Client`s over in-process
`connect.Route` channels in one binary — including `cp3b`, which is where the key schedule is
actually proven. This one crosses an operator's mesh to a server it did not start, so it is the
only thing here that can find a defect that lives in the gap between them. It found the first
one: a message server that enables no provide mode accepts no peer's frames, logs nothing, and
answers `ready` the whole time.

It needs credentials and a server, so it is a command rather than a test: `go test ./...` on a
developer's machine must not require an operator account.

    liveprobe \
      -a  <file holding party A's by_client_jwt> \
      -b  <file holding party B's by_client_jwt> \
      -server <the message server's client_id> \
      -host beta-test.net \
      -dir /var/lib/urmessage/probe

Each `by_client_jwt` is a `network_client` credential minted by `POST /network/auth-client`
against that operator, per spec B §9.1. **They are secrets**: pass paths, never values, and keep
the files at mode 600.

`-dir` is where each party's **durable** state lives, and it now matters: step 7 kills a client and
starts it again over the same directory. Use a path that survives the run, and note that each
party holds a single-writer exclusion on its own subdirectory — if a second probe is refused with
"the state directory is held", a previous run is still alive.

## The eight steps, and what each one is for

1. **Hello on both parties.** A 32-octet `server_nonce`, and the capabilities the server
   advertises are PRINTED — `max_records_per_fetch`, `max_request_bytes`,
   `attestation_supported`. The fetch-page step needs the first of those to be set sensibly, and
   the third is the one that is false on the deployed server today.
2. **A founds a group, adds B, opens it.** Epoch 0 → the commit → §6.1's founding commit, the wrap
   set, the marker.
3. **B joins and reads the string A typed**, and answers it. This is what CP3b proved in one
   process; here it crosses the mesh.
4. **`-lines` messages in order** (default 600), which is what crosses a fetch page. §4.3.4
   truncates a page by `limit` **or** by `max_response_bytes` and calls both NORMAL; `Receive`
   must page until the server says `complete`. The step prints the page count, and **warns loudly
   if one page carried everything** — in which case `-lines` is below this server's
   `max_records_per_fetch` and the truncation path was not exercised.
5. **A third member — and the refusal.** The alpha adds **exactly one** member, in the commit that
   opens epoch 1, before `Open`. A second add is a second epoch and none of it is built. So this
   step does not add a third member: it holds that a second `AddMember` is refused **by name**
   (`ErrAlphaOneAdd` / `ErrGroupOpen`) rather than as a `REASON_REJECTED` a caller has to decode.
   With `-c <a third by_client_jwt>` it uses a real third device's key package; without it, B's own
   stands in. **This is a gap being measured, not a feature being tested.**
6. **A `-big` octet message** (default 40000), which crosses §4.6's 2048-octet cut as roughly
   twenty frames and is reassembled on the far side. No live test had ever fragmented. The text is
   compared octet for octet and the step prints the offset of the first difference if there is one.
7. **B is killed mid-conversation and started again over the same directory.** This is S2-14. The
   device, both durable stores, the transport and the connect client are all dropped and a new
   everything is opened; the only thing that crosses is the disk. It holds that B comes back into
   the same group at the same epoch under the same leaf, opens a record A sealed **before** the
   restart, **reads back the two lines B ITSELF sent before the kill**, and seals one A opens
   after it. That middle clause is new and it is the one that used to be missing: a restored
   group's log starts empty and `Receive` skipped every record whose `sender_handle` was its own,
   so a user who closed the app and reopened it got the other side's half of the conversation and
   none of their own — with a nil error. A probe that checks only the far side's half cannot see
   that, and this one could not.

   **This step lands in the operator's reconnect window every time, and that is expected.**
   Measured on the deployed server: a `client_id` that has just re-dialled **is not routed to for
   about sixty seconds** — the connection attaches, the Hello goes out and nothing comes back.
   Step 7 re-dials B under the same `client_id`, so its `Connect` meets that window on every run.
   `Device.Connect` now **retries with backoff across it** and prints `reconnecting: Hello attempt
   N ...` for each unanswered try, so the step takes up to a minute and says why rather than
   failing. `-reconnect <duration>` raises the budget above urmessage's 90s default. If it ends in
   `ErrReconnecting` the window outlasted the budget — **that is the operator finding (item 5 of
   `msgrepo/docs/reports/2026-09-15-operator-and-connect-findings.md`), not a restore failure**,
   and the step says so by name. None of this removes the sixty seconds; the user waits them.
8. **Two senders at once.** Both parties send 20 lines concurrently. Each line is distinct, so a
   lost one and a duplicated one are both visible in the counts.

Then the counters, per party: `fetched opened ceremony own otherClasses FAILED submitted rebound
pages unattested`. **`FAILED` must be 0.**

## What it does NOT assert

- **That the plaintext is absent from the server's `message_record` rows.** It is (measured on the
  first deployment: 6 rows, 0 matches), but this probe holds no database credential and should
  not. Read it out of the server's database by hand.
- **That the server returned everything it has — in full.** §4.3.4's fetch attestation is the
  Ed25519 signature that would say so, and the deployed server holds no fleet key and signs nothing
  (`msgrepo/api/fetch.go:112`). The client checks the two halves that need no key — a server that
  *advertises* attestation and sends none is refused, and an attestation that describes a
  different page is refused — and **counts** every page whose signature it could not verify in
  `unattested`.

  **The gross case is now caught, and it was free.** §4.3.4's `high_water_record_id` is the
  server's own statement of the highest record it holds for this group, it arrives on every page,
  and it needs no key. A page the server calls `complete` that names a high water above everything
  it handed over is `ErrFetchOmitted`, and this probe fails on it by name. This used to say "a
  server that silently omits records is still undetectable", flat, and that was too strong.

  **What is still undetectable, and is genuinely S2-27's:** a server omitting records from the
  *middle* of a page, and a server that lies about its own high water. Both need the signature
  over the record-id vector and nothing else will do.

  **The false positive, and it is not live yet.** §7.2's retention sweep would prune records out
  from under a high water that is `next_record_id - 1` and never comes down, so a group whose
  oldest records had expired would produce exactly this signal with no dishonesty anywhere. That
  sweep is **not built**: over the server repo, `grep -rn "DELETE FROM" --include=*.go
  --include=*.sql .` answers two lines, both `DELETE FROM migration_audit` in a startup test, and
  nothing deletes a `message_record` row. The `prune_after` column and the sweep's worklist index
  exist and the sweep does not. So today a red run here is an omission; against a server new
  enough to sweep, check its retention settings first.

- **That two copies of a `-dir` are safe.** They are not. A COPIED app-data directory -- a backup
  restored onto a second machine, a `cp -r` of the folder -- is two devices at one leaf with one
  stream counter, and two records under one `(epoch, sender_handle, stream_index)` are one record
  key and one nonce. (This is *not* the same as running the probe twice over one `-dir` in
  sequence: a second run founds a fresh group id, so the old group's indices still match its own
  reserver. What a second run over one `-dir` actually hits is step 7's `B was in one group and N
  came back from the disk`, because `Restore` brings back every group the directory holds. Use a
  fresh `-dir` per run.) A restored group refuses to seal until it has
  compared its stream position against the server, and a group that finds an index its own
  reserver never allocated refuses to seal at all (`ErrIdentityInUse`). That catches every copy
  that is *behind* the original, before it seals. It does not catch two copies that are exactly
  level and both send before either fetches — that is **S2-28**, and closing it needs a new leaf
  for the copy, which is an MLS Update commit a restored group cannot make.

## Building it

There is no committed binary and there should not be: this probe's audience is an operator on a
deployed Linux VPS, and the `windows/amd64` executable that used to be tracked here was 35 MB of
git weight that served nobody, had to be rebuilt anyway, and was the single artefact in this tree
most likely to be picked up and run by mistake. It also went stale the moment `main.go` changed.

```sh
cd sdk/liveprobe
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o liveprobe .
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o liveprobe-arm64 .
```

`CGO_ENABLED=0` is what makes the result a static binary an operator can copy onto a host that has
no toolchain on it.
