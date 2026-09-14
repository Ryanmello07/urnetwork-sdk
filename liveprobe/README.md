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
   restart, and seals one A opens after it.
8. **Two senders at once.** Both parties send 20 lines concurrently. Each line is distinct, so a
   lost one and a duplicated one are both visible in the counts.

Then the counters, per party: `fetched opened ceremony own otherClasses FAILED submitted rebound
pages unattested`. **`FAILED` must be 0.**

## What it does NOT assert

- **That the plaintext is absent from the server's `message_record` rows.** It is (measured on the
  first deployment: 6 rows, 0 matches), but this probe holds no database credential and should
  not. Read it out of the server's database by hand.
- **That the server returned everything it has.** §4.3.4's fetch attestation is the Ed25519
  signature that would say so, and the deployed server holds no fleet key and signs nothing
  (`msgrepo/api/fetch.go:112`). The client checks the two halves that need no key — a server that
  *advertises* attestation and sends none is refused, and an attestation that describes a
  different page is refused — and **counts** every page whose signature it could not verify in
  `unattested`. A server that silently omits records is still undetectable. That is **S2-27**.
