# liveprobe

Two real URnetwork accounts, two real platform connections, one **deployed** message server: a
text typed by one party comes back to the other.

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
      -host beta-test.net

Each `by_client_jwt` is a `network_client` credential minted by `POST /network/auth-client`
against that operator, per spec B §9.1. **They are secrets**: pass paths, never values, and keep
the files at mode 600.

What it asserts, in order: both parties Hello and are issued a 32-octet `server_nonce`; A founds
a group; B publishes a key package and A adds it; A opens the group on the server and sends; B
joins from the invite and reads back **the same string**; B answers and A reads that. It fails on
the first step that does not hold, and prints each party's `Stats` at the end — `FailedOpen` must
be 0.

What it does NOT assert, and what still has to be read out of the server's database by hand: that
the plaintext is absent from `message_record`. It is (measured: 6 rows, 0 matches), but this
probe holds no database credential and should not.
