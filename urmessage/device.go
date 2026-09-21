package urmessage

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/urnetwork/connect/messagegroup"
	"github.com/urnetwork/connect/mls"
	"github.com/urnetwork/connect/protocol"
	"github.com/urnetwork/sdk"
)

// THE EPOCH ZERO EXPORTER, RESTATED HERE BECAUSE connect DOES NOT PUBLISH IT.
//
// group_handle_key is GroupHandleKey(StorageRoot(mls_secret[0], pq_secret)), and mls_secret[n] is
// the group handle's exporter output under this label at this length -- messagegroup/session.go
// line 858, where both are unexported constants (mlsSecretLabel, mlsSecretBytes). A caller outside
// that package that has to derive the key at epoch zero, and hand it to a device that will
// construct its session at epoch one, has no way to ask for the values and must restate them.
// messagegroup/enginejoin_test.go restates them too, at engineJoinExporterLabel.
//
// THIS IS THEREFORE A SECOND SITE OF ONE CONSTANT BY CONSTRUCTION OF THE VISIBILITY RULES, and it
// is filed rather than absorbed: the exact change connect owes is to export these two, for example
// as messagegroup.MlsSecretLabel and messagegroup.MlsSecretBytes, after which this pair is
// deleted. Until then, a label changed in connect gives every device founded by this package a
// group_handle_key its own session does not derive -- which shows up as the joiner computing a
// different sender_handle and every record being refused as an untracked sender, not as a build
// failure.
const (
	storageExporterLabel = "URmessage/v1/storage"
	storageExporterBytes = 32
)

// The MLS cipher suite this build founds and joins groups on.
const deviceCipherSuite = mls.CipherSuiteX25519ChaCha20Sha256Ed25519

// DeviceConfig is one device's collaborators. Everything whose zero value would be a silent hole
// is refused by [NewDevice].
type DeviceConfig struct {
	// The 10.1 binding this device speaks over. REQUIRED, and the caller's: this package never
	// dials, never authenticates and never closes the connect client under it. S2-7, and the
	// package document says what the alpha's answer does not cover.
	Transport *sdk.MessageTransport

	// The durable allocator of 5.6's stream indices. REQUIRED and NOT defaulted to an in-memory
	// one: a reservation that does not survive a restart re-issues an index under an unmoved
	// class key, which is a reused nonce under a reused record key.
	// sdk.NewStreamIndexReserver over sdk.OpenStreamStore is the one this module ships.
	Reserver messagegroup.StreamIndexReserver

	// Where MLS keeps its group state and private keys. [NewMemoryStateStore] when nil, which
	// persists nothing -- see its document.
	StateStore mls.StateStore

	// The clock every record's sent_at and expire_at is read from. time.Now().UnixMilli when nil.
	NowMs func() int64

	// Where this device's signature keys, X-Wing seed and pq_secret are drawn from.
	// crypto/rand.Reader when nil.
	Random io.Reader

	// How [Device.Connect] rides out a reconnect window. The zero value is the default policy
	// and is what every caller that says nothing gets; see [ConnectPolicy].
	Connect ConnectPolicy

	// The receiving-client authorization decision on an ingested commit: MASTER §11's "rejected
	// by every receiving client on validation." NIL is the alpha's behaviour and allows every
	// commit -- the full role model (item 242) is not built. It is a config field now, before the
	// role model, so the CALL is on the ingest path and a later step fills the body without moving
	// it. See [CommitAuthorizer].
	CommitAuthorizer CommitAuthorizer
}

// ── §4.3.1's Hello, across an operator window this package does not own ──────────────────────

// THE WINDOW, MEASURED ON THE DEPLOYED SERVER RATHER THAN INFERRED. One client, one client_id,
// nothing else running:
//
//	baseline, a fresh connection                            Hello OK in 27ms
//	close the client, then re-dial and Hello repeatedly:
//	  +12s FAILED  +24s FAILED  +37s FAILED  +49s FAILED  +1m1s FAILED  +1m1s OK in 32ms
//
// Attempts 5 and 6 fall in the SAME SECOND, so it is a hard edge at about 60 seconds and not a
// gradual recovery; reproduced three times with different gaps. From the client the new connection
// attaches, routes register, the Hello goes out and NOTHING COMES BACK -- no error, no refusal,
// silence until the transport's own deadline. Filed against the operator in msgrepo
// `docs/reports/2026-09-15-operator-and-connect-findings.md` item 5, and it is THEIRS: the
// candidate causes are two 60-second settings in the operator's own resident, and whether the fix
// is to invalidate the old route when a new connection for the same client_id registers is not this
// package's call.
//
// WHAT IS OURS IS THAT WE USED TO CALL IT A FAILURE. [Device.Connect] sent one Hello and returned a
// hard error, and EVERY REAL CLIENT RECONNECTS -- app resume, laptop lid, network flap, a restart --
// so every one of those was an error where the truth was "not yet".
//
// THIS DOES NOT REMOVE THE SIXTY SECONDS AND NOTHING HERE CAN. The user still waits them and the
// operator item stays open. What it does is stop calling them a failure, and stop making the caller
// invent the retry loop.
type ConnectPolicy struct {
	// Budget is the total elapsed time [Device.Connect] will keep trying for. Zero takes
	// [defaultConnectBudget].
	//
	// IT BOUNDS HOW LONG ONE CALL BLOCKS AND IT IS NOT A CLAIM THAT THE WINDOW IS OVER. That
	// distinction is the whole reason [ErrReconnecting] exists: when the budget is spent and
	// every attempt looked like silence, the answer is "not yet, ask again" rather than
	// "failed", so a budget that runs out before the operator's window closes costs a caller one
	// more call and never a false verdict.
	Budget time.Duration

	// AttemptTimeout is how long ONE Hello is given before it is abandoned and the next attempt
	// is scheduled. Zero takes [defaultConnectAttempt]. An attempt is never given more than what
	// is left of [ConnectPolicy.Budget], so a Budget shorter than this is one attempt of the
	// Budget's length and not one of this.
	//
	// IT IS SHORTER THAN THE TRANSPORT'S OWN 30s DEADLINE ON PURPOSE. Inside the window the
	// server answers nothing at all, so waiting the transport's full deadline spends the budget
	// on silence and buys three attempts where it could buy seven. A Hello is idempotent by
	// construction -- the server replaces its nonce at every one -- and a late answer to an
	// abandoned attempt is dropped rather than adopted, because the nonce is taken in
	// `messageTransport.Hello` AFTER its Call returns and an abandoned Call has already
	// forgotten its waiter.
	AttemptTimeout time.Duration

	// FirstBackoff and MaxBackoff are the pause between attempts, doubling from the first up to
	// the maximum. Zero takes [defaultConnectFirstBackoff] and [defaultConnectMaxBackoff].
	//
	// THERE IS NO JITTER, AND THAT IS A DECISION RATHER THAN AN OMISSION. Jitter buys spread
	// over a CONTENDED resource; this window is per client_id -- it is the operator's own route
	// state for one client and no other client's reconnect makes it longer or shorter -- so
	// there is nothing here to spread, and a deterministic schedule is one a case can assert
	// exactly. The day this rides out something shared, jitter is the change.
	FirstBackoff time.Duration
	MaxBackoff   time.Duration

	// OnAttempt, when set, is called after every Hello that did not connect, before the pause.
	// It is how a caller says "Reconnecting..." to a user DURING the window rather than after
	// it, which a blocking call cannot otherwise do. It must not call back into this device.
	OnAttempt func(ConnectAttempt)
}

// ConnectAttempt is one Hello that did not connect, as [ConnectPolicy.OnAttempt] sees it.
type ConnectAttempt struct {
	// Attempt counts from 1.
	Attempt int
	// Elapsed is how long [Device.Connect] has been trying.
	Elapsed time.Duration
	// Backoff is how long it is about to wait before the next attempt. Zero when there will not
	// be one, AND zero when the next attempt is the last and follows at once because a full pause
	// would have left the budget nothing to try with (see [Device.Connect]).
	Backoff time.Duration
	// Err is why this attempt did not connect.
	Err error
}

const (
	// defaultConnectBudget covers the measured ~60s window with margin.
	//
	// NINETY SECONDS, AND THE NUMBER IS ARGUED RATHER THAN ROUND. The measured edge is at about
	// 61s from the close of the previous connection. The two candidate causes named in the
	// operator report are both 60-second settings, so a mechanism that starts its 60s at some
	// point AFTER the disconnect rather than at it puts the worst case somewhat past 61s; 90s is
	// half as long again as anything measured. A bound UNDER the window would be a bound that
	// does not cover the case it exists for, which is why this is not 30s.
	defaultConnectBudget = 90 * time.Second

	// defaultConnectAttempt is one Hello's deadline. Ten seconds is generous for a round trip
	// that measures 27ms on a good connection and short enough that the budget buys attempts
	// rather than silence.
	defaultConnectAttempt = 10 * time.Second

	defaultConnectFirstBackoff = 1 * time.Second
	defaultConnectMaxBackoff   = 8 * time.Second
)

func (self ConnectPolicy) withDefaults() ConnectPolicy {
	if self.Budget <= 0 {
		self.Budget = defaultConnectBudget
	}
	if self.AttemptTimeout <= 0 {
		self.AttemptTimeout = defaultConnectAttempt
	}
	if self.FirstBackoff <= 0 {
		self.FirstBackoff = defaultConnectFirstBackoff
	}
	if self.MaxBackoff <= 0 {
		self.MaxBackoff = defaultConnectMaxBackoff
	}
	if self.MaxBackoff < self.FirstBackoff {
		self.MaxBackoff = self.FirstBackoff
	}
	return self
}

// Device is one device: its MLS engine and identity, the transport it speaks over, and the groups
// it is a member of.
//
// It is safe for concurrent use. Every method that touches a group takes that group's lock, and
// the MLS session under it is serialized through its own goroutine by connect/messagegroup.
type Device struct {
	transport *sdk.MessageTransport
	reserver  messagegroup.StreamIndexReserver
	crypto    mls.CryptoProvider
	engine    messagegroup.GroupEngine
	leafKeys  []byte

	// The store the engine was built over, HELD BESIDE the engine for [DeviceStore]: every
	// durable-only path in this package -- [Device.Restore], [Device.persistGroup],
	// [Device.persistSent] -- asks this value whether it is a [DeviceStore] and does nothing when
	// it is not. The query, so the claim is checkable: `grep -n "self.stateStore" urmessage/*.go`
	// answers those three type assertions and nothing else.
	//
	// IT USED TO BE HELD FOR A SECOND REASON AND THAT REASON IS GONE. Until LoadGroup landed,
	// `restoreOne` called `mls.LoadGroup` DIRECTLY -- because `messagegroup.GroupEngine` had four
	// methods and none of them opened a persisted group -- so this field was also the *mls.Store
	// half of a GroupConfig this package assembled itself, and a `signer mls.SignaturePrivateKey`
	// field stood beside it to be the other argument that call took. J1-8 is CLOSED: the engine
	// opens the group, the signer it signs with is the engine's own copy, and the field that
	// existed only to feed that call has been deleted rather than left as state nothing reads.
	stateStore mls.StateStore

	// The credential identity this device founds and joins under: its signer's public half. See
	// [NewDevice] for why it is that value and not another.
	identityPub []byte
	nowMs       func() int64
	random      io.Reader

	// connect is [DeviceConfig.Connect] with its defaults filled in ONCE, at construction. It
	// is read without a lock and never written after, which is what lets [Device.Connect] be
	// called concurrently without the policy being a second thing to synchronise.
	connect ConnectPolicy

	// commitAuthorizer is [DeviceConfig.CommitAuthorizer], read on the commit-ingest path. Nil
	// allows every commit, which is the alpha until the role model lands. Read without a lock and
	// never written after construction, for `connect`'s reason one field up.
	commitAuthorizer CommitAuthorizer

	mutex  sync.Mutex
	groups map[string]*Group
}

// NewDevice opens this device's identity and its MLS engine.
//
// THE IDENTITY IS PERSISTED WHEN THE STORE CAN HOLD ONE, AND DRAWN FRESH WHEN IT CANNOT, and which
// of the two happened is a fact about the store the caller supplied rather than a mode.
//
//   - Over a [DeviceStore] -- which [OpenDurableStateStore] is -- the signature key pair and the
//     leaf keys body are read back if the directory holds them and are minted and written once if
//     it does not. That is what makes a restart a RESTORE: [mls.LoadGroup] verifies the restored
//     group's own leaf against the key handed in, so a device with a new signature key is refused
//     by every group it was in, and a durable store would be write-only without this.
//   - Over anything else -- [MemoryStateStore], or a caller's own map -- a fresh pair is drawn
//     every process, exactly as before this paragraph existed. A device that restarts is then a
//     new device: it is not the leaf any group remembers, and it re-joins rather than resumes.
//
// THE X-WING LEAF PRIVATE KEY IS STILL DROPPED, on both paths, and that is not new and is not
// fixed here. [messagegroup.XwingGenerateKey] draws a pair, the PUBLIC half is encoded into the
// leaf keys extension, and the private half is unreferenced the moment it is drawn -- which was
// already true before any store existed. Nothing in the alpha opens a device wrap (6.1's wraps
// carry no key material; see [alphaWrapBody]), so nothing needs it today. What it means is
// concrete and is worth writing down: this device can never open an X-Wing device wrap addressed
// to the leaf it publishes, so the day 6.1's fan-out actually carries an epoch secret, persisting
// the leaf keys body without the key under it leaves a device advertising a wrap target it cannot
// read. FILED AS S2-26: the device X-Wing leaf key is drawn and dropped.
func NewDevice(config DeviceConfig) (*Device, error) {
	if config.Transport == nil {
		return nil, ErrNoTransport
	}
	if config.Reserver == nil {
		return nil, ErrNoReserver
	}
	random := config.Random
	if random == nil {
		random = rand.Reader
	}
	nowMs := config.NowMs
	if nowMs == nil {
		nowMs = func() int64 { return time.Now().UnixMilli() }
	}
	stateStore := config.StateStore
	if stateStore == nil {
		stateStore = NewMemoryStateStore()
	}

	crypto, err := mls.NewCryptoProvider(deviceCipherSuite)
	if err != nil {
		return nil, fmt.Errorf("urmessage: the mls crypto provider: %w", err)
	}
	signer, signerPub, leafKeys, err := deviceIdentity(crypto, stateStore, random)
	if err != nil {
		return nil, err
	}
	// THE CREDENTIAL IDENTITY IS THE SIGNER'S PUBLIC HALF, which is a decision and not an
	// accident. The alpha has no identity system at all -- contact cards and the rendezvous are
	// out of scope -- so the only thing a credential could honestly name is the key this device
	// signs with, and naming anything else would be publishing an identity nobody can check.
	// What a member reads off MemberAt is therefore exactly "the leaf that signs", and MG-1's
	// obligation -- that a joiner must decide whether it expected THAT identity -- is the
	// caller's and is not met here.
	engine, err := messagegroup.NewConnectMlsEngine(crypto, stateStore, signer,
		mls.BasicCredential(signerPub), leafKeys)
	if err != nil {
		return nil, fmt.Errorf("urmessage: the mls engine: %w", err)
	}
	return &Device{
		transport:        config.Transport,
		reserver:         config.Reserver,
		connect:          config.Connect.withDefaults(),
		crypto:           crypto,
		engine:           engine,
		leafKeys:         leafKeys,
		stateStore:       stateStore,
		identityPub:      append([]byte(nil), signerPub...),
		nowMs:            nowMs,
		random:           random,
		commitAuthorizer: config.CommitAuthorizer,
		groups:           map[string]*Group{},
	}, nil
}

// deviceIdentity is the signature key pair and the leaf keys body this device runs under: read
// back from a durable store when there is one, minted and written once when there is not.
//
// THE MINT-AND-WRITE IS ONE STEP AND ITS FAILURE IS THE CALL'S. A device that minted an identity,
// failed to write it and ran anyway would found groups under a key the next process cannot
// produce -- which is the same state as no store at all, reached by a path nobody would look at
// again.
//
// A STORE THAT REFUSES FOR ANY OTHER REASON IS NOT TREATED AS AN EMPTY ONE. Only
// [ErrNoDeviceIdentity] falls through to the mint; a disk that would not answer is returned,
// because minting over it would silently replace an identity that is still on the disk and leave
// every group this device is in unreachable.
func deviceIdentity(crypto mls.CryptoProvider, stateStore mls.StateStore, random io.Reader) (
	mls.SignaturePrivateKey, mls.SignaturePublicKey, []byte, error) {

	store, durable := stateStore.(DeviceStore)
	if durable {
		pub, priv, leafKeys, err := store.GetDeviceIdentity()
		switch {
		case err == nil:
			return mls.SignaturePrivateKey(priv), mls.SignaturePublicKey(pub), leafKeys, nil
		case errors.Is(err, ErrNoDeviceIdentity):
			// the ordinary state of a fresh directory: fall through and mint.
		default:
			return nil, nil, nil, fmt.Errorf("urmessage: this device's persisted identity: %w", err)
		}
	}
	signer, signerPub, err := crypto.SignatureKeyPair()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("urmessage: this device's signature key pair: %w", err)
	}
	xwing, err := messagegroup.XwingGenerateKey(random)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("urmessage: this device's x-wing key: %w", err)
	}
	leafKeys, err := (&mls.LeafKeysExtension{
		AlgId:          mls.AlgIdXwing,
		DeviceXwingPub: xwing.Public().Bytes(),
	}).Encode()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("urmessage: this device's leaf keys extension: %w", err)
	}
	if durable {
		if err := store.PutDeviceIdentity(signerPub, signer, leafKeys.ExtensionData); err != nil {
			return nil, nil, nil, fmt.Errorf("urmessage: this device's identity could not be persisted: %w", err)
		}
	}
	return signer, signerPub, leafKeys.ExtensionData, nil
}

// Connect performs 4.3.1's Hello and rebinds every live group onto the nonce it issued.
//
// IT IS THE ONLY PLACE A NONCE ENTERS THIS PACKAGE and it is idempotent: calling it again is a
// reconnect, which is the S2-2 case the package document states. A group whose session refuses the
// new nonce is reported here rather than at its next send.
//
// IT RETRIES A HELLO THAT IS NOT ANSWERED, ACROSS THE OPERATOR WINDOW DESCRIBED AT [ConnectPolicy],
// AND IT SAYS "NOT YET" RATHER THAN "FAILED". A reconnecting client_id is not routed to for about
// sixty seconds on the deployed server; this call rides that out and, if its budget runs out first,
// answers [ErrReconnecting] so that a caller can tell "keep waiting" from "something is wrong".
//
// AND THE TWO KINDS OF FAILURE ARE NOT THE SAME KIND, which is the whole of what makes the retry
// safe. SILENCE is retried: no answer arrived, and the one thing known about the server is that it
// has said nothing. AN ANSWER IS NOT: a Hello the server REFUSED by reason, or one that issued no
// server_nonce, is the server speaking, and speaking is not the state this window produces --
// retrying it would turn one clear refusal into ninety seconds of the same refusal. So
// [ErrHelloRefused] and [ErrNotConnected] come straight back on the first attempt, exactly as
// before.
//
// THE CALLER'S OWN ctx STILL ENDS IT IMMEDIATELY. A cancelled or expired caller context is not
// "not yet": it is the caller saying stop, and it is returned rather than retried.
//
// THE BUDGET BOUNDS THE CALL, AND UNTIL THIS PARAGRAPH IT DID NOT. The budget used to be consulted
// only AFTER an attempt returned, and nothing asked whether the NEXT attempt fitted in what was
// left, so one call could return a whole AttemptTimeout past its budget: a 500 ms budget blocked
// for the 10 s default attempt, and the defaults' own schedule returned at about 100 s against the
// 90 s the C header states. For a UI that is a hang. Now every attempt is CUT TO WHAT IS LEFT of the
// budget -- so a budget shorter than one attempt is one attempt of the budget's length -- and when a
// full pause would leave nothing for another attempt, the rest of the budget is spent on one last
// attempt at once rather than on a pause no attempt follows.
// TestTheConnectBudgetBoundsTheCallWhateverTheAttemptTimeout holds it.
func (self *Device) Connect(ctx context.Context) error {
	policy := self.connect
	started := time.Now()
	backoff := policy.FirstBackoff
	var lastErr error
	lastChance := false
	for attempt := 1; ; attempt += 1 {
		timeout := policy.AttemptTimeout
		if remaining := policy.Budget - time.Since(started); remaining < timeout {
			timeout = remaining
		}
		if timeout <= 0 {
			// reachable only when a pause overran what was left of the budget. An attempt with
			// no time is not an attempt, and it is not reported as one. NOTHING GOES RED WITHOUT
			// THIS CLAUSE, measured: a pause is only taken when strictly more than it is left, so
			// only a timer firing late reaches here, and no case can make one.
			return self.reconnecting(attempt-1, time.Since(started), lastErr)
		}
		reason, hello, err := self.helloOnce(ctx, timeout)
		switch {
		case err == nil && reason != protocol.Reason_REASON_OK:
			// THE SERVER SPOKE. Not this window, and not retried.
			return fmt.Errorf("%w: %v", ErrHelloRefused, reason)
		case err == nil && len(hello.GetServerNonce()) == 0:
			return fmt.Errorf("%w: Hello issued no server_nonce", ErrNotConnected)
		case err == nil:
			return self.rebindAll()
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			// the CALLER's context, not the per-attempt one. Stop means stop.
			return fmt.Errorf("urmessage: Hello: %w", ctxErr)
		}
		lastErr = err
		elapsed := time.Since(started)
		remaining := policy.Budget - elapsed
		final := lastChance || remaining <= 0
		pause := backoff
		switch {
		case final:
			pause = 0
		case remaining <= pause:
			// A FULL PAUSE WOULD LEAVE NOTHING TO TRY WITH. The pause exists to space attempts
			// out, and a pause that no attempt follows only lengthens the block; so the rest of
			// the budget is ONE attempt, at once, and then the call ends whatever it answers --
			// which is also what stops an attempt that fails instantly from looping here.
			pause = 0
			lastChance = true
		}
		if policy.OnAttempt != nil {
			policy.OnAttempt(ConnectAttempt{
				Attempt: attempt, Elapsed: elapsed, Backoff: pause, Err: err,
			})
		}
		if final {
			return self.reconnecting(attempt, elapsed, lastErr)
		}
		if err := self.pause(ctx, pause); err != nil {
			return fmt.Errorf("urmessage: Hello: %w", err)
		}
		if backoff < policy.MaxBackoff {
			backoff *= 2
			if policy.MaxBackoff < backoff {
				backoff = policy.MaxBackoff
			}
		}
	}
}

// reconnecting is the "not yet, ask again" answer a budget spent on silence gets.
func (self *Device) reconnecting(attempts int, elapsed time.Duration, lastErr error) error {
	return fmt.Errorf(
		"%w: %d Hello attempts over %v were not answered; a reconnecting client_id is not routed to for about 60s on this server (msgrepo operator item 5), so this is 'not yet' rather than 'failed': %w",
		ErrReconnecting, attempts, elapsed.Round(time.Millisecond), lastErr)
}

// helloOnce is one Hello under its own deadline, so that a server answering nothing costs this
// attempt's timeout rather than the transport's.
//
// THE PER-ATTEMPT CONTEXT IS DERIVED FROM THE CALLER'S, so a cancelled caller cancels the attempt
// in flight and the loop above can tell the two apart by asking the CALLER's context afterwards.
func (self *Device) helloOnce(ctx context.Context, timeout time.Duration) (
	protocol.Reason, *protocol.HelloResponse, error) {

	attemptCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	reason, hello, err := self.transport.Hello(attemptCtx)
	if err != nil {
		return protocol.Reason_REASON_INTERNAL, nil, fmt.Errorf("urmessage: Hello: %w", err)
	}
	return reason, hello, nil
}

// pause waits, or answers the caller's context ending first.
func (self *Device) pause(ctx context.Context, howLong time.Duration) error {
	if howLong <= 0 {
		return nil
	}
	timer := time.NewTimer(howLong)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// rebindAll moves every live session onto the nonce this transport now holds.
func (self *Device) rebindAll() error {
	for _, group := range self.Groups() {
		if err := group.rebind(); err != nil {
			return err
		}
	}
	return nil
}

// KeyPackage publishes one single-use MLS key package, which is what another device adds to a
// group with.
//
// IT IS SINGLE USE AND THE STORE ENFORCES THAT: the private halves are taken destructively at the
// join, so two joins off one published package is not something this device can do.
func (self *Device) KeyPackage() ([]byte, error) {
	keyPackage, err := self.engine.NewKeyPackage()
	if err != nil {
		return nil, fmt.Errorf("urmessage: this device's key package: %w", err)
	}
	return keyPackage, nil
}

// Groups is every group this device holds, in no particular order.
func (self *Device) Groups() []*Group {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	groups := make([]*Group, 0, len(self.groups))
	for _, group := range self.groups {
		groups = append(groups, group)
	}
	return groups
}

// Close closes every group's session. The transport and the connect client under it are the
// caller's and are not closed.
func (self *Device) Close() error {
	self.mutex.Lock()
	groups := make([]*Group, 0, len(self.groups))
	for _, group := range self.groups {
		groups = append(groups, group)
	}
	self.groups = map[string]*Group{}
	self.mutex.Unlock()
	var first error
	for _, group := range groups {
		if err := group.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// nonce is the connection's server_nonce and the Hello count it was issued at, or a refusal that
// names the absence.
func (self *Device) nonce() ([]byte, uint64, error) {
	nonce := self.transport.Nonce()
	if len(nonce) == 0 {
		return nil, 0, ErrNotConnected
	}
	return nonce, self.transport.NonceEpoch(), nil
}

// createMlsGroup founds the MLS group one [Group] is a view of.
//
// The policy names this device as the group's owner, which is the only role there is to assign
// before there is a second member and is what mls.GroupPolicyExtension.Validate requires. It is
// canonicalized before it is encoded, because the extension travels inside the group context and
// two members that encoded it differently would export different secrets.
func (self *Device) createMlsGroup(groupId []byte) (messagegroup.GroupHandle, error) {
	policy := &mls.GroupPolicyExtension{
		Roles: []mls.RoleEntry{{MemberId: self.identityPub, Role: mls.RoleOwner}},
	}
	if err := policy.Canonicalize(); err != nil {
		return nil, fmt.Errorf("urmessage: the group policy: %w", err)
	}
	encoded, err := policy.Encode()
	if err != nil {
		return nil, fmt.Errorf("urmessage: the group policy: %w", err)
	}
	handle, err := self.engine.CreateGroup(groupId, encoded.ExtensionData, self.leafKeys)
	if err != nil {
		return nil, fmt.Errorf("urmessage: CreateGroup: %w", err)
	}
	return handle, nil
}

func (self *Device) hold(group *Group) {
	self.mutex.Lock()
	defer self.mutex.Unlock()
	self.groups[string(group.id)] = group
}
