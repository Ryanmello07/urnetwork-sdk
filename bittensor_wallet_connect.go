//go:build !js && !ios_extension

package sdk

// The connection to a Bittensor wallet app that an app holds itself. Where a
// BittensorWalletSession on a phone sends the user through the bridge page,
// this pairs with the wallet over WalletConnect v2 (package walletconnect) and
// has it sign the server's challenges. Every Sign still runs through a
// BittensorWalletSession of its own, so what an acceptable proof is stays
// decided there. bittensor_wallet.go is not changed, and nothing here is
// reached by an app that does not ask for it.
//
// The glue is one mutex over all state. What the client tells arrives on its
// event goroutine, the challenge of each Sign is fetched on a goroutine of
// its own, and the listeners are called by a notifier goroutine; each of the
// three runs under connect.HandleError.

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/urnetwork/connect"

	"github.com/urnetwork/sdk/sn/ss58"
	"github.com/urnetwork/sdk/walletconnect"
	"github.com/urnetwork/sdk/walletconnect/wire"
)

const (
	// nothing asked yet
	BittensorWalletConnectStateIdle = "idle"
	// the sdk is working (relay, challenge, publish); nothing for the user to do
	BittensorWalletConnectStateConnecting = "connecting"
	// the pairing is at the relay: the wallet has to be opened and the user
	// approves the connection there
	BittensorWalletConnectStateAwaitingApproval = "awaiting_approval"
	// the sign request is with the wallet; the user approves the signature there
	BittensorWalletConnectStateAwaitingSignature = "awaiting_signature"
	// the Sign succeeded: TakeProof hands the proof out. Sign may be called again.
	BittensorWalletConnectStateSigned = "signed"
	// the Sign failed and the wallet connection is still open: Result says
	// why. Sign may be called again.
	BittensorWalletConnectStateFailed = "failed"
	// the connection is over. Result says why when a failure ended it.
	BittensorWalletConnectStateClosed = "closed"
)

// A BittensorWalletResult.BridgeErrorCode beside the BittensorWalletBridgeError*
// codes: the wallet does not offer the Bittensor chain or the sign method.
const BittensorWalletBridgeErrorUnsupportedChain = "unsupported_chain"

// BittensorWalletConnectListener is called once for every state entered, and
// once whenever Connected changes while the state is connecting,
// awaiting_approval or awaiting_signature. Calls are made one at a time, in
// order, on a goroutine of the connection: never on the caller's thread and
// never with a lock held. Every method of the connection may be called from
// inside a call. Read the details from the connection and hop to the ui thread.
type BittensorWalletConnectListener interface {
	BittensorWalletConnectChanged(state string)
}

// an account the wallet approved on the Bittensor chain
type bittensorWalletConnectAccount struct {
	address string // as the wallet spells it, under any ss58 prefix: what a request names
	pubkey  [32]byte
}

// BittensorWalletConnect is one connection to one wallet app, held by the app.
// It pairs over WalletConnect v2, asks the wallet to sign server challenges
// (polkadot_signMessage on the Bittensor chain) and hands out the same
// BittensorWalletProof a BittensorWalletSession does. Nothing is stored: a
// process that dies takes the connection with it. Safe for concurrent use; no
// method waits for the network.
type BittensorWalletConnect struct {
	ctx         context.Context // the constructor's: the client lives under it
	fetchCtx    context.Context // its child, for the challenge fetches: ended when the connection is over
	cancelFetch context.CancelFunc
	walletId    string
	platform    string
	projectId   string
	appId       string
	links       *bittensorWalletAppLinks // of the wallet-app table: read only
	listeners   *connect.CallbackList[BittensorWalletConnectListener]

	// test seams; set before the first Sign
	nowMillis       func() int64
	fetchChallenge  func(ctx context.Context, args *AuthWalletChallengeArgs) (*AuthWalletChallengeResult, error)
	configureClient func(config *walletconnect.Config) // called once, before walletconnect.NewClient

	stateLock sync.Mutex
	client    *walletconnect.Client // from the first Sign on
	over      bool                  // the client has ended, and the wallet session with it
	state     string
	purpose   string
	family    string // of the first Sign; every later one is of it (design A.3 rule 5)
	signs     int    // the Sign calls accepted: a challenge leg acts only for the one it began with

	// of the pending Sign
	expected  string // its expectedAddress
	session   *BittensorWalletSession
	requestId int64

	accounts   []bittensorWalletConnectAccount // those of the wallet that are addresses, in its order
	account    string                          // the one in use, as the wallet spells it
	address    string                          // the same under prefix 42
	pairingUri string
	connected  bool
	foreground bool
	linkTaken  bool // TakeWalletLink has given the link of this state

	proof                *BittensorWalletProof // waits to be taken
	proofExpiresAtMillis int64
	result               *BittensorWalletResult

	// the calls the listeners are still to get, each with its state, and
	// whether the notifier runs
	pending   []string
	notifying bool
}

// NewBittensorWalletConnect prepares a connection to a wallet app. walletId is
// an entry of the wallet-app table for the platform: a wallet_app row of
// BittensorWalletChoiceIdList(platform), or an entry that is not listed yet
// (for a device test). api fetches the
// challenges (the Api the screen already uses); the connection ends with it.
// projectId is the app's WalletConnect project id. appId is the app's bundle
// id (ios) or application id (android), presented to the relay; "" presents
// nothing. Nothing touches the network until Sign. The caller owns Close.
// Errors: unsupported_platform (not ios or android), unsupported_wallet,
// walletconnect_unavailable (no project id), no_challenge (no api).
func NewBittensorWalletConnect(api *Api, walletId string, platform string, projectId string, appId string) (*BittensorWalletConnect, error) {
	if api == nil {
		return nil, fmt.Errorf("%s: no api", BittensorWalletErrorNoChallenge)
	}
	c, err := newBittensorWalletConnect(api.ctx, walletId, platform, projectId, appId)
	if err != nil {
		return nil, err
	}
	c.fetchChallenge = api.AuthWalletChallengeSyncWithContext
	return c, nil
}

// newBittensorWalletConnect is the constructor without an Api: the context
// the connection lives under, and no challenge fetcher (tests set the seams).
func newBittensorWalletConnect(ctx context.Context, walletId string, platform string, projectId string, appId string) (*BittensorWalletConnect, error) {
	// the table answers for the two phones only, so the platform comes first
	if platform != BittensorWalletPlatformIos && platform != BittensorWalletPlatformAndroid {
		return nil, fmt.Errorf("%s: %s", BittensorWalletErrorUnsupportedPlatform, platform)
	}
	// looked up once, here: tests replace the table
	_, links := bittensorWalletAppEntryFor(walletId, platform)
	if links == nil {
		return nil, fmt.Errorf("%s: %s", BittensorWalletErrorUnsupportedWallet, walletId)
	}
	projectId = strings.TrimSpace(projectId)
	if projectId == "" {
		return nil, fmt.Errorf("%s: no WalletConnect project id", BittensorWalletBridgeErrorWalletConnectUnavailable)
	}
	fetchCtx, cancelFetch := context.WithCancel(ctx)
	return &BittensorWalletConnect{
		ctx:         ctx,
		fetchCtx:    fetchCtx,
		cancelFetch: cancelFetch,
		walletId:    walletId,
		platform:    platform,
		projectId:   projectId,
		appId:       strings.TrimSpace(appId),
		links:       links,
		listeners:   connect.NewCallbackList[BittensorWalletConnectListener](),
		nowMillis:   func() int64 { return time.Now().UnixMilli() },
		state:       BittensorWalletConnectStateIdle,
		foreground:  true,
	}, nil
}

// clientConfig is the client of this connection (design B.2; B.3 R3, R15).
func (self *BittensorWalletConnect) clientConfig() *walletconnect.Config {
	log := connect.DefaultLogger()
	config := &walletconnect.Config{
		ProjectId:       self.projectId,
		IdentifierName:  "bundleId",
		IdentifierValue: self.appId,
		Metadata: wire.Metadata{
			Name:        BittensorWalletDappName,
			Description: "URnetwork",
			Url:         "https://ur.io",
			Icons:       []string{"https://ur.io/favicon.ico"},
		},
		NamespaceKey: "polkadot",
		Chain:        BittensorWalletConnectChain,
		Method:       BittensorWalletConnectMethod,
		// called on the loop of the client and, through SignMessage, on the
		// goroutine of a challenge leg
		Now: self.nowMillis,
		OnEvent: func(ev walletconnect.Event) {
			connect.HandleError(func() { self.onEvent(ev) })
		},
		Logf: func(format string, args ...any) {
			if verbose := log.V(2); verbose.Enabled() {
				verbose.Infof("[bwc]"+format, args...)
			}
		},
	}
	if self.platform == BittensorWalletPlatformAndroid {
		// there the process goes on for about a minute behind the wallet
		config.IdentifierName, config.BackgroundSocketSeconds = "packageName", 45
	}
	if self.configureClient != nil {
		self.configureClient(config)
	}
	return config
}

func (self *BittensorWalletConnect) WalletId() string {
	return self.walletId
}

// Sign asks the wallet for one proof. purpose is a BittensorWalletPurpose*.
// expectedAddress is as in BittensorWalletSession.ChallengeArgs: "" = the
// wallet's first Bittensor account (or the one already in use); otherwise the
// challenge is bound to that address and only that account may sign. The first
// Sign pairs with the wallet; a later one reuses the wallet session. Returns at
// once; the outcome arrives as a state change.
// Errors (no state change): unknown purpose, invalid_ss58_address,
// purpose_mismatch (the connection served another purpose family: login and
// create are one family, add is one, connect is one), busy (a Sign is
// pending), closed (the wallet connection is over: make a new one).
func (self *BittensorWalletConnect) Sign(purpose string, expectedAddress string) error {
	family := purpose
	switch purpose {
	case BittensorWalletPurposeLogin, BittensorWalletPurposeAdd, BittensorWalletPurposeConnect:
	case BittensorWalletPurposeCreate:
		family = BittensorWalletPurposeLogin
	default:
		return fmt.Errorf("unknown purpose: %s", purpose)
	}
	expectedAddress = strings.TrimSpace(expectedAddress)
	if expectedAddress != "" && !ValidateSs58(expectedAddress) {
		return fmt.Errorf("%s: %s", BittensorWalletErrorInvalidAddress, expectedAddress)
	}
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	switch {
	case self.family != "" && self.family != family:
		return fmt.Errorf("%s: the connection signs for %s", BittensorWalletErrorPurposeMismatch, self.family)
	case self.state == BittensorWalletConnectStateClosed || self.over:
		return errors.New("closed: the wallet connection is over")
	case self.state != BittensorWalletConnectStateIdle && self.state != BittensorWalletConnectStateSigned && self.state != BittensorWalletConnectStateFailed:
		return errors.New("busy: a Sign is pending")
	}
	first := self.client == nil
	if first {
		client, err := walletconnect.NewClient(self.ctx, self.clientConfig())
		if err != nil {
			return fmt.Errorf("%s: %s", BittensorWalletBridgeErrorWalletConnectUnavailable, err)
		}
		self.client = client
	}
	self.signs++
	self.family, self.purpose, self.expected = family, purpose, expectedAddress
	// a proof that was not taken is dropped (design A.3 rule 6)
	self.proof, self.result = nil, nil
	self.session = newBittensorWalletConnectSession(self.walletId, self.platform, purpose)
	self.enter(BittensorWalletConnectStateConnecting)
	if first {
		self.client.SetForeground(self.foreground)
		self.client.Pair()
	} else if self.choose() {
		self.challenge()
	}
	return nil
}

func (self *BittensorWalletConnect) State() string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.state
}

// Purpose is the purpose of the current or last Sign ("" before the first).
func (self *BittensorWalletConnect) Purpose() string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.purpose
}

// Address is the wallet account in use, ss58 prefix 42 ("" until the wallet
// approved the connection).
func (self *BittensorWalletConnect) Address() string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.address
}

// PairingUri is the wc: uri while awaiting_approval ("" otherwise). Whoever
// holds it can answer in the wallet's place: never log it, never send it
// anywhere but to the wallet.
func (self *BittensorWalletConnect) PairingUri() string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.pairingUri
}

// WalletLink is the link that opens the wallet app for what is pending: while
// awaiting_approval the link that hands the pairing over, while
// awaiting_signature the link that brings the wallet forward. "" when there is
// nothing to open. For an "Open wallet" button. As secret as PairingUri.
func (self *BittensorWalletConnect) WalletLink() string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.walletLink()
}

func (self *BittensorWalletConnect) walletLink() string {
	switch self.state {
	case BittensorWalletConnectStateAwaitingApproval:
		return bittensorWalletAppLink(self.links.pair, self.pairingUri, 0)
	case BittensorWalletConnectStateAwaitingSignature:
		return bittensorWalletAppLink(self.links.foreground, "", self.requestId)
	}
	return ""
}

// TakeWalletLink is WalletLink for opening the wallet without a tap: it
// returns the link at most once per waiting state entered, and only while the
// app is in the foreground (SetForeground) and Connected, so a user who
// already approved in the wallet is not sent back. It returns "" for a create
// request: that one is explained on screen and opened with the button. Call
// it on every listener call and whenever the app becomes active, and open what
// it returns.
func (self *BittensorWalletConnect) TakeWalletLink() string {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.linkTaken || !self.foreground || !self.connected ||
		self.state == BittensorWalletConnectStateAwaitingSignature && self.purpose == BittensorWalletPurposeCreate {
		return ""
	}
	link := self.walletLink()
	self.linkTaken = link != ""
	return link
}

// TakeProof hands the proof of the last Sign out exactly once: the first call
// in state signed returns it, every other call returns nil. A proof whose
// challenge expired while it waited is not handed out: the state becomes
// failed with challenge_expired.
func (self *BittensorWalletConnect) TakeProof() *BittensorWalletProof {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	// one waits in the state signed only
	proof := self.proof
	if proof == nil {
		return nil
	}
	self.proof = nil
	if self.proofExpiresAtMillis <= self.nowMillis() {
		proof, self.result = nil, &BittensorWalletResult{ErrorCode: BittensorWalletErrorExpired}
		self.enter(BittensorWalletConnectStateFailed)
	}
	if self.over {
		// the wallet session ended while the proof waited (design A.3 rule 8)
		self.enter(BittensorWalletConnectStateClosed)
	}
	return proof
}

// Result is why the last Sign failed (state failed) or why the connection
// ended (state closed); nil otherwise. It never holds a proof. A copy.
func (self *BittensorWalletConnect) Result() *BittensorWalletResult {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.result == nil {
		return nil
	}
	result := *self.result
	return &result
}

// Connected reports that the relay socket is up, every topic is subscribed on
// it and what the wallet sent meanwhile has been read. False while
// reconnecting, in the background once the socket was closed, and right after
// the app returns.
func (self *BittensorWalletConnect) Connected() bool {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	return self.connected
}

// SetForeground tells the connection that the app left the foreground (false)
// or is in front again (true). In the background the relay socket is closed on
// purpose (ios at once, android after 45 s) so the wallet's messages are stored
// instead of waiting on a silent peer; on the way back the socket is replaced
// at once and what the wallet sent is collected. A connection starts in the
// foreground. Correctness does not depend on these calls; they remove waits.
func (self *BittensorWalletConnect) SetForeground(foreground bool) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if foreground && !self.foreground {
		// The client lets go of its socket and reads what the wallet sent.
		// It tells so later; until it has read, TakeWalletLink must not
		// send a user back who has approved already.
		self.setConnected(false)
	}
	self.foreground = foreground
	if self.client != nil {
		self.client.SetForeground(foreground)
	}
}

func (self *BittensorWalletConnect) AddBittensorWalletConnectListener(listener BittensorWalletConnectListener) Sub {
	callbackId := self.listeners.Add(listener)
	return newSub(func() {
		self.listeners.Remove(callbackId)
	})
}

// Close ends the connection: a pending Sign is abandoned, an untaken proof is
// dropped, the wallet session is deleted at the wallet (best effort) and the
// socket is closed. Returns at once. Idempotent.
func (self *BittensorWalletConnect) Close() {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	self.proof, self.result = nil, nil
	if self.state != BittensorWalletConnectStateClosed {
		self.enter(BittensorWalletConnectStateClosed)
	}
}

// enter is the one place the state changes; the lock is held. The listeners
// are told of it by the notifier.
func (self *BittensorWalletConnect) enter(state string) {
	self.state = state
	self.linkTaken = false
	if state != BittensorWalletConnectStateAwaitingApproval {
		self.pairingUri = "" // design F.1
	}
	switch state {
	case BittensorWalletConnectStateSigned, BittensorWalletConnectStateFailed, BittensorWalletConnectStateClosed:
		// the Sign is over, and its session is let go (design A.7 step 8)
		if self.session != nil {
			self.session.Cancel()
			self.session = nil
		}
	}
	if state == BittensorWalletConnectStateClosed {
		// Over for good: a challenge fetch is abandoned, and the client
		// deletes the wallet session if there is one and it has not ended.
		self.connected = false
		self.cancelFetch()
		if self.client != nil {
			self.client.Close()
		}
	}
	self.tell(state)
}

// setConnected takes a change of Connected. The listeners are told of one
// while a Sign waits: TakeWalletLink depends on it then.
func (self *BittensorWalletConnect) setConnected(connected bool) {
	if self.connected == connected {
		return
	}
	self.connected = connected
	switch self.state {
	case BittensorWalletConnectStateConnecting, BittensorWalletConnectStateAwaitingApproval, BittensorWalletConnectStateAwaitingSignature:
		self.tell(self.state)
	}
}

// tell queues a call of the listeners; the lock is held. The notifier is a
// goroutine that runs while calls wait, never two at a time, so the calls are
// made in order, off the caller's goroutine and with no lock held (design
// A.3 rule 1).
func (self *BittensorWalletConnect) tell(state string) {
	self.pending = append(self.pending, state)
	if !self.notifying {
		self.notifying = true
		go connect.HandleError(self.notify)
	}
}

func (self *BittensorWalletConnect) notify() {
	for {
		self.stateLock.Lock()
		if len(self.pending) == 0 {
			self.notifying = false
			self.stateLock.Unlock()
			return
		}
		state := self.pending[0]
		self.pending = self.pending[1:]
		self.stateLock.Unlock()
		for _, listener := range self.listeners.Get() {
			connect.HandleError(func() { listener.BittensorWalletConnectChanged(state) })
		}
	}
}

// fail ends the pending Sign with a failure of the wallet or the relay, as
// the app is told it (design A.5): a bridge code, and a sentence that is
// written here. Of an error of the client only the kind and the code are
// used, so no text of a wallet reaches a result. In failed the wallet session
// is still there, in closed it is over. The lock is held.
func (self *BittensorWalletConnect) fail(state string, kind walletconnect.ErrorKind, code int) {
	bridgeErrorCode, message := BittensorWalletBridgeErrorWallet, "The wallet could not complete the request."
	switch kind {
	case walletconnect.ErrRejected:
		bridgeErrorCode, message = BittensorWalletBridgeErrorUserRejected, "The request was declined in the wallet."
	case walletconnect.ErrExpired:
		bridgeErrorCode, message = BittensorWalletBridgeErrorWalletConnectExpired, "The request expired before the wallet answered."
	case walletconnect.ErrUnavailable:
		bridgeErrorCode, message = BittensorWalletBridgeErrorWalletConnectUnavailable, "The wallet connection service could not be reached."
	case walletconnect.ErrUnsupported:
		bridgeErrorCode, message = BittensorWalletBridgeErrorUnsupportedChain, "The wallet does not support Bittensor sign-in."
	case walletconnect.ErrNoAccount:
		bridgeErrorCode, message = BittensorWalletBridgeErrorNoAccount, "The wallet has no Bittensor account to sign with."
	case walletconnect.ErrDeleted:
		message = "The wallet ended the connection."
	}
	if bridgeErrorCode == BittensorWalletBridgeErrorWallet && code != 0 {
		message += fmt.Sprintf(" (code %d)", code)
	}
	self.result = self.session.failWalletConnect(bridgeErrorCode, message)
	self.enter(state)
}

// onEvent takes what the client tells, one event at a time and in order.
func (self *BittensorWalletConnect) onEvent(ev walletconnect.Event) {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.state == BittensorWalletConnectStateClosed {
		return // what the client tells while it ends is of no use
	}
	switch ev.Kind {
	case walletconnect.EventConnected:
		self.setConnected(ev.Connected)
	case walletconnect.EventPairingReady:
		self.pairingUri = ev.PairingUri
		self.enter(BittensorWalletConnectStateAwaitingApproval)
	case walletconnect.EventSessionSettled:
		// design A.7 step 2: what is no address, under any prefix, is passed over
		for _, account := range ev.Accounts {
			address := wire.AccountAddress(account)
			if pubkey, _, err := ss58.Decode(address); err == nil {
				self.accounts = append(self.accounts, bittensorWalletConnectAccount{address, pubkey})
			}
		}
		if len(self.accounts) == 0 {
			self.fail(BittensorWalletConnectStateClosed, walletconnect.ErrNoAccount, 0)
		} else if self.choose() {
			self.enter(BittensorWalletConnectStateConnecting)
			self.challenge()
		}
	case walletconnect.EventRequestSent:
		self.enter(BittensorWalletConnectStateAwaitingSignature)
	case walletconnect.EventRequestResult:
		self.answered(ev.Signature)
	case walletconnect.EventRequestFailed:
		// The wallet session is still there, unless the wallet has ended it
		// or does not serve the request, for which it is deleted.
		state := BittensorWalletConnectStateFailed
		if ev.Err.Kind == walletconnect.ErrUnsupported || ev.Err.Kind == walletconnect.ErrDeleted {
			state = BittensorWalletConnectStateClosed
		}
		self.fail(state, ev.Err.Kind, ev.Err.Code)
	case walletconnect.EventClosed:
		self.over, self.connected = true, false
		switch self.state {
		case BittensorWalletConnectStateSigned:
			// a proof that was not taken waits on (design A.3 rule 8)
			if self.proof == nil {
				self.enter(BittensorWalletConnectStateClosed)
			}
		case BittensorWalletConnectStateFailed:
			self.enter(BittensorWalletConnectStateClosed)
		default:
			// A Sign is pending. With no error the client ended by itself,
			// at the end of its linger or of the context: the Sign is told
			// what it is told when the wallet ends the session.
			if ev.Err == nil {
				ev.Err = &walletconnect.Error{Kind: walletconnect.ErrDeleted}
			}
			self.fail(BittensorWalletConnectStateClosed, ev.Err.Kind, ev.Err.Code)
		}
	}
}

// choose takes the account of the pending Sign from those the wallet approved
// (design A.7 step 2): the one of the typed address, and with none typed the
// one in use, or the first. The lock is held. A typed address the wallet does
// not hold ends the connection before a challenge is asked for: false.
func (self *BittensorWalletConnect) choose() bool {
	i := 0
	if self.expected != "" {
		// Sign has checked that it is an address
		pubkey, _ := ss58.DecodeWithPrefix(self.expected, SnSs58Prefix)
		i = slices.IndexFunc(self.accounts, func(account bittensorWalletConnectAccount) bool { return account.pubkey == pubkey })
	} else if self.account != "" {
		return true
	}
	if i < 0 {
		self.result = self.session.failWalletConnect(BittensorWalletBridgeErrorAddressNotInWallet, "The wallet does not hold the address you entered.")
		self.enter(BittensorWalletConnectStateClosed)
		return false
	}
	self.account = self.accounts[i].address
	self.address, _ = ss58.Encode(self.accounts[i].pubkey, SnSs58Prefix)
	return true
}

// challenge begins the challenge leg of the pending Sign (design A.6) on a
// goroutine of its own; the lock is held.
func (self *BittensorWalletConnect) challenge() {
	sign, client, session := self.signs, self.client, self.session
	args := session.ChallengeArgs(self.expected)
	go connect.HandleError(func() {
		// Until the challenge is there: three attempts that count, 1 s and
		// 3 s apart and 15 s each, within 60 s of running time.
		var challenge *AuthWalletChallengeResult
		began := client.RunningSeconds()
		for counted, repeated := 0, 0; ; {
			epoch := client.ResumeEpoch()
			ctx, cancel := context.WithTimeout(self.fetchCtx, 15*time.Second)
			result, err := self.fetchChallenge(ctx, args)
			cancel()
			if err == nil {
				challenge = result
				break
			}
			if client.ResumeEpoch() != epoch && repeated < 3 {
				// the process was suspended in it, which says nothing of
				// the server: again at once, and not counted
				repeated++
				continue
			}
			if counted++; counted == 3 || client.RunningSeconds()-began >= 60 {
				break
			}
			select {
			case <-self.fetchCtx.Done():
				return
			case <-time.After(time.Duration(2*counted-1) * time.Second):
			}
		}
		self.stateLock.Lock()
		defer self.stateLock.Unlock()
		if self.signs != sign || self.state != BittensorWalletConnectStateConnecting {
			return // the connection was closed meanwhile, or this is not the pending Sign any more
		}
		// no challenge, or one that is none, is refused by the session
		if session.SetChallenge(challenge, self.nowMillis()) != nil {
			self.result = &BittensorWalletResult{ErrorCode: session.ErrorCode()}
			self.enter(BittensorWalletConnectStateFailed)
			return
		}
		// Once: it arms the session (design A.7 step 4). The wallet is sent
		// the text of the challenge and not its hex, for the address as the
		// wallet spells it.
		session.SignRequest()
		self.requestId = client.SignMessage(self.account, session.Message(), session.ExpiresAtMillis())
	})
}

// answered takes the wallet's answer to the request; the lock is held. The
// session of the Sign decides whether it is a proof (design A.7 step 6).
func (self *BittensorWalletConnect) answered(signature string) {
	// 65 bytes of which the first names the kind of key (01: sr25519) are
	// the signature behind that byte
	if raw, err := hex.DecodeString(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(signature)), "0x")); err == nil && len(raw) == 65 && raw[0] == 1 {
		signature = hex.EncodeToString(raw[1:])
	}
	address := self.expected
	if address == "" {
		address = self.address
	}
	result := self.session.HandleSignature(address, signature, self.nowMillis())
	if result.Proof == nil {
		self.result = result
		self.enter(BittensorWalletConnectStateFailed)
		return
	}
	self.proof, self.proofExpiresAtMillis = result.Proof, self.session.ExpiresAtMillis()
	self.enter(BittensorWalletConnectStateSigned)
}

// newBittensorWalletConnectSession is the session of one Sign: one challenge,
// on the walletconnect transport, which is the one that is asked to sign and
// takes a signature, and with no redirect link, so that no url can be handed
// to it as a return (design A.7 step 1, F.6).
func newBittensorWalletConnectSession(walletId string, platform string, purpose string) *BittensorWalletSession {
	return &BittensorWalletSession{
		walletId:  walletId,
		platform:  platform,
		transport: BittensorWalletTransportWalletConnect,
		purpose:   purpose,
		state:     BittensorWalletStateIdle,
	}
}

// failWalletConnect is the mirror of the error branch of HandleBridgeReturn
// for a failure the app-held connection reports: it fails a session that
// waits for the wallet, and builds the result. A failure can come before the
// session waits (the pairing, the challenge), so there is no result of
// not_awaiting_wallet here.
func (self *BittensorWalletSession) failWalletConnect(bridgeErrorCode string, message string) *BittensorWalletResult {
	self.stateLock.Lock()
	defer self.stateLock.Unlock()
	if self.state == BittensorWalletStateAwaitingWallet {
		self.failWithLock(BittensorWalletErrorWallet)
	}
	return &BittensorWalletResult{
		ErrorCode:       BittensorWalletErrorWallet,
		ErrorMessage:    message,
		BridgeErrorCode: bridgeErrorCode,
	}
}
