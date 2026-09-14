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

	// The store the engine was built over, HELD BESIDE the engine because a restore needs it
	// directly: [mls.LoadGroup] takes a *mls.GroupConfig and messagegroup.GroupEngine has no
	// method that opens a persisted group. That is J1-8; see [restoredHandle].
	stateStore mls.StateStore

	// This device's MLS signature private key. mls clones it into every group it founds or
	// joins, and this copy exists for one reason: [mls.LoadGroup] takes the signer as an
	// argument and NOT out of the persisted blob -- deliberately, because a signature key is
	// the device across every group and an epoch state is one group at one epoch.
	signer mls.SignaturePrivateKey

	// The credential identity this device founds and joins under: its signer's public half. See
	// [NewDevice] for why it is that value and not another.
	identityPub []byte
	nowMs       func() int64
	random      io.Reader

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
		transport:   config.Transport,
		reserver:    config.Reserver,
		crypto:      crypto,
		engine:      engine,
		leafKeys:    leafKeys,
		stateStore:  stateStore,
		signer:      append(mls.SignaturePrivateKey(nil), signer...),
		identityPub: append([]byte(nil), signerPub...),
		nowMs:       nowMs,
		random:      random,
		groups:      map[string]*Group{},
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
func (self *Device) Connect(ctx context.Context) error {
	reason, hello, err := self.transport.Hello(ctx)
	if err != nil {
		return fmt.Errorf("urmessage: Hello: %w", err)
	}
	if reason != protocol.Reason_REASON_OK {
		return fmt.Errorf("%w: %v", ErrHelloRefused, reason)
	}
	if len(hello.GetServerNonce()) == 0 {
		return fmt.Errorf("%w: Hello issued no server_nonce", ErrNotConnected)
	}
	return self.rebindAll()
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
