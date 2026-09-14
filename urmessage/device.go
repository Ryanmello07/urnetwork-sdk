package urmessage

import (
	"context"
	"crypto/rand"
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

	// The credential identity this device founds and joins under: its signer's public half. See
	// [NewDevice] for why it is that value and not another.
	identityPub []byte
	nowMs       func() int64
	random      io.Reader

	mutex  sync.Mutex
	groups map[string]*Group
}

// NewDevice draws this device's identity and opens its MLS engine.
//
// THE IDENTITY IS DRAWN HERE AND IS NOT PERSISTED. Recovery and multi-device are out of scope for
// the alpha, so a device that restarts is a new device: it has a new signature key pair, it is not
// the leaf any group remembers, and it re-joins rather than resumes.
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
	signer, signerPub, err := crypto.SignatureKeyPair()
	if err != nil {
		return nil, fmt.Errorf("urmessage: this device's signature key pair: %w", err)
	}
	// THE CREDENTIAL IDENTITY IS THE SIGNER'S PUBLIC HALF, which is a decision and not an
	// accident. The alpha has no identity system at all -- contact cards and the rendezvous are
	// out of scope -- so the only thing a credential could honestly name is the key this device
	// signs with, and naming anything else would be publishing an identity nobody can check.
	// What a member reads off MemberAt is therefore exactly "the leaf that signs", and MG-1's
	// obligation -- that a joiner must decide whether it expected THAT identity -- is the
	// caller's and is not met here.
	xwing, err := messagegroup.XwingGenerateKey(random)
	if err != nil {
		return nil, fmt.Errorf("urmessage: this device's x-wing key: %w", err)
	}
	leafKeys, err := (&mls.LeafKeysExtension{
		AlgId:          mls.AlgIdXwing,
		DeviceXwingPub: xwing.Public().Bytes(),
	}).Encode()
	if err != nil {
		return nil, fmt.Errorf("urmessage: this device's leaf keys extension: %w", err)
	}
	engine, err := messagegroup.NewConnectMlsEngine(crypto, stateStore, signer,
		mls.BasicCredential(signerPub), leafKeys.ExtensionData)
	if err != nil {
		return nil, fmt.Errorf("urmessage: the mls engine: %w", err)
	}
	return &Device{
		transport:   config.Transport,
		reserver:    config.Reserver,
		crypto:      crypto,
		engine:      engine,
		leafKeys:    leafKeys.ExtensionData,
		identityPub: append([]byte(nil), signerPub...),
		nowMs:       nowMs,
		random:      random,
		groups:      map[string]*Group{},
	}, nil
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
