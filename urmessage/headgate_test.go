package urmessage

import (
	"crypto/rand"
	"crypto/sha256"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"
	"time"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/messagegroup"
)

// ── invariant H1, as a gate rather than a paragraph ──────────────────────────────────────────

// keySourceAeadTagBytes' local twin: chacha20poly1305.Overhead, which connect names
// recordAeadTagBytes at messagegroup/recordaead.go:67. It is written here as the number the codec
// derives rather than imported, because the derivation is the point: 9 octets of head plus 16 of
// tag is 25 octets of ct_head, which is what the live table holds on all 3,758 rows.
const headAeadTagBytes = 16

// EVERY RECORD THIS BUILD SEALS CARRIES A 25 OCTET ct_head, ON ALL FOUR RECORD KINDS.
//
// WHAT THIS CATCHES AND WHEN, which is how a gate is judged. It removes "a record whose head is not
// 9 octets" from the set of records this build can produce, and it catches on the SEAL side at TEST
// TIME -- before anything ships, not on receipt and not in production. The complement it removes is
// non-empty and is the whole point: any future head field, any kind-dependent head width, any
// second head layout.
//
// WHY THAT COMPLEMENT MATTERS MORE THAN AN OCTET. ct_body's width is QUANTISED and the server
// ENFORCES the equality -- octet_length(ct_body) = size_bucket_bytes[b] + 16, spec B §5.1 check 3,
// msgrepo/api/submit.go:299-306 -- so a body is length-opaque by construction. ct_head is not: it
// travels as a bare WriteOpaqueLP (connect/message/codec.go:155) bounded only by a 64 KiB cap, so
// it is length-TRANSPARENT by construction. A head whose presence or width depends on what a record
// SAYS therefore leaks that to the server, permanently, on every PERMANENT and DURABLE row already
// stored -- ct_head is erased only for EPH(1..5) -- and no later change un-leaks them. That is the
// one irreversible thing in the 2026-09-17 ruling, and this case is what keeps the door shut by
// RULING rather than by accident.
//
// THE FOUR KINDS ARE THE FOUR SEAL SITES: the founding commit (group.go, Open step 1), the device
// wrap (step 2), the epoch-complete marker (step 3) and the application record
// ([Group.sendContentLocked]). They are sealed here the way those four sites seal them --
// TestTheFourSealSitesAllPassEncodeHead is what holds this case's four against the file's four, so
// that a fifth site, or a site that stopped passing encodeHead, is red rather than uncovered.
//
// keysource_test.go's TestEveryKeyedOctetOfARecordIsReproducibleFromTheExporterAndTheTwoInjectedValuesAlone
// is the assertion shape this follows, one repo over.
func TestEveryRecordThisBuildSealsCarriesA25OctetCtHead(t *testing.T) {
	sealed := sealOneOfEveryRecordKind(t)
	if len(sealed) != 4 {
		t.Fatalf("this case sealed %d record kinds and the build has four", len(sealed))
	}
	for _, one := range sealed {
		if len(one.record.CtHead) != headBytes+headAeadTagBytes {
			t.Errorf("%s: ct_head is %d octets, want %d (%d octets of head plus a %d octet tag)",
				one.name, len(one.record.CtHead), headBytes+headAeadTagBytes, headBytes, headAeadTagBytes)
		}
		t.Logf("%s: ct_head %d octets, ct_body %d octets, class %d",
			one.name, len(one.record.CtHead), len(one.record.CtBody), one.record.Header.RetentionClass)
	}
	// AND THE WIDTH IS THE ONE THE CODEC DERIVES, not a constant this file chose. A headBytes
	// that moved with this number moved with it would be two copies of one mistake.
	if headBytes != 1+8 {
		t.Errorf("headBytes is %d; the head is version ‖ sent_at and is frozen at 9 octets", headBytes)
	}
	if headVersion != 0x02 {
		t.Errorf("headVersion is 0x%02x; the content envelope announces itself as 0x02", headVersion)
	}
}

// THE FOUR SEAL SITES ALL PASS encodeHead, AND THERE ARE FOUR OF THEM.
//
// The case above seals its own four records, which makes it a statement about encodeHead's width
// and not yet a statement about the FILE. This is the other half: every SealRecord call in
// group.go hands encodeHead's answer as its head argument, and there are exactly four. A fifth site
// -- or one that built a head some other way -- would leave the case above green over a build that
// seals a head it never measured.
func TestTheFourSealSitesAllPassEncodeHead(t *testing.T) {
	path := filepath.Join("group.go")
	fileSet := token.NewFileSet()
	syntax, err := parser.ParseFile(fileSet, path, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	sites := []string{}
	ast.Inspect(syntax, func(node ast.Node) bool {
		call, isCall := node.(*ast.CallExpr)
		if !isCall {
			return true
		}
		selector, isSelector := call.Fun.(*ast.SelectorExpr)
		if !isSelector || selector.Sel.Name != "SealRecord" {
			return true
		}
		where := fileSet.Position(call.Pos()).String()
		sites = append(sites, where)
		if len(call.Args) != 7 {
			t.Errorf("%s: SealRecord takes 7 arguments and this call passes %d", where, len(call.Args))
			return true
		}
		head, isCall := call.Args[3].(*ast.CallExpr)
		if !isCall {
			t.Errorf("%s: the head argument is not a call, so it is not encodeHead's answer", where)
			return true
		}
		name, isName := head.Fun.(*ast.Ident)
		if !isName || name.Name != "encodeHead" {
			t.Errorf("%s: the head argument is not encodeHead(...), so this record's head is built somewhere this suite does not measure", where)
		}
		return true
	})
	if len(sites) != 4 {
		t.Errorf("group.go holds %d SealRecord call(s) and the build has four record kinds: %v", len(sites), sites)
	}
	t.Logf("the four seal sites: %v", sites)
}

// ── one of every record kind, sealed the way the build seals it ──────────────────────────────

type sealedKind struct {
	name   string
	record *message.Record
}

// sealOneOfEveryRecordKind founds a group the way [Device.CreateGroup], [Group.AddMember] and
// [Group.Open] found one, and seals one record of each of the four kinds through the same sessions
// at the same classes.
//
// IT DOES NOT GO THROUGH [Group.Open] and it cannot: Open submits, and a submit needs a server,
// which is what the cp3b module is for. What it needs from Open is the SEAL ARGUMENTS, and those
// are held against the file by TestTheFourSealSitesAllPassEncodeHead.
func sealOneOfEveryRecordKind(t *testing.T) []sealedKind {
	t.Helper()
	alice := openCrossProcessDevice(t, filepath.Join(t.TempDir(), "alice"))
	defer alice.close()
	bob := openCrossProcessDevice(t, filepath.Join(t.TempDir(), "bob"))
	defer bob.close()

	groupId := make([]byte, GroupIdBytes)
	if _, err := rand.Read(groupId); err != nil {
		t.Fatalf("drawing a group id: %v", err)
	}
	handle := alice.createGroup(t, groupId)
	defer handle.Close()

	mlsSecret, err := handle.Export(storageExporterLabel, nil, storageExporterBytes)
	if err != nil {
		t.Fatalf("the epoch zero exporter: %v", err)
	}
	pqSecret, err := messagegroup.NewPqSecret(rand.Reader)
	if err != nil {
		t.Fatalf("pq_secret: %v", err)
	}
	groupHandleKey := messagegroup.GroupHandleKey(messagegroup.StorageRoot(mlsSecret, pqSecret))

	// THE FOUNDING SESSION IS BUILT BEFORE THE COMMIT MOVES THE HANDLE, which is
	// [Device.CreateGroup]'s own order and is load-bearing: a session installs its epoch's whole
	// key schedule at construction, so this one goes on sealing epoch ZERO records after the
	// handle has moved to epoch one. That is what §4.3.2's self-certified founding commit needs.
	founding := newCrossProcessSession(t, handle, pqSecret, nil, alice.reserver, "a founding nonce")
	defer founding.Close()

	keyPackage, err := bob.engine.NewKeyPackage()
	if err != nil {
		t.Fatalf("bob's key package: %v", err)
	}
	if _, err := handle.ProposeAdd(keyPackage); err != nil {
		t.Fatalf("ProposeAdd: %v", err)
	}
	commit, _, _, err := handle.Commit(nil)
	if err != nil {
		handle.ClearPendingCommit()
		t.Fatalf("Commit: %v", err)
	}
	if err := handle.MergePendingCommit(); err != nil {
		t.Fatalf("MergePendingCommit: %v", err)
	}
	epoch := handle.Epoch()
	session := newCrossProcessSession(t, handle, pqSecret, groupHandleKey, alice.reserver, "an epoch one nonce")
	defer session.Close()

	keys, err := session.EpochKeys()
	if err != nil {
		t.Fatalf("this epoch's keys: %v", err)
	}
	defer keys.Destroy()
	writeKey, err := keys.WriteKey()
	if err != nil {
		t.Fatalf("write_key: %v", err)
	}
	readKey, err := keys.ReadKey()
	if err != nil {
		t.Fatalf("read_key: %v", err)
	}
	groupContext, err := handle.GroupContextBytes()
	if err != nil {
		t.Fatalf("the group context: %v", err)
	}
	contextHash := sha256.Sum256(groupContext)
	wrapTarget := messagegroup.WrapTargetHandle(groupHandleKey, epoch, 0)

	nowMs := time.Now().UnixMilli()
	sealed := []sealedKind{}

	// (1) the founding commit, at epoch zero, PERMANENT, is_commit.
	commitRecord, err := founding.SealRecord(message.RetentionPermanent, 0, true,
		encodeHead(nowMs), commit, 0, &message.ServerAttachment{
			Kind: message.AttachmentEpoch,
			Epoch: &message.EpochAttachment{
				Epoch:             epoch,
				AlgId:             epochAttachmentAlgId,
				WriteKey:          writeKey,
				ReadKey:           readKey,
				GroupContextHash:  contextHash[:],
				ExpectedWrapCount: 2,
			},
		})
	if err != nil {
		t.Fatalf("sealing the founding commit: %v", err)
	}
	sealed = append(sealed, sealedKind{"the founding commit", commitRecord})

	// (2) one device wrap, PERMANENT, carrying no key material.
	wrap, err := session.SealRecord(message.RetentionPermanent, 0, false,
		encodeHead(nowMs), []byte(alphaWrapBody), 0, &message.ServerAttachment{
			Kind: message.AttachmentWrap,
			Wrap: &message.WrapTag{WrapTargetHandle: append([]byte(nil), wrapTarget[:]...), Epoch: epoch},
		})
	if err != nil {
		t.Fatalf("sealing an epoch wrap: %v", err)
	}
	sealed = append(sealed, sealedKind{"an epoch wrap", wrap})

	// (3) the marker that closes the fan-out, DURABLE.
	marker, err := session.SealRecord(message.RetentionDurable, 0, false,
		encodeHead(nowMs), []byte(alphaEpochCompleteBody), 0, &message.ServerAttachment{
			Kind:     message.AttachmentComplete,
			Complete: &message.EpochComplete{Epoch: epoch, WrapCount: 2},
		})
	if err != nil {
		t.Fatalf("sealing the epoch complete marker: %v", err)
	}
	sealed = append(sealed, sealedKind{"the epoch complete marker", marker})

	// (4) an application record: DURABLE, no attachment, and a CONTENT ENVELOPE as its body,
	// which is the one of the four the 2026-09-17 ruling changed.
	plaintext, err := encodeText("a line, inside a content envelope")
	if err != nil {
		t.Fatalf("encodeText: %v", err)
	}
	application, err := session.SealRecord(message.RetentionDurable, 0, false,
		encodeHead(nowMs), plaintext, 0, nil)
	if err != nil {
		t.Fatalf("sealing an application record: %v", err)
	}
	sealed = append(sealed, sealedKind{"an application record", application})

	return sealed
}
