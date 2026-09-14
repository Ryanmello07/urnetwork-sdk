package urmessage

import (
	"encoding/binary"
	"fmt"

	"github.com/urnetwork/connect/message"
	"github.com/urnetwork/connect/protocol"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// ── §4.3.3's projection, as a client populates it ────────────────────────────────────────────

// projectionOf is the §4.3.3 projection of one sealed record: the header fields the server indexes
// on, beside the `record_bytes` they are a projection OF.
//
// It is built from the PARSE and never from the values this package passed to the sealer, because
// §5.1 check 3 compares the two and a check whose two sides come from one expression is a check
// that cannot fail. The join of the retention class and the eph bucket is
// [message.RetentionClassWire] and is not restated here: §12.1 A-1 is written against a second
// copy of that table.
func projectionOf(record *message.Record) (*protocol.Record, error) {
	header := &record.Header
	attachment, err := message.ParseServerAttachment(header.ServerAttachment)
	if err != nil {
		return nil, err
	}
	retentionWire, err := message.RetentionClassWire(header.RetentionClass, header.EphBucket)
	if err != nil {
		return nil, err
	}
	recordBytes, err := message.EncodeRecord(record)
	if err != nil {
		return nil, err
	}
	projection := &protocol.Record{
		SenderHandle:   append([]byte{}, header.SenderHandle[:]...),
		Epoch:          header.Epoch,
		StreamIndex:    header.StreamIndex,
		IsCommit:       header.IsCommit,
		RetentionClass: uint32(retentionWire),
		SizeBucket:     uint32(header.SizeBucket),
		ExpireAtMs:     header.ExpireAt,
		BodyHash:       append([]byte{}, header.BodyHash[:]...),
		BlobId:         append([]byte{}, header.BlobId...),
		RecordBytes:    recordBytes,
	}
	if attachment != nil && attachment.Wrap != nil {
		projection.WrapTargetHandle = append([]byte{}, attachment.Wrap.WrapTargetHandle...)
	}
	if attachment != nil && attachment.Recovery != nil {
		projection.RecoveryHandle = append([]byte{}, attachment.Recovery.RecoveryHandle...)
	}
	return projection, nil
}

// ── §4.3.8's req_auth, which the read path is authorized by ──────────────────────────────────

// authorizeFetch computes §4.3.8's `req_auth` over the request's own canonical bytes, under the
// read key of the epoch the request names, over this connection's nonce.
//
// The request is mutated in place and authorized LAST, which is the ordering the authenticator
// forces: it covers the deterministic marshal of the body with `req_auth` itself cleared, so a
// caller that filled the field and then changed another one would be sending a MAC over a request
// it did not send.
func authorizeFetch(request *protocol.FetchRequest, readKey []byte, serverNonce []byte) error {
	if len(readKey) == 0 {
		return fmt.Errorf("%w: a fetch is macced under the epoch's read key", ErrFetchRefused)
	}
	if len(serverNonce) == 0 {
		return ErrNotConnected
	}
	op, err := opOf(request)
	if err != nil {
		return err
	}
	request.ReqAuth = nil
	canonical, err := proto.MarshalOptions{Deterministic: true}.Marshal(request)
	if err != nil {
		return err
	}
	auth := message.ComputeRequestAuth(readKey, serverNonce, op, canonical)
	request.ReqAuth = auth[:]
	return nil
}

// opOf is §4.3.8's `op`: the field number of the arm of `MessageServerRequest.body` that carries
// this type, read out of the compiled descriptor rather than written down.
//
// A switch over the typed wrappers is where a copy-paste puts a fetch under the submit op, and the
// MAC then covers an operation nobody asked for.
func opOf(body proto.Message) (uint8, error) {
	field, err := armOf(body)
	if err != nil {
		return 0, err
	}
	if number := field.Number(); number < 0 || 255 < number {
		return 0, fmt.Errorf("urmessage: %s is arm %d, which is not a u8",
			body.ProtoReflect().Descriptor().FullName(), field.Number())
	}
	return uint8(field.Number()), nil
}

func armOf(body proto.Message) (protoreflect.FieldDescriptor, error) {
	oneof := (&protocol.MessageServerRequest{}).ProtoReflect().Descriptor().Oneofs().ByName("body")
	if oneof == nil {
		return nil, fmt.Errorf("urmessage: MessageServerRequest declares no body oneof")
	}
	want := body.ProtoReflect().Descriptor().FullName()
	for index := 0; index < oneof.Fields().Len(); index += 1 {
		field := oneof.Fields().Get(index)
		if field.Kind() != protoreflect.MessageKind || field.Message().FullName() != want {
			continue
		}
		return field, nil
	}
	return nil, fmt.Errorf("urmessage: no arm of MessageServerRequest.body carries %s", want)
}

// ── the head this build writes ───────────────────────────────────────────────────────────────

// The version byte every head this package seals starts with. It is INSIDE `ct_head`, so the
// server never sees it and it costs nothing on the wire that is readable by anyone but a member.
//
// It exists so that the day this package puts a second field in the head -- a reply-to, a content
// type -- a record written by the older build is refused with a sentence rather than parsed as
// something it is not.
const headVersion byte = 0x01

// headBytes is the octets a head of this version is: the version, then `sent_at` as unix
// milliseconds, big endian.
const headBytes = 1 + 8

// encodeHead builds one record's head from the clock reading its sender took.
func encodeHead(sentAtMs int64) []byte {
	head := make([]byte, headBytes)
	head[0] = headVersion
	binary.BigEndian.PutUint64(head[1:], uint64(sentAtMs))
	return head
}

// decodeHead reads back what encodeHead wrote, and refuses anything else.
//
// Every octet it reads was authenticated by the head AEAD before this function sees it, so a
// refusal here means the two builds disagree rather than that somebody tampered.
func decodeHead(head []byte) (int64, error) {
	if len(head) != headBytes {
		return 0, fmt.Errorf("%w: %d octets, want %d", ErrHeadFormat, len(head), headBytes)
	}
	if head[0] != headVersion {
		return 0, fmt.Errorf("%w: version %#02x, want %#02x", ErrHeadFormat, head[0], headVersion)
	}
	return int64(binary.BigEndian.Uint64(head[1:])), nil
}
