//go:build !js && !ios_extension

package wire

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strconv"
)

// The relay's calls and its one push (relay-server-rpc).
const (
	MethodPublish      = "irn_publish"
	MethodSubscribe    = "irn_subscribe"
	MethodUnsubscribe  = "irn_unsubscribe"
	MethodSubscription = "irn_subscription"
)

const jsonRpcVersion = "2.0"

// NewRelayId is the id of a call to the relay: the time in milliseconds
// followed by six digits from rand, 19 digits in all (relay-server-rpc: a "19
// digit unique identifier"). It does not fit a float64, which is why an id is
// an int64 here and raw JSON in a Frame.
//
// The digits only keep ids apart, they protect nothing: a source that fails
// gives six zeros. Two ids of one millisecond can be equal, so whoever
// matches answers by id keeps its pending ids distinct.
func NewRelayId(nowMillis int64, rand io.Reader) int64 {
	return nowMillis*1_000_000 + entropy(rand, 1_000_000)
}

// NewPeerId is the id of a message to the wallet: the time in milliseconds
// followed by three digits from rand, 16 digits in all. That stays below
// 2^53, so a peer written in JavaScript, which reads every number as a
// double, reads it exactly. What NewRelayId says about equal ids holds here
// with three digits.
func NewPeerId(nowMillis int64, rand io.Reader) int64 {
	return nowMillis*1_000 + entropy(rand, 1_000)
}

// entropy is a number in [0, n) from eight bytes of rand, or 0 when rand
// gives none.
func entropy(rand io.Reader, n uint64) int64 {
	if rand == nil {
		return 0
	}
	var b [8]byte
	if _, err := io.ReadFull(rand, b[:]); err != nil {
		return 0
	}
	return int64(binary.BigEndian.Uint64(b[:]) % n)
}

// RpcError is the error member of a response.
//
// It is written as it is declared and read whatever its shape, so that an
// error a peer wrote badly is still an error: it ends the wait for the answer
// at once, where a frame that cannot be read is passed over and the wait
// runs to its deadline.
//
//   - Code may be a number whose value is an integer (5000, 5000.0, 5e3) or
//     a string holding an integer ("5000"). One that is missing, is anything
//     else or does not fit 32 bits is RpcCodeMalformed. The 32 bits are for
//     every target, so that a frame reads the same on all of them.
//   - Message may be any JSON value. One that is not a string is kept as its
//     JSON text, null as "null"; a missing one is empty.
//   - An error that is no object, a bare string or a number, has no member
//     to read: its code is RpcCodeMalformed and it has no message.
//
// An error member that is null is no error.
type RpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// RpcCodeMalformed is the Code of an error that was read with no code of its
// own that can be used. No specification this client follows assigns it: the
// codes of the Sign protocol are positive and JSON-RPC's own are -32768 to
// -32000. It is not 0, which a caller may keep for no code at all. A peer
// that sends -1 itself is not told apart.
const RpcCodeMalformed = -1

// UnmarshalJSON reads an error as the comment on RpcError says. It does not
// fail.
func (e *RpcError) UnmarshalJSON(text []byte) error {
	if string(text) == "null" {
		return nil
	}
	var members struct {
		Code    json.RawMessage `json:"code"`
		Message json.RawMessage `json:"message"`
	}
	// what is no object leaves both members empty
	_ = json.Unmarshal(text, &members)
	*e = RpcError{Code: rpcCode(members.Code), Message: string(members.Message)}
	if len(members.Message) > 0 && members.Message[0] == '"' {
		_ = json.Unmarshal(members.Message, &e.Message)
	}
	return nil
}

// rpcCode is the code that raw, the JSON of a code member (empty for a
// missing one), stands for.
func rpcCode(raw json.RawMessage) int {
	if len(raw) > 0 && raw[0] == '"' {
		var held string
		_ = json.Unmarshal(raw, &held)
		if code, err := strconv.ParseInt(held, 10, 32); err == nil {
			return int(code)
		}
		return RpcCodeMalformed
	}
	// an integer of 32 bits is exact as a float64. What is no number fails
	// here, and so does one too large to be finite.
	number, err := strconv.ParseFloat(string(raw), 64)
	if err != nil || number != math.Trunc(number) || number < math.MinInt32 || number > math.MaxInt32 {
		return RpcCodeMalformed
	}
	return int(number)
}

// Frame is any JSON-RPC object as it is read: a call or a push of the relay,
// or a message of the wallet out of its envelope.
//
// Id is the id exactly as it arrived. An acknowledgement must carry it back
// digit for digit, and the relay's ids are too long for a float64, so it is
// never turned into a number here.
//
// Result is nil when the frame has no result member and "null" when it has
// one that is null.
type Frame struct {
	Id      json.RawMessage `json:"id"`
	Jsonrpc string          `json:"jsonrpc"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *RpcError       `json:"error,omitempty"`
}

// ParseFrame reads one JSON-RPC object. Text that is not one JSON object, or
// whose jsonrpc or method member is of another type than a Frame's, is an
// error; the error says nothing of the text. The error member is read as
// RpcError says, whatever it is.
func ParseFrame(text []byte) (*Frame, error) {
	// the decoder takes "null" for a struct without complaint, so the
	// object is asked for here
	if start := bytes.TrimLeft(text, " \t\r\n"); len(start) == 0 || start[0] != '{' {
		return nil, errors.New("walletconnect: not a json-rpc object")
	}
	frame := &Frame{}
	if err := json.Unmarshal(text, frame); err != nil {
		return nil, errors.New("walletconnect: not a json-rpc object")
	}
	return frame, nil
}

// IsRequest reports whether the frame has a method: a request or a push, not
// a response.
func (f *Frame) IsRequest() bool {
	return f != nil && f.Method != ""
}

// IdToken is an id as a Frame holds it.
func IdToken(id int64) json.RawMessage {
	return strconv.AppendInt(nil, id, 10)
}

type requestFrame struct {
	Id      int64  `json:"id"`
	Jsonrpc string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  any    `json:"params"`
}

type resultFrame struct {
	Id      json.RawMessage `json:"id"`
	Jsonrpc string          `json:"jsonrpc"`
	Result  any             `json:"result"`
}

type errorFrame struct {
	Id      json.RawMessage `json:"id"`
	Jsonrpc string          `json:"jsonrpc"`
	Error   RpcError        `json:"error"`
}

// RequestFrame is {"id":..,"jsonrpc":"2.0","method":..,"params":..}. Like the
// two functions below it gives nil for a value MarshalCompact cannot write.
func RequestFrame(id int64, method string, params any) []byte {
	return MarshalCompact(requestFrame{
		Id:      id,
		Jsonrpc: jsonRpcVersion,
		Method:  method,
		Params:  params,
	})
}

// ResultFrame is {"id":..,"jsonrpc":"2.0","result":..}. The id is written as
// it is given, which for the answer to a frame that was read is as it
// arrived.
func ResultFrame(id json.RawMessage, result any) []byte {
	return MarshalCompact(resultFrame{
		Id:      echoId(id),
		Jsonrpc: jsonRpcVersion,
		Result:  result,
	})
}

// ErrorFrame is {"id":..,"jsonrpc":"2.0","error":{"code":..,"message":..}}.
func ErrorFrame(id json.RawMessage, code int, message string) []byte {
	return MarshalCompact(errorFrame{
		Id:      echoId(id),
		Jsonrpc: jsonRpcVersion,
		Error:   RpcError{Code: code, Message: message},
	})
}

// a frame that arrived with no id is answered with null, as JSON-RPC has it
func echoId(id json.RawMessage) json.RawMessage {
	if len(id) == 0 {
		return json.RawMessage("null")
	}
	return id
}

// PublishParams are the params of irn_publish. Ttl is in seconds; the relay
// keeps the message that long for a recipient that is away.
type PublishParams struct {
	Topic   string `json:"topic"`
	Message string `json:"message"`
	Ttl     int    `json:"ttl"`
	Tag     int    `json:"tag"`
}

// SubscribeParams are the params of irn_subscribe. Its result is the
// subscription id, a string.
type SubscribeParams struct {
	Topic string `json:"topic"`
}

// UnsubscribeParams are the params of irn_unsubscribe.
type UnsubscribeParams struct {
	Topic string `json:"topic"`
	Id    string `json:"id"`
}

// SubscriptionData is one message as the relay pushes it.
type SubscriptionData struct {
	Topic       string `json:"topic"`
	Message     string `json:"message"`
	PublishedAt int64  `json:"publishedAt"`
	Tag         int    `json:"tag"`
}

// SubscriptionParams are the params of irn_subscription. Id is the
// subscription id; the id to acknowledge is the frame's.
type SubscriptionParams struct {
	Id   string           `json:"id"`
	Data SubscriptionData `json:"data"`
}
