//go:build !js && !ios_extension

package wire

// Ids, frames and Sign messages, byte for byte. The proposal and the request
// are the strings ur.io's JavaScript client produces for the same inputs; the
// relay frames are frames the relay sent. See vectors_test.go for where the
// other fixed values come from.

import (
	"bytes"
	cryptorand "crypto/rand"
	"encoding/json"
	"io"
	"math"
	"strconv"
	"strings"
	"testing"
)

const (
	proposalId = int64(1759900000000123)
	requestId  = int64(1759900000000456)
	deleteId   = int64(1759900000000789)

	// as ur.io's JavaScript client serialises them
	proposeJson = `{"id":1759900000000123,"jsonrpc":"2.0","method":"wc_sessionPropose","params":{"relays":[{"protocol":"irn"}],"proposer":{"publicKey":"8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a","metadata":{"name":"URnetwork","description":"URnetwork","url":"https://ur.io","icons":["https://ur.io/favicon.ico"]}},"requiredNamespaces":{"polkadot":{"chains":["polkadot:2f0555cc76fc2840a25a6ea3b9637146"],"methods":["polkadot_signMessage"],"events":[]}},"optionalNamespaces":{}}}`
	requestJson = `{"id":1759900000000456,"jsonrpc":"2.0","method":"wc_sessionRequest","params":{"request":{"method":"polkadot_signMessage","params":{"address":"5F3sa2TJAWMqDhXG6jhV4N8ko9SxwGy8TpaNS1repo5EYjQX","message":"Sign in to URnetwork\nChallenge: abc\nTimestamp: 1700000000"}},"chainId":"polkadot:2f0555cc76fc2840a25a6ea3b9637146"}}`
	deleteJson  = `{"id":1759900000000789,"jsonrpc":"2.0","method":"wc_sessionDelete","params":{"code":6000,"message":"User disconnected."}}`

	// the same two messages in the layout of the porting notes
	proposeLayout = `{"id":1759900000000123,"jsonrpc":"2.0","method":"wc_sessionPropose","params":{
  "relays":[{"protocol":"irn"}],
  "proposer":{"publicKey":"8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
              "metadata":{"name":"URnetwork","description":"URnetwork","url":"https://ur.io","icons":["https://ur.io/favicon.ico"]}},
  "requiredNamespaces":{"polkadot":{"chains":["polkadot:2f0555cc76fc2840a25a6ea3b9637146"],"methods":["polkadot_signMessage"],"events":[]}},
  "optionalNamespaces":{}}}`
	requestLayout = `{"id":1759900000000456,"jsonrpc":"2.0","method":"wc_sessionRequest","params":{
  "request":{"method":"polkadot_signMessage","params":{"address":"5F3sa2TJAWMqDhXG6jhV4N8ko9SxwGy8TpaNS1repo5EYjQX","message":"Sign in to URnetwork\nChallenge: abc\nTimestamp: 1700000000"}},
  "chainId":"polkadot:2f0555cc76fc2840a25a6ea3b9637146"}}`

	challengeMessage = "Sign in to URnetwork\nChallenge: abc\nTimestamp: 1700000000"

	// a subscription id the relay returned
	subscriptionId = "8eb729a33e623236df2199d7b297e1a737d00f7c14c71f9246e96c5ac135b04e"
)

func urnetworkMetadata() Metadata {
	return Metadata{
		Name:        "URnetwork",
		Description: "URnetwork",
		Url:         "https://ur.io",
		Icons:       []string{"https://ur.io/favicon.ico"},
	}
}

func compactJson(t *testing.T, text string) string {
	t.Helper()
	var buffer bytes.Buffer
	if err := json.Compact(&buffer, []byte(text)); err != nil {
		t.Fatalf("bad json fixture: %v", err)
	}
	return buffer.String()
}

func TestTV7IdsAndFrames(t *testing.T) {
	const nowMillis = int64(1759900000000)

	t.Run("relay ids print as 19 digits and peer ids as 16", func(t *testing.T) {
		// eight bytes of the source, big endian, modulo the entropy range
		for _, v := range []struct {
			entropy string
			relayId int64
			peerId  int64
		}{
			{"0000000000000000", 1759900000000000000, 1759900000000000},
			{"ffffffffffffffff", 1759900000000551615, 1759900000000615},
			{"0102030405060708", 1759900000000382856, 1759900000000856},
		} {
			relayId := NewRelayId(nowMillis, bytes.NewReader(mustHex(t, v.entropy)))
			if relayId != v.relayId {
				t.Errorf("NewRelayId with %s: got %d, want %d", v.entropy, relayId, v.relayId)
			}
			digits := strconv.FormatInt(relayId, 10)
			if len(digits) != 19 {
				t.Errorf("NewRelayId with %s: %s has %d digits, want 19", v.entropy, digits, len(digits))
			}
			if got := string(IdToken(relayId)); got != digits {
				t.Errorf("IdToken: got %s, want %s", got, digits)
			}
			// a json number with every digit and no exponent
			if got := string(MarshalCompact(relayId)); got != digits {
				t.Errorf("MarshalCompact of a relay id: got %s, want %s", got, digits)
			}

			peerId := NewPeerId(nowMillis, bytes.NewReader(mustHex(t, v.entropy)))
			if peerId != v.peerId {
				t.Errorf("NewPeerId with %s: got %d, want %d", v.entropy, peerId, v.peerId)
			}
			digits = strconv.FormatInt(peerId, 10)
			if len(digits) != 16 {
				t.Errorf("NewPeerId with %s: %s has %d digits, want 16", v.entropy, digits, len(digits))
			}
			if got := string(IdToken(peerId)); got != digits {
				t.Errorf("IdToken: got %s, want %s", got, digits)
			}
			// a peer written in JavaScript reads it as a double: below 2^53
			if peerId >= 1<<53 {
				t.Errorf("NewPeerId with %s: %d is not below 2^53", v.entropy, peerId)
			}
		}

		relayIds := map[int64]bool{}
		peerIds := map[int64]bool{}
		for range 2000 {
			relayId := NewRelayId(nowMillis, cryptorand.Reader)
			if relayId < nowMillis*1_000_000 || relayId >= (nowMillis+1)*1_000_000 {
				t.Fatalf("NewRelayId: %d is outside its millisecond", relayId)
			}
			relayIds[relayId] = true
			peerId := NewPeerId(nowMillis, cryptorand.Reader)
			if peerId < nowMillis*1_000 || peerId >= (nowMillis+1)*1_000 {
				t.Fatalf("NewPeerId: %d is outside its millisecond", peerId)
			}
			peerIds[peerId] = true
		}
		if len(relayIds) < 1900 || len(peerIds) < 500 {
			t.Errorf("the entropy is not used: %d relay ids and %d peer ids out of 2000", len(relayIds), len(peerIds))
		}

		// a source that fails gives the bare timestamp, never a panic
		for name, reader := range map[string]io.Reader{
			"failing": failingReader{},
			"short":   bytes.NewReader([]byte{1, 2, 3}),
			"nil":     nil,
		} {
			if got := NewRelayId(nowMillis, reader); got != nowMillis*1_000_000 {
				t.Errorf("NewRelayId with a %s reader: got %d", name, got)
			}
			if got := NewPeerId(nowMillis, reader); got != nowMillis*1_000 {
				t.Errorf("NewPeerId with a %s reader: got %d", name, got)
			}
		}
	})

	t.Run("an id is echoed digit for digit", func(t *testing.T) {
		for _, id := range []string{
			"1791419882856123457", // 19 digits: a double would end in ...392
			"458603517300150",     // 15 digits, as the relay numbers its pushes
			"1791419989330610360",
			"9223372036854775807",
			"99999999999999999999999", // more than 64 bits
			"0",
			"-7",
			"1.0e3",
			`"an-id"`,
			`"<&>"`,
			"null",
		} {
			frame, err := ParseFrame([]byte(`{"id":` + id + `,"jsonrpc":"2.0","method":"irn_subscription","params":{}}`))
			if err != nil {
				t.Errorf("ParseFrame id %s: %v", id, err)
				continue
			}
			if string(frame.Id) != id {
				t.Errorf("ParseFrame id %s: kept as %s", id, frame.Id)
			}
			if got, want := string(ResultFrame(frame.Id, true)), `{"id":`+id+`,"jsonrpc":"2.0","result":true}`; got != want {
				t.Errorf("ResultFrame:\n got %s\nwant %s", got, want)
			}
			if got, want := string(ErrorFrame(frame.Id, 5000, "User rejected.")), `{"id":`+id+`,"jsonrpc":"2.0","error":{"code":5000,"message":"User rejected."}}`; got != want {
				t.Errorf("ErrorFrame:\n got %s\nwant %s", got, want)
			}
		}

		// surrounding white space is not part of the id
		frame, err := ParseFrame([]byte("{ \"id\" :\t1791419882856123457 ,\n\"jsonrpc\" : \"2.0\" , \"result\" : true }"))
		if err != nil {
			t.Fatalf("ParseFrame: %v", err)
		}
		if string(frame.Id) != "1791419882856123457" {
			t.Errorf("ParseFrame: id kept as %q", frame.Id)
		}

		// a frame with no id is answered with null
		frame, err = ParseFrame([]byte(`{"jsonrpc":"2.0","method":"irn_subscription","params":{}}`))
		if err != nil {
			t.Fatalf("ParseFrame without an id: %v", err)
		}
		if got := string(ResultFrame(frame.Id, true)); got != `{"id":null,"jsonrpc":"2.0","result":true}` {
			t.Errorf("ResultFrame without an id: got %s", got)
		}
		if got := string(ResultFrame(json.RawMessage{}, true)); got != `{"id":null,"jsonrpc":"2.0","result":true}` {
			t.Errorf("ResultFrame with an empty id: got %s", got)
		}
	})

	t.Run("frames as the relay sends them", func(t *testing.T) {
		// the result of irn_subscribe
		frame, err := ParseFrame([]byte(`{"id":1791419989033865469,"jsonrpc":"2.0","result":"` + subscriptionId + `"}`))
		if err != nil {
			t.Fatalf("ParseFrame: %v", err)
		}
		if frame.IsRequest() || frame.Error != nil || frame.Method != "" || frame.Params != nil {
			t.Errorf("a result is not a request and has no error: %+v", frame)
		}
		if frame.Jsonrpc != "2.0" || string(frame.Id) != "1791419989033865469" {
			t.Errorf("frame: %s %s", frame.Jsonrpc, frame.Id)
		}
		var result string
		if err := json.Unmarshal(frame.Result, &result); err != nil || result != subscriptionId {
			t.Errorf("result: got %q, %v", result, err)
		}

		// a push
		frame, err = ParseFrame([]byte(`{"id":458603517300150,"jsonrpc":"2.0","method":"irn_subscription","params":{"id":"` + subscriptionId + `","data":{"topic":"` + sessionTopic + `","message":"` + envelope + `","publishedAt":1791419989,"tag":1100,"attestation":"ignored"}}}`))
		if err != nil {
			t.Fatalf("ParseFrame: %v", err)
		}
		if !frame.IsRequest() || frame.Method != MethodSubscription || frame.Result != nil || frame.Error != nil {
			t.Errorf("a push is a request: %+v", frame)
		}
		var push SubscriptionParams
		if err := json.Unmarshal(frame.Params, &push); err != nil {
			t.Fatalf("push params: %v", err)
		}
		want := SubscriptionParams{
			Id: subscriptionId,
			Data: SubscriptionData{
				Topic:       sessionTopic,
				Message:     envelope,
				PublishedAt: 1791419989,
				Tag:         1100,
			},
		}
		if push != want {
			t.Errorf("push: got %+v, want %+v", push, want)
		}
		if got := string(ResultFrame(frame.Id, true)); got != `{"id":458603517300150,"jsonrpc":"2.0","result":true}` {
			t.Errorf("acknowledgement: got %s", got)
		}

		// the acknowledgement of a publish
		frame, err = ParseFrame([]byte(`{"id":1791419989330610360,"jsonrpc":"2.0","result":true}`))
		if err != nil {
			t.Fatalf("ParseFrame: %v", err)
		}
		if frame.IsRequest() || string(frame.Result) != "true" {
			t.Errorf("acknowledgement: %+v", frame)
		}

		// an error
		frame, err = ParseFrame([]byte(`{"id":1791419989330610360,"jsonrpc":"2.0","error":{"code":-32000,"message":"Message: TtlTooShort","data":"TtlTooShort"}}`))
		if err != nil {
			t.Fatalf("ParseFrame: %v", err)
		}
		if frame.IsRequest() || frame.Result != nil || frame.Error == nil {
			t.Fatalf("error frame: %+v", frame)
		}
		if *frame.Error != (RpcError{Code: -32000, Message: "Message: TtlTooShort"}) {
			t.Errorf("error: got %+v", *frame.Error)
		}

		// result null is a result, not an absent one
		frame, err = ParseFrame([]byte(`{"id":1,"jsonrpc":"2.0","result":null,"error":null}`))
		if err != nil {
			t.Fatalf("ParseFrame: %v", err)
		}
		if string(frame.Result) != "null" || frame.Error != nil {
			t.Errorf("result null: %+v", frame)
		}
	})

	t.Run("a peer message out of its envelope", func(t *testing.T) {
		plaintext, err := Open(mustKey(t, envelopeSymKey), envelope)
		if err != nil {
			t.Fatalf("Open: %v", err)
		}
		frame, err := ParseFrame(plaintext)
		if err != nil {
			t.Fatalf("ParseFrame: %v", err)
		}
		if !frame.IsRequest() || frame.Method != "wc_sessionPing" || string(frame.Id) != "1" || string(frame.Params) != "{}" {
			t.Errorf("frame: %+v", frame)
		}
	})

	t.Run("what is not a json-rpc object is refused", func(t *testing.T) {
		for _, text := range []string{
			"",
			" ",
			"null",
			"true",
			"7",
			`"text"`,
			"[]",
			`[{"id":1,"jsonrpc":"2.0","result":true}]`,
			"{",
			`{"id":1,"jsonrpc":"2.0","result":true} trailing`,
			`{"id":1,"jsonrpc":"2.0","result":true}{"id":2}`,
			"not json at all, with a secret in it",
			// the method is typed: one of another type fails the frame
			`{"id":1,"jsonrpc":"2.0","method":5}`,
		} {
			frame, err := ParseFrame([]byte(text))
			if err == nil {
				t.Errorf("ParseFrame %q: no error", text)
				continue
			}
			if frame != nil {
				t.Errorf("ParseFrame %q: a frame came back with the error", text)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Errorf("ParseFrame %q: the error repeats the frame: %v", text, err)
			}
		}
	})

	t.Run("an error is read whatever its shape", func(t *testing.T) {
		for _, v := range []struct {
			member  string // the error member of a response
			code    int
			message string
		}{
			{`{"code":5000,"message":"User rejected."}`, 5000, "User rejected."},
			// a number with a fraction or an exponent that is an integer
			{`{"code":5000.0,"message":"m"}`, 5000, "m"},
			{`{"code":5e3,"message":"m"}`, 5000, "m"},
			// a string holding an integer
			{`{"code":"5000","message":"m"}`, 5000, "m"},
			{`{"code":"-32000","message":"m"}`, -32000, "m"},
			// a message that is no string is kept as its json, null too
			{`{"code":5000,"message":7}`, 5000, "7"},
			{`{"code":5000,"message":{"reason":["no"]}}`, 5000, `{"reason":["no"]}`},
			{`{"code":5000,"message":null}`, 5000, "null"},
			{`{"code":5000}`, 5000, ""},
			// white space around a member is not part of it
			{"{ \"code\" :\t\"5000\" ,\n\"message\" : 7 }", 5000, "7"},
			// a code is 32 bits, on every target
			{`{"code":2147483647,"message":"m"}`, math.MaxInt32, "m"},
			{`{"code":-2147483648,"message":"m"}`, math.MinInt32, "m"},
			{`{"code":2147483648,"message":"m"}`, RpcCodeMalformed, "m"},
			{`{"code":-2147483649,"message":"m"}`, RpcCodeMalformed, "m"},
			{`{"code":"2147483648","message":"m"}`, RpcCodeMalformed, "m"},
			// no code that can be used
			{`{"message":"m"}`, RpcCodeMalformed, "m"},
			{`{"code":null,"message":"m"}`, RpcCodeMalformed, "m"},
			{`{"code":true,"message":"m"}`, RpcCodeMalformed, "m"},
			{`{"code":5000.5,"message":"m"}`, RpcCodeMalformed, "m"},
			{`{"code":"5e3","message":"m"}`, RpcCodeMalformed, "m"},
			{`{"code":"","message":"m"}`, RpcCodeMalformed, "m"},
			{`{}`, RpcCodeMalformed, ""},
			// an error that is no object has neither
			{`"a secret text"`, RpcCodeMalformed, ""},
			{`5000`, RpcCodeMalformed, ""},
			{`false`, RpcCodeMalformed, ""},
		} {
			frame, err := ParseFrame([]byte(`{"id":1,"jsonrpc":"2.0","error":` + v.member + `}`))
			if err != nil || frame.Error == nil {
				t.Errorf("ParseFrame with the error %s: %v", v.member, err)
				continue
			}
			if want := (RpcError{Code: v.code, Message: v.message}); *frame.Error != want {
				t.Errorf("the error %s: got %+v, want %+v", v.member, *frame.Error, want)
			}
		}
		if RpcCodeMalformed != -1 {
			t.Errorf("RpcCodeMalformed: got %d, want -1", RpcCodeMalformed)
		}
		// null is no error, also for an RpcError that is decoded by itself
		kept := RpcError{Code: 7, Message: "kept"}
		if err := json.Unmarshal([]byte("null"), &kept); err != nil || kept != (RpcError{Code: 7, Message: "kept"}) {
			t.Errorf("an RpcError decoded from null: got %+v, %v", kept, err)
		}
	})

	t.Run("relay calls", func(t *testing.T) {
		if MethodPublish != "irn_publish" || MethodSubscribe != "irn_subscribe" || MethodUnsubscribe != "irn_unsubscribe" || MethodSubscription != "irn_subscription" {
			t.Errorf("method names: %s %s %s %s", MethodPublish, MethodSubscribe, MethodUnsubscribe, MethodSubscription)
		}
		for _, v := range []struct {
			name  string
			frame []byte
			want  string
		}{
			{"subscribe",
				RequestFrame(1791419989033865469, MethodSubscribe, SubscribeParams{Topic: sessionTopic}),
				`{"id":1791419989033865469,"jsonrpc":"2.0","method":"irn_subscribe","params":{"topic":"` + sessionTopic + `"}}`},
			{"publish",
				RequestFrame(1791419989330610360, MethodPublish, PublishParams{Topic: sessionTopic, Message: envelope, Ttl: TtlFiveMinutes, Tag: TagSessionPropose}),
				`{"id":1791419989330610360,"jsonrpc":"2.0","method":"irn_publish","params":{"topic":"` + sessionTopic + `","message":"` + envelope + `","ttl":300,"tag":1100}}`},
			{"publish with tag 0",
				RequestFrame(1791419989330610360, MethodPublish, PublishParams{Topic: sessionTopic, Message: "m", Ttl: TtlOneDay, Tag: TagUnsupported}),
				`{"id":1791419989330610360,"jsonrpc":"2.0","method":"irn_publish","params":{"topic":"` + sessionTopic + `","message":"m","ttl":86400,"tag":0}}`},
			{"unsubscribe",
				RequestFrame(1791419989330610361, MethodUnsubscribe, UnsubscribeParams{Topic: sessionTopic, Id: subscriptionId}),
				`{"id":1791419989330610361,"jsonrpc":"2.0","method":"irn_unsubscribe","params":{"topic":"` + sessionTopic + `","id":"` + subscriptionId + `"}}`},
			{"push, as a test relay writes it",
				RequestFrame(458603517300150, MethodSubscription, SubscriptionParams{Id: subscriptionId, Data: SubscriptionData{Topic: sessionTopic, Message: "m", PublishedAt: 1791419989, Tag: 1101}}),
				`{"id":458603517300150,"jsonrpc":"2.0","method":"irn_subscription","params":{"id":"` + subscriptionId + `","data":{"topic":"` + sessionTopic + `","message":"m","publishedAt":1791419989,"tag":1101}}}`},
			{"empty params stay an object",
				RequestFrame(1, "wc_sessionPing", struct{}{}),
				`{"id":1,"jsonrpc":"2.0","method":"wc_sessionPing","params":{}}`},
			{"a result that is a string",
				ResultFrame(IdToken(1791419989033865469), subscriptionId),
				`{"id":1791419989033865469,"jsonrpc":"2.0","result":"` + subscriptionId + `"}`},
			{"a result that is an object",
				ResultFrame(IdToken(requestId), json.RawMessage(`{"signature":"0xab"}`)),
				`{"id":1759900000000456,"jsonrpc":"2.0","result":{"signature":"0xab"}}`},
			{"a result that is null",
				ResultFrame(IdToken(requestId), nil),
				`{"id":1759900000000456,"jsonrpc":"2.0","result":null}`},
			{"an error",
				ErrorFrame(IdToken(requestId), 1001, "Unsupported method wc_sessionFoo"),
				`{"id":1759900000000456,"jsonrpc":"2.0","error":{"code":1001,"message":"Unsupported method wc_sessionFoo"}}`},
			{"an error with a negative code and text that html escaping would change",
				ErrorFrame(json.RawMessage(`"x"`), -32000, `a <b> & "c"`),
				`{"id":"x","jsonrpc":"2.0","error":{"code":-32000,"message":"a <b> & \"c\""}}`},
		} {
			if string(v.frame) != v.want {
				t.Errorf("%s:\n got %s\nwant %s", v.name, v.frame, v.want)
			}
		}

		// what cannot be written gives nil, never a broken frame
		if got := RequestFrame(1, MethodPublish, make(chan int)); got != nil {
			t.Errorf("RequestFrame with params that cannot be encoded: got %s", got)
		}
		if got := ResultFrame(IdToken(1), make(chan int)); got != nil {
			t.Errorf("ResultFrame with a result that cannot be encoded: got %s", got)
		}
		if got := ResultFrame(json.RawMessage(`{"id":`), true); got != nil {
			t.Errorf("ResultFrame with an id that is not json: got %s", got)
		}
		if got := ErrorFrame(json.RawMessage(`12 34`), 1, "m"); got != nil {
			t.Errorf("ErrorFrame with an id that is not json: got %s", got)
		}
	})
}

func TestTV8Messages(t *testing.T) {
	t.Run("wc_sessionPropose", func(t *testing.T) {
		if proposeJson != compactJson(t, proposeLayout) {
			t.Fatalf("the two fixtures of the proposal differ")
		}
		got := string(ProposeRequest(proposalId, mustKey(t, rfc7748AlicePublic), urnetworkMetadata(), "polkadot", bittensorChain, bittensorMethod))
		if got != proposeJson {
			t.Fatalf("ProposeRequest:\n got %s\nwant %s", got, proposeJson)
		}
		// empty containers stay containers
		for _, part := range []string{`"events":[]`, `"optionalNamespaces":{}`, `"relays":[{"protocol":"irn"}]`} {
			if !strings.Contains(got, part) {
				t.Errorf("ProposeRequest has no %s", part)
			}
		}
		if strings.Contains(strings.ToLower(got), "redirect") {
			t.Errorf("ProposeRequest mentions a redirect")
		}
		for _, absent := range []string{"expiry", "pairingTopic", "sessionProperties", "verifyUrl", "null"} {
			if strings.Contains(got, absent) {
				t.Errorf("ProposeRequest has %q", absent)
			}
		}

		// metadata with no icon still sends an array
		bare := string(ProposeRequest(proposalId, mustKey(t, rfc7748AlicePublic), Metadata{Name: "n"}, "polkadot", bittensorChain, bittensorMethod))
		if !strings.Contains(bare, `"metadata":{"name":"n","description":"","url":"","icons":[]}`) {
			t.Errorf("ProposeRequest without icons: got %s", bare)
		}
		// and the caller's value is not touched
		metadata := Metadata{Name: "n"}
		_ = ProposeRequest(proposalId, Key{}, metadata, "polkadot", bittensorChain, bittensorMethod)
		if metadata.Icons != nil {
			t.Errorf("ProposeRequest changed its argument")
		}

		// it reads back as a request with that id
		frame, err := ParseFrame([]byte(got))
		if err != nil {
			t.Fatalf("ParseFrame: %v", err)
		}
		if !frame.IsRequest() || frame.Method != "wc_sessionPropose" || string(frame.Id) != "1759900000000123" {
			t.Errorf("frame: %s %s", frame.Method, frame.Id)
		}
	})

	t.Run("the metadata has no redirect", func(t *testing.T) {
		if got := string(MarshalCompact(urnetworkMetadata())); got != `{"name":"URnetwork","description":"URnetwork","url":"https://ur.io","icons":["https://ur.io/favicon.ico"]}` {
			t.Errorf("metadata: got %s", got)
		}
		// what a wallet sends beyond the four fields is dropped on reading
		var metadata Metadata
		if err := json.Unmarshal([]byte(`{"name":"W","description":"d","url":"https://w.example","icons":[],"redirect":{"native":"w://","universal":"https://w.example/wc"},"verifyUrl":"https://v.example"}`), &metadata); err != nil {
			t.Fatalf("metadata: %v", err)
		}
		if got := string(MarshalCompact(metadata)); got != `{"name":"W","description":"d","url":"https://w.example","icons":[]}` {
			t.Errorf("metadata read from a wallet: got %s", got)
		}
	})

	t.Run("wc_sessionRequest", func(t *testing.T) {
		if requestJson != compactJson(t, requestLayout) {
			t.Fatalf("the two fixtures of the request differ")
		}
		got := string(SessionRequest(requestId, bittensorChain, bittensorMethod, bittensorAddress, challengeMessage))
		if got != requestJson {
			t.Fatalf("SessionRequest:\n got %s\nwant %s", got, requestJson)
		}
		if strings.Contains(strings.ToLower(got), "redirect") {
			t.Errorf("SessionRequest mentions a redirect")
		}
		if strings.Contains(got, "expiry") {
			t.Errorf("SessionRequest has an expiry")
		}

		// any text survives the trip, and html escaping is off
		message := "a <b> & \"c\" \\ é \u2028 \x00 end"
		got = string(SessionRequest(requestId, bittensorChain, bittensorMethod, bittensorAddress, message))
		if !strings.Contains(got, `a <b> & \"c\" \\ é`) {
			t.Errorf("SessionRequest escapes more than json needs: %s", got)
		}
		frame, err := ParseFrame([]byte(got))
		if err != nil {
			t.Fatalf("ParseFrame: %v", err)
		}
		var params struct {
			Request struct {
				Method string `json:"method"`
				Params struct {
					Address string `json:"address"`
					Message string `json:"message"`
				} `json:"params"`
			} `json:"request"`
			ChainId string `json:"chainId"`
		}
		if err := json.Unmarshal(frame.Params, &params); err != nil {
			t.Fatalf("params: %v", err)
		}
		if params.Request.Params.Message != message || params.Request.Params.Address != bittensorAddress || params.Request.Method != bittensorMethod || params.ChainId != bittensorChain {
			t.Errorf("params: got %+v", params)
		}
	})

	t.Run("wc_sessionDelete", func(t *testing.T) {
		if got := string(SessionDeleteRequest(deleteId)); got != deleteJson {
			t.Errorf("SessionDeleteRequest:\n got %s\nwant %s", got, deleteJson)
		}
	})

	t.Run("the answer to a proposal", func(t *testing.T) {
		frame, err := ParseFrame([]byte(`{"id":1759900000000123,"jsonrpc":"2.0","result":{"relay":{"protocol":"irn"},"responderPublicKey":"` + rfc7748BobPublic + `"}}`))
		if err != nil {
			t.Fatalf("ParseFrame: %v", err)
		}
		var result ProposeResult
		if err := json.Unmarshal(frame.Result, &result); err != nil {
			t.Fatalf("result: %v", err)
		}
		if result.ResponderPublicKey != rfc7748BobPublic {
			t.Errorf("responderPublicKey: got %s", result.ResponderPublicKey)
		}
		// the proposer derives the session key from it
		responder, err := ParseKey(result.ResponderPublicKey)
		if err != nil {
			t.Fatalf("ParseKey: %v", err)
		}
		symKey, err := DeriveSymKey(mustKey(t, rfc7748AlicePrivate), responder)
		if err != nil {
			t.Fatalf("DeriveSymKey: %v", err)
		}
		if symKey.Hex() != sessionSymKey || Topic(symKey) != sessionTopic {
			t.Errorf("session key: got %s", symKey.Hex())
		}
	})

	t.Run("wc_sessionSettle", func(t *testing.T) {
		account := bittensorChain + ":" + bittensorAddress
		frame, err := ParseFrame([]byte(`{"id":1759900000000999,"jsonrpc":"2.0","method":"wc_sessionSettle","params":{"relay":{"protocol":"irn"},"controller":{"publicKey":"` + rfc7748BobPublic + `","metadata":{"name":"W","description":"d","url":"https://w.example","icons":[],"redirect":{"native":"w://"}}},"namespaces":{"polkadot":{"accounts":["` + account + `"],"methods":["polkadot_signMessage"],"events":[]}},"expiry":1700604800}}`))
		if err != nil {
			t.Fatalf("ParseFrame: %v", err)
		}
		var settle SettleParams
		if err := json.Unmarshal(frame.Params, &settle); err != nil {
			t.Fatalf("params: %v", err)
		}
		if settle.Controller.PublicKey != rfc7748BobPublic {
			t.Errorf("controller: got %s", settle.Controller.PublicKey)
		}
		if err := ValidateNamespaces("polkadot", bittensorChain, bittensorMethod, settle.Namespaces); err != nil {
			t.Errorf("namespaces: %d %s", err.Code, err.Message)
		}
		if got := ChainAccounts(settle.Namespaces, "polkadot", bittensorChain); len(got) != 1 || got[0] != account {
			t.Errorf("accounts: got %q", got)
		}
		if expiry, ok := settle.ExpiryUnix(); !ok || expiry != 1700604800 {
			t.Errorf("ExpiryUnix: got %d, %v", expiry, ok)
		}

		// an expiry that is a string is refused, as is one that is missing
		for text, want := range map[string]bool{
			`{"expiry":1700604800}`:   true,
			`{"expiry":"1700604800"}`: false,
			`{"expiry":null}`:         false,
			`{"expiry":true}`:         false,
			`{"expiry":{}}`:           false,
			`{"expiry":[1700604800]}`: false,
			`{}`:                      false,
		} {
			var settle SettleParams
			if err := json.Unmarshal([]byte(text), &settle); err != nil {
				t.Errorf("%s: %v", text, err)
				continue
			}
			expiry, ok := settle.ExpiryUnix()
			if ok != want || (ok && expiry != 1700604800) || (!ok && expiry != 0) {
				t.Errorf("%s: ExpiryUnix is %d, %v", text, expiry, ok)
			}
		}
	})

	t.Run("ExpiryUnix takes a json number and nothing else", func(t *testing.T) {
		for _, v := range []struct {
			raw  string
			want int64
			ok   bool
		}{
			{"1700604800", 1700604800, true},
			{"0", 0, true},
			{"-5", -5, true},
			{"-0", 0, true},
			{"9223372036854775807", math.MaxInt64, true},
			{" 1700604800\n", 1700604800, true},
			// a number with a fraction or an exponent is still a number
			{"1700604800.9", 1700604800, true},
			{"1.7006048e9", 1700604800, true},
			{"17006048E+2", 1700604800, true},
			{"-0.5", -1, true},
			// beyond 64 bits: the nearest value
			{"99999999999999999999", math.MaxInt64, true},
			{"1e30", math.MaxInt64, true},
			{"-1e30", math.MinInt64, true},
			// not finite
			{"1e999", 0, false},
			{"-1e999", 0, false},
			// not a number
			{`"1700604800"`, 0, false},
			{`""`, 0, false},
			{"null", 0, false},
			{"true", 0, false},
			{"{}", 0, false},
			{"[1700604800]", 0, false},
			{"", 0, false},
			{" ", 0, false},
			// what Go's number parsers take and json does not
			{"+5", 0, false},
			{"01", 0, false},
			{".5", 0, false},
			{"5.", 0, false},
			{"1e", 0, false},
			{"1e+", 0, false},
			{"-", 0, false},
			{"--1", 0, false},
			{"0x10", 0, false},
			{"1_000", 0, false},
			{"NaN", 0, false},
			{"Infinity", 0, false},
			{"12abc", 0, false},
			{"1 2", 0, false},
		} {
			settle := &SettleParams{Expiry: json.RawMessage(v.raw)}
			got, ok := settle.ExpiryUnix()
			if got != v.want || ok != v.ok {
				t.Errorf("ExpiryUnix of %q: got %d, %v; want %d, %v", v.raw, got, ok, v.want, v.ok)
			}
		}
		if got, ok := (&SettleParams{}).ExpiryUnix(); ok || got != 0 {
			t.Errorf("ExpiryUnix with no expiry: got %d, %v", got, ok)
		}
	})
}

func TestTagsAndTtls(t *testing.T) {
	for name, v := range map[string][2]int{
		"wc_pairingDelete":              {TagPairingDelete, 1000},
		"wc_pairingDelete response":     {TagPairingDeleteResponse, 1001},
		"wc_pairingPing":                {TagPairingPing, 1002},
		"wc_pairingPing response":       {TagPairingPingResponse, 1003},
		"wc_sessionPropose":             {TagSessionPropose, 1100},
		"wc_sessionPropose approve":     {TagSessionProposeApprove, 1101},
		"wc_sessionSettle":              {TagSessionSettle, 1102},
		"wc_sessionSettle response":     {TagSessionSettleResponse, 1103},
		"wc_sessionUpdate":              {TagSessionUpdate, 1104},
		"wc_sessionUpdate response":     {TagSessionUpdateResponse, 1105},
		"wc_sessionExtend":              {TagSessionExtend, 1106},
		"wc_sessionExtend response":     {TagSessionExtendResponse, 1107},
		"wc_sessionRequest":             {TagSessionRequest, 1108},
		"wc_sessionRequest response":    {TagSessionRequestResponse, 1109},
		"wc_sessionEvent":               {TagSessionEvent, 1110},
		"wc_sessionEvent response":      {TagSessionEventResponse, 1111},
		"wc_sessionDelete":              {TagSessionDelete, 1112},
		"wc_sessionDelete response":     {TagSessionDeleteResponse, 1113},
		"wc_sessionPing":                {TagSessionPing, 1114},
		"wc_sessionPing response":       {TagSessionPingResponse, 1115},
		"wc_sessionPropose reject":      {TagSessionProposeReject, 1120},
		"wc_sessionPropose auto reject": {TagSessionProposeAutoReject, 1121},
		"unsupported method":            {TagUnsupported, 0},
		"five minutes":                  {TtlFiveMinutes, 300},
		"one day":                       {TtlOneDay, 86400},
		"ping":                          {TtlPing, 30},
	} {
		if v[0] != v[1] {
			t.Errorf("%s: got %d, want %d", name, v[0], v[1])
		}
	}
}

// A method of this package called on nil gives the zero answer, not a panic.
func TestNilReceivers(t *testing.T) {
	var frame *Frame
	if frame.IsRequest() {
		t.Errorf("a nil frame is a request")
	}
	var pairing *Pairing
	if got := pairing.Uri(); got != "" {
		t.Errorf("a nil pairing has the uri %q", got)
	}
	var settle *SettleParams
	if expiry, ok := settle.ExpiryUnix(); ok || expiry != 0 {
		t.Errorf("a nil settle has the expiry %d, %v", expiry, ok)
	}
	// the result of ValidateNamespaces for a valid session, were it printed
	var valid *NamespaceError
	if got := valid.Error(); got != "<nil>" {
		t.Errorf("a nil namespace error prints %q", got)
	}
}
