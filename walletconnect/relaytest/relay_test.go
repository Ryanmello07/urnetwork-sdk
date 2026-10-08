//go:build !js && !ios_extension

package relaytest

// The relay is tested the way the later packages use it: with in-process
// peers, and with a plain websocket client on one of its in-memory
// connections. Every test but the last runs in a synctest bubble, so the
// waits below (six seconds for a held result, five minutes for a message's
// life) take no real time and are exact.
//
// The numbers in these tests are the ones that were measured on the hosted
// relay: the 6 second acknowledgement window, the ping every 30 seconds, the
// close with 4010, the 120 second leeway of a token, the status and the body
// of every refusal.

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"testing/synctest"
	"time"

	"github.com/gorilla/websocket"

	"github.com/urnetwork/sdk/walletconnect/wire"
)

const (
	testRelayUrl  = "wss://relay.walletconnect.com"
	testRelayHost = "relay.walletconnect.com"
	testProjectId = "test-project"
	testTarget    = testRelayUrl + "?projectId=" + testProjectId

	loadBalancing = "Disconnecting for load balancing reasons"
)

var (
	topicA = strings.Repeat("a", 64)
	topicB = strings.Repeat("b", 64)
	topicC = strings.Repeat("c", 64)
	topicD = strings.Repeat("d", 64)
	topicE = strings.Repeat("e", 64)
	topicF = strings.Repeat("f", 64)
)

// inBubble runs f with a relay on the clock of a synctest bubble and closes
// the relay when f returns. The bubble cannot end while a goroutine of the
// relay or of one of its clients is left, so every test also shows that
// Close leaves none.
func inBubble(t *testing.T, options RelayOptions, f func(t *testing.T, relay *Relay)) {
	t.Helper()
	synctest.Test(t, func(t *testing.T) {
		relay := NewRelay(options)
		defer relay.Close()
		f(t, relay)
	})
}

func testSeed(n byte) wire.Key {
	var seed wire.Key
	for i := range seed {
		seed[i] = n
	}
	return seed
}

// clientIdOf is the client id the relay knows the key of seed by.
func clientIdOf(seed wire.Key) string {
	public, _ := wire.ClientKey(seed).Public().(ed25519.PublicKey)
	return wire.DidKey(public)
}

// claimsOf are the claims of an acceptable token of seed at the time now.
func claimsOf(seed wire.Key, now int64) wire.RelayClaims {
	return wire.RelayClaims{
		Iss: clientIdOf(seed),
		Sub: testSeed(0x5b).Hex(),
		Aud: testRelayUrl,
		Iat: now - wire.RelayAuthBackdateSeconds,
		Exp: now + wire.RelayAuthBackdateSeconds,
		Act: "client_auth",
	}
}

func tokenOf(seed wire.Key, claims wire.RelayClaims) string {
	return wire.SignToken(claims, wire.ClientKey(seed))
}

func bearer(token string) http.Header {
	header := http.Header{}
	header.Set("Authorization", "Bearer "+token)
	return header
}

// open makes a websocket handshake on one of the relay's connections.
func open(ctx context.Context, relay *Relay, target string, header http.Header) (*websocket.Conn, *http.Response, error) {
	dialer := websocket.Dialer{NetDialTLSContext: relay.DialTLS}
	return dialer.DialContext(ctx, target, header)
}

// knock is the outcome of a handshake: 101, or the status and the body of
// the refusal.
func knock(t *testing.T, relay *Relay, target string, header http.Header) (int, string) {
	t.Helper()
	ws, response, err := open(t.Context(), relay, target, header)
	if err == nil {
		ws.Close()
		return http.StatusSwitchingProtocols, ""
	}
	if !errors.Is(err, websocket.ErrBadHandshake) || response == nil {
		t.Fatalf("handshake: %v", err)
	}
	body, _ := io.ReadAll(response.Body)
	return response.StatusCode, string(body)
}

// rawClient is a websocket client on one of the relay's connections. It reads
// every frame and, unless told to, acknowledges none: the test decides.
type rawClient struct {
	t        *testing.T
	ws       *websocket.Conn
	clientId string
	dialed   time.Time
	nextId   int64

	writeMu sync.Mutex

	mu          sync.Mutex
	frames      []*wire.Frame
	other       []int // the sizes of text frames that are not json-rpc
	pings       []time.Duration
	pingSizes   []int
	pongs       []string
	answerPings bool
	autoAck     bool
	readErr     error
}

func connect(t *testing.T, relay *Relay, seed wire.Key) *rawClient {
	t.Helper()
	return connectWith(t, relay, seed, nil)
}

// connectWith is connect with a chance to set the socket up before anything
// is read from it.
func connectWith(t *testing.T, relay *Relay, seed wire.Key, prepare func(ws *websocket.Conn)) *rawClient {
	t.Helper()
	token := tokenOf(seed, claimsOf(seed, time.Now().Unix()))
	ws, _, err := open(t.Context(), relay, testTarget, bearer(token))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if prepare != nil {
		prepare(ws)
	}
	c := &rawClient{
		t:           t,
		ws:          ws,
		clientId:    clientIdOf(seed),
		dialed:      time.Now(),
		answerPings: true,
	}
	ws.SetPingHandler(func(data string) error {
		c.mu.Lock()
		c.pings = append(c.pings, time.Since(c.dialed))
		c.pingSizes = append(c.pingSizes, len(data))
		answer := c.answerPings
		c.mu.Unlock()
		if !answer {
			return nil
		}
		return ws.WriteControl(websocket.PongMessage, []byte(data), time.Now().Add(time.Second))
	})
	ws.SetPongHandler(func(data string) error {
		c.mu.Lock()
		c.pongs = append(c.pongs, data)
		c.mu.Unlock()
		return nil
	})
	go c.read()
	return c
}

// read is the client's reader. Like any client it lets go of a socket that
// failed.
func (c *rawClient) read() {
	defer c.ws.Close()
	for {
		_, text, err := c.ws.ReadMessage()
		if err != nil {
			c.mu.Lock()
			c.readErr = err
			c.mu.Unlock()
			return
		}
		frame, err := wire.ParseFrame(text)
		c.mu.Lock()
		if err != nil {
			c.other = append(c.other, len(text))
		} else {
			c.frames = append(c.frames, frame)
		}
		ack := err == nil && c.autoAck && frame.Method == wire.MethodSubscription
		c.mu.Unlock()
		if ack {
			c.write(wire.ResultFrame(frame.Id, true))
		}
	}
}

func (c *rawClient) write(text []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.ws.WriteMessage(websocket.TextMessage, text)
}

func (c *rawClient) send(text []byte) {
	c.t.Helper()
	if err := c.write(text); err != nil {
		c.t.Fatalf("write: %v", err)
	}
}

// call writes a request with a 19 digit id, as a client's are, and returns
// the id.
func (c *rawClient) call(method string, params any) int64 {
	c.t.Helper()
	c.nextId++
	id := int64(1_700_000_000_000_000_000) + c.nextId
	c.send(wire.RequestFrame(id, method, params))
	return id
}

func (c *rawClient) subscribe(topic string) int64 {
	c.t.Helper()
	return c.call(wire.MethodSubscribe, wire.SubscribeParams{Topic: topic})
}

func (c *rawClient) publish(topic string, message string, tag int, ttl int) int64 {
	c.t.Helper()
	return c.call(wire.MethodPublish, wire.PublishParams{Topic: topic, Message: message, Ttl: ttl, Tag: tag})
}

// ack acknowledges a push, with its id as it came.
func (c *rawClient) ack(push *wire.Frame) {
	c.t.Helper()
	c.send(wire.ResultFrame(push.Id, true))
}

// close lets go of the socket with no close frame.
func (c *rawClient) close() {
	c.ws.Close()
}

func (c *rawClient) acknowledgeEverything() {
	c.mu.Lock()
	c.autoAck = true
	c.mu.Unlock()
}

func (c *rawClient) answerNoPing() {
	c.mu.Lock()
	c.answerPings = false
	c.mu.Unlock()
}

// take is what arrived since the last take, once the bubble is at rest.
func (c *rawClient) take() []*wire.Frame {
	synctest.Wait()
	c.mu.Lock()
	defer c.mu.Unlock()
	frames := c.frames
	c.frames = nil
	return frames
}

// ended is the error the client's reader stopped with, nil while it reads.
func (c *rawClient) ended() error {
	synctest.Wait()
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.readErr
}

func (c *rawClient) pinged() ([]time.Duration, []int) {
	synctest.Wait()
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.pings), slices.Clone(c.pingSizes)
}

// ponged is the payload of every pong the client read.
func (c *rawClient) ponged() []string {
	synctest.Wait()
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.pongs)
}

func (c *rawClient) otherFrames() []int {
	synctest.Wait()
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.other)
}

// subscribed sends irn_subscribe, waits for the relay's answer and returns
// the subscription id and what came behind the result.
func (c *rawClient) subscribed(topic string) (string, []*wire.Frame) {
	c.t.Helper()
	id := c.subscribe(topic)
	time.Sleep(subscribeLatency)
	frames := c.take()
	if len(frames) == 0 || frames[0].IsRequest() || frames[0].Error != nil || string(frames[0].Id) != strconv.FormatInt(id, 10) {
		c.t.Fatalf("irn_subscribe: the result is not the first frame: %q", told(frames))
	}
	var subscriptionId string
	if err := json.Unmarshal(frames[0].Result, &subscriptionId); err != nil || !isHex64(subscriptionId) {
		c.t.Fatalf("irn_subscribe: the result is not a subscription id: %q", told(frames[:1]))
	}
	return subscriptionId, frames[1:]
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	return strings.Trim(s, "0123456789abcdef") == ""
}

// told is what a client read, one line for each frame, so that a test
// compares a whole sequence at once.
func told(frames []*wire.Frame) []string {
	lines := make([]string, 0, len(frames))
	for _, frame := range frames {
		switch {
		case frame.Method == wire.MethodSubscription:
			var params wire.SubscriptionParams
			if err := json.Unmarshal(frame.Params, &params); err != nil {
				lines = append(lines, "push with other params")
				continue
			}
			lines = append(lines, pushed(params.Data.Topic, params.Data.Message, params.Data.Tag))
		case frame.IsRequest():
			lines = append(lines, "request "+frame.Method)
		case frame.Error != nil:
			lines = append(lines, fmt.Sprintf("error %s %d %s", string(frame.Id), frame.Error.Code, frame.Error.Message))
		default:
			lines = append(lines, fmt.Sprintf("result %s %s", string(frame.Id), string(frame.Result)))
		}
	}
	return lines
}

func pushed(topic string, message string, tag int) string {
	return fmt.Sprintf("push %s %s %d", topic, message, tag)
}

func result(id int64, value string) string {
	return fmt.Sprintf("result %d %s", id, value)
}

func failed(id int64, code int, message string) string {
	return fmt.Sprintf("error %d %d %s", id, code, message)
}

func expect(t *testing.T, what string, got []string, want ...string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Fatalf("%s:\n got  %q\n want %q", what, got, want)
	}
}

// received is what a connection was handed since the last call, once the
// bubble is at rest.
func received(conn Conn) []Message {
	var messages []Message
	for {
		synctest.Wait()
		select {
		case message, ok := <-conn.Messages():
			if !ok {
				return messages
			}
			messages = append(messages, message)
		default:
			return messages
		}
	}
}

func expectMessages(t *testing.T, what string, conn Conn, want ...Message) {
	t.Helper()
	if got := received(conn); !slices.Equal(got, want) {
		t.Fatalf("%s:\n got  %v\n want %v", what, got, want)
	}
}

// timersOf is the number of timers the relay has running.
func timersOf(relay *Relay) int {
	relay.mu.Lock()
	defer relay.mu.Unlock()
	return len(relay.timers)
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// closeCode is the code of the close frame a reader stopped with, 0 when it
// stopped for another reason. A connection that ends with no close frame
// reads as 1006.
func closeCode(err error) (int, string) {
	var closed *websocket.CloseError
	if errors.As(err, &closed) {
		return closed.Code, closed.Text
	}
	return 0, ""
}

// A message published before anyone subscribed waits for the first other
// client id that subscribes. Its publisher never gets it, whether it
// subscribes before or after, and a third client gets nothing.
func TestRelayHoldsAMessageForTheFirstOtherClient(t *testing.T) {
	inBubble(t, RelayOptions{}, func(t *testing.T, relay *Relay) {
		dapp := relay.Peer("dapp")
		wallet := relay.Peer("wallet")
		third := relay.Peer("third")

		// published first, subscribed afterwards
		must(t, dapp.Publish(topicA, "proposal", wire.TagSessionPropose, wire.TtlFiveMinutes))
		must(t, dapp.Subscribe(topicA))
		expectMessages(t, "the publisher, subscribing afterwards", dapp)

		time.Sleep(20 * time.Second)
		must(t, wallet.Subscribe(topicA))
		expectMessages(t, "the first other client", wallet, Message{Topic: topicA, Message: "proposal", Tag: wire.TagSessionPropose})

		must(t, third.Subscribe(topicA))
		expectMessages(t, "a third client", third)
		must(t, wallet.Subscribe(topicA))
		expectMessages(t, "the first other client, asking again", wallet)
		expectMessages(t, "the publisher", dapp)

		// subscribed first, published afterwards (the order of a pairing topic)
		must(t, dapp.Subscribe(topicB))
		must(t, dapp.Publish(topicB, "second proposal", wire.TagSessionPropose, wire.TtlFiveMinutes))
		expectMessages(t, "the publisher, subscribed before", dapp)
		must(t, wallet.Subscribe(topicB))
		expectMessages(t, "the first other client", wallet, Message{Topic: topicB, Message: "second proposal", Tag: wire.TagSessionPropose})

		// with both subscribed each is handed what the other publishes
		must(t, wallet.Publish(topicB, "response", wire.TagSessionProposeApprove, wire.TtlFiveMinutes))
		expectMessages(t, "the dapp", dapp, Message{Topic: topicB, Message: "response", Tag: wire.TagSessionProposeApprove})
		expectMessages(t, "the wallet", wallet)

		// a client id is any text, the empty one too
		nameless := relay.Peer("")
		must(t, nameless.Publish(topicC, "from nobody", wire.TagSessionPropose, wire.TtlFiveMinutes))
		must(t, nameless.Subscribe(topicC))
		expectMessages(t, "the publisher with no name", nameless)
		must(t, wallet.Subscribe(topicC))
		expectMessages(t, "the first other client", wallet, Message{Topic: topicC, Message: "from nobody", Tag: wire.TagSessionPropose})
		must(t, wallet.Publish(topicC, "for nobody", wire.TagSessionProposeApprove, wire.TtlFiveMinutes))
		expectMessages(t, "the client with no name", nameless, Message{Topic: topicC, Message: "for nobody", Tag: wire.TagSessionProposeApprove})
		must(t, wallet.Publish(topicC, "for nobody", wire.TagSessionProposeApprove, wire.TtlFiveMinutes))
		expectMessages(t, "the client with no name, the same again", nameless, Message{Topic: topicC, Message: "for nobody", Tag: wire.TagSessionProposeApprove})
		nameless.Close()
		must(t, wallet.Publish(topicC, "kept for nobody", wire.TagSessionProposeApprove, wire.TtlFiveMinutes))
		nameless = relay.Peer("")
		must(t, nameless.Subscribe(topicC))
		expectMessages(t, "the client with no name, back", nameless, Message{Topic: topicC, Message: "kept for nobody", Tag: wire.TagSessionProposeApprove})
	})
}

// The same over sockets, where the frames can be read: a push has a 15 digit
// id, names the subscription and dates the message in seconds.
func TestRelayPushFrame(t *testing.T) {
	inBubble(t, RelayOptions{}, func(t *testing.T, relay *Relay) {
		dapp := connect(t, relay, testSeed(1))
		wallet := connect(t, relay, testSeed(2))

		dapp.subscribed(topicA)
		publishedAt := time.Now().Unix()
		proposal := dapp.publish(topicA, "proposal", wire.TagSessionPropose, wire.TtlFiveMinutes)
		expect(t, "the dapp, with nobody to push to", told(dapp.take()), result(proposal, "true"))

		time.Sleep(20 * time.Second)
		subscriptionId, frames := wallet.subscribed(topicA)
		expect(t, "the wallet", told(frames), pushed(topicA, "proposal", wire.TagSessionPropose))
		push := frames[0]
		if id := string(push.Id); len(id) != 15 || strings.Trim(id, "0123456789") != "" {
			t.Fatalf("a push id has 15 digits, got %s", id)
		}
		var params wire.SubscriptionParams
		must(t, json.Unmarshal(push.Params, &params))
		if params.Id != subscriptionId {
			t.Fatalf("the push names subscription %s, the subscribe returned %s", params.Id, subscriptionId)
		}
		if params.Data.PublishedAt != publishedAt {
			t.Fatalf("publishedAt %d, want the second of the publish, %d", params.Data.PublishedAt, publishedAt)
		}
		wallet.ack(push)
		expect(t, "the dapp never reads its own message", told(dapp.take()))

		// the answer is pushed live, and the wallet's result waits for the
		// dapp's acknowledgement
		response := wallet.publish(topicA, "response", wire.TagSessionProposeApprove, wire.TtlFiveMinutes)
		frames = dapp.take()
		expect(t, "the dapp", told(frames), pushed(topicA, "response", wire.TagSessionProposeApprove))
		expect(t, "the wallet, before the acknowledgement", told(wallet.take()))
		dapp.ack(frames[0])
		expect(t, "the wallet, after it", told(wallet.take()), result(response, "true"))

		// what the relay recorded of the wallet's socket is what was on it
		pushId, err := strconv.ParseInt(string(push.Id), 10, 64)
		must(t, err)
		wantPush := string(wire.RequestFrame(pushId, wire.MethodSubscription, wire.SubscriptionParams{
			Id: subscriptionId,
			Data: wire.SubscriptionData{
				Topic:       topicA,
				Message:     "proposal",
				PublishedAt: publishedAt,
				Tag:         wire.TagSessionPropose,
			},
		}))
		recorded := relay.Frames(wallet.clientId)
		if len(recorded) < 3 || recorded[2].ToRelay || recorded[2].Text != wantPush {
			t.Fatalf("the third frame of the wallet's socket is not the push %s", wantPush)
		}
	})
}

// An acknowledged push is never delivered again. An unacknowledged one is
// pushed again on the next irn_subscribe of the same client id, on the same
// socket and on a new one, and never to another client id.
func TestRelayPushesAnUnacknowledgedMessageAgainOnSubscribe(t *testing.T) {
	inBubble(t, RelayOptions{}, func(t *testing.T, relay *Relay) {
		seed := testSeed(1)
		sender := connect(t, relay, testSeed(9))
		first := connect(t, relay, seed)

		// acknowledged
		first.subscribed(topicA)
		one := sender.publish(topicA, "one", wire.TagSessionRequestResponse, wire.TtlFiveMinutes)
		frames := first.take()
		expect(t, "live", told(frames), pushed(topicA, "one", wire.TagSessionRequestResponse))
		first.ack(frames[0])
		expect(t, "the sender", told(sender.take()), result(one, "true"))
		_, frames = first.subscribed(topicA)
		expect(t, "acknowledged, the same socket", told(frames))
		second := connect(t, relay, seed)
		_, frames = second.subscribed(topicA)
		expect(t, "acknowledged, a new socket", told(frames))
		_, frames = connect(t, relay, testSeed(2)).subscribed(topicA)
		expect(t, "acknowledged, another client id", told(frames))
		second.close()

		// not acknowledged
		first.subscribed(topicB)
		two := sender.publish(topicB, "two", wire.TagSessionRequestResponse, wire.TtlFiveMinutes)
		frames = first.take()
		expect(t, "live", told(frames), pushed(topicB, "two", wire.TagSessionRequestResponse))
		firstPush := string(frames[0].Id)
		time.Sleep(15 * time.Second)
		expect(t, "nothing is pushed a second time by itself", told(first.take()))
		expect(t, "the sender, after the window", told(sender.take()), result(two, "true"))

		_, frames = first.subscribed(topicB)
		expect(t, "unacknowledged, the same socket", told(frames), pushed(topicB, "two", wire.TagSessionRequestResponse))
		if again := string(frames[0].Id); again == firstPush {
			t.Fatalf("the second push of a message has the id of the first, %s", again)
		}
		third := connect(t, relay, seed)
		_, frames = third.subscribed(topicB)
		expect(t, "unacknowledged, a new socket", told(frames), pushed(topicB, "two", wire.TagSessionRequestResponse))
		_, other := connect(t, relay, testSeed(3)).subscribed(topicB)
		expect(t, "unacknowledged, another client id", told(other))

		third.ack(frames[0])
		_, frames = third.subscribed(topicB)
		expect(t, "acknowledged at last, the new socket", told(frames))
		_, frames = first.subscribed(topicB)
		expect(t, "acknowledged at last, the old socket", told(frames))
		third.close()

		// acknowledged too late: after the window it does not count
		first.subscribed(topicC)
		sender.publish(topicC, "three", wire.TagSessionRequestResponse, wire.TtlFiveMinutes)
		frames = first.take()
		expect(t, "live", told(frames), pushed(topicC, "three", wire.TagSessionRequestResponse))
		time.Sleep(6*time.Second + time.Millisecond)
		first.ack(frames[0])
		_, frames = first.subscribed(topicC)
		expect(t, "after a late acknowledgement", told(frames), pushed(topicC, "three", wire.TagSessionRequestResponse))
		time.Sleep(6*time.Second - time.Millisecond)
		first.ack(frames[0])
		_, frames = first.subscribed(topicC)
		expect(t, "after an acknowledgement a millisecond before the window ends", told(frames))
	})
}

// An acknowledgement is the result true with the id of the push, digit for
// digit, from the socket the push went to. Anything else leaves the message
// in the mailbox.
func TestRelayAcknowledgementIsExact(t *testing.T) {
	inBubble(t, RelayOptions{}, func(t *testing.T, relay *Relay) {
		seed := testSeed(1)
		sender := relay.Peer("sender")
		client := connect(t, relay, seed)
		other := connect(t, relay, seed)
		client.subscribed(topicA)

		go sender.Publish(topicA, "answer", wire.TagSessionRequestResponse, wire.TtlFiveMinutes)
		frames := client.take()
		expect(t, "live", told(frames), pushed(topicA, "answer", wire.TagSessionRequestResponse))
		id := frames[0].Id

		pushId, err := strconv.ParseInt(string(id), 10, 64)
		must(t, err)
		client.send(wire.ResultFrame(wire.IdToken(pushId+1), true))                      // another id
		client.send(wire.ResultFrame(id, false))                                         // not true
		client.send(wire.ErrorFrame(id, 5000, "no"))                                     // an error
		client.send([]byte(`{"id":` + string(id) + `.0,"jsonrpc":"2.0","result":true}`)) // the id as another number
		other.send(wire.ResultFrame(id, true))                                           // another socket of the client
		_, frames = client.subscribed(topicA)
		expect(t, "after five answers that are no acknowledgement", told(frames), pushed(topicA, "answer", wire.TagSessionRequestResponse))

		client.ack(frames[0])
		_, frames = client.subscribed(topicA)
		expect(t, "after the acknowledgement", told(frames))
	})
}

// Nothing is pushed on a new socket before irn_subscribe.
func TestRelayPushesNothingBeforeSubscribe(t *testing.T) {
	inBubble(t, RelayOptions{}, func(t *testing.T, relay *Relay) {
		seed := testSeed(1)
		sender := relay.Peer("sender")
		first := connect(t, relay, seed)
		first.subscribed(topicA)
		first.close()
		synctest.Wait()

		must(t, sender.Publish(topicA, "answer", wire.TagSessionProposeApprove, wire.TtlFiveMinutes))
		second := connect(t, relay, seed)
		time.Sleep(10 * time.Second)
		expect(t, "a new socket that did not subscribe", told(second.take()))
		_, frames := second.subscribed(topicB)
		expect(t, "subscribed to another topic", told(frames))
		_, frames = second.subscribed(topicA)
		expect(t, "subscribed", told(frames), pushed(topicA, "answer", wire.TagSessionProposeApprove))
	})
}

// The publisher's result is held while the recipient's socket is silent:
// 6 seconds, 12 when switched, and not at all when the recipient has no
// socket.
func TestRelayHoldsThePublishersResult(t *testing.T) {
	inBubble(t, RelayOptions{}, func(t *testing.T, relay *Relay) {
		seed := testSeed(1)
		silent := connect(t, relay, seed)
		silent.subscribed(topicA)
		wallet := relay.Peer("wallet")
		publisher := connect(t, relay, testSeed(2))

		holds := func(what string, want time.Duration) {
			t.Helper()
			// an in-process publisher
			start := time.Now()
			must(t, wallet.Publish(topicA, what+", peer", wire.TagSessionProposeApprove, wire.TtlFiveMinutes))
			if held := time.Since(start); held != want {
				t.Fatalf("%s: a peer's publish returned after %v, want %v", what, held, want)
			}
			// a socket publisher: the result frame
			id := publisher.publish(topicA, what+", socket", wire.TagSessionProposeApprove, wire.TtlFiveMinutes)
			if want > 0 {
				time.Sleep(want - time.Millisecond)
				expect(t, what+": just before the hold ends", told(publisher.take()))
				time.Sleep(time.Millisecond)
			}
			expect(t, what+": when the hold ends", told(publisher.take()), result(id, "true"))
		}

		holds("the default", 6*time.Second)
		relay.SetAckHold(6100 * time.Millisecond)
		holds("6.1 s", 6100*time.Millisecond)
		relay.SetAckHold(12 * time.Second)
		holds("12 s", 12*time.Second)
		relay.SetAckHold(0)
		holds("the default again", 6*time.Second)

		// every one of those was pushed at once, once
		want := []string{}
		for _, what := range []string{"the default", "6.1 s", "12 s", "the default again"} {
			want = append(want,
				pushed(topicA, what+", peer", wire.TagSessionProposeApprove),
				pushed(topicA, what+", socket", wire.TagSessionProposeApprove),
			)
		}
		frames := silent.take()
		expect(t, "the silent socket", told(frames), want...)

		// an acknowledgement ends the hold
		id := publisher.publish(topicA, "acknowledged", wire.TagSessionProposeApprove, wire.TtlFiveMinutes)
		time.Sleep(2 * time.Second)
		frames = silent.take()
		expect(t, "the silent socket", told(frames), pushed(topicA, "acknowledged", wire.TagSessionProposeApprove))
		expect(t, "before the acknowledgement", told(publisher.take()))
		silent.ack(frames[0])
		expect(t, "after the acknowledgement", told(publisher.take()), result(id, "true"))

		// a socket of the recipient that is not subscribed to the topic
		// holds nothing
		silent.call(wire.MethodUnsubscribe, wire.UnsubscribeParams{Topic: topicA, Id: "any"})
		silent.take()
		holds("unsubscribed", 0)
		expect(t, "the unsubscribed socket", told(silent.take()))

		// nor does a recipient with no socket
		silent.close()
		synctest.Wait()
		holds("no socket", 0)

		// what was not pushed is kept for the recipient
		again := connect(t, relay, seed)
		_, frames = again.subscribed(topicA)
		if lines := told(frames); len(lines) != 12 || lines[8] != pushed(topicA, "unsubscribed, peer", wire.TagSessionProposeApprove) || lines[11] != pushed(topicA, "no socket, socket", wire.TagSessionProposeApprove) {
			t.Fatalf("the mailbox of the recipient: %q", lines)
		}
	})
}

// A silent socket does not keep a message from a healthy socket of the same
// client: the relay tries the other one when the window has passed, and
// answers the publisher when that one acknowledges.
func TestRelayTriesAnotherSocketOfTheSameClient(t *testing.T) {
	inBubble(t, RelayOptions{}, func(t *testing.T, relay *Relay) {
		seed := testSeed(1)
		wallet := relay.Peer("wallet")
		old := connect(t, relay, seed)
		old.subscribed(topicA)
		relay.SetZombie(old.clientId, true)
		fresh := connect(t, relay, seed)
		fresh.acknowledgeEverything()
		fresh.subscribed(topicA)

		start := time.Now()
		must(t, wallet.Publish(topicA, "answer", wire.TagSessionRequestResponse, wire.TtlFiveMinutes))
		if held := time.Since(start); held != 6*time.Second {
			t.Fatalf("the publish returned after %v, want 6s", held)
		}
		expect(t, "the socket that is dead", told(old.take()))
		expect(t, "the healthy socket", told(fresh.take()), pushed(topicA, "answer", wire.TagSessionRequestResponse))
		var at time.Duration
		for _, frame := range relay.Frames(fresh.clientId) {
			if !frame.ToRelay && strings.Contains(frame.Text, wire.MethodSubscription) {
				at = frame.At.Sub(start)
			}
		}
		if at != 6*time.Second {
			t.Fatalf("the healthy socket was pushed to after %v, want 6s", at)
		}
		_, frames := fresh.subscribed(topicA)
		expect(t, "acknowledged", told(frames))

		// two healthy sockets of one client: the message goes to one of
		// them, the older, and the other is not handed it
		relay.SetZombie(old.clientId, false)
		old.acknowledgeEverything()
		must(t, wallet.Publish(topicA, "second answer", wire.TagSessionRequestResponse, wire.TtlFiveMinutes))
		expect(t, "the older socket", told(old.take()), pushed(topicA, "second answer", wire.TagSessionRequestResponse))
		expect(t, "the newer socket", told(fresh.take()))
	})
}

// The same message string published twice is one delivery while the first
// copy is undelivered, and a second delivery after the first was
// acknowledged.
func TestRelayMergesAnIdenticalMessage(t *testing.T) {
	inBubble(t, RelayOptions{}, func(t *testing.T, relay *Relay) {
		seed := testSeed(1)
		sender := relay.Peer("sender")
		request := pushed(topicA, "request", wire.TagSessionRequest)

		// nobody subscribed yet
		must(t, sender.Publish(topicA, "request", wire.TagSessionRequest, wire.TtlFiveMinutes))
		must(t, sender.Publish(topicA, "request", wire.TagSessionRequest, wire.TtlFiveMinutes))
		receiver := connect(t, relay, seed)
		_, frames := receiver.subscribed(topicA)
		expect(t, "two copies, nobody subscribed", told(frames), request)

		// pushed and not acknowledged
		start := time.Now()
		must(t, sender.Publish(topicA, "request", wire.TagSessionRequest, wire.TtlFiveMinutes))
		if held := time.Since(start); held != 0 {
			t.Fatalf("a merged publish was held %v", held)
		}
		expect(t, "a third copy, the first unacknowledged", told(receiver.take()))
		_, again := receiver.subscribed(topicA)
		expect(t, "the mailbox still holds one", told(again), request)

		// acknowledged: the next copy is a new message, delivered live
		receiver.ack(frames[0])
		// the relay takes a socket's frame in a goroutine of its own: the
		// acknowledgement is in before the peer publishes
		synctest.Wait()
		receiver.acknowledgeEverything()
		must(t, sender.Publish(topicA, "request", wire.TagSessionRequest, wire.TtlFiveMinutes))
		expect(t, "a copy after the acknowledgement", told(receiver.take()), request)
		_, frames = receiver.subscribed(topicA)
		expect(t, "and it was acknowledged", told(frames))

		// and from the mailbox
		receiver.close()
		synctest.Wait()
		must(t, sender.Publish(topicA, "request", wire.TagSessionRequest, wire.TtlFiveMinutes))
		must(t, sender.Publish(topicA, "request", wire.TagSessionRequest, wire.TtlFiveMinutes))
		must(t, sender.Publish(topicA, "another", wire.TagSessionRequest, wire.TtlFiveMinutes))
		back := connect(t, relay, seed)
		_, frames = back.subscribed(topicA)
		expect(t, "two copies and another message, the recipient away", told(frames), request, pushed(topicA, "another", wire.TagSessionRequest))

		if published := relay.Published(); len(published) != 7 {
			t.Fatalf("every publish is recorded, merged or not: got %d, want 7", len(published))
		}
	})
}

// A message with ttl 300 is delivered at 270 s and gone at 330 s.
func TestRelayTtl(t *testing.T) {
	inBubble(t, RelayOptions{}, func(t *testing.T, relay *Relay) {
		sender := relay.Peer("sender")

		// waiting for the first other client
		must(t, sender.Publish(topicA, "kept", wire.TagSessionPropose, wire.TtlFiveMinutes))
		must(t, sender.Publish(topicB, "gone", wire.TagSessionPropose, wire.TtlFiveMinutes))
		// waiting for a client the relay knows, and pushed to it once
		known := relay.Peer("known")
		must(t, known.Subscribe(topicC))
		known.Close()
		must(t, sender.Publish(topicC, "kept for a known client", wire.TagSessionSettle, wire.TtlFiveMinutes))
		silent := connect(t, relay, testSeed(1))
		silent.subscribed(topicC)
		go sender.Publish(topicC, "pushed once", wire.TagSessionSettle, wire.TtlFiveMinutes)
		expect(t, "live", told(silent.take()), pushed(topicC, "pushed once", wire.TagSessionSettle))

		time.Sleep(270*time.Second - subscribeLatency)
		early := relay.Peer("early")
		must(t, early.Subscribe(topicA))
		expectMessages(t, "at 270 s", early, Message{Topic: topicA, Message: "kept", Tag: wire.TagSessionPropose})
		known = relay.Peer("known")
		must(t, known.Subscribe(topicC))
		expectMessages(t, "at 270 s, a known client", known,
			Message{Topic: topicC, Message: "kept for a known client", Tag: wire.TagSessionSettle},
			Message{Topic: topicC, Message: "pushed once", Tag: wire.TagSessionSettle},
		)
		_, frames := silent.subscribed(topicC)
		expect(t, "at 270 s, pushed again", told(frames), pushed(topicC, "pushed once", wire.TagSessionSettle))

		time.Sleep(60*time.Second - subscribeLatency)
		late := relay.Peer("late")
		must(t, late.Subscribe(topicB))
		expectMessages(t, "at 330 s", late)
		_, frames = silent.subscribed(topicC)
		expect(t, "at 330 s, never acknowledged", told(frames))

		// the limit itself: there until the last moment of its life
		must(t, sender.Publish(topicD, "thirty", wire.TagSessionPing, wire.TtlPing))
		must(t, sender.Publish(topicE, "thirty", wire.TagSessionPing, wire.TtlPing))
		time.Sleep(30*time.Second - time.Millisecond)
		must(t, early.Subscribe(topicD))
		expectMessages(t, "a millisecond before the end", early, Message{Topic: topicD, Message: "thirty", Tag: wire.TagSessionPing})
		time.Sleep(time.Millisecond)
		must(t, late.Subscribe(topicE))
		expectMessages(t, "at the end", late)

		// one mailbox with a message that is gone and one that is not
		away := relay.Peer("away")
		must(t, away.Subscribe(topicF))
		away.Close()
		must(t, sender.Publish(topicF, "short lived", wire.TagSessionPing, wire.TtlPing))
		must(t, sender.Publish(topicF, "long lived", wire.TagSessionRequest, wire.TtlFiveMinutes))
		time.Sleep(time.Minute)
		away = relay.Peer("away")
		must(t, away.Subscribe(topicF))
		expectMessages(t, "the mailbox after a minute", away, Message{Topic: topicF, Message: "long lived", Tag: wire.TagSessionRequest})
	})
}

// The relay takes a ttl of 30 seconds to 30 days and refuses any other, as
// the hosted one does.
func TestRelayTtlRange(t *testing.T) {
	inBubble(t, RelayOptions{}, func(t *testing.T, relay *Relay) {
		client := connect(t, relay, testSeed(1))
		peer := relay.Peer("peer")

		short := client.publish(topicA, "short", wire.TagSessionPing, 29)
		least := client.publish(topicA, "least", wire.TagSessionPing, 30)
		most := client.publish(topicA, "most", wire.TagSessionPing, 2592000)
		long := client.publish(topicA, "long", wire.TagSessionPing, 2592001)
		expect(t, "the client", told(client.take()),
			failed(short, -32000, "Message: TtlTooShort"),
			result(least, "true"),
			result(most, "true"),
			failed(long, -32000, "Message: TtlTooLong"),
		)
		if err := peer.Publish(topicB, "short", wire.TagSessionPing, 29); err == nil {
			t.Fatal("a peer published with ttl 29")
		}
		if err := peer.Publish(topicB, "long", wire.TagSessionPing, 2592001); err == nil {
			t.Fatal("a peer published with ttl 2592001")
		}
		must(t, peer.Publish(topicB, "least", wire.TagSessionPing, 30))

		must(t, peer.Subscribe(topicA))
		expectMessages(t, "what was taken", peer,
			Message{Topic: topicA, Message: "least", Tag: wire.TagSessionPing},
			Message{Topic: topicA, Message: "most", Tag: wire.TagSessionPing},
		)
		if published := relay.Published(); len(published) != 3 {
			t.Fatalf("a refused publish is not recorded: got %d records, want 3", len(published))
		}
	})
}

// The subscription id is the same for the same client id and topic across
// sockets, and another for another client id or topic.
func TestRelaySubscriptionIdIsStable(t *testing.T) {
	inBubble(t, RelayOptions{}, func(t *testing.T, relay *Relay) {
		seed := testSeed(1)
		first := connect(t, relay, seed)
		idA, _ := first.subscribed(topicA)
		idB, _ := first.subscribed(topicB)
		if again, _ := first.subscribed(topicA); again != idA {
			t.Fatalf("the same socket: %s, then %s", idA, again)
		}
		if idA == idB {
			t.Fatalf("two topics have one subscription id, %s", idA)
		}
		first.close()

		second := connect(t, relay, seed)
		if again, _ := second.subscribed(topicA); again != idA {
			t.Fatalf("a new socket of the client: %s, was %s", again, idA)
		}
		other := connect(t, relay, testSeed(2))
		if id, _ := other.subscribed(topicA); id == idA {
			t.Fatalf("another client id has the same subscription id, %s", id)
		}
	})
}

// A ping every 30 seconds. A socket that answers is kept.
func TestRelayPingsEvery30Seconds(t *testing.T) {
	inBubble(t, RelayOptions{}, func(t *testing.T, relay *Relay) {
		client := connect(t, relay, testSeed(1))
		time.Sleep(125 * time.Second)
		pings, sizes := client.pinged()
		if want := []time.Duration{30 * time.Second, 60 * time.Second, 90 * time.Second, 120 * time.Second}; !slices.Equal(pings, want) {
			t.Fatalf("pings at %v, want %v", pings, want)
		}
		if !slices.Equal(sizes, []int{9, 9, 9, 9}) {
			t.Fatalf("ping payloads of %v bytes, want 9 each", sizes)
		}
		if err := client.ended(); err != nil {
			t.Fatalf("a socket that answered every ping ended: %v", err)
		}
		if open := relay.OpenSockets(client.clientId); open != 1 {
			t.Fatalf("%d open sockets, want 1", open)
		}

		// the relay answers a ping of the client, as any websocket peer
		// does; a zombie is not heard
		must(t, client.ws.WriteControl(websocket.PingMessage, []byte("from the client"), time.Now().Add(time.Second)))
		if pongs := client.ponged(); !slices.Equal(pongs, []string{"from the client"}) {
			t.Fatalf("the pongs of the relay: %q", pongs)
		}
		relay.SetZombie(client.clientId, true)
		must(t, client.ws.WriteControl(websocket.PingMessage, []byte("into a zombie"), time.Now().Add(time.Second)))
		if pongs := client.ponged(); len(pongs) != 1 {
			t.Fatalf("a zombie answered a ping: %q", pongs)
		}
	})
}

// A socket that answers no ping is closed with 4010 after 60 seconds.
func TestRelayClosesASocketThatAnswersNoPing(t *testing.T) {
	inBubble(t, RelayOptions{}, func(t *testing.T, relay *Relay) {
		// silent from the start
		client := connect(t, relay, testSeed(1))
		client.answerNoPing()
		time.Sleep(60*time.Second - time.Millisecond)
		if err := client.ended(); err != nil {
			t.Fatalf("closed before 60 s: %v", err)
		}
		if pings, _ := client.pinged(); !slices.Equal(pings, []time.Duration{30 * time.Second}) {
			t.Fatalf("pings at %v, want one at 30s", pings)
		}
		time.Sleep(time.Millisecond)
		if code, text := closeCode(client.ended()); code != 4010 || text != loadBalancing {
			t.Fatalf("at 60 s: close %d %q, want 4010 %q", code, text, loadBalancing)
		}
		if open := relay.OpenSockets(client.clientId); open != 0 {
			t.Fatalf("%d open sockets, want none", open)
		}

		// silent after two answered pings: closed when the second
		// unanswered ping would be due
		later := connect(t, relay, testSeed(2))
		time.Sleep(61 * time.Second)
		later.answerNoPing()
		time.Sleep(58 * time.Second)
		if err := later.ended(); err != nil {
			t.Fatalf("closed at 119 s: %v", err)
		}
		time.Sleep(time.Second)
		if code, _ := closeCode(later.ended()); code != 4010 {
			t.Fatalf("at 120 s: close %d, want 4010", code)
		}
		if pings, _ := later.pinged(); !slices.Equal(pings, []time.Duration{30 * time.Second, 60 * time.Second, 90 * time.Second}) {
			t.Fatalf("pings at %v, want 30s, 60s and 90s", pings)
		}
	})
}

// Each refusal of the upgrade handler, its status and its body, and what
// Handshakes records of the request.
func TestRelayUpgrade(t *testing.T) {
	seed := testSeed(1)
	const (
		originRefused = `{"error":"Unauthorized: origin not allowed"}`
		accepted      = ""
	)
	allowed := RelayOptions{
		Origins:      []string{"https://ur.io"},
		BundleIds:    []string{"network.ur"},
		PackageNames: []string{"com.bringyour.network"},
	}
	// a request with an acceptable token, and changes to it
	token := func(now int64, change func(claims *wire.RelayClaims)) string {
		claims := claimsOf(seed, now)
		if change != nil {
			change(&claims)
		}
		return tokenOf(seed, claims)
	}
	with := func(query string, headers ...string) func(now int64) (string, http.Header) {
		return func(now int64) (string, http.Header) {
			header := bearer(token(now, nil))
			for i := 0; i+1 < len(headers); i += 2 {
				header.Set(headers[i], headers[i+1])
			}
			return query, header
		}
	}
	claims := func(change func(claims *wire.RelayClaims, now int64)) func(now int64) (string, http.Header) {
		return func(now int64) (string, http.Header) {
			return "projectId=" + testProjectId, bearer(token(now, func(claims *wire.RelayClaims) { change(claims, now) }))
		}
	}
	fixed := func(body string) func(now int64) string {
		return func(int64) string { return body }
	}

	cases := []struct {
		name    string
		options RelayOptions
		request func(now int64) (query string, header http.Header)
		status  int
		body    func(now int64) string
		// the token verifies, so the record names the client
		named bool
	}{
		{
			name:    "nothing presented",
			request: with("projectId=" + testProjectId),
			status:  101, body: fixed(accepted), named: true,
		},
		{
			name:    "no project id",
			request: with(""),
			status:  400, body: fixed(`{"error":"Project ID is missing"}`), named: true,
		},
		{
			name:    "an empty project id",
			request: with("projectId="),
			status:  400, body: fixed(`{"error":"Project ID is missing"}`), named: true,
		},
		{
			name:    "an unknown project id",
			request: with("projectId=00000000000000000000000000000000"),
			status:  403, body: fixed(`{"error":"Project not found"}`), named: true,
		},
		{
			name:    "a project id of the options",
			options: RelayOptions{ProjectIds: []string{"13470f178edb2a9098d2261d03245975", "other"}},
			request: with("projectId=other"),
			status:  101, body: fixed(accepted), named: true,
		},
		{
			name:    "the default project id with other options",
			options: RelayOptions{ProjectIds: []string{"other"}},
			request: with("projectId=" + testProjectId),
			status:  403, body: fixed(`{"error":"Project not found"}`), named: true,
		},
		{
			name: "no token",
			request: func(int64) (string, http.Header) {
				return "projectId=" + testProjectId, http.Header{}
			},
			status: 401, body: fixed(`{"error":"JWT is missing"}`),
		},
		{
			name: "a header that is no bearer token",
			request: func(int64) (string, http.Header) {
				header := http.Header{}
				header.Set("Authorization", "Basic dXI6aW8=")
				return "projectId=" + testProjectId, header
			},
			status: 401, body: fixed(`{"error":"JWT is missing"}`),
		},
		{
			name: "a changed signature",
			request: func(now int64) (string, http.Header) {
				good := token(now, nil)
				return "projectId=" + testProjectId, bearer(good[:len(good)-2] + "AA")
			},
			status: 401, body: fixed(`{"error":"JWT validation error: Invalid signature"}`),
		},
		{
			name: "a token signed by another key",
			request: func(now int64) (string, http.Header) {
				return "projectId=" + testProjectId, bearer(tokenOf(testSeed(7), claimsOf(seed, now)))
			},
			status: 401, body: fixed(`{"error":"JWT validation error: Invalid signature"}`),
		},
		{
			name: "text that is no token",
			request: func(int64) (string, http.Header) {
				return "projectId=" + testProjectId, bearer("not.a.token")
			},
			status: 401, body: fixed(`{"error":"JWT validation error: Invalid signature"}`),
		},
		{
			// a token is about 430 characters; one of thousands is not
			// looked at, though this one would verify
			name:    "a token longer than any client's",
			request: claims(func(claims *wire.RelayClaims, _ int64) { claims.Sub = strings.Repeat("5b", 2000) }),
			status:  401, body: fixed(`{"error":"JWT validation error: Invalid signature"}`),
		},
		{
			name:    "a token of a length a client's could have",
			request: claims(func(claims *wire.RelayClaims, _ int64) { claims.Sub = strings.Repeat("5b", 1000) }),
			status:  101, body: fixed(accepted), named: true,
		},
		{
			name:    "another audience",
			request: claims(func(claims *wire.RelayClaims, _ int64) { claims.Aud = "https://example.org" }),
			status:  401, body: fixed(`{"error":"JWT validation error: Invalid audience"}`), named: true,
		},
		{
			name:    "the other relay url as audience",
			request: claims(func(claims *wire.RelayClaims, _ int64) { claims.Aud = "wss://relay.walletconnect.org" }),
			status:  101, body: fixed(accepted), named: true,
		},
		{
			name:    "an audience of the options",
			options: RelayOptions{Audiences: []string{"wss://relay.example"}},
			request: claims(func(claims *wire.RelayClaims, _ int64) { claims.Aud = "wss://relay.example" }),
			status:  101, body: fixed(accepted), named: true,
		},
		{
			name:    "the default audience with other options",
			options: RelayOptions{Audiences: []string{"wss://relay.example"}},
			request: with("projectId=" + testProjectId),
			status:  401, body: fixed(`{"error":"JWT validation error: Invalid audience"}`), named: true,
		},
		{
			name:    "issued 121 s ahead",
			request: claims(func(claims *wire.RelayClaims, now int64) { claims.Iat = now + 121 }),
			status:  401,
			body: func(now int64) string {
				return fmt.Sprintf(`{"error":"JWT validation error: JWT Token is not yet valid: basic.iat: %d, now + time_leeway: %d, time_leeway: 120"}`, now+121, now+120)
			},
			named: true,
		},
		{
			name:    "issued 120 s ahead",
			request: claims(func(claims *wire.RelayClaims, now int64) { claims.Iat = now + 120 }),
			status:  101, body: fixed(accepted), named: true,
		},
		{
			name:    "issued now",
			request: claims(func(claims *wire.RelayClaims, now int64) { claims.Iat = now }),
			status:  101, body: fixed(accepted), named: true,
		},
		{
			name:    "expired a second ago",
			request: claims(func(claims *wire.RelayClaims, now int64) { claims.Exp = now - 1 }),
			status:  401,
			body: func(now int64) string {
				return fmt.Sprintf(`{"error":"JWT validation error: JWT Token is expired: Some(%d)"}`, now-1)
			},
			named: true,
		},
		{
			name:    "expiring now",
			request: claims(func(claims *wire.RelayClaims, now int64) { claims.Exp = now }),
			status:  401,
			body: func(now int64) string {
				return fmt.Sprintf(`{"error":"JWT validation error: JWT Token is expired: Some(%d)"}`, now)
			},
			named: true,
		},
		{
			name:    "expiring in a second",
			request: claims(func(claims *wire.RelayClaims, now int64) { claims.Exp = now + 1 }),
			status:  101, body: fixed(accepted), named: true,
		},
		{
			name: "the token in the auth parameter",
			request: func(now int64) (string, http.Header) {
				return "projectId=" + testProjectId + "&auth=" + token(now, nil), http.Header{}
			},
			status: 101, body: fixed(accepted), named: true,
		},
		{
			name:    "an unknown parameter",
			request: with("projectId=" + testProjectId + "&foo=bar&ua=wc-2%2Fgo-0.1.0"),
			status:  101, body: fixed(accepted), named: true,
		},
		{
			name:    "an origin with no list",
			request: with("projectId="+testProjectId, "Origin", "https://ur.io"),
			status:  403, body: fixed(originRefused), named: true,
		},
		{
			name:    "an origin of the list",
			options: allowed,
			request: with("projectId="+testProjectId, "Origin", "https://ur.io"),
			status:  101, body: fixed(accepted), named: true,
		},
		{
			name:    "another origin",
			options: allowed,
			request: with("projectId="+testProjectId, "Origin", "https://example.org"),
			status:  403, body: fixed(originRefused), named: true,
		},
		{
			name:    "a bundle id as an origin",
			options: allowed,
			request: with("projectId="+testProjectId, "Origin", "network.ur"),
			status:  403, body: fixed(originRefused), named: true,
		},
		{
			name:    "a bundle id with no list",
			request: with("projectId=" + testProjectId + "&bundleId=network.ur"),
			status:  403, body: fixed(originRefused), named: true,
		},
		{
			name:    "a bundle id of the list",
			options: allowed,
			request: with("projectId=" + testProjectId + "&bundleId=network.ur"),
			status:  101, body: fixed(accepted), named: true,
		},
		{
			name:    "a bundle id of the list in capitals",
			options: allowed,
			request: with("projectId=" + testProjectId + "&bundleId=NETWORK.UR"),
			status:  101, body: fixed(accepted), named: true,
		},
		{
			name:    "another bundle id",
			options: allowed,
			request: with("projectId=" + testProjectId + "&bundleId=network.ur.extension"),
			status:  403, body: fixed(originRefused), named: true,
		},
		{
			name:    "an empty bundle id",
			options: allowed,
			request: with("projectId=" + testProjectId + "&bundleId="),
			status:  403, body: fixed(originRefused), named: true,
		},
		{
			name:    "a package name as a bundle id",
			options: allowed,
			request: with("projectId=" + testProjectId + "&bundleId=com.bringyour.network"),
			status:  403, body: fixed(originRefused), named: true,
		},
		{
			name:    "a package name with no list",
			request: with("projectId=" + testProjectId + "&packageName=com.bringyour.network"),
			status:  403, body: fixed(originRefused), named: true,
		},
		{
			name:    "a package name of the list",
			options: allowed,
			request: with("projectId=" + testProjectId + "&packageName=com.bringyour.network"),
			status:  101, body: fixed(accepted), named: true,
		},
		{
			name:    "another package name",
			options: allowed,
			request: with("projectId=" + testProjectId + "&packageName=com.bringyour.networkx"),
			status:  403, body: fixed(originRefused), named: true,
		},
		{
			name:    "a bundle id as a package name",
			options: allowed,
			request: with("projectId=" + testProjectId + "&packageName=network.ur"),
			status:  403, body: fixed(originRefused), named: true,
		},
		{
			name:    "an origin of the list decides before a bundle id",
			options: allowed,
			request: with("projectId="+testProjectId+"&bundleId=com.example.app", "Origin", "https://ur.io"),
			status:  101, body: fixed(accepted), named: true,
		},
		{
			name:    "another origin decides before a bundle id",
			options: allowed,
			request: with("projectId="+testProjectId+"&bundleId=network.ur", "Origin", "https://example.org"),
			status:  403, body: fixed(originRefused), named: true,
		},
		{
			name:    "a bundle id of the list decides before a package name",
			options: allowed,
			request: with("projectId=" + testProjectId + "&bundleId=network.ur&packageName=com.example.app"),
			status:  101, body: fixed(accepted), named: true,
		},
		{
			name:    "the project id is looked at before the token",
			request: func(int64) (string, http.Header) { return "", http.Header{} },
			status:  400, body: fixed(`{"error":"Project ID is missing"}`),
		},
		{
			name: "the token is looked at before the origin",
			request: func(int64) (string, http.Header) {
				header := http.Header{}
				header.Set("Origin", "https://example.org")
				return "projectId=" + testProjectId, header
			},
			status: 401, body: fixed(`{"error":"JWT is missing"}`),
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			inBubble(t, c.options, func(t *testing.T, relay *Relay) {
				now := time.Now().Unix()
				query, header := c.request(now)
				target := testRelayUrl
				if query != "" {
					target += "?" + query
				}
				status, body := knock(t, relay, target, header)
				if want := c.body(now); status != c.status || body != want {
					t.Fatalf("answered %d %s, want %d %s", status, body, c.status, want)
				}

				synctest.Wait()
				handshakes := relay.Handshakes()
				if len(handshakes) != 1 {
					t.Fatalf("%d handshakes recorded, want 1", len(handshakes))
				}
				recorded := handshakes[0]
				if recorded.Status != c.status || recorded.Body != c.body(now) {
					t.Fatalf("recorded %d %s, want %d %s", recorded.Status, recorded.Body, c.status, c.body(now))
				}
				if recorded.Host != testRelayHost {
					t.Fatalf("recorded the host %q, want %q", recorded.Host, testRelayHost)
				}
				if recorded.Query.Encode() != mustQuery(t, query) {
					t.Fatalf("recorded another query than the request's")
				}
				for name, values := range header {
					if !slices.Equal(recorded.Header[name], values) {
						t.Fatalf("the %s header is not recorded as it was sent", name)
					}
				}
				if _, sent := header["Origin"]; !sent {
					if _, found := recorded.Header["Origin"]; found {
						t.Fatal("recorded an Origin header that was not sent")
					}
				}
				wantId := ""
				if c.named {
					wantId = clientIdOf(seed)
				}
				if recorded.ClientId != wantId {
					t.Fatalf("recorded the client id %q, want %q", recorded.ClientId, wantId)
				}
				wantIds := []string{}
				if c.named {
					wantIds = append(wantIds, wantId)
				}
				if ids := relay.ClientIds(); !slices.Equal(ids, wantIds) {
					t.Fatalf("client ids %q, want %q", ids, wantIds)
				}
				if relay.Dials() != 1 {
					t.Fatalf("%d dials, want 1", relay.Dials())
				}
			})
		})
	}
}

func mustQuery(t *testing.T, query string) string {
	t.Helper()
	request, err := http.NewRequest(http.MethodGet, "https://"+testRelayHost+"/?"+query, nil)
	must(t, err)
	return request.URL.Query().Encode()
}

// A request that is no websocket upgrade is answered like the hosted relay
// answers it, before anything else is looked at.
func TestRelayAnswersARequestThatIsNoUpgrade(t *testing.T) {
	inBubble(t, RelayOptions{}, func(t *testing.T, relay *Relay) {
		conn, err := relay.DialTLS(t.Context(), "tcp", testRelayHost+":443")
		must(t, err)
		defer conn.Close()
		_, err = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+testRelayHost+"\r\n\r\n")
		must(t, err)
		response, err := http.ReadResponse(bufio.NewReader(conn), nil)
		must(t, err)
		body, _ := io.ReadAll(response.Body)
		const want = "Connection header did not include 'upgrade'"
		if response.StatusCode != 400 || string(body) != want {
			t.Fatalf("answered %d %s, want 400 %s", response.StatusCode, body, want)
		}
		synctest.Wait()
		handshakes := relay.Handshakes()
		if len(handshakes) != 1 || handshakes[0].Status != 400 || handshakes[0].Body != want || handshakes[0].ClientId != "" {
			t.Fatalf("recorded %d handshakes, want one with 400 and no client", len(handshakes))
		}

		// An upgrade request the relay has nothing against, and that is no
		// websocket handshake after all (it has no key): the refusal is the
		// websocket library's, and there was no socket.
		seed := testSeed(1)
		broken, err := relay.DialTLS(t.Context(), "tcp", testRelayHost+":443")
		must(t, err)
		defer broken.Close()
		_, err = io.WriteString(broken, "GET /?projectId="+testProjectId+" HTTP/1.1\r\nHost: "+testRelayHost+
			"\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nAuthorization: Bearer "+
			tokenOf(seed, claimsOf(seed, time.Now().Unix()))+"\r\n\r\n")
		must(t, err)
		response, err = http.ReadResponse(bufio.NewReader(broken), nil)
		must(t, err)
		if response.StatusCode != 400 {
			t.Fatalf("answered %d, want 400", response.StatusCode)
		}
		synctest.Wait()
		handshakes = relay.Handshakes()
		if len(handshakes) != 2 || handshakes[1].Status != 400 || handshakes[1].ClientId != clientIdOf(seed) {
			t.Fatalf("recorded %d handshakes, want a second one with 400 and the client", len(handshakes))
		}
		if open, timers := relay.OpenSockets(""), timersOf(relay); open != 0 || timers != 0 {
			t.Fatalf("%d open sockets and %d timers after a handshake that failed, want none", open, timers)
		}
		// the client's next socket is its first
		client := connect(t, relay, seed)
		client.subscribe(topicA)
		synctest.Wait()
		if frames := relay.Frames(client.clientId); len(frames) != 1 || frames[0].Socket != 1 {
			t.Fatalf("the socket after a handshake that failed is not the client's first: %v", frames)
		}
	})
}

// The handshake is recorded, and the socket counted, before the client has
// its answer: what a test reads right after a dial is the state after it.
func TestRelayHandshakeIsRecordedBeforeItIsAnswered(t *testing.T) {
	inBubble(t, RelayOptions{}, func(t *testing.T, relay *Relay) {
		seed := testSeed(1)
		ws, _, err := open(t.Context(), relay, testTarget, bearer(tokenOf(seed, claimsOf(seed, time.Now().Unix()))))
		must(t, err)
		defer ws.Close()
		// no synctest.Wait here
		if handshakes := relay.Handshakes(); len(handshakes) != 1 || handshakes[0].Status != 101 {
			t.Fatalf("%d handshakes recorded when the dial returned, want one with 101", len(handshakes))
		}
		if ids := relay.ClientIds(); !slices.Equal(ids, []string{clientIdOf(seed)}) {
			t.Fatalf("client ids %q when the dial returned", ids)
		}
		if open := relay.OpenSockets(clientIdOf(seed)); open != 1 {
			t.Fatalf("%d open sockets when the dial returned, want 1", open)
		}
	})
}

// SetOffline: dials fail at once, with connection refused. Sockets that
// are open stay.
func TestRelaySetOffline(t *testing.T) {
	inBubble(t, RelayOptions{}, func(t *testing.T, relay *Relay) {
		seed := testSeed(1)
		client := connect(t, relay, seed)
		header := bearer(tokenOf(seed, claimsOf(seed, time.Now().Unix())))

		relay.SetOffline(true)
		start := time.Now()
		_, _, err := open(t.Context(), relay, testTarget, header)
		if !errors.Is(err, syscall.ECONNREFUSED) {
			t.Fatalf("a dial while offline: %v, want connection refused", err)
		}
		if waited := time.Since(start); waited != 0 {
			t.Fatalf("a dial while offline failed after %v, want at once", waited)
		}
		if relay.Dials() != 2 || len(relay.Handshakes()) != 1 {
			t.Fatalf("%d dials and %d handshakes, want 2 and 1", relay.Dials(), len(relay.Handshakes()))
		}
		client.subscribed(topicA)
		if open := relay.OpenSockets(client.clientId); open != 1 {
			t.Fatalf("%d open sockets while offline, want the one that was open", open)
		}

		relay.SetOffline(false)
		connect(t, relay, seed)
		if relay.Dials() != 3 || relay.OpenSockets(client.clientId) != 2 {
			t.Fatalf("%d dials and %d open sockets after coming back, want 3 and 2", relay.Dials(), relay.OpenSockets(client.clientId))
		}
	})
}

// HangDials: the next n dials do not complete until their context ends.
func TestRelayHangDials(t *testing.T) {
	inBubble(t, RelayOptions{}, func(t *testing.T, relay *Relay) {
		seed := testSeed(1)
		header := bearer(tokenOf(seed, claimsOf(seed, time.Now().Unix())))
		relay.HangDials(2)
		for _, timeout := range []time.Duration{8 * time.Second, 3 * time.Second} {
			ctx, cancel := context.WithTimeout(t.Context(), timeout)
			start := time.Now()
			_, _, err := open(ctx, relay, testTarget, header)
			cancel()
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("a hung dial: %v, want the context's deadline", err)
			}
			if waited := time.Since(start); waited != timeout {
				t.Fatalf("a hung dial returned after %v, want %v", waited, timeout)
			}
		}
		if relay.Dials() != 2 || len(relay.Handshakes()) != 0 {
			t.Fatalf("%d dials and %d handshakes, want 2 and none", relay.Dials(), len(relay.Handshakes()))
		}
		connect(t, relay, seed)
		if relay.Dials() != 3 {
			t.Fatalf("%d dials, want 3", relay.Dials())
		}
		// a dial whose context is over is no dial
		over, cancel := context.WithCancel(t.Context())
		cancel()
		if _, err := relay.DialTLS(over, "tcp", testRelayHost+":443"); !errors.Is(err, context.Canceled) {
			t.Fatalf("a dial with a context that is over: %v", err)
		}

		// a dial that hangs when the relay closes is let go
		relay.HangDials(1)
		done := make(chan error, 1)
		go func() {
			_, _, err := open(t.Context(), relay, testTarget, header)
			done <- err
		}()
		synctest.Wait()
		relay.Close()
		synctest.Wait()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("a hung dial completed when the relay closed")
			}
		default:
			t.Fatal("a hung dial outlived the relay")
		}
	})
}

// RefuseHandshakes: the next n upgrades get this status and body.
func TestRelayRefuseHandshakes(t *testing.T) {
	inBubble(t, RelayOptions{}, func(t *testing.T, relay *Relay) {
		seed := testSeed(1)
		header := bearer(tokenOf(seed, claimsOf(seed, time.Now().Unix())))
		const body = `{"error":"Unauthorized: origin not allowed"}`
		relay.RefuseHandshakes(2, 403, body)
		for i := range 2 {
			if status, got := knock(t, relay, testTarget, header); status != 403 || got != body {
				t.Fatalf("handshake %d answered %d %s, want 403 %s", i+1, status, got, body)
			}
		}
		if status, _ := knock(t, relay, testTarget, header); status != 101 {
			t.Fatalf("the third handshake answered %d, want 101", status)
		}
		// a refused upgrade was no socket: the next one is the client's
		// second
		accepted := connect(t, relay, seed)
		accepted.subscribe(topicA)
		synctest.Wait()
		if frames := relay.Frames(accepted.clientId); len(frames) != 1 || frames[0].Socket != 2 {
			t.Fatalf("the socket after two refused upgrades and one accepted is not the second: %v", frames)
		}
		accepted.close()
		synctest.Wait()
		// a status the relay would never give by itself, and a request it
		// would have refused anyway
		relay.RefuseHandshakes(1, 503, "busy")
		if status, got := knock(t, relay, testRelayUrl, http.Header{}); status != 503 || got != "busy" {
			t.Fatalf("answered %d %s, want 503 busy", status, got)
		}
		if status, _ := knock(t, relay, testRelayUrl, http.Header{}); status != 400 {
			t.Fatalf("answered %d afterwards, want the relay's own 400", status)
		}

		synctest.Wait()
		var statuses []int
		var named []bool
		for _, handshake := range relay.Handshakes() {
			statuses = append(statuses, handshake.Status)
			named = append(named, handshake.ClientId == clientIdOf(seed))
		}
		if !slices.Equal(statuses, []int{403, 403, 101, 101, 503, 400}) || !slices.Equal(named, []bool{true, true, true, true, false, false}) {
			t.Fatalf("recorded the statuses %v (named %v)", statuses, named)
		}
		if open := relay.OpenSockets(""); open != 0 {
			t.Fatalf("%d open sockets, want none", open)
		}
	})
}

// CloseAfterUpgrade: the next n sockets are closed with this code right
// after the upgrade.
func TestRelayCloseAfterUpgrade(t *testing.T) {
	inBubble(t, RelayOptions{}, func(t *testing.T, relay *Relay) {
		seed := testSeed(1)
		relay.CloseAfterUpgrade(2, 4010)
		for i := range 2 {
			start := time.Now()
			client := connect(t, relay, seed)
			if code, text := closeCode(client.ended()); code != 4010 || text != loadBalancing {
				t.Fatalf("socket %d: close %d %q, want 4010 %q", i+1, code, text, loadBalancing)
			}
			if waited := time.Since(start); waited != 0 {
				t.Fatalf("socket %d was closed after %v, want at once", i+1, waited)
			}
		}
		client := connect(t, relay, seed)
		if err := client.ended(); err != nil {
			t.Fatalf("the third socket ended: %v", err)
		}
		client.subscribed(topicA)

		relay.CloseAfterUpgrade(1, 1001)
		if code, text := closeCode(connect(t, relay, seed).ended()); code != 1001 || text != "" {
			t.Fatalf("close %d %q, want 1001 with no reason", code, text)
		}

		synctest.Wait()
		handshakes := relay.Handshakes()
		for _, handshake := range handshakes {
			if handshake.Status != 101 {
				t.Fatalf("a handshake is recorded with %d, want 101 for all", handshake.Status)
			}
		}
		if len(handshakes) != 4 || relay.OpenSockets(client.clientId) != 1 {
			t.Fatalf("%d handshakes and %d open sockets, want 4 and 1", len(handshakes), relay.OpenSockets(client.clientId))
		}
		var closes []string
		for _, frame := range relay.Frames(client.clientId) {
			if strings.HasPrefix(frame.Text, "close ") {
				closes = append(closes, fmt.Sprintf("%d %s", frame.Socket, frame.Text))
			}
		}
		expect(t, "the close frames recorded", closes, "1 close 4010 "+loadBalancing, "2 close 4010 "+loadBalancing, "4 close 1001")
	})
}

// Drop: the connections are closed with no close frame.
func TestRelayDrop(t *testing.T) {
	inBubble(t, RelayOptions{}, func(t *testing.T, relay *Relay) {
		one := connect(t, relay, testSeed(1))
		oneAgain := connect(t, relay, testSeed(1))
		two := connect(t, relay, testSeed(2))
		three := connect(t, relay, testSeed(3))

		relay.Drop(one.clientId)
		for _, client := range []*rawClient{one, oneAgain} {
			if code, _ := closeCode(client.ended()); code != websocket.CloseAbnormalClosure {
				t.Fatalf("a dropped socket read %v, want the end of the connection with no close frame", client.ended())
			}
		}
		if err := two.ended(); err != nil {
			t.Fatalf("another client's socket ended: %v", err)
		}
		if relay.OpenSockets(one.clientId) != 0 || relay.OpenSockets("") != 2 {
			t.Fatalf("%d open sockets of the client and %d in all, want 0 and 2", relay.OpenSockets(one.clientId), relay.OpenSockets(""))
		}

		relay.Drop("")
		for _, client := range []*rawClient{two, three} {
			if code, _ := closeCode(client.ended()); code != websocket.CloseAbnormalClosure {
				t.Fatalf("a dropped socket read %v", client.ended())
			}
		}
		if relay.OpenSockets("") != 0 {
			t.Fatalf("%d open sockets, want none", relay.OpenSockets(""))
		}
		for _, frame := range relay.Frames("") {
			if strings.HasPrefix(frame.Text, "close ") {
				t.Fatalf("a close frame is recorded for a dropped socket: %s", frame.Text)
			}
		}

		// what was not acknowledged is still there for the client
		relay.Drop("nobody")
		back := connect(t, relay, testSeed(1))
		back.subscribed(topicA)
		go relay.Peer("sender").Publish(topicA, "answer", wire.TagSessionRequestResponse, wire.TtlFiveMinutes)
		expect(t, "live", told(back.take()), pushed(topicA, "answer", wire.TagSessionRequestResponse))
		relay.Drop(back.clientId)
		synctest.Wait()
		_, frames := connect(t, relay, testSeed(1)).subscribed(topicA)
		expect(t, "after the drop", told(frames), pushed(topicA, "answer", wire.TagSessionRequestResponse))

		// a publisher that waits for a socket is answered when the socket
		// is gone
		waiting := connect(t, relay, testSeed(4))
		silent := connect(t, relay, testSeed(5))
		silent.subscribed(topicB)
		id := waiting.publish(topicB, "held", wire.TagSessionRequestResponse, wire.TtlFiveMinutes)
		time.Sleep(2 * time.Second)
		expect(t, "the publisher, the recipient silent", told(waiting.take()))
		relay.Drop(silent.clientId)
		expect(t, "the publisher, the recipient dropped", told(waiting.take()), result(id, "true"))

		// a subscribe the relay had not answered when the socket was
		// dropped subscribed nothing: the topic does not know the client
		inFlight := connect(t, relay, testSeed(6))
		inFlight.subscribe(topicC)
		synctest.Wait()
		relay.Drop(inFlight.clientId)
		time.Sleep(time.Second)
		sender := relay.Peer("sender")
		must(t, sender.Publish(topicC, "settle", wire.TagSessionSettle, wire.TtlFiveMinutes))
		first := relay.Peer("first")
		must(t, first.Subscribe(topicC))
		expectMessages(t, "the first client that did subscribe", first, Message{Topic: topicC, Message: "settle", Tag: wire.TagSessionSettle})

		// with every socket gone no timer of the relay is left
		relay.Drop("")
		synctest.Wait()
		if timers := timersOf(relay); timers != 0 {
			t.Fatalf("%d timers left with no socket", timers)
		}
	})
}

// CloseSockets: a close frame with the code and the reason, behind what
// the relay had already written.
func TestRelayCloseSockets(t *testing.T) {
	inBubble(t, RelayOptions{}, func(t *testing.T, relay *Relay) {
		one := connect(t, relay, testSeed(1))
		two := connect(t, relay, testSeed(2))
		three := connect(t, relay, testSeed(3))

		id := one.publish(topicA, "last words", wire.TagSessionPing, wire.TtlPing)
		synctest.Wait()
		relay.CloseSockets(one.clientId, 4010, loadBalancing)
		if relay.OpenSockets(one.clientId) != 0 {
			t.Fatalf("%d open sockets right after the call, want none", relay.OpenSockets(one.clientId))
		}
		if code, text := closeCode(one.ended()); code != 4010 || text != loadBalancing {
			t.Fatalf("close %d %q, want 4010 %q", code, text, loadBalancing)
		}
		expect(t, "what the relay wrote before the close frame", told(one.take()), result(id, "true"))
		if err := two.ended(); err != nil {
			t.Fatalf("another client's socket ended: %v", err)
		}

		relay.CloseSockets("", 1012, "")
		for _, client := range []*rawClient{two, three} {
			if code, text := closeCode(client.ended()); code != 1012 || text != "" {
				t.Fatalf("close %d %q, want 1012 with no reason", code, text)
			}
		}
		if relay.OpenSockets("") != 0 {
			t.Fatalf("%d open sockets, want none", relay.OpenSockets(""))
		}
		var closes []string
		for _, frame := range relay.Frames("") {
			if !frame.ToRelay && strings.HasPrefix(frame.Text, "close ") {
				closes = append(closes, frame.Text)
			}
		}
		expect(t, "the close frames recorded", closes, "close 4010 "+loadBalancing, "close 1012", "close 1012")

		// what a client writes to a socket the relay has closed is not
		// taken. This client does not read, so the close frame is still on
		// its way when the call is written.
		seed := testSeed(4)
		ws, _, err := open(t.Context(), relay, testTarget, bearer(tokenOf(seed, claimsOf(seed, time.Now().Unix()))))
		must(t, err)
		defer ws.Close()
		relay.CloseSockets(clientIdOf(seed), 1000, "")
		published, recorded := len(relay.Published()), len(relay.Frames(clientIdOf(seed)))
		must(t, ws.WriteMessage(websocket.TextMessage, wire.RequestFrame(1, wire.MethodPublish, wire.PublishParams{Topic: topicB, Message: "too late", Ttl: wire.TtlFiveMinutes, Tag: wire.TagSessionRequest})))
		synctest.Wait()
		if len(relay.Published()) != published || len(relay.Frames(clientIdOf(seed))) != recorded {
			t.Fatal("a call on a socket the relay had closed was taken")
		}

		// a socket can be closed, or dropped, the moment its dial returns:
		// the relay may still be setting it up
		for range 50 {
			quick := connect(t, relay, testSeed(5))
			relay.CloseSockets(quick.clientId, 4010, loadBalancing)
			if code, text := closeCode(quick.ended()); code != 4010 || text != loadBalancing {
				t.Fatalf("closed right after the dial: close %d %q, want 4010 %q", code, text, loadBalancing)
			}
			quick = connect(t, relay, testSeed(5))
			relay.Drop(quick.clientId)
			if code, _ := closeCode(quick.ended()); code != websocket.CloseAbnormalClosure {
				t.Fatalf("dropped right after the dial: the client read %v", quick.ended())
			}
		}
		if open, timers := relay.OpenSockets(""), timersOf(relay); open != 0 || timers != 0 {
			t.Fatalf("%d open sockets and %d timers, want none", open, timers)
		}
	})
}

// A client that closes its socket is answered with its close frame, and the
// relay records the one it read: this is how a test tells a close from a
// drop.
func TestRelayRecordsAClientsCloseFrame(t *testing.T) {
	inBubble(t, RelayOptions{}, func(t *testing.T, relay *Relay) {
		closing := connect(t, relay, testSeed(1))
		leaving := connect(t, relay, testSeed(2))

		must(t, closing.ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, "done"), time.Now().Add(time.Second)))
		if code, text := closeCode(closing.ended()); code != websocket.CloseNormalClosure || text != "" {
			t.Fatalf("the relay answered close %d %q, want 1000 with no reason", code, text)
		}
		leaving.close()
		synctest.Wait()

		if relay.OpenSockets("") != 0 {
			t.Fatalf("%d open sockets, want none", relay.OpenSockets(""))
		}
		var closes []string
		for _, frame := range relay.Frames(closing.clientId) {
			closes = append(closes, fmt.Sprintf("%v %s", frame.ToRelay, frame.Text))
		}
		expect(t, "a socket that was closed", closes, "true close 1000 done", "false close 1000")
		if frames := relay.Frames(leaving.clientId); len(frames) != 0 {
			t.Fatalf("%d frames recorded for a socket that was let go, want none", len(frames))
		}
	})
}

// SetZombie: frames are swallowed in both directions and the connection
// is kept.
func TestRelaySetZombie(t *testing.T) {
	inBubble(t, RelayOptions{}, func(t *testing.T, relay *Relay) {
		seed := testSeed(1)
		sender := relay.Peer("sender")
		client := connect(t, relay, seed)
		client.subscribed(topicA)
		healthy := connect(t, relay, testSeed(2))

		relay.SetZombie(client.clientId, true)
		// towards the relay: a call is not answered
		lost := client.subscribe(topicB)
		time.Sleep(time.Second)
		expect(t, "a call into a zombie", told(client.take()))
		// towards the client: a push is not read, so the publisher waits
		start := time.Now()
		must(t, sender.Publish(topicA, "answer", wire.TagSessionProposeApprove, wire.TtlFiveMinutes))
		if held := time.Since(start); held != 6*time.Second {
			t.Fatalf("a publish to a zombie returned after %v, want 6s", held)
		}
		// the subscribe that was swallowed subscribed nothing: nobody is
		// waited for
		start = time.Now()
		must(t, sender.Publish(topicB, "never subscribed", wire.TagSessionSettle, wire.TtlFiveMinutes))
		if held := time.Since(start); held != 0 {
			t.Fatalf("a publish to the topic of a swallowed subscribe was held %v", held)
		}
		expect(t, "a push to a zombie", told(client.take()))
		// nor did a publish that was swallowed publish
		published := len(relay.Published())
		client.publish(topicD, "swallowed", wire.TagSessionRequest, wire.TtlFiveMinutes)
		synctest.Wait()
		if got := len(relay.Published()); got != published {
			t.Fatalf("the publish of a zombie was taken")
		}
		if err := client.ended(); err != nil || relay.OpenSockets(client.clientId) != 1 {
			t.Fatalf("the connection of a zombie is kept: ended %v, %d open", err, relay.OpenSockets(client.clientId))
		}
		// another client is not touched
		healthy.subscribed(topicC)

		// what the client wrote is recorded, what it was not sent is not
		var texts []string
		for _, frame := range relay.Frames(client.clientId)[2:] {
			texts = append(texts, fmt.Sprintf("%v %s", frame.ToRelay, frame.Text))
		}
		expect(t, "recorded while a zombie", texts,
			"true "+string(wire.RequestFrame(lost, wire.MethodSubscribe, wire.SubscribeParams{Topic: topicB})),
			"true "+string(wire.RequestFrame(lost+1, wire.MethodPublish, wire.PublishParams{Topic: topicD, Message: "swallowed", Ttl: wire.TtlFiveMinutes, Tag: wire.TagSessionRequest})),
		)

		// back to life: nothing comes by itself, the subscribe that was
		// swallowed had no effect, and the next one reads the mailbox
		relay.SetZombie(client.clientId, false)
		time.Sleep(time.Second)
		expect(t, "after the zombie", told(client.take()))
		_, frames := client.subscribed(topicA)
		expect(t, "subscribed again", told(frames), pushed(topicA, "answer", wire.TagSessionProposeApprove))
		client.ack(frames[0])
		_, frames = client.subscribed(topicB)
		expect(t, "the topic of the swallowed subscribe", told(frames), pushed(topicB, "never subscribed", wire.TagSessionSettle))
		must(t, sender.Subscribe(topicD))
		expectMessages(t, "the topic of the swallowed publish", sender)

		// every socket client at once, and a socket opened afterwards is
		// healthy
		relay.SetZombie("", true)
		healthy.subscribe(topicA)
		client.subscribe(topicC)
		time.Sleep(time.Second)
		expect(t, "one zombie of all", told(healthy.take()))
		expect(t, "another zombie of all", told(client.take()))
		connect(t, relay, testSeed(3)).subscribed(topicA)
		must(t, sender.Subscribe(topicC))
		relay.SetZombie("", false)
		healthy.subscribed(topicA)
	})
}

// A zombie the client let go of is still a socket to the relay, which hears
// nothing of it: until the ping that is not answered, or until the zombie is
// lifted.
func TestRelayKeepsAZombieTheClientLetGo(t *testing.T) {
	inBubble(t, RelayOptions{}, func(t *testing.T, relay *Relay) {
		seed := testSeed(1)
		client := connect(t, relay, seed)
		relay.SetZombie(client.clientId, true)
		client.close()
		time.Sleep(59 * time.Second)
		if open := relay.OpenSockets(client.clientId); open != 1 {
			t.Fatalf("%d open sockets at 59 s, want the zombie", open)
		}
		time.Sleep(time.Second)
		synctest.Wait()
		if open := relay.OpenSockets(client.clientId); open != 0 {
			t.Fatalf("%d open sockets at 60 s, want none", open)
		}

		// a client that closes its zombie with a close frame is not heard
		// either
		other := connect(t, relay, testSeed(2))
		gone := connect(t, relay, testSeed(2))
		relay.SetZombie(other.clientId, true)
		must(t, other.ws.WriteControl(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(time.Second)))
		other.close()
		gone.close()
		synctest.Wait()
		if open := relay.OpenSockets(other.clientId); open != 2 {
			t.Fatalf("%d open sockets, want the two zombies", open)
		}
		relay.SetZombie(other.clientId, false)
		if open := relay.OpenSockets(other.clientId); open != 0 {
			t.Fatalf("%d open sockets after the zombie was lifted, want none", open)
		}

		// a pong out of a zombie is not heard either: the socket is closed
		// when its second ping would be due
		mute := connect(t, relay, testSeed(3))
		relay.SetZombie(mute.clientId, true)
		time.Sleep(31 * time.Second)
		must(t, mute.ws.WriteControl(websocket.PongMessage, []byte("relaytest"), time.Now().Add(time.Second)))
		time.Sleep(29 * time.Second)
		synctest.Wait()
		if open := relay.OpenSockets(mute.clientId); open != 0 {
			t.Fatalf("%d open sockets 60 s after a zombie was made, want none", open)
		}
		if pings, _ := mute.pinged(); len(pings) != 0 {
			t.Fatalf("a zombie was pinged at %v", pings)
		}
	})
}

// A peer can be a zombie too: it is how a test has a wallet that is there
// and says nothing.
func TestRelaySetZombieOnAPeer(t *testing.T) {
	inBubble(t, RelayOptions{}, func(t *testing.T, relay *Relay) {
		wallet := relay.Peer("wallet")
		must(t, wallet.Subscribe(topicA))
		dapp := connect(t, relay, testSeed(1))

		relay.SetZombie("wallet", true)
		relay.SetAckHold(6100 * time.Millisecond)
		request := dapp.publish(topicA, "request", wire.TagSessionRequest, wire.TtlFiveMinutes)
		time.Sleep(6100*time.Millisecond - time.Millisecond)
		expect(t, "the dapp, a wallet that says nothing", told(dapp.take()))
		time.Sleep(time.Millisecond)
		expect(t, "the dapp, at 6.1 s", told(dapp.take()), result(request, "true"))
		relay.SetAckHold(12 * time.Second)
		second := dapp.publish(topicA, "second request", wire.TagSessionRequest, wire.TtlFiveMinutes)
		time.Sleep(12*time.Second - time.Millisecond)
		expect(t, "the dapp, a wallet that says nothing", told(dapp.take()))
		time.Sleep(time.Millisecond)
		expect(t, "the dapp, at 12 s", told(dapp.take()), result(second, "true"))
		expectMessages(t, "the wallet, a zombie", wallet)
		if err := wallet.Publish(topicA, "response", wire.TagSessionRequestResponse, wire.TtlFiveMinutes); err == nil {
			t.Fatal("a zombie published")
		}
		if err := wallet.Subscribe(topicA); err == nil {
			t.Fatal("a zombie subscribed")
		}
		if published := relay.Published(); len(published) != 2 {
			t.Fatalf("%d publishes recorded, want the dapp's two", len(published))
		}

		// every socket client is not every peer
		relay.SetZombie("wallet", false)
		relay.SetZombie("", true)
		must(t, wallet.Subscribe(topicA))
		expectMessages(t, "the wallet, back", wallet,
			Message{Topic: topicA, Message: "request", Tag: wire.TagSessionRequest},
			Message{Topic: topicA, Message: "second request", Tag: wire.TagSessionRequest},
		)
		relay.SetZombie("", false)
	})
}

// LoseNextPublishAck: the next irn_publish is accepted and never
// answered.
func TestRelayLoseNextPublishAck(t *testing.T) {
	inBubble(t, RelayOptions{}, func(t *testing.T, relay *Relay) {
		client := connect(t, relay, testSeed(1))
		other := connect(t, relay, testSeed(2))
		wallet := relay.Peer("wallet")
		must(t, wallet.Subscribe(topicA))

		relay.LoseNextPublishAck(client.clientId)
		kept := other.publish(topicA, "another client's", wire.TagSessionRequest, wire.TtlFiveMinutes)
		// two sockets have two readers: the relay takes their frames in the
		// order they were written only when the first was taken before the
		// second is written
		synctest.Wait()
		client.publish(topicA, "request", wire.TagSessionRequest, wire.TtlFiveMinutes)
		next := client.publish(topicA, "next", wire.TagSessionRequest, wire.TtlFiveMinutes)
		time.Sleep(60 * time.Second)
		expect(t, "the client", told(client.take()), result(next, "true"))
		expect(t, "another client", told(other.take()), result(kept, "true"))
		expectMessages(t, "the wallet", wallet,
			Message{Topic: topicA, Message: "another client's", Tag: wire.TagSessionRequest},
			Message{Topic: topicA, Message: "request", Tag: wire.TagSessionRequest},
			Message{Topic: topicA, Message: "next", Tag: wire.TagSessionRequest},
		)
		if published := relay.Published(); len(published) != 3 || published[1].Message != "request" {
			t.Fatalf("%d publishes recorded, want 3 with the unanswered one second", len(published))
		}

		// any socket client
		relay.LoseNextPublishAck("")
		must(t, wallet.Publish(topicB, "a peer's", wire.TagSessionRequest, wire.TtlFiveMinutes))
		other.publish(topicA, "lost", wire.TagSessionRequest, wire.TtlFiveMinutes)
		synctest.Wait()
		found := client.publish(topicA, "found", wire.TagSessionRequest, wire.TtlFiveMinutes)
		time.Sleep(60 * time.Second)
		expect(t, "the client whose result was lost", told(other.take()))
		expect(t, "the client after it", told(client.take()), result(found, "true"))
	})
}

// DuplicateNextPush: the next push of the topic to a socket is written
// twice.
func TestRelayDuplicateNextPush(t *testing.T) {
	inBubble(t, RelayOptions{}, func(t *testing.T, relay *Relay) {
		dapp := connect(t, relay, testSeed(1))
		dapp.subscribed(topicA)
		dapp.subscribed(topicB)
		wallet := relay.Peer("wallet")
		must(t, wallet.Subscribe(topicA))

		relay.DuplicateNextPush(topicA)
		// a push to a peer, and one on another topic, are not the one
		request := dapp.publish(topicA, "request", wire.TagSessionRequest, wire.TtlFiveMinutes)
		expect(t, "the dapp", told(dapp.take()), result(request, "true"))
		expectMessages(t, "the wallet", wallet, Message{Topic: topicA, Message: "request", Tag: wire.TagSessionRequest})
		go wallet.Publish(topicB, "on another topic", wire.TagSessionSettle, wire.TtlFiveMinutes)
		frames := dapp.take()
		expect(t, "another topic", told(frames), pushed(topicB, "on another topic", wire.TagSessionSettle))
		dapp.ack(frames[0])

		go wallet.Publish(topicA, "response", wire.TagSessionRequestResponse, wire.TtlFiveMinutes)
		frames = dapp.take()
		response := pushed(topicA, "response", wire.TagSessionRequestResponse)
		expect(t, "the duplicated push", told(frames), response, response)
		if string(frames[0].Id) == string(frames[1].Id) {
			t.Fatalf("the two pushes have one id, %s", string(frames[0].Id))
		}
		// either acknowledgement takes the message
		dapp.ack(frames[1])
		_, frames = dapp.subscribed(topicA)
		expect(t, "acknowledged", told(frames))

		// once
		go wallet.Publish(topicA, "second response", wire.TagSessionRequestResponse, wire.TtlFiveMinutes)
		frames = dapp.take()
		expect(t, "the next push", told(frames), pushed(topicA, "second response", wire.TagSessionRequestResponse))
		dapp.ack(frames[0])

		// a push out of the mailbox is duplicated like a live one
		relay.DuplicateNextPush(topicC)
		must(t, wallet.Publish(topicC, "stored", wire.TagSessionSettle, wire.TtlFiveMinutes))
		_, frames = dapp.subscribed(topicC)
		stored := pushed(topicC, "stored", wire.TagSessionSettle)
		expect(t, "out of the mailbox", told(frames), stored, stored)
	})
}

// FailCalls: a json-rpc error to the next n calls of a method, of a
// socket client.
func TestRelayFailCalls(t *testing.T) {
	inBubble(t, RelayOptions{}, func(t *testing.T, relay *Relay) {
		client := connect(t, relay, testSeed(1))
		peer := relay.Peer("peer")

		relay.FailCalls(wire.MethodSubscribe, 2, -32000, "boom")
		must(t, peer.Subscribe(topicA))
		must(t, peer.Publish(topicA, "stored", wire.TagSessionSettle, wire.TtlFiveMinutes))
		var ids []int64
		for range 3 {
			id := client.subscribe(topicA)
			ids = append(ids, id)
			// one at a time: the relay has answered before the next is
			// written
			time.Sleep(subscribeLatency)
			synctest.Wait()
		}
		frames := client.take()
		if len(frames) != 4 || frames[2].Error != nil {
			t.Fatalf("three subscribes with two failures: %q", told(frames))
		}
		expect(t, "three subscribes with two failures", told(frames),
			failed(ids[0], -32000, "boom"),
			failed(ids[1], -32000, "boom"),
			fmt.Sprintf("result %d %s", ids[2], string(frames[2].Result)),
			pushed(topicA, "stored", wire.TagSessionSettle),
		)
		client.ack(frames[3])

		// a failed subscribe subscribed nothing
		relay.FailCalls(wire.MethodSubscribe, 1, -32000, "boom")
		failedSubscribe := client.subscribe(topicB)
		time.Sleep(subscribeLatency)
		expect(t, "a failed subscribe", told(client.take()), failed(failedSubscribe, -32000, "boom"))
		start := time.Now()
		must(t, peer.Publish(topicB, "not pushed", wire.TagSessionSettle, wire.TtlFiveMinutes))
		if held := time.Since(start); held != 0 {
			t.Fatalf("a publish to the topic of a failed subscribe was held %v", held)
		}
		expect(t, "after a failed subscribe", told(client.take()))

		// a failed publish stored nothing
		relay.FailCalls(wire.MethodPublish, 1, 4000, "no")
		before := len(relay.Published())
		refused := client.publish(topicC, "refused", wire.TagSessionRequest, wire.TtlFiveMinutes)
		taken := client.publish(topicC, "taken", wire.TagSessionRequest, wire.TtlFiveMinutes)
		expect(t, "two publishes with one failure", told(client.take()), failed(refused, 4000, "no"), result(taken, "true"))
		must(t, peer.Subscribe(topicC))
		expectMessages(t, "the peer", peer, Message{Topic: topicC, Message: "taken", Tag: wire.TagSessionRequest})
		if recorded := len(relay.Published()) - before; recorded != 1 {
			t.Fatalf("%d publishes recorded, want the one that was taken", recorded)
		}

		// another method is not touched, and a new call replaces the old one
		relay.FailCalls(wire.MethodUnsubscribe, 5, 1, "old")
		relay.FailCalls(wire.MethodUnsubscribe, 1, 2, "new")
		ok := client.publish(topicC, "fine", wire.TagSessionRequest, wire.TtlFiveMinutes)
		first := client.call(wire.MethodUnsubscribe, wire.UnsubscribeParams{Topic: topicA, Id: "any"})
		second := client.call(wire.MethodUnsubscribe, wire.UnsubscribeParams{Topic: topicA, Id: "any"})
		expect(t, "a publish and two unsubscribes", told(client.take()), result(ok, "true"), failed(first, 2, "new"), result(second, "true"))

		// none: the failures that are left are taken back
		relay.FailCalls(wire.MethodPublish, 3, 4000, "no")
		relay.FailCalls(wire.MethodPublish, 0, 4000, "no")
		ok = client.publish(topicC, "fine again", wire.TagSessionRequest, wire.TtlFiveMinutes)
		expect(t, "a publish after the failures were taken back", told(client.take()), result(ok, "true"))
	})
}

// SendOversized: one text frame of this size.
func TestRelaySendOversized(t *testing.T) {
	inBubble(t, RelayOptions{}, func(t *testing.T, relay *Relay) {
		const limit = 1 << 20
		limited := connectWith(t, relay, testSeed(1), func(ws *websocket.Conn) { ws.SetReadLimit(limit) })
		unlimited := connect(t, relay, testSeed(2))
		limited.subscribed(topicA)

		relay.SendOversized(limited.clientId, limit)
		if sizes := limited.otherFrames(); !slices.Equal(sizes, []int{limit}) {
			t.Fatalf("a frame of the limit: read frames of %v bytes", sizes)
		}
		relay.SendOversized("", limit+1)
		if err := limited.ended(); !errors.Is(err, websocket.ErrReadLimit) {
			t.Fatalf("a frame above the limit: the reader ended with %v, want the read limit", err)
		}
		if sizes := unlimited.otherFrames(); !slices.Equal(sizes, []int{limit + 1}) {
			t.Fatalf("a client with no limit read frames of %v bytes", sizes)
		}
		if open := relay.OpenSockets(limited.clientId); open != 0 {
			t.Fatalf("%d open sockets of the client that let go, want none", open)
		}
	})
}

// Two subscribes written back to back can receive a stored push before
// the result of its topic: the stored messages of the first topic come
// before any result, the results come last call first, and the stored
// messages of the other topics follow them.
func TestRelayBackToBackSubscribes(t *testing.T) {
	inBubble(t, RelayOptions{}, func(t *testing.T, relay *Relay) {
		sender := relay.Peer("sender")
		must(t, sender.Publish(topicA, "pairing answer", wire.TagSessionProposeApprove, wire.TtlFiveMinutes))
		must(t, sender.Publish(topicA, "pairing delete", wire.TagPairingDelete, wire.TtlOneDay))
		must(t, sender.Publish(topicB, "settle", wire.TagSessionSettle, wire.TtlFiveMinutes))
		client := connect(t, relay, testSeed(1))

		a := client.subscribe(topicA)
		b := client.subscribe(topicB)
		c := client.subscribe(topicC)
		expect(t, "before the relay answers", told(client.take()))
		time.Sleep(subscribeLatency)
		frames := client.take()
		if len(frames) != 6 {
			t.Fatalf("three subscribes back to back: %q", told(frames))
		}
		expect(t, "three subscribes back to back", told(frames),
			pushed(topicA, "pairing answer", wire.TagSessionProposeApprove),
			pushed(topicA, "pairing delete", wire.TagPairingDelete),
			fmt.Sprintf("result %d %s", c, string(frames[2].Result)),
			fmt.Sprintf("result %d %s", b, string(frames[3].Result)),
			fmt.Sprintf("result %d %s", a, string(frames[4].Result)),
			pushed(topicB, "settle", wire.TagSessionSettle),
		)
		for _, frame := range frames[2:5] {
			var subscriptionId string
			if err := json.Unmarshal(frame.Result, &subscriptionId); err != nil || !isHex64(subscriptionId) {
				t.Fatalf("a result is no subscription id: %q", told(frames))
			}
		}

		// one at a time: the result first (subscribed insists on it)
		must(t, sender.Publish(topicD, "stored", wire.TagSessionRequestResponse, wire.TtlFiveMinutes))
		other := connect(t, relay, testSeed(2))
		_, frames = other.subscribed(topicD)
		expect(t, "one subscribe with a stored message", told(frames), pushed(topicD, "stored", wire.TagSessionRequestResponse))

		// another call ends the wait for more subscribes, so that the
		// calls of a socket take effect in their order
		fresh := connect(t, relay, testSeed(3))
		must(t, sender.Publish(topicE, "for the fresh one", wire.TagSessionRequestResponse, wire.TtlFiveMinutes))
		subscribe := fresh.subscribe(topicE)
		publish := fresh.publish(topicF, "published behind a subscribe", wire.TagSessionRequest, wire.TtlFiveMinutes)
		unsubscribe := fresh.call(wire.MethodUnsubscribe, wire.UnsubscribeParams{Topic: topicE, Id: "any"})
		frames = fresh.take()
		if len(frames) != 4 {
			t.Fatalf("a subscribe, a publish and an unsubscribe back to back: %q", told(frames))
		}
		expect(t, "a subscribe, a publish and an unsubscribe back to back", told(frames),
			fmt.Sprintf("result %d %s", subscribe, string(frames[0].Result)),
			pushed(topicE, "for the fresh one", wire.TagSessionRequestResponse),
			result(publish, "true"),
			result(unsubscribe, "true"),
		)
		// the unsubscribe came last and counts
		start := time.Now()
		must(t, sender.Publish(topicE, "after the unsubscribe", wire.TagSessionRequestResponse, wire.TtlFiveMinutes))
		if held := time.Since(start); held != 0 {
			t.Fatalf("a publish to an unsubscribed socket was held %v", held)
		}
		expect(t, "after the unsubscribe", told(fresh.take()))
	})
}

// A client that does not read what it is sent is let go after five seconds:
// nothing in the relay waits for it for ever.
func TestRelayLetsGoOfAClientThatDoesNotRead(t *testing.T) {
	inBubble(t, RelayOptions{}, func(t *testing.T, relay *Relay) {
		seed := testSeed(1)
		ws, _, err := open(t.Context(), relay, testTarget, bearer(tokenOf(seed, claimsOf(seed, time.Now().Unix()))))
		must(t, err)
		defer ws.Close()
		// a call, and nobody reads the answer
		must(t, ws.WriteMessage(websocket.TextMessage, wire.RequestFrame(1, wire.MethodUnsubscribe, wire.UnsubscribeParams{Topic: topicA, Id: "any"})))
		time.Sleep(5*time.Second - time.Millisecond)
		synctest.Wait()
		if open := relay.OpenSockets(clientIdOf(seed)); open != 1 {
			t.Fatalf("%d open sockets before five seconds have passed, want 1", open)
		}
		time.Sleep(time.Millisecond)
		synctest.Wait()
		if open := relay.OpenSockets(clientIdOf(seed)); open != 0 {
			t.Fatalf("%d open sockets after five seconds, want none", open)
		}
		if _, _, err := ws.ReadMessage(); err == nil {
			t.Fatal("the client read a frame from a socket the relay let go of")
		}
	})
}

// What is not a call the relay knows is answered with an error or not at
// all, and breaks nothing.
func TestRelayOtherFrames(t *testing.T) {
	inBubble(t, RelayOptions{}, func(t *testing.T, relay *Relay) {
		client := connect(t, relay, testSeed(1))
		fetch := client.call("irn_fetchMessages", wire.SubscribeParams{Topic: topicA})
		client.send([]byte("not json"))
		client.send([]byte(`{"id":1,"jsonrpc":"2.0","result":true}`))
		must(t, client.ws.WriteMessage(websocket.BinaryMessage, []byte{0, 1, 2}))
		noTopic := client.call(wire.MethodSubscribe, wire.SubscribeParams{})
		noParams := client.call(wire.MethodPublish, "text")
		nothing := client.call(wire.MethodUnsubscribe, wire.UnsubscribeParams{})
		time.Sleep(subscribeLatency)
		expect(t, "the client", told(client.take()),
			failed(fetch, -32601, "Method not found"),
			failed(noTopic, -32602, "Invalid params"),
			failed(noParams, -32602, "Invalid params"),
			failed(nothing, -32602, "Invalid params"),
		)
		client.subscribed(topicA)
		if recorded := len(relay.Frames(client.clientId)); recorded != 12 {
			t.Fatalf("%d frames recorded, want the seven text frames of the client and the five of the relay", recorded)
		}
		peer := relay.Peer("peer")
		if peer.Subscribe("") == nil || peer.Publish("", "to nowhere", wire.TagSessionPing, wire.TtlPing) == nil {
			t.Fatal("a peer subscribed to no topic, or published to none")
		}
		if published := relay.Published(); len(published) != 0 {
			t.Fatalf("%d publishes recorded, want none", len(published))
		}
	})
}

// Dials, Handshakes, ClientIds, OpenSockets, Published and Frames.
func TestRelayObservation(t *testing.T) {
	inBubble(t, RelayOptions{}, func(t *testing.T, relay *Relay) {
		seedA, seedB := testSeed(1), testSeed(2)
		idA, idB := clientIdOf(seedA), clientIdOf(seedB)
		start := time.Now()

		if relay.Dials() != 0 || len(relay.Handshakes()) != 0 || len(relay.ClientIds()) != 0 || relay.OpenSockets("") != 0 || len(relay.Published()) != 0 || len(relay.Frames("")) != 0 {
			t.Fatal("a new relay has seen something")
		}
		a := connect(t, relay, seedA)
		b := connect(t, relay, seedB)
		time.Sleep(time.Second)
		a2 := connect(t, relay, seedA)
		peer := relay.Peer("peer")
		if ids := relay.ClientIds(); !slices.Equal(ids, []string{idA, idB}) {
			t.Fatalf("client ids %q, want the two socket clients in the order of their first handshake", ids)
		}
		if relay.Dials() != 3 || len(relay.Handshakes()) != 3 {
			t.Fatalf("%d dials and %d handshakes, want 3 and 3", relay.Dials(), len(relay.Handshakes()))
		}
		if relay.OpenSockets(idA) != 2 || relay.OpenSockets(idB) != 1 || relay.OpenSockets("") != 3 || relay.OpenSockets("peer") != 0 {
			t.Fatalf("open sockets: %d, %d, %d in all, %d of a peer", relay.OpenSockets(idA), relay.OpenSockets(idB), relay.OpenSockets(""), relay.OpenSockets("peer"))
		}
		a.close()
		synctest.Wait()
		if relay.OpenSockets(idA) != 1 {
			t.Fatalf("%d open sockets after one was closed, want 1", relay.OpenSockets(idA))
		}

		// frames, with the socket they were on and the time
		subscribe := a2.subscribe(topicA)
		time.Sleep(subscribeLatency)
		frames := a2.take()
		publish := a2.publish(topicB, "from a socket", wire.TagSessionRequest, wire.TtlFiveMinutes)
		a2.take()
		must(t, peer.Publish(topicB, "from a peer", wire.TagSessionRequestResponse, wire.TtlOneDay))
		b.subscribe(topicC)
		time.Sleep(subscribeLatency)
		b.take()

		want := []RecordedFrame{
			{Socket: 2, ToRelay: true, Text: string(wire.RequestFrame(subscribe, wire.MethodSubscribe, wire.SubscribeParams{Topic: topicA})), At: start.Add(time.Second)},
			{Socket: 2, ToRelay: false, Text: `{"id":` + strconv.FormatInt(subscribe, 10) + `,"jsonrpc":"2.0","result":` + string(frames[0].Result) + `}`, At: start.Add(time.Second + subscribeLatency)},
			{Socket: 2, ToRelay: true, Text: string(wire.RequestFrame(publish, wire.MethodPublish, wire.PublishParams{Topic: topicB, Message: "from a socket", Ttl: wire.TtlFiveMinutes, Tag: wire.TagSessionRequest})), At: start.Add(time.Second + subscribeLatency)},
			{Socket: 2, ToRelay: false, Text: `{"id":` + strconv.FormatInt(publish, 10) + `,"jsonrpc":"2.0","result":true}`, At: start.Add(time.Second + subscribeLatency)},
		}
		if got := relay.Frames(idA); !sameFrames(got, want) {
			t.Fatalf("the frames of a client:\n got  %v\n want %v", got, want)
		}
		framesOfB := relay.Frames(idB)
		if len(framesOfB) != 2 || framesOfB[0].Socket != 1 || !framesOfB[0].ToRelay || framesOfB[1].ToRelay {
			t.Fatalf("the frames of the other client: %v", framesOfB)
		}
		if all := relay.Frames(""); len(all) != 6 || !sameFrames(all[:4], want) || !sameFrames(all[4:], framesOfB) {
			t.Fatalf("the frames of every client: %v", all)
		}
		if frames := relay.Frames("peer"); len(frames) != 0 {
			t.Fatalf("%d frames of a peer, want none", len(frames))
		}

		wantPublished := []Published{
			{ClientId: idA, Topic: topicB, Message: "from a socket", Tag: wire.TagSessionRequest, Ttl: wire.TtlFiveMinutes, At: start.Add(time.Second + subscribeLatency)},
			{ClientId: "peer", Topic: topicB, Message: "from a peer", Tag: wire.TagSessionRequestResponse, Ttl: wire.TtlOneDay, At: start.Add(time.Second + subscribeLatency)},
		}
		if got := relay.Published(); !slices.EqualFunc(got, wantPublished, func(a Published, b Published) bool {
			return a.ClientId == b.ClientId && a.Topic == b.Topic && a.Message == b.Message && a.Tag == b.Tag && a.Ttl == b.Ttl && a.At.Equal(b.At)
		}) {
			t.Fatalf("published:\n got  %v\n want %v", got, wantPublished)
		}

		// what is returned is the caller's own
		relay.Handshakes()[0].Query.Set("projectId", "changed")
		relay.Handshakes()[0].Header.Set("Authorization", "changed")
		relay.ClientIds()[0] = "changed"
		relay.Published()[0].Message = "changed"
		relay.Frames("")[0].Text = "changed"
		if handshake := relay.Handshakes()[0]; handshake.Query.Get("projectId") != testProjectId || handshake.Header.Get("Authorization") == "changed" {
			t.Fatal("a caller changed a recorded handshake")
		}
		if relay.ClientIds()[0] != idA || relay.Published()[0].Message != "from a socket" || relay.Frames("")[0].Text != want[0].Text {
			t.Fatal("a caller changed what the relay recorded")
		}
	})
}

func sameFrames(got []RecordedFrame, want []RecordedFrame) bool {
	return slices.EqualFunc(got, want, func(a RecordedFrame, b RecordedFrame) bool {
		return a.Socket == b.Socket && a.ToRelay == b.ToRelay && a.Text == b.Text && a.At.Equal(b.At)
	})
}

// The clock of the options dates what the relay records and decides what a
// token and a message are worth.
func TestRelayNow(t *testing.T) {
	var clock atomic.Int64
	clock.Store(1_700_000_000)
	inBubble(t, RelayOptions{Now: func() time.Time { return time.Unix(clock.Load(), 0) }}, func(t *testing.T, relay *Relay) {
		now := time.Unix(clock.Load(), 0)
		seed := testSeed(1)
		// a token of the bubble's time, the year 2000, is long expired
		stale := bearer(tokenOf(seed, claimsOf(seed, time.Now().Unix())))
		if status, _ := knock(t, relay, testTarget, stale); status != 401 {
			t.Fatalf("a token of another time was answered %d, want 401", status)
		}
		ws, _, err := open(t.Context(), relay, testTarget, bearer(tokenOf(seed, claimsOf(seed, now.Unix()))))
		must(t, err)
		must(t, ws.WriteMessage(websocket.TextMessage, wire.RequestFrame(1, wire.MethodUnsubscribe, wire.UnsubscribeParams{Topic: topicA, Id: "any"})))
		synctest.Wait()
		if frames := relay.Frames(""); len(frames) != 2 || !frames[0].At.Equal(now) || !frames[1].At.Equal(now) {
			t.Fatalf("frames dated at another time than the options' clock")
		}
		ws.Close()

		sender, receiver := relay.Peer("sender"), relay.Peer("receiver")
		must(t, sender.Publish(topicA, "kept", wire.TagSessionPropose, wire.TtlFiveMinutes))
		must(t, sender.Publish(topicB, "gone", wire.TagSessionPropose, wire.TtlFiveMinutes))
		if published := relay.Published(); len(published) != 2 || !published[0].At.Equal(now) {
			t.Fatalf("published at another time than the options' clock")
		}
		// the bubble's clock does not age a message
		time.Sleep(time.Hour)
		must(t, receiver.Subscribe(topicA))
		expectMessages(t, "an hour of the bubble later", receiver, Message{Topic: topicA, Message: "kept", Tag: wire.TagSessionPropose})
		// the options' clock does
		clock.Add(300)
		must(t, receiver.Subscribe(topicB))
		expectMessages(t, "five minutes of the options' clock later", receiver)
	})
}

// Close ends everything: sockets, peers, held publishes, the handshake of a
// client that never sent its request. It can be called twice, and what is
// asked of a closed relay fails.
func TestRelayClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		relay := NewRelay(RelayOptions{})
		seed := testSeed(1)
		header := bearer(tokenOf(seed, claimsOf(seed, time.Now().Unix())))
		client := connect(t, relay, seed)
		client.subscribed(topicA)
		peer := relay.Peer("peer")
		idle, err := relay.DialTLS(t.Context(), "tcp", testRelayHost+":443")
		must(t, err)
		held := make(chan error, 1)
		go func() {
			held <- peer.Publish(topicA, "held", wire.TagSessionRequestResponse, wire.TtlFiveMinutes)
		}()
		// a subscribe that is not answered yet
		client.subscribe(topicB)
		// and a socket the relay is closing, whose client does not read the
		// close frame
		stuckSeed := testSeed(2)
		stuck, _, err := open(t.Context(), relay, testTarget, bearer(tokenOf(stuckSeed, claimsOf(stuckSeed, time.Now().Unix()))))
		must(t, err)
		defer stuck.Close()
		relay.CloseSockets(clientIdOf(stuckSeed), 1000, "")
		synctest.Wait()

		start := time.Now()
		relay.Close()
		// Close has waited for the relay's goroutines, and for nothing else
		relay.mu.Lock()
		writers, pending := len(relay.writing), len(relay.pending)
		relay.mu.Unlock()
		if timers := timersOf(relay); writers != 0 || pending != 0 || timers != 0 {
			t.Fatalf("when Close returned: %d writers, %d connections not answered, %d timers", writers, pending, timers)
		}
		if waited := time.Since(start); waited != 0 {
			t.Fatalf("Close took %v", waited)
		}
		relay.Close()
		synctest.Wait()
		select {
		case err := <-held:
			if !errors.Is(err, errRelayClosed) {
				t.Fatalf("a held publish when the relay closed: %v", err)
			}
		default:
			t.Fatal("a held publish outlived the relay")
		}
		if code, _ := closeCode(client.ended()); code != websocket.CloseAbnormalClosure {
			t.Fatalf("the socket of a closed relay read %v", client.ended())
		}
		if _, err := idle.Read(make([]byte, 1)); err == nil {
			t.Fatal("a connection that never sent a request outlived the relay")
		}
		idle.Close()
		if _, ok := <-peer.Messages(); ok {
			t.Fatal("a peer of a closed relay was handed a message")
		}
		if err := peer.Subscribe(topicA); !errors.Is(err, errRelayClosed) {
			t.Fatalf("a peer's subscribe at a closed relay: %v", err)
		}
		if err := peer.Publish(topicA, "late", wire.TagSessionRequestResponse, wire.TtlFiveMinutes); !errors.Is(err, errRelayClosed) {
			t.Fatalf("a peer's publish at a closed relay: %v", err)
		}
		late := relay.Peer("late")
		if err := late.Subscribe(topicA); err == nil {
			t.Fatal("a peer made after the close subscribed")
		}
		if _, ok := <-late.Messages(); ok {
			t.Fatal("a peer made after the close was handed a message")
		}
		late.Close()
		if _, _, err := open(t.Context(), relay, testTarget, header); !errors.Is(err, errRelayClosed) {
			t.Fatalf("a dial to a closed relay: %v", err)
		}
		if relay.OpenSockets("") != 0 {
			t.Fatalf("%d open sockets at a closed relay", relay.OpenSockets(""))
		}
		// the faults and the observation of a closed relay do nothing and
		// do not fail
		relay.Drop("")
		relay.CloseSockets("", 1000, "")
		relay.SetZombie("", false)
		relay.SendOversized("", 10)
		if len(relay.Handshakes()) != 2 || relay.Dials() != 4 {
			t.Fatalf("%d handshakes and %d dials, want 2 and 4", len(relay.Handshakes()), relay.Dials())
		}
	})
}

// A peer that is closed leaves its mailbox to the next peer of its client
// id, like a socket client that comes back.
func TestRelayPeerClose(t *testing.T) {
	inBubble(t, RelayOptions{}, func(t *testing.T, relay *Relay) {
		sender := relay.Peer("sender")
		wallet := relay.Peer("wallet")
		must(t, wallet.Subscribe(topicA))
		must(t, sender.Publish(topicA, "unread", wire.TagSessionRequest, wire.TtlFiveMinutes))
		wallet.Close()
		wallet.Close()
		synctest.Wait()
		if _, ok := <-wallet.Messages(); ok {
			t.Fatal("a closed peer handed out a message")
		}
		if wallet.Subscribe(topicA) == nil || wallet.Publish(topicA, "late", wire.TagSessionRequest, wire.TtlFiveMinutes) == nil {
			t.Fatal("a closed peer subscribed or published")
		}

		start := time.Now()
		must(t, sender.Publish(topicA, "while away", wire.TagSessionRequest, wire.TtlFiveMinutes))
		if held := time.Since(start); held != 0 {
			t.Fatalf("a publish to a peer that is away was held %v", held)
		}
		back := relay.Peer("wallet")
		expectMessages(t, "before it subscribes", back)
		must(t, back.Subscribe(topicA))
		// the first was acknowledged when it was handed over, read or not
		expectMessages(t, "the peer that came back", back, Message{Topic: topicA, Message: "while away", Tag: wire.TagSessionRequest})

		// a peer that is closed while its publish is held
		silent := connect(t, relay, testSeed(1))
		silent.subscribed(topicB)
		held := make(chan error, 1)
		go func() {
			held <- back.Publish(topicB, "held", wire.TagSessionRequestResponse, wire.TtlFiveMinutes)
		}()
		synctest.Wait()
		back.Close()
		synctest.Wait()
		select {
		case err := <-held:
			if !errors.Is(err, errPeerClosed) {
				t.Fatalf("a held publish when its peer closed: %v", err)
			}
		default:
			t.Fatal("a held publish outlived its peer")
		}
	})
}

// The socket client of DialRelay against this relay: header authentication,
// calls, and an acknowledgement for every push. Outside this test it runs
// only against the hosted relay, in a test that has to be asked for.
func TestDialRelayClient(t *testing.T) {
	inBubble(t, RelayOptions{}, func(t *testing.T, relay *Relay) {
		seed := testSeed(1)
		dialer := &websocket.Dialer{NetDialTLSContext: relay.DialTLS}
		conn, err := dialRelay(t.Context(), dialer, testRelayUrl, testProjectId, seed)
		must(t, err)
		peer := relay.Peer("peer")

		handshakes := relay.Handshakes()
		if len(handshakes) != 1 || handshakes[0].Status != 101 || handshakes[0].ClientId != clientIdOf(seed) {
			t.Fatalf("%d handshakes, want one accepted of the seed's client id", len(handshakes))
		}
		recorded := handshakes[0]
		if !strings.HasPrefix(recorded.Header.Get("Authorization"), "Bearer ") {
			t.Fatal("the token is not in the Authorization header")
		}
		if _, found := recorded.Header["Origin"]; found {
			t.Fatal("an Origin header was sent")
		}
		if recorded.Query.Encode() != "projectId="+testProjectId || recorded.Host != testRelayHost {
			t.Fatalf("dialled %s with the parameters %q", recorded.Host, recorded.Query.Encode())
		}
		claims, err := wire.VerifyToken(strings.TrimPrefix(recorded.Header.Get("Authorization"), "Bearer "))
		must(t, err)
		now := time.Now().Unix()
		if claims.Aud != testRelayUrl || claims.Iat != now-43200 || claims.Exp != now+43200 || claims.Act != "client_auth" || len(claims.Sub) != 64 {
			t.Fatal("the token is not the one of a client: audience, 12 hours either side of now, client_auth, a 32 byte nonce")
		}

		// subscribe, and what was stored comes; every push is acknowledged
		must(t, peer.Publish(topicA, "stored", wire.TagSessionPropose, wire.TtlFiveMinutes))
		must(t, conn.Subscribe(topicA))
		expectMessages(t, "out of the mailbox", conn, Message{Topic: topicA, Message: "stored", Tag: wire.TagSessionPropose})
		must(t, peer.Subscribe(topicA))
		start := time.Now()
		must(t, peer.Publish(topicA, "live", wire.TagSessionRequest, wire.TtlFiveMinutes))
		if held := time.Since(start); held != 0 {
			t.Fatalf("a publish to the socket client was held %v: it did not acknowledge", held)
		}
		expectMessages(t, "live", conn, Message{Topic: topicA, Message: "live", Tag: wire.TagSessionRequest})
		// a frame that is no json-rpc is passed over
		relay.SendOversized("", 10)
		must(t, conn.Subscribe(topicA))
		expectMessages(t, "acknowledged", conn)

		// publish
		must(t, conn.Publish(topicA, "response", wire.TagSessionRequestResponse, wire.TtlFiveMinutes))
		expectMessages(t, "the peer", peer, Message{Topic: topicA, Message: "response", Tag: wire.TagSessionRequestResponse})
		published := relay.Published()
		if last := published[len(published)-1]; last.ClientId != clientIdOf(seed) || last.Ttl != wire.TtlFiveMinutes || last.Tag != wire.TagSessionRequestResponse {
			t.Fatalf("the publish was recorded as %v", last)
		}

		// a call the relay refuses, and one it never answers
		relay.FailCalls(wire.MethodSubscribe, 1, -32000, "boom")
		if err := conn.Subscribe(topicB); err == nil || !strings.Contains(err.Error(), "boom") {
			t.Fatalf("a refused subscribe: %v", err)
		}
		if err := conn.Publish(topicA, "short", wire.TagSessionPing, 1); err == nil || !strings.Contains(err.Error(), "TtlTooShort") {
			t.Fatalf("a refused publish: %v", err)
		}
		relay.LoseNextPublishAck("")
		start = time.Now()
		if err := conn.Publish(topicA, "unanswered", wire.TagSessionPing, wire.TtlPing); err == nil {
			t.Fatal("a publish that was never answered succeeded")
		}
		if waited := time.Since(start); waited != 15*time.Second {
			t.Fatalf("a publish that was never answered returned after %v, want 15s", waited)
		}

		// close: a close frame, the channel ends, later calls fail
		conn.Close()
		conn.Close()
		synctest.Wait()
		if _, ok := <-conn.Messages(); ok {
			t.Fatal("a closed socket client handed out a message")
		}
		if err := conn.Subscribe(topicA); !errors.Is(err, errConnClosed) {
			t.Fatalf("the subscribe of a closed socket client: %v", err)
		}
		if err := conn.Publish(topicA, "late", wire.TagSessionPing, wire.TtlPing); !errors.Is(err, errConnClosed) {
			t.Fatalf("the publish of a closed socket client: %v", err)
		}
		if relay.OpenSockets("") != 0 {
			t.Fatalf("%d open sockets, want none", relay.OpenSockets(""))
		}
		frames := relay.Frames(clientIdOf(seed))
		if last := frames[len(frames)-2]; !last.ToRelay || last.Text != "close 1000" {
			t.Fatalf("the client's last frame is %q, want a close frame with 1000", last.Text)
		}

		// a refusal names the status, and a relay that ends the socket ends
		// the client
		if _, err := dialRelay(t.Context(), dialer, testRelayUrl, "unknown", seed); err == nil || !strings.Contains(err.Error(), "403") || !strings.Contains(err.Error(), "Project not found") {
			t.Fatalf("a refused dial: %v", err)
		}
		relay.SetOffline(true)
		if _, err := dialRelay(t.Context(), dialer, testRelayUrl, testProjectId, seed); !errors.Is(err, syscall.ECONNREFUSED) {
			t.Fatalf("a dial to nobody: %v", err)
		}
		relay.SetOffline(false)
		dropped, err := dialRelay(t.Context(), dialer, testRelayUrl+"?ua=test", testProjectId, seed)
		must(t, err)
		handshakes = relay.Handshakes()
		if query := handshakes[len(handshakes)-1].Query.Encode(); query != "projectId="+testProjectId+"&ua=test" {
			t.Fatalf("a relay url with a query was dialled with %q", query)
		}
		relay.Drop("")
		synctest.Wait()
		if _, ok := <-dropped.Messages(); ok {
			t.Fatal("a dropped socket client handed out a message")
		}
		if err := dropped.Subscribe(topicA); !errors.Is(err, errConnClosed) {
			t.Fatalf("the subscribe of a dropped socket client: %v", err)
		}
	})
}

// The relay on the real clock, as a test outside a bubble uses it: nothing in
// it needs a bubble.
func TestRelayOnTheRealClock(t *testing.T) {
	relay := NewRelay(RelayOptions{})
	defer relay.Close()
	next := func(conn Conn) Message {
		t.Helper()
		select {
		case message := <-conn.Messages():
			return message
		case <-time.After(10 * time.Second):
			t.Fatal("no message within ten seconds")
			return Message{}
		}
	}
	dapp, wallet := relay.Peer("dapp"), relay.Peer("wallet")
	must(t, dapp.Subscribe(topicA))
	must(t, dapp.Publish(topicA, "proposal", wire.TagSessionPropose, wire.TtlFiveMinutes))
	must(t, wallet.Subscribe(topicA))
	if got := next(wallet); got != (Message{Topic: topicA, Message: "proposal", Tag: wire.TagSessionPropose}) {
		t.Fatalf("the wallet was handed %v", got)
	}
	must(t, wallet.Publish(topicA, "response", wire.TagSessionProposeApprove, wire.TtlFiveMinutes))
	if got := next(dapp); got != (Message{Topic: topicA, Message: "response", Tag: wire.TagSessionProposeApprove}) {
		t.Fatalf("the dapp was handed %v", got)
	}

	seed := testSeed(1)
	conn, err := dialRelay(context.Background(), &websocket.Dialer{NetDialTLSContext: relay.DialTLS}, testRelayUrl, testProjectId, seed)
	must(t, err)
	must(t, conn.Subscribe(topicB))
	must(t, wallet.Subscribe(topicB))
	must(t, wallet.Publish(topicB, "settle", wire.TagSessionSettle, wire.TtlFiveMinutes))
	if got := next(conn); got != (Message{Topic: topicB, Message: "settle", Tag: wire.TagSessionSettle}) {
		t.Fatalf("the socket client was handed %v", got)
	}
	must(t, conn.Publish(topicB, "acknowledged", wire.TagSessionSettleResponse, wire.TtlFiveMinutes))
	if got := next(wallet); got != (Message{Topic: topicB, Message: "acknowledged", Tag: wire.TagSessionSettleResponse}) {
		t.Fatalf("the wallet was handed %v", got)
	}
	conn.Close()
}
