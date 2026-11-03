// Error-path tests for the SC node state machine: the connect handshake
// against a hub that answers badly, and the frame-filter rules in the
// connected state.
//
// These call the unexported methods directly with a real WebSocket pair, so
// a failure names the exact frame rather than a TLS or reconnect symptom.
package scnet

import (
	"bufio"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet/sc"
)

func nodeForTest(t *testing.T) *Node {
	t.Helper()
	n, err := NewNode(NodeConfig{
		VMAC:          sc.MAC{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		UUID:          sc.UUID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		Hubs:          []string{"ws://127.0.0.1:1/"},
		AllowInsecure: true,
		DialTimeout:   200 * time.Millisecond,
		MaxMessage:    4096,
	}, zap.NewNop())
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	return n
}

// wsPair returns (node side, hub side). The node is the WebSocket client, so
// its frames are masked; the hub side reads them and writes unmasked frames.
func wsPair(t *testing.T) (*wsConn, *wsConn) {
	t.Helper()
	nodeRaw, hubRaw := tcpPair(t)
	_ = nodeRaw.SetDeadline(time.Now().Add(5 * time.Second))
	_ = hubRaw.SetDeadline(time.Now().Add(5 * time.Second))
	node := &wsConn{conn: nodeRaw, br: bufio.NewReader(nodeRaw), client: true, maxMessage: 4096}
	hub := &wsConn{conn: hubRaw, br: bufio.NewReader(hubRaw), client: false, maxMessage: 4096}
	return node, hub
}

// serveConnect reads the node's Connect-Request and lets the test answer it.
func serveConnect(t *testing.T, hub *wsConn, respond func(id uint16, hdr sc.Header)) {
	t.Helper()
	go func() {
		op, msg, err := hub.ReadMessage()
		if err != nil || op != opBinary {
			return
		}
		hdr, err := sc.Parse(msg)
		if err != nil {
			return
		}
		respond(hdr.MessageID, hdr)
	}()
}

func acceptPayload(t *testing.T, vmac sc.MAC) []byte {
	t.Helper()
	p, err := sc.ConnectAccept{VMAC: vmac, UUID: sc.UUID{1, 2, 3}, MaxBVLC: 1497, MaxNPDU: 1440}.Encode()
	if err != nil {
		t.Fatalf("encode accept: %v", err)
	}
	return p
}

func TestConnectHandshakePaths(t *testing.T) {
	hubMAC := sc.MAC{0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01}

	cases := []struct {
		name    string
		respond func(t *testing.T, hub *wsConn, id uint16, hdr sc.Header)
		ok      bool
	}{
		{"accept", func(t *testing.T, hub *wsConn, id uint16, _ sc.Header) {
			_ = hub.WriteBinary(mustHeader(t, sc.FuncConnectAccept, id, acceptPayload(t, hubMAC)))
		}, true},
		{"ignores unrelated frames then accepts", func(t *testing.T, hub *wsConn, id uint16, _ sc.Header) {
			// A Result for another function, then an accept for the wrong
			// message ID, then the real one.
			_ = hub.WriteBinary(mustHeader(t, sc.FuncResult, id,
				mustResultACK(t, sc.FuncHeartbeatRequest)))
			_ = hub.WriteBinary(mustHeader(t, sc.FuncConnectAccept, id+1, acceptPayload(t, hubMAC)))
			_ = hub.WriteBinary(mustHeader(t, sc.FuncConnectAccept, id, acceptPayload(t, hubMAC)))
		}, true},
		{"result NAK", func(t *testing.T, hub *wsConn, id uint16, _ sc.Header) {
			p, _ := sc.Result{Function: sc.FuncConnectRequest, Code: sc.ResultNAK, ErrorClass: 1, ErrorCode: 2, Details: "no"}.Encode()
			_ = hub.WriteBinary(mustHeader(t, sc.FuncResult, id, p))
		}, false},
		{"malformed accept payload", func(t *testing.T, hub *wsConn, id uint16, _ sc.Header) {
			_ = hub.WriteBinary(mustHeader(t, sc.FuncConnectAccept, id, []byte{1, 2, 3}))
		}, false},
		{"text message", func(t *testing.T, hub *wsConn, _ uint16, _ sc.Header) {
			_ = hub.writeFrame(opText, []byte("hello"))
		}, false},
		{"hub closes", func(t *testing.T, hub *wsConn, _ uint16, _ sc.Header) {
			_ = hub.Close()
		}, false},
		{"no answer", func(t *testing.T, _ *wsConn, _ uint16, _ sc.Header) {
			time.Sleep(400 * time.Millisecond)
		}, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			n := nodeForTest(t)
			node, hub := wsPair(t)
			serveConnect(t, hub, func(id uint16, hdr sc.Header) { c.respond(t, hub, id, hdr) })

			err := n.connectHandshake(node)
			if c.ok {
				if err != nil {
					t.Fatalf("connectHandshake: %v", err)
				}
				// connected is set by Run, not by the handshake, so read
				// the recorded hub VMAC directly.
				if n.hubVMAC != hubMAC {
					t.Fatalf("hub vmac = %v, want %v", n.hubVMAC, hubMAC)
				}
				return
			}
			if err == nil {
				t.Fatal("bad connect response accepted")
			}
		})
	}
}

func mustHeader(t *testing.T, fn sc.Function, id uint16, payload []byte) []byte {
	t.Helper()
	b, err := sc.Header{Function: fn, MessageID: id, Payload: payload}.Marshal()
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	return b
}

func mustResultACK(t *testing.T, fn sc.Function) []byte {
	t.Helper()
	p, err := sc.Result{Function: fn, Code: sc.ResultACK}.Encode()
	if err != nil {
		t.Fatalf("encode result: %v", err)
	}
	return p
}

func TestHandleFrameFilters(t *testing.T) {
	n := nodeForTest(t)
	own := n.VMAC()
	other := sc.MAC{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x02}
	origin := sc.MAC{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01}

	var got [][]byte
	n.SetNPDUHandler(func(_ *sc.MAC, npdu []byte) {
		got = append(got, append([]byte(nil), npdu...))
	})

	// A frame without an origin cannot be attributed: dropped.
	if err := n.handleFrame(nil, sc.Header{Function: sc.FuncEncapsulatedNPDU, Payload: []byte{1}}); err != nil {
		t.Fatalf("nil-origin frame: %v", err)
	}
	// A frame addressed to another node: dropped.
	if err := n.handleFrame(nil, sc.Header{Function: sc.FuncEncapsulatedNPDU, Orig: &origin, Dest: &other, Payload: []byte{2}}); err != nil {
		t.Fatalf("other-dest frame: %v", err)
	}
	// Addressed to us, to broadcast, and with no destination: delivered.
	for _, dest := range []*sc.MAC{&own, &sc.BroadcastMAC, nil} {
		if err := n.handleFrame(nil, sc.Header{Function: sc.FuncEncapsulatedNPDU, Orig: &origin, Dest: dest, Payload: []byte{3}}); err != nil {
			t.Fatalf("deliverable frame: %v", err)
		}
	}
	if len(got) != 3 {
		t.Fatalf("delivered %d npdus, want 3", len(got))
	}

	// Advertisement updates the hub status; a malformed one is ignored.
	adv, _ := sc.Advertisement{HubStatus: sc.HubStatusConnectedPrimary, MaxBVLC: 1497, MaxNPDU: 1440}.Encode()
	if err := n.handleFrame(nil, sc.Header{Function: sc.FuncAdvertisement, Payload: adv}); err != nil {
		t.Fatalf("advertisement: %v", err)
	}
	if status, seen := n.HubStatus(); !seen || status != sc.HubStatusConnectedPrimary {
		t.Fatalf("hub status = %d, seen=%v", status, seen)
	}
	if err := n.handleFrame(nil, sc.Header{Function: sc.FuncAdvertisement, Payload: []byte{1}}); err != nil {
		t.Fatalf("malformed advertisement: %v", err)
	}

	// A stray heartbeat ACK is accepted silently.
	if err := n.handleFrame(nil, sc.Header{Function: sc.FuncHeartbeatACK, MessageID: 9}); err != nil {
		t.Fatalf("heartbeat ack: %v", err)
	}

	// A Disconnect-Request is acknowledged and ends the connection.
	node, hub := wsPair(t)
	if err := n.handleFrame(node, sc.Header{Function: sc.FuncDisconnectRequest, MessageID: 7}); err == nil {
		t.Fatal("Disconnect-Request did not end the serve loop")
	}
	if _, msg, err := hub.ReadMessage(); err != nil {
		t.Fatalf("read Disconnect-ACK: %v", err)
	} else if hdr, err := sc.Parse(msg); err != nil || hdr.Function != sc.FuncDisconnectACK || hdr.MessageID != 7 {
		t.Fatalf("disconnect ack = %+v, %v", hdr, err)
	}
}

func TestHandleFrameHeartbeatRequestAcknowledges(t *testing.T) {
	n := nodeForTest(t)
	node, hub := wsPair(t)
	if err := n.handleFrame(node, sc.Header{Function: sc.FuncHeartbeatRequest, MessageID: 42}); err != nil {
		t.Fatalf("heartbeat request: %v", err)
	}
	_, msg, err := hub.ReadMessage()
	if err != nil {
		t.Fatalf("read ACK: %v", err)
	}
	hdr, err := sc.Parse(msg)
	if err != nil || hdr.Function != sc.FuncHeartbeatACK || hdr.MessageID != 42 {
		t.Fatalf("ACK = %+v, %v", hdr, err)
	}
}

func TestNodeAccessors(t *testing.T) {
	n := nodeForTest(t)
	if n.UUID() != (sc.UUID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}) {
		t.Fatalf("UUID = %v", n.UUID())
	}
	if n.VMAC() != (sc.MAC{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}) {
		t.Fatalf("VMAC = %v", n.VMAC())
	}
	if _, ok := n.HubVMAC(); ok {
		t.Fatal("HubVMAC reported a hub before connecting")
	}
	if n.Connected() {
		t.Fatal("Connected true before connecting")
	}
}
