package scnet

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

func TestParseFrameHeader(t *testing.T) {
	const max = 4096
	cases := []struct {
		name         string
		in           []byte
		expectMasked bool
		wantErr      bool
		wantLen      int
		wantHdr      int
		wantOpcode   byte
	}{
		{"small unmasked binary", []byte{0x82, 0x03, 1, 2, 3}, false, false, 3, 2, opBinary},
		{"small masked binary", []byte{0x82, 0x83, 1, 2, 3, 4, 9, 9, 9}, true, false, 3, 6, opBinary},
		{"16-bit length", append([]byte{0x82, 0x7E, 0x01, 0x00}, make([]byte, 256)...), false, false, 256, 4, opBinary},
		{"64-bit length", append([]byte{0x82, 0x7F, 0, 0, 0, 0, 0, 0, 1, 0}, make([]byte, 256)...), false, false, 256, 10, opBinary},
		{"reserved bits", []byte{0xC2, 0x00}, false, true, 0, 0, opBinary},
		{"unmasked to server", []byte{0x82, 0x00}, true, true, 0, 0, opBinary},
		{"masked from server", []byte{0x82, 0x80, 1, 2, 3, 4}, false, true, 0, 0, opBinary},
		{"control too long", append([]byte{0x88, 0x7E, 0x01, 0x00}, make([]byte, 256)...), false, true, 0, 0, opClose},
		{"fragmented control", []byte{0x08, 0x00}, false, true, 0, 0, opClose},
		{"unknown opcode", []byte{0x83, 0x00}, false, true, 0, 0, 0x3},
		{"truncated", []byte{0x82}, false, true, 0, 0, opBinary},
		{"payload over max", []byte{0x82, 0x7F, 0, 0, 0, 0, 0, 0x10, 0, 0}, false, true, 0, 0, opBinary},
		{"64-bit high bit", []byte{0x82, 0x7F, 0x80, 0, 0, 0, 0, 0, 0, 0}, false, true, 0, 0, opBinary},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, err := parseFrameHeader(c.in, c.expectMasked, max)
			if c.wantErr {
				if err == nil {
					t.Fatalf("accepted %x", c.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("rejected %x: %v", c.in, err)
			}
			if h.payloadLen != c.wantLen || h.headerLen != c.wantHdr || h.opcode != c.wantOpcode {
				t.Fatalf("header = %+v, want len=%d hdr=%d op=%d", h, c.wantLen, c.wantHdr, c.wantOpcode)
			}
		})
	}
}

func TestParseFrameUnmasks(t *testing.T) {
	// A masked client frame carrying "abc".
	key := [4]byte{0x11, 0x22, 0x33, 0x44}
	masked := make([]byte, 0, 7)
	for i, b := range []byte("abc") {
		masked = append(masked, b^key[i&3])
	}
	frame := append([]byte{0x82, 0x80 | 3, key[0], key[1], key[2], key[3]}, masked...)
	h, payload, err := parseFrame(frame, true, 4096)
	if err != nil {
		t.Fatal(err)
	}
	if h.opcode != opBinary || !bytes.Equal(payload, []byte("abc")) {
		t.Fatalf("frame = %+v payload = %q", h, payload)
	}
}

func TestWriteReadRoundTrip(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	cw := &wsConn{conn: client, br: bufio.NewReader(client), client: true, maxMessage: 4096}
	sw := &wsConn{conn: server, br: bufio.NewReader(server), client: false, maxMessage: 4096}
	_ = cw.SetDeadline(time.Now().Add(3 * time.Second))
	_ = sw.SetDeadline(time.Now().Add(3 * time.Second))

	// client -> server
	go func() { _ = cw.WriteBinary([]byte("hello")) }()
	op, msg, err := sw.ReadMessage()
	if err != nil || op != opBinary || string(msg) != "hello" {
		t.Fatalf("server read = %d %q %v", op, msg, err)
	}

	// server -> client
	go func() { _ = sw.WriteBinary([]byte("world")) }()
	op, msg, err = cw.ReadMessage()
	if err != nil || op != opBinary || string(msg) != "world" {
		t.Fatalf("client read = %d %q %v", op, msg, err)
	}
}

func TestHandshake(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	serverCh := make(chan *wsConn, 1)
	errCh := make(chan error, 1)
	go func() {
		sc, err := wsServerHandshake(c2, HubSubprotocol, time.Now().Add(3*time.Second))
		if err != nil {
			errCh <- err
			return
		}
		serverCh <- sc
	}()

	client, err := wsClientHandshake(context.Background(), c1, "hub.example:47812", "/", HubSubprotocol, time.Now().Add(3*time.Second))
	if err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	var server *wsConn
	select {
	case server = <-serverCh:
	case err := <-errCh:
		t.Fatalf("server handshake: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("server handshake timed out")
	}
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	_ = server.SetDeadline(time.Now().Add(3 * time.Second))

	go func() { _ = client.WriteBinary([]byte("sc-frame")) }()
	op, msg, err := server.ReadMessage()
	if err != nil || op != opBinary || string(msg) != "sc-frame" {
		t.Fatalf("server read = %d %q %v", op, msg, err)
	}
	go func() { _ = server.WriteBinary([]byte("reply")) }()
	_, msg, err = client.ReadMessage()
	if err != nil || string(msg) != "reply" {
		t.Fatalf("client read = %q %v", msg, err)
	}
}

func TestHandshakeRejectsWrongSubprotocol(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go func() {
		_, _ = wsServerHandshake(c2, HubSubprotocol, time.Now().Add(3*time.Second))
	}()
	// Client asks for a subprotocol the server will not grant.
	_, err := wsClientHandshake(context.Background(), c1, "hub.example:47812", "/", DirectSubprotocol, time.Now().Add(3*time.Second))
	if err == nil {
		t.Fatal("handshake with the wrong subprotocol succeeded")
	}
}

func TestParseHubURL(t *testing.T) {
	h, err := parseHubURL("wss://hub.example:47812/sc?x=1")
	if err != nil {
		t.Fatal(err)
	}
	if !h.secure || h.host != "hub.example" || h.hostPort != "hub.example:47812" || h.path != "/sc?x=1" {
		t.Fatalf("hub = %+v", h)
	}
	h, err = parseHubURL("wss://hub.example")
	if err != nil || h.hostPort != "hub.example:443" {
		t.Fatalf("hub = %+v, err = %v", h, err)
	}
	h, err = parseHubURL("ws://127.0.0.1:9000/")
	if err != nil || h.secure {
		t.Fatalf("hub = %+v, err = %v", h, err)
	}
	for _, raw := range []string{"http://hub", "wss://", "not-a-url", ""} {
		if _, err := parseHubURL(raw); err == nil {
			t.Errorf("parseHubURL(%q) succeeded", raw)
		}
	}
}

func FuzzParseFrame(f *testing.F) {
	seeds := [][]byte{
		{0x82, 0x03, 1, 2, 3},
		{0x82, 0x83, 1, 2, 3, 4, 9, 9, 9},
		{0x88, 0x00},
		{0x89, 0x00},
		{0x8A, 0x00},
		{0x02, 0x00},
		{0x82, 0x7E, 0x01, 0x00, 0, 0, 0, 0},
		{0x82, 0x7F, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0},
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, expectMasked := range []bool{true, false} {
			h, payload, err := parseFrame(b, expectMasked, 1<<20)
			if err != nil {
				continue
			}
			if h.headerLen+h.payloadLen > len(b) {
				t.Fatalf("parser consumed past the buffer: %x", b)
			}
			if len(payload) != h.payloadLen {
				t.Fatalf("payload length %d, header says %d", len(payload), h.payloadLen)
			}
			// Re-encoding the decoded frame with the same mask expectation
			// must decode to the same header and payload.
			var buf bytes.Buffer
			if err := writeFrameTo(&buf, expectMasked, h.opcode, payload); err != nil {
				t.Fatalf("re-encode: %v", err)
			}
			h2, p2, err := parseFrame(buf.Bytes(), expectMasked, 1<<20)
			if err != nil {
				t.Fatalf("re-parse: %v (%x)", err, buf.Bytes())
			}
			if h2.opcode != h.opcode || !bytes.Equal(p2, payload) {
				t.Fatalf("round trip changed the frame: %+v/%x vs %+v/%x", h, payload, h2, p2)
			}
		}
	})
}
