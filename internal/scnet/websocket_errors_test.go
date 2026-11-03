// Error-path and framing tests for the WebSocket layer.
//
// The happy-path handshake and round trip are covered in websocket_test.go.
// This file pins what a hostile or broken hub does: a bad upgrade response,
// a malformed upgrade request, interleaved control frames, fragmented
// messages, and the bounds that stop a declared length from becoming an
// allocation.
package scnet

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestWSAcceptKnownVector(t *testing.T) {
	// RFC 6455 §1.3 example.
	if got, want := wsAccept("dGhlIHNhbXBsZSBub25jZQ=="), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="; got != want {
		t.Fatalf("wsAccept = %q, want %q", got, want)
	}
}

func TestCheckUpgradeResponse(t *testing.T) {
	key := "dGhlIHNhbXBsZSBub25jZQ=="
	valid := func() http.Header {
		h := http.Header{}
		h.Set("Upgrade", "websocket")
		h.Set("Connection", "Upgrade")
		h.Set("Sec-WebSocket-Accept", wsAccept(key))
		return h
	}
	cases := []struct {
		name  string
		code  int
		head  func(http.Header)
		proto string
		ok    bool
	}{
		{"valid", 101, func(h http.Header) {}, "", true},
		{"valid with subprotocol", 101, func(h http.Header) { h.Set("Sec-WebSocket-Protocol", "hub") }, "hub", true},
		{"not switching protocols", 200, func(h http.Header) {}, "", false},
		{"missing upgrade", 101, func(h http.Header) { h.Del("Upgrade") }, "", false},
		{"missing connection", 101, func(h http.Header) { h.Del("Connection") }, "", false},
		{"bad accept", 101, func(h http.Header) { h.Set("Sec-WebSocket-Accept", "wrong") }, "", false},
		{"wrong subprotocol", 101, func(h http.Header) { h.Set("Sec-WebSocket-Protocol", "other") }, "hub", false},
		{"missing subprotocol", 101, func(h http.Header) {}, "hub", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := valid()
			c.head(h)
			resp := &http.Response{
				StatusCode: c.code,
				Status:     fmt.Sprintf("%d %s", c.code, http.StatusText(c.code)),
				Header:     h,
			}
			err := checkUpgradeResponse(resp, key, c.proto)
			if c.ok && err != nil {
				t.Fatalf("valid response rejected: %v", err)
			}
			if !c.ok && err == nil {
				t.Fatal("invalid response accepted")
			}
		})
	}
}

// writeRawResponse runs the server side of a client handshake: it reads the
// request, then writes whatever the test wants back.
func writeRawResponse(t *testing.T, conn net.Conn, respond func(key string) string) {
	t.Helper()
	go func() {
		defer conn.Close()
		req, err := http.ReadRequest(bufio.NewReader(conn))
		if err != nil {
			return
		}
		_, _ = io.WriteString(conn, respond(req.Header.Get("Sec-WebSocket-Key")))
	}()
}

func TestClientHandshakeRejectsBadUpgrade(t *testing.T) {
	cases := []struct {
		name    string
		respond func(string) string
		proto   string
	}{
		{"http error", func(string) string {
			return "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
		}, ""},
		{"no upgrade header", func(key string) string {
			return "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + wsAccept(key) + "\r\n\r\n"
		}, ""},
		{"no connection header", func(key string) string {
			return "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: " + wsAccept(key) + "\r\n\r\n"
		}, ""},
		{"bad accept", func(string) string {
			return "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: nope\r\n\r\n"
		}, ""},
		{"wrong subprotocol", func(key string) string {
			return "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" +
				"Sec-WebSocket-Accept: " + wsAccept(key) + "\r\nSec-WebSocket-Protocol: other\r\n\r\n"
		}, "hub"},
		{"garbage", func(string) string { return "not http at all\r\n\r\n" }, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c1, c2 := net.Pipe()
			defer c1.Close()
			writeRawResponse(t, c2, c.respond)
			_, err := wsClientHandshake(context.Background(), c1, "hub.example:47812", "/", c.proto, time.Now().Add(3*time.Second))
			if err == nil {
				t.Fatal("bad upgrade response accepted")
			}
		})
	}
}

func TestServerHandshakeRejectsMalformedRequests(t *testing.T) {
	cases := []struct {
		name string
		req  string
	}{
		{"not a get", "POST / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: k\r\n\r\n"},
		{"no upgrade", "GET / HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: k\r\n\r\n"},
		{"no connection", "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: k\r\n\r\n"},
		{"wrong version", "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 8\r\nSec-WebSocket-Key: k\r\n\r\n"},
		{"no key", "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\n\r\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c1, c2 := tcpPair(t)
			go func() {
				_, _ = io.WriteString(c1, c.req)
			}()
			if _, err := wsServerHandshake(c2, HubSubprotocol, time.Now().Add(3*time.Second)); err == nil {
				t.Fatal("malformed upgrade request accepted")
			}
		})
	}

	// A client that offers a different subprotocol is refused.
	c1, c2 := tcpPair(t)
	go func() {
		_, _ = io.WriteString(c1, "GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
			"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: k\r\nSec-WebSocket-Protocol: direct\r\n\r\n")
	}()
	if _, err := wsServerHandshake(c2, HubSubprotocol, time.Now().Add(3*time.Second)); err == nil {
		t.Fatal("unoffered subprotocol accepted")
	}
}

// writeFrame writes one unmasked frame (the server role) directly, so the
// test can control FIN and fragmentation.
func writeFrame(w io.Writer, fin bool, opcode byte, payload []byte) error {
	var hdr [10]byte
	hdr[0] = opcode
	if fin {
		hdr[0] |= 0x80
	}
	n := 2
	if len(payload) < 126 {
		hdr[1] = byte(len(payload))
	} else if len(payload) <= 0xFFFF {
		hdr[1] = 126
		binary.BigEndian.PutUint16(hdr[2:4], uint16(len(payload)))
		n = 4
	} else {
		hdr[1] = 127
		binary.BigEndian.PutUint64(hdr[2:10], uint64(len(payload)))
		n = 10
	}
	if _, err := w.Write(hdr[:n]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

func newClientReader(conn net.Conn, maxMessage int) *wsConn {
	return &wsConn{conn: conn, br: bufio.NewReader(conn), client: true, maxMessage: maxMessage}
}

// tcpPair is a buffered loopback pair. net.Pipe is synchronous, which turns
// a frame reply written from the read path into a deadlock when the test is
// also writing; real sockets have buffers and match production.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			accepted <- c
		}
	}()
	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		_ = ln.Close()
		t.Fatalf("dial: %v", err)
	}
	server := <-accepted
	_ = ln.Close()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client, server
}

func TestReadMessageAnswersPingAndIgnoresPong(t *testing.T) {
	a, b := tcpPair(t)
	c := newClientReader(a, 4096)
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))

	go func() {
		_ = writeFrame(b, true, opPing, []byte("ping"))
		_ = writeFrame(b, true, opPong, []byte("pong"))
		_ = writeFrame(b, true, opBinary, []byte("data"))
	}()

	op, msg, err := c.ReadMessage()
	if err != nil || op != opBinary || string(msg) != "data" {
		t.Fatalf("ReadMessage = %d %q %v", op, msg, err)
	}
	// The pong reply to the ping must have been written to b.
	_ = b.SetReadDeadline(time.Now().Add(time.Second))
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(b, hdr); err != nil {
		t.Fatalf("read pong: %v", err)
	}
	if hdr[0]&0x0F != opPong {
		t.Fatalf("reply opcode = 0x%x, want pong", hdr[0]&0x0F)
	}
	// Drain the pong payload ("ping", 4 bytes).
	if _, err := io.ReadFull(b, make([]byte, 4)); err != nil {
		t.Fatalf("read pong payload: %v", err)
	}
}

func TestReadMessageCloseReturnsEOF(t *testing.T) {
	a, b := tcpPair(t)
	c := newClientReader(a, 4096)
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	go func() { _ = writeFrame(b, true, opClose, nil) }()
	if _, _, err := c.ReadMessage(); err != io.EOF {
		t.Fatalf("ReadMessage after close = %v, want io.EOF", err)
	}
}

func TestReadMessageFragmentation(t *testing.T) {
	a, b := tcpPair(t)
	c := newClientReader(a, 4096)
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	go func() {
		_ = writeFrame(b, false, opBinary, []byte("he"))
		_ = writeFrame(b, false, opContinuation, []byte("ll"))
		_ = writeFrame(b, true, opContinuation, []byte("o"))
	}()
	op, msg, err := c.ReadMessage()
	if err != nil || op != opBinary || string(msg) != "hello" {
		t.Fatalf("fragmented ReadMessage = %d %q %v", op, msg, err)
	}
}

func TestReadMessageRejectsBadSequences(t *testing.T) {
	cases := []struct {
		name   string
		max    int
		frames func(net.Conn)
	}{
		{"continuation without start", 4096, func(w net.Conn) {
			_ = writeFrame(w, true, opContinuation, []byte("x"))
		}},
		{"new data frame while fragmented", 4096, func(w net.Conn) {
			_ = writeFrame(w, false, opBinary, []byte("a"))
			_ = writeFrame(w, true, opBinary, []byte("b"))
		}},
		{"message exceeds max", 4, func(w net.Conn) {
			_ = writeFrame(w, false, opBinary, []byte("abc"))
			_ = writeFrame(w, true, opContinuation, []byte("def"))
		}},
		{"unknown opcode", 4096, func(w net.Conn) {
			_ = writeFrame(w, true, 0x3, nil)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			conn := newClientReader(a, c.max)
			_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
			go c.frames(b)
			if _, _, err := conn.ReadMessage(); err == nil {
				t.Fatal("bad frame sequence accepted")
			}
		})
	}
}

func TestWriteFrameToRejectsOversizeControl(t *testing.T) {
	var buf bytes.Buffer
	if err := writeFrameTo(&buf, false, opClose, make([]byte, 126)); err == nil {
		t.Fatal("126-byte control frame accepted")
	}
	if err := writeFrameTo(&buf, false, opPing, make([]byte, 125)); err != nil {
		t.Fatalf("125-byte control frame rejected: %v", err)
	}
}

func TestWriteFrameLengthBoundaries(t *testing.T) {
	for _, n := range []int{0, 125, 126, 65535, 65536} {
		var buf bytes.Buffer
		payload := bytes.Repeat([]byte{0xAB}, n)
		if err := writeFrameTo(&buf, false, opBinary, payload); err != nil {
			t.Fatalf("write %d bytes: %v", n, err)
		}
		h, got, err := parseFrame(buf.Bytes(), false, 1<<20)
		if err != nil {
			t.Fatalf("parse %d bytes: %v", n, err)
		}
		if h.payloadLen != n || !bytes.Equal(got, payload) {
			t.Fatalf("round trip %d bytes: header=%d payload=%d", n, h.payloadLen, len(got))
		}
	}
}
