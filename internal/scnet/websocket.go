// Package scnet is the BACnet/SC transport: TLS 1.3, the WebSocket framing
// (RFC 6455) that carries BVLC-SC messages, and the node-to-hub connection
// state machine (connect, heartbeat, reconnect).
//
// BACnet/SC rides a WebSocket, and this project treats the WebSocket frame
// parser as part of the attack surface rather than trusting a dependency with
// it: the parser is small, bounded, and fuzzed (FuzzParseFrame). Only what a
// BACnet/SC peer uses is implemented — binary messages, ping/pong, close, and
// fragmentation — with extensions and text messages rejected.
package scnet

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// WebSocket opcodes (RFC 6455 §5.2).
const (
	opContinuation byte = 0x0
	opText         byte = 0x1
	opBinary       byte = 0x2
	opClose        byte = 0x8
	opPing         byte = 0x9
	opPong         byte = 0xA
)

// wsGUID is the fixed key suffix from RFC 6455 §1.3.
const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// defaultMaxMessage bounds an assembled WebSocket message. A BACnet/SC frame is
// small (the standard's own BVLC ceiling is well under 64 KiB); anything larger
// is a peer that is not speaking SC, or is hostile.
const defaultMaxMessage = 64 * 1024

// wsAccept computes the Sec-WebSocket-Accept value for a client key.
func wsAccept(key string) string {
	h := sha1.Sum([]byte(key + wsGUID)) //nolint:gosec // RFC 6455 mandates SHA-1 here; it is not a security primitive.
	return base64.StdEncoding.EncodeToString(h[:])
}

// wsConn is a single WebSocket connection. It is not safe to call ReadMessage
// from more than one goroutine; writes are serialized internally, so a
// control-frame reply from the read path may run alongside a data write.
type wsConn struct {
	conn       net.Conn
	br         *bufio.Reader
	client     bool
	maxMessage int

	wmu sync.Mutex
}

// SetDeadline sets the read and write deadline on the underlying connection.
func (c *wsConn) SetDeadline(t time.Time) error { return c.conn.SetDeadline(t) }

// SetReadDeadline sets the read deadline on the underlying connection.
func (c *wsConn) SetReadDeadline(t time.Time) error { return c.conn.SetReadDeadline(t) }

// Close sends a close frame (best effort) and closes the connection.
func (c *wsConn) Close() error {
	_ = c.writeFrame(opClose, nil)
	return c.conn.Close()
}

// ReadMessage reads the next binary or text message, answering pings and
// ignoring pongs. It returns io.EOF when the peer closes the connection.
func (c *wsConn) ReadMessage() (byte, []byte, error) {
	var (
		msgOpcode byte
		msg       []byte
	)
	for {
		hdrBytes := make([]byte, 14) // longest possible frame header
		if _, err := io.ReadFull(c.br, hdrBytes[:2]); err != nil {
			return 0, nil, err
		}
		hdr, err := parseFrameHeader(hdrBytes, !c.client, c.maxMessage)
		if err != nil {
			return 0, nil, err
		}
		if _, err := io.ReadFull(c.br, hdrBytes[2:hdr.headerLen]); err != nil {
			return 0, nil, err
		}
		hdr, err = parseFrameHeader(hdrBytes[:hdr.headerLen], !c.client, c.maxMessage)
		if err != nil {
			return 0, nil, err
		}
		payload := make([]byte, hdr.payloadLen)
		if _, err := io.ReadFull(c.br, payload); err != nil {
			return 0, nil, err
		}
		if hdr.masked {
			unmask(payload, hdr.maskKey)
		}

		switch hdr.opcode {
		case opPing:
			if err := c.writeFrame(opPong, payload); err != nil {
				return 0, nil, err
			}
			continue
		case opPong:
			continue
		case opClose:
			_ = c.writeFrame(opClose, nil)
			return 0, nil, io.EOF
		case opBinary, opText:
			if msgOpcode != 0 {
				return 0, nil, fmt.Errorf("websocket: new data frame while fragmented message open")
			}
			if hdr.fin {
				return hdr.opcode, payload, nil
			}
			msgOpcode, msg = hdr.opcode, payload
		case opContinuation:
			if msgOpcode == 0 {
				return 0, nil, fmt.Errorf("websocket: continuation without a start frame")
			}
			msg = append(msg, payload...)
			if len(msg) > c.maxMessage {
				return 0, nil, fmt.Errorf("websocket: message exceeds %d bytes", c.maxMessage)
			}
			if hdr.fin {
				return msgOpcode, msg, nil
			}
		default:
			return 0, nil, fmt.Errorf("websocket: unknown opcode 0x%x", hdr.opcode)
		}
	}
}

// WriteBinary sends one binary message.
func (c *wsConn) WriteBinary(payload []byte) error { return c.writeFrame(opBinary, payload) }

func (c *wsConn) writeFrame(opcode byte, payload []byte) error {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	return writeFrameTo(c.conn, c.client, opcode, payload)
}

// frameHeader is a decoded WebSocket frame header.
type frameHeader struct {
	fin        bool
	opcode     byte
	masked     bool
	maskKey    [4]byte
	payloadLen int
	headerLen  int
}

// parseFrameHeader decodes a frame header from b. b must contain at least two
// bytes; headerLen bytes must be present in b for success. expectMasked states
// whether the receiver requires masked frames (a server requires masking, a
// client forbids it). maxMessage bounds the declared payload; it prevents a
// hostile 64-bit length from steering a huge allocation.
func parseFrameHeader(b []byte, expectMasked bool, maxMessage int) (frameHeader, error) {
	var h frameHeader
	if len(b) < 2 {
		return h, fmt.Errorf("websocket: frame header %d bytes, need 2", len(b))
	}
	h.fin = b[0]&0x80 != 0
	if b[0]&0x70 != 0 {
		// RSV1..3: no extension is negotiated, so they must be zero.
		return h, fmt.Errorf("websocket: reserved bits set (0x%02x)", b[0])
	}
	h.opcode = b[0] & 0x0F
	h.masked = b[1]&0x80 != 0
	length := int(b[1] & 0x7F)
	off := 2

	switch length {
	case 126:
		if len(b) < off+2 {
			return h, fmt.Errorf("websocket: 16-bit length past end")
		}
		length = int(binary.BigEndian.Uint16(b[off : off+2]))
		off += 2
	case 127:
		if len(b) < off+8 {
			return h, fmt.Errorf("websocket: 64-bit length past end")
		}
		v := binary.BigEndian.Uint64(b[off : off+8])
		if v>>63 != 0 {
			return h, fmt.Errorf("websocket: 64-bit length with high bit set")
		}
		if v > uint64(maxMessage) {
			return h, fmt.Errorf("websocket: payload %d exceeds %d", v, maxMessage)
		}
		length = int(v)
		off += 8
	}
	if length > maxMessage {
		return h, fmt.Errorf("websocket: payload %d exceeds %d", length, maxMessage)
	}
	if h.masked {
		if len(b) < off+4 {
			return h, fmt.Errorf("websocket: mask key past end")
		}
		copy(h.maskKey[:], b[off:off+4])
		off += 4
	}
	if h.masked != expectMasked {
		if expectMasked {
			return h, fmt.Errorf("websocket: client frame is not masked")
		}
		return h, fmt.Errorf("websocket: server frame is masked")
	}
	if h.opcode >= opClose { // control frames
		if !h.fin {
			return h, fmt.Errorf("websocket: fragmented control frame")
		}
		if length > 125 {
			return h, fmt.Errorf("websocket: control frame %d bytes, max 125", length)
		}
	}
	switch h.opcode {
	case opContinuation, opText, opBinary, opClose, opPing, opPong:
	default:
		return h, fmt.Errorf("websocket: unknown opcode 0x%x", h.opcode)
	}
	h.payloadLen = length
	h.headerLen = off
	return h, nil
}

// parseFrame decodes one complete frame from b and returns the unmasked
// payload. It is the fuzz entry point: it never reads past b.
func parseFrame(b []byte, expectMasked bool, maxMessage int) (frameHeader, []byte, error) {
	h, err := parseFrameHeader(b, expectMasked, maxMessage)
	if err != nil {
		return h, nil, err
	}
	if len(b) < h.headerLen+h.payloadLen {
		return h, nil, fmt.Errorf("websocket: payload %d bytes past end", h.payloadLen)
	}
	payload := append([]byte(nil), b[h.headerLen:h.headerLen+h.payloadLen]...)
	if h.masked {
		unmask(payload, h.maskKey)
	}
	return h, payload, nil
}

func unmask(payload []byte, key [4]byte) {
	for i := range payload {
		payload[i] ^= key[i&3]
	}
}

func writeFrameTo(w io.Writer, client bool, opcode byte, payload []byte) error {
	if opcode >= opClose && len(payload) > 125 {
		return fmt.Errorf("websocket: control frame %d bytes, max 125", len(payload))
	}
	var header [14]byte
	header[0] = 0x80 | opcode // FIN set; a message is written in one frame
	n := 2
	switch {
	case len(payload) < 126:
		header[1] = byte(len(payload))
	case len(payload) <= 0xFFFF:
		header[1] = 126
		binary.BigEndian.PutUint16(header[2:4], uint16(len(payload)))
		n = 4
	default:
		header[1] = 127
		binary.BigEndian.PutUint64(header[2:10], uint64(len(payload)))
		n = 10
	}
	if client {
		header[1] |= 0x80
		var key [4]byte
		if _, err := rand.Read(key[:]); err != nil {
			return err
		}
		copy(header[n:n+4], key[:])
		n += 4
		if _, err := w.Write(header[:n]); err != nil {
			return err
		}
		masked := make([]byte, len(payload))
		copy(masked, payload)
		unmask(masked, key)
		_, err := w.Write(masked)
		return err
	}
	if _, err := w.Write(header[:n]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// wsClientHandshake upgrades an established connection to a WebSocket, speaking
// the client role. host is the Host header value (host or host:port), path the
// request target, and subprotocol the value for Sec-WebSocket-Protocol (empty
// to omit). deadline bounds the handshake.
func wsClientHandshake(ctx context.Context, conn net.Conn, host, path, subprotocol string, deadline time.Time) (*wsConn, error) {
	if path == "" {
		path = "/"
	}
	var keyBytes [16]byte
	if _, err := rand.Read(keyBytes[:]); err != nil {
		return nil, fmt.Errorf("websocket: key: %w", err)
	}
	key := base64.StdEncoding.EncodeToString(keyBytes[:])

	var b strings.Builder
	fmt.Fprintf(&b, "GET %s HTTP/1.1\r\n", path)
	fmt.Fprintf(&b, "Host: %s\r\n", host)
	b.WriteString("Upgrade: websocket\r\n")
	b.WriteString("Connection: Upgrade\r\n")
	fmt.Fprintf(&b, "Sec-WebSocket-Key: %s\r\n", key)
	b.WriteString("Sec-WebSocket-Version: 13\r\n")
	if subprotocol != "" {
		fmt.Fprintf(&b, "Sec-WebSocket-Protocol: %s\r\n", subprotocol)
	}
	b.WriteString("\r\n")

	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	defer conn.SetDeadline(time.Time{}) //nolint:errcheck // best effort
	if _, err := io.WriteString(conn, b.String()); err != nil {
		return nil, fmt.Errorf("websocket: write request: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	if err != nil {
		return nil, fmt.Errorf("websocket: read response: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck // body is empty on 101
	if err := checkUpgradeResponse(resp, key, subprotocol); err != nil {
		return nil, err
	}
	return &wsConn{conn: conn, br: br, client: true, maxMessage: defaultMaxMessage}, nil
}

func checkUpgradeResponse(resp *http.Response, key, subprotocol string) error {
	if resp.StatusCode != http.StatusSwitchingProtocols {
		return fmt.Errorf("websocket: server returned %s", resp.Status)
	}
	if !tokenListContains(resp.Header.Values("Upgrade"), "websocket") {
		return fmt.Errorf("websocket: server did not upgrade")
	}
	if !tokenListContains(resp.Header.Values("Connection"), "upgrade") {
		return fmt.Errorf("websocket: upgrade response without Connection: Upgrade")
	}
	if got := resp.Header.Get("Sec-WebSocket-Accept"); got != wsAccept(key) {
		return fmt.Errorf("websocket: bad Sec-WebSocket-Accept")
	}
	if subprotocol != "" {
		if got := resp.Header.Get("Sec-WebSocket-Protocol"); got != subprotocol {
			return fmt.Errorf("websocket: server chose subprotocol %q, want %q", got, subprotocol)
		}
	}
	return nil
}

// wsServerHandshake performs the server side of the upgrade on an accepted
// connection. It exists so the test hub speaks the real wire protocol rather
// than a mock; the proxy itself is always a client.
func wsServerHandshake(conn net.Conn, subprotocol string, deadline time.Time) (*wsConn, error) {
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	defer conn.SetDeadline(time.Time{}) //nolint:errcheck // best effort
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return nil, fmt.Errorf("websocket: read request: %w", err)
	}
	defer req.Body.Close() //nolint:errcheck // no body on an upgrade request
	key := req.Header.Get("Sec-WebSocket-Key")
	if req.Method != http.MethodGet ||
		!tokenListContains(req.Header.Values("Upgrade"), "websocket") ||
		!tokenListContains(req.Header.Values("Connection"), "upgrade") ||
		req.Header.Get("Sec-WebSocket-Version") != "13" ||
		key == "" {
		_ = writeHTTPError(conn, http.StatusBadRequest)
		return nil, fmt.Errorf("websocket: malformed upgrade request")
	}
	chosen := ""
	if subprotocol != "" {
		if !tokenListContains(req.Header.Values("Sec-WebSocket-Protocol"), subprotocol) {
			_ = writeHTTPError(conn, http.StatusBadRequest)
			return nil, fmt.Errorf("websocket: client did not offer %q", subprotocol)
		}
		chosen = subprotocol
	}
	var b strings.Builder
	b.WriteString("HTTP/1.1 101 Switching Protocols\r\n")
	b.WriteString("Upgrade: websocket\r\n")
	b.WriteString("Connection: Upgrade\r\n")
	fmt.Fprintf(&b, "Sec-WebSocket-Accept: %s\r\n", wsAccept(key))
	if chosen != "" {
		fmt.Fprintf(&b, "Sec-WebSocket-Protocol: %s\r\n", chosen)
	}
	b.WriteString("\r\n")
	if _, err := io.WriteString(conn, b.String()); err != nil {
		return nil, fmt.Errorf("websocket: write response: %w", err)
	}
	return &wsConn{conn: conn, br: br, client: false, maxMessage: defaultMaxMessage}, nil
}

func writeHTTPError(w io.Writer, code int) error {
	_, err := fmt.Fprintf(w, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
		code, http.StatusText(code))
	return err
}

// tokenListContains reports whether any of the comma-separated header values
// contains token (case-insensitive).
func tokenListContains(values []string, token string) bool {
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

// hubURL is a parsed BACnet/SC hub endpoint.
type hubURL struct {
	raw      string
	secure   bool
	host     string
	hostPort string
	path     string
}

func parseHubURL(raw string) (hubURL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return hubURL{}, fmt.Errorf("sc: hub URL %q: %w", raw, err)
	}
	switch u.Scheme {
	case "wss":
	case "ws":
	default:
		return hubURL{}, fmt.Errorf("sc: hub URL %q: scheme must be wss (or ws for tests)", raw)
	}
	if u.Host == "" {
		return hubURL{}, fmt.Errorf("sc: hub URL %q has no host", raw)
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "wss" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return hubURL{
		raw:      raw,
		secure:   u.Scheme == "wss",
		host:     u.Hostname(),
		hostPort: net.JoinHostPort(u.Hostname(), port),
		path:     path,
	}, nil
}

// dialHub establishes the TCP/TLS connection and performs the WebSocket client
// handshake to a hub endpoint.
func dialHub(ctx context.Context, hub hubURL, tlsConfig *tls.Config, subprotocol string, timeout time.Duration) (*wsConn, error) {
	d := &net.Dialer{Timeout: timeout}
	var conn net.Conn
	var err error
	if hub.secure {
		cfg := &tls.Config{MinVersion: tls.VersionTLS13}
		if tlsConfig != nil {
			cfg = tlsConfig.Clone()
			if cfg.MinVersion == 0 {
				cfg.MinVersion = tls.VersionTLS13
			}
		}
		if cfg.ServerName == "" {
			cfg.ServerName = hub.host
		}
		tconn, derr := tls.DialWithDialer(d, "tcp", hub.hostPort, cfg)
		if derr != nil {
			return nil, fmt.Errorf("sc: dial %s: %w", hub.hostPort, derr)
		}
		conn = tconn
	} else {
		conn, err = d.DialContext(ctx, "tcp", hub.hostPort)
		if err != nil {
			return nil, fmt.Errorf("sc: dial %s: %w", hub.hostPort, err)
		}
	}
	deadline := time.Now().Add(timeout)
	wc, err := wsClientHandshake(ctx, conn, hub.hostPort, hub.path, subprotocol, deadline)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return wc, nil
}
