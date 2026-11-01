package scnet

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"go.uber.org/zap"

	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet/sc"
)

// WebSocket subprotocols used by BACnet/SC (ASHRAE 135, and bacnet-stack's
// BSC_WEBSOCKET_*_PROTOCOL_STR).
const (
	// HubSubprotocol attaches a node to a hub.
	HubSubprotocol = "hub.bsc.bacnet.org"
	// DirectSubprotocol is a direct node-to-node connection. The proxy is
	// always a hub client, so it is defined only for completeness.
	DirectSubprotocol = "dc.bsc.bacnet.org"
)

// ErrNotConnected is returned by SendNPDU when the node has no live hub
// connection. Callers must treat it as "try again", not as a fatal error.
var ErrNotConnected = errors.New("sc: not connected to a hub")

// errPeerDisconnected ends the serve loop when the peer sends a Disconnect.
var errPeerDisconnected = errors.New("sc: peer disconnected")

// NodeConfig configures an SC node. Zero values take the defaults documented
// on each field.
type NodeConfig struct {
	// VMAC is this node's 6-octet virtual MAC. Required, and must be unique
	// on the hub.
	VMAC sc.MAC
	// UUID is this node's device UUID. Required.
	UUID sc.UUID
	// Hubs are hub WebSocket URLs, primary first, failover after. Required.
	// A wss:// URL is required unless AllowInsecure is set.
	Hubs []string
	// TLS is the client TLS configuration. The server name is filled from the
	// hub URL when unset; the minimum version is forced to TLS 1.3.
	TLS *tls.Config
	// MaxBVLC and MaxNPDU are the node's limits, advertised in the
	// Connect-Request. Default 1497 and 1440.
	MaxBVLC uint16
	MaxNPDU uint16
	// DialTimeout bounds the TCP/TLS dial, the WebSocket handshake and the
	// connect handshake. Default 10s.
	DialTimeout time.Duration
	// HeartbeatInterval is how often an idle node sends a Heartbeat-Request.
	// Default 30s.
	HeartbeatInterval time.Duration
	// HeartbeatTimeout bounds the wait for a Heartbeat-ACK. Default 60s.
	HeartbeatTimeout time.Duration
	// ReconnectMin and ReconnectMax bound the exponential reconnect backoff.
	// Default 1s and 30s.
	ReconnectMin time.Duration
	ReconnectMax time.Duration
	// AllowInsecure permits ws:// hubs. It exists only so tests can exercise
	// the framing without certificates; BACnet/SC requires TLS, so a
	// production configuration must not set it.
	AllowInsecure bool
	// MaxMessage bounds an inbound WebSocket message. Default 64 KiB.
	MaxMessage int
}

func (c *NodeConfig) withDefaults() {
	if c.MaxBVLC == 0 {
		c.MaxBVLC = 1497
	}
	if c.MaxNPDU == 0 {
		c.MaxNPDU = 1440
	}
	if c.DialTimeout == 0 {
		c.DialTimeout = 10 * time.Second
	}
	if c.HeartbeatInterval == 0 {
		c.HeartbeatInterval = 30 * time.Second
	}
	if c.HeartbeatTimeout == 0 {
		c.HeartbeatTimeout = 60 * time.Second
	}
	if c.ReconnectMin == 0 {
		c.ReconnectMin = time.Second
	}
	if c.ReconnectMax == 0 {
		c.ReconnectMax = 30 * time.Second
	}
	if c.MaxMessage == 0 {
		c.MaxMessage = defaultMaxMessage
	}
}

// Node is a BACnet/SC node that attaches to a hub and relays NPDUs to and from
// other nodes on that hub. It owns the WebSocket connection, the connect
// handshake, heartbeats and reconnection; the caller owns policy.
type Node struct {
	cfg  NodeConfig
	log  *zap.Logger
	hubs []hubURL

	ids atomic.Uint32

	mu        sync.RWMutex
	conn      *wsConn
	connected bool
	hubVMAC   sc.MAC
	hubStatus uint8
	hubSeen   bool

	onNPDU func(orig *sc.MAC, npdu []byte)
}

// NewNode validates cfg and returns a node ready to Run.
func NewNode(cfg NodeConfig, log *zap.Logger) (*Node, error) {
	if log == nil {
		log = zap.NewNop()
	}
	cfg.withDefaults()
	if cfg.VMAC.IsZero() {
		return nil, fmt.Errorf("sc: node vmac is all zero")
	}
	if cfg.UUID == (sc.UUID{}) {
		return nil, fmt.Errorf("sc: node uuid is all zero")
	}
	if len(cfg.Hubs) == 0 {
		return nil, fmt.Errorf("sc: no hub URLs configured")
	}
	hubs := make([]hubURL, 0, len(cfg.Hubs))
	for _, raw := range cfg.Hubs {
		hub, err := parseHubURL(raw)
		if err != nil {
			return nil, err
		}
		if !hub.secure && !cfg.AllowInsecure {
			return nil, fmt.Errorf("sc: hub URL %q is not wss (set AllowInsecure only in tests)", raw)
		}
		hubs = append(hubs, hub)
	}
	return &Node{cfg: cfg, log: log, hubs: hubs}, nil
}

// SetNPDUHandler registers the callback for inbound Encapsulated-NPDU
// messages. orig is the sending node's VMAC, or nil for the connection-peer
// shorthand; npdu is valid only for the duration of the call. It must be set
// before Run.
func (n *Node) SetNPDUHandler(fn func(orig *sc.MAC, npdu []byte)) { n.onNPDU = fn }

// VMAC returns the node's own virtual MAC.
func (n *Node) VMAC() sc.MAC { return n.cfg.VMAC }

// UUID returns the node's device UUID.
func (n *Node) UUID() sc.UUID { return n.cfg.UUID }

// Connected reports whether the node currently has a live hub connection.
func (n *Node) Connected() bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.connected
}

// HubVMAC returns the VMAC the hub advertised in the Connect-Accept, if a
// connection has been established.
func (n *Node) HubVMAC() (sc.MAC, bool) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	if !n.connected {
		return sc.MAC{}, false
	}
	return n.hubVMAC, true
}

// HubStatus returns the most recent hub connection status from an
// Advertisement, and whether one has been seen.
func (n *Node) HubStatus() (uint8, bool) {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.hubStatus, n.hubSeen
}

// SendNPDU sends an Encapsulated-NPDU carrying npdu to the node with the given
// VMAC through the hub. It returns ErrNotConnected when there is no live
// connection.
func (n *Node) SendNPDU(dest sc.MAC, npdu []byte) error {
	if dest.IsZero() {
		return fmt.Errorf("sc: send to the zero vmac")
	}
	orig := n.cfg.VMAC
	return n.send(sc.Header{
		Function:  sc.FuncEncapsulatedNPDU,
		MessageID: n.nextID(),
		Orig:      &orig,
		Dest:      &dest,
		Payload:   npdu,
	})
}

func (n *Node) send(hdr sc.Header) error {
	buf, err := hdr.Marshal()
	if err != nil {
		return err
	}
	n.mu.RLock()
	c := n.conn
	n.mu.RUnlock()
	if c == nil {
		return ErrNotConnected
	}
	return c.WriteBinary(buf)
}

func (n *Node) nextID() uint16 { return uint16(n.ids.Add(1)) }

// Run connects to a hub and serves until ctx is cancelled, reconnecting with
// backoff and cycling through the configured hubs. It returns ctx.Err() on
// cancellation.
func (n *Node) Run(ctx context.Context) error {
	backoff := n.cfg.ReconnectMin
	idx := 0
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		connected, err := n.connectAndServe(ctx, n.hubs[idx])
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		n.log.Warn("sc: hub connection ended", zap.String("hub", n.hubs[idx].raw), zap.Error(err))
		if connected {
			// A successful attach means the hub is healthy; keep using it and
			// reset the backoff rather than penalising a late failure.
			backoff = n.cfg.ReconnectMin
		} else {
			idx = (idx + 1) % len(n.hubs)
			backoff = min(backoff*2, n.cfg.ReconnectMax)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
	}
}

// connectAndServe dials one hub, completes the connect handshake and serves
// the connection. connected reports whether the handshake succeeded (so the
// caller can distinguish "hub down" from "hub died mid-session").
func (n *Node) connectAndServe(ctx context.Context, hub hubURL) (connected bool, err error) {
	conn, err := dialHub(ctx, hub, n.cfg.TLS, HubSubprotocol, n.cfg.DialTimeout)
	if err != nil {
		return false, err
	}
	defer conn.Close() //nolint:errcheck // best effort

	if err := n.connectHandshake(conn); err != nil {
		return false, err
	}
	n.setConn(conn)
	defer n.clearConn()

	n.log.Info("sc: attached to hub",
		zap.String("hub", hub.raw),
		zap.String("vmac", n.cfg.VMAC.String()),
		zap.String("uuid", n.cfg.UUID.String()))

	return true, n.serve(ctx, conn)
}

// connectHandshake sends a Connect-Request and waits for the Connect-Accept
// (or a Result NAK). On success the hub's VMAC is recorded.
func (n *Node) connectHandshake(conn *wsConn) error {
	id := n.nextID()
	payload, err := sc.ConnectRequest{
		VMAC:    n.cfg.VMAC,
		UUID:    n.cfg.UUID,
		MaxBVLC: n.cfg.MaxBVLC,
		MaxNPDU: n.cfg.MaxNPDU,
	}.Encode()
	if err != nil {
		return err
	}
	// A Connect-Request carries no header addresses: the node's identity is in
	// the payload, and the hub's is not yet known (bacnet-stack sends NULL,
	// NULL via bvlc_sc_encode_common).
	if err := n.sendOn(conn, sc.Header{Function: sc.FuncConnectRequest, MessageID: id, Payload: payload}); err != nil {
		return err
	}
	deadline := time.Now().Add(n.cfg.DialTimeout)
	for {
		if err := conn.SetReadDeadline(deadline); err != nil {
			return err
		}
		op, msg, err := conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("sc: awaiting connect-accept: %w", err)
		}
		if op != opBinary {
			return fmt.Errorf("sc: connect-accept was not a binary message")
		}
		hdr, err := sc.Parse(msg)
		if err != nil {
			return fmt.Errorf("sc: connect-accept: %w", err)
		}
		switch hdr.Function {
		case sc.FuncConnectAccept:
			if hdr.MessageID != id {
				n.log.Debug("sc: connect-accept for an unexpected message id",
					zap.Uint16("got", hdr.MessageID), zap.Uint16("want", id))
				continue
			}
			acc, err := sc.DecodeConnectAccept(hdr.Payload)
			if err != nil {
				return fmt.Errorf("sc: connect-accept: %w", err)
			}
			if acc.VMAC.IsZero() {
				return fmt.Errorf("sc: connect-accept carried a zero hub vmac")
			}
			n.mu.Lock()
			n.hubVMAC = acc.VMAC
			n.mu.Unlock()
			return nil
		case sc.FuncResult:
			res, err := sc.DecodeResult(hdr.Payload)
			if err != nil {
				return fmt.Errorf("sc: connect rejected: %w", err)
			}
			if res.Function == sc.FuncConnectRequest && res.Code == sc.ResultNAK {
				return fmt.Errorf("sc: connect rejected: class %d code %d %s",
					res.ErrorClass, res.ErrorCode, res.Details)
			}
			n.log.Debug("sc: ignoring unrelated Result during connect")
		default:
			n.log.Debug("sc: ignoring frame during connect",
				zap.String("function", hdr.Function.String()))
		}
	}
}

// serve runs the connected read loop, sending heartbeats while idle.
func (n *Node) serve(ctx context.Context, conn *wsConn) error {
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = conn.Close()
		case <-done:
		}
	}()

	next := time.Now().Add(n.cfg.HeartbeatInterval)
	for {
		if err := conn.SetReadDeadline(next); err != nil {
			return err
		}
		op, msg, err := conn.ReadMessage()
		if err != nil {
			if isTimeout(err) {
				if !n.heartbeat(conn) {
					return fmt.Errorf("sc: heartbeat not acknowledged")
				}
				next = time.Now().Add(n.cfg.HeartbeatInterval)
				continue
			}
			return err
		}
		if op != opBinary {
			return fmt.Errorf("sc: received a non-binary websocket message")
		}
		hdr, err := sc.Parse(msg)
		if err != nil {
			n.log.Warn("sc: dropping malformed frame", zap.Error(err))
			continue
		}
		if err := n.handleFrame(conn, hdr); err != nil {
			return err
		}
		// Any traffic means the connection is live; only an idle connection
		// needs a heartbeat, so restart the idle timer.
		next = time.Now().Add(n.cfg.HeartbeatInterval)
	}
}

// heartbeat sends a Heartbeat-Request and waits for the matching ACK,
// handling other frames that arrive in the meantime. It reports whether the
// ACK arrived before the timeout.
func (n *Node) heartbeat(conn *wsConn) bool {
	id := n.nextID()
	if err := n.sendOn(conn, sc.Header{Function: sc.FuncHeartbeatRequest, MessageID: id}); err != nil {
		return false
	}
	deadline := time.Now().Add(n.cfg.HeartbeatTimeout)
	for {
		if err := conn.SetReadDeadline(deadline); err != nil {
			return false
		}
		op, msg, err := conn.ReadMessage()
		if err != nil {
			return false
		}
		if op != opBinary {
			return false
		}
		hdr, err := sc.Parse(msg)
		if err != nil {
			continue
		}
		if hdr.Function == sc.FuncHeartbeatACK {
			if hdr.MessageID == id {
				return true
			}
			continue
		}
		if err := n.handleFrame(conn, hdr); err != nil {
			return false
		}
	}
}

// handleFrame processes one inbound BVLC-SC frame in the connected state.
func (n *Node) handleFrame(conn *wsConn, hdr sc.Header) error {
	switch hdr.Function {
	case sc.FuncEncapsulatedNPDU:
		if n.onNPDU != nil {
			n.onNPDU(hdr.Orig, hdr.Payload)
		}
	case sc.FuncAdvertisement:
		if adv, err := sc.DecodeAdvertisement(hdr.Payload); err == nil {
			n.mu.Lock()
			n.hubStatus = adv.HubStatus
			n.hubSeen = true
			n.mu.Unlock()
		} else {
			n.log.Debug("sc: bad advertisement", zap.Error(err))
		}
	case sc.FuncHeartbeatRequest:
		return n.sendOn(conn, sc.Header{Function: sc.FuncHeartbeatACK, MessageID: hdr.MessageID})
	case sc.FuncHeartbeatACK:
		// A stray ACK; the wait in heartbeat() consumes the matching one.
	case sc.FuncDisconnectRequest:
		_ = n.sendOn(conn, sc.Header{Function: sc.FuncDisconnectACK, MessageID: hdr.MessageID})
		return errPeerDisconnected
	case sc.FuncResult:
		n.log.Debug("sc: received a Result", zap.Uint16("message_id", hdr.MessageID))
	case sc.FuncAddressResolution, sc.FuncAddressResolutionACK:
		// The proxy is a hub client only and accepts no direct connections, so
		// it has no WebSocket URI to advertise.
	default:
		n.log.Debug("sc: ignoring frame", zap.String("function", hdr.Function.String()))
	}
	return nil
}

func (n *Node) sendOn(conn *wsConn, hdr sc.Header) error {
	buf, err := hdr.Marshal()
	if err != nil {
		return err
	}
	return conn.WriteBinary(buf)
}

func (n *Node) setConn(c *wsConn) {
	n.mu.Lock()
	n.conn = c
	n.connected = true
	n.mu.Unlock()
}

func (n *Node) clearConn() {
	n.mu.Lock()
	n.conn = nil
	n.connected = false
	n.mu.Unlock()
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}
