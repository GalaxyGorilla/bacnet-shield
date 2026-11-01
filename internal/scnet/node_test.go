package scnet

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet/sc"
)

// genCert returns a self-signed TLS server certificate for 127.0.0.1 and a
// pool that trusts it, so the node test exercises real TLS 1.3 verification.
func genCert(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "bacnet-shield-sc-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// testHub is a minimal BACnet/SC hub: it performs the WebSocket upgrade, the
// Connect-Accept handshake, heartbeat and disconnect ACKs, and relays
// Encapsulated-NPDUs. It is deliberately the real wire protocol, not a mock of
// the Node.
type testHub struct {
	t    *testing.T
	ln   net.Listener
	url  string
	pool *x509.CertPool

	vmac sc.MAC
	uuid sc.UUID

	mu       sync.Mutex
	conns    []*hubConn
	connects int
	hearts   int

	// dropHeartbeats makes the hub stop acknowledging Heartbeat-Requests, so
	// a test can drive the node's "heartbeat not acknowledged" path.
	dropHeartbeats bool

	npdus chan hubNPDU
}

type hubConn struct {
	c    *wsConn
	vmac sc.MAC
	uuid sc.UUID
}

type hubNPDU struct {
	orig *sc.MAC
	dest *sc.MAC
	data []byte
}

func newTestHub(t *testing.T) *testHub {
	t.Helper()
	cert, pool := genCert(t)
	h := &testHub{
		t:     t,
		pool:  pool,
		vmac:  sc.MAC{0xAA, 0xBB, 0xCC, 0x00, 0x00, 0x01},
		uuid:  sc.UUID{0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89},
		npdus: make(chan hubNPDU, 16),
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.ln = ln
	h.url = "wss://" + ln.Addr().String() + "/"
	t.Cleanup(func() { _ = ln.Close() })
	go h.acceptLoop()
	return h
}

func (h *testHub) acceptLoop() {
	for {
		raw, err := h.ln.Accept()
		if err != nil {
			return
		}
		go h.serveConn(raw)
	}
}

func (h *testHub) serveConn(raw net.Conn) {
	conn, err := wsServerHandshake(raw, HubSubprotocol, time.Now().Add(5*time.Second))
	if err != nil {
		_ = raw.Close()
		return
	}
	hc := &hubConn{c: conn}
	defer func() {
		_ = conn.Close()
		h.mu.Lock()
		for i, c := range h.conns {
			if c == hc {
				h.conns = append(h.conns[:i], h.conns[i+1:]...)
				break
			}
		}
		h.mu.Unlock()
	}()
	for {
		op, msg, err := conn.ReadMessage()
		if err != nil || op != opBinary {
			return
		}
		frame, err := sc.Parse(msg)
		if err != nil {
			continue
		}
		switch frame.Function {
		case sc.FuncConnectRequest:
			req, err := sc.DecodeConnectRequest(frame.Payload)
			if err != nil || req.VMAC.IsZero() {
				_ = hc.send(sc.Header{Function: sc.FuncResult, MessageID: frame.MessageID, Payload: mustResultNAK(sc.FuncConnectRequest)})
				return
			}
			hc.vmac, hc.uuid = req.VMAC, req.UUID
			h.mu.Lock()
			h.conns = append(h.conns, hc)
			h.connects++
			h.mu.Unlock()
			payload, _ := sc.ConnectAccept{VMAC: h.vmac, UUID: h.uuid, MaxBVLC: 1497, MaxNPDU: 1440}.Encode()
			_ = hc.send(sc.Header{Function: sc.FuncConnectAccept, MessageID: frame.MessageID, Payload: payload})
		case sc.FuncHeartbeatRequest:
			h.mu.Lock()
			h.hearts++
			drop := h.dropHeartbeats
			h.mu.Unlock()
			if drop {
				continue
			}
			_ = hc.send(sc.Header{Function: sc.FuncHeartbeatACK, MessageID: frame.MessageID})
		case sc.FuncDisconnectRequest:
			_ = hc.send(sc.Header{Function: sc.FuncDisconnectACK, MessageID: frame.MessageID})
			return
		case sc.FuncEncapsulatedNPDU:
			// A hub learns who sent a frame from the connection, so a node
			// must not assert its own originating VMAC; bacnet-stack's hub
			// NAKs such a frame ("'Originating Virtual Address' field must
			// be absent"). Enforce the same rule here so a regression fails
			// locally instead of only against the Docker interop hub.
			if frame.Orig != nil {
				_ = hc.send(sc.Header{Function: sc.FuncResult, MessageID: frame.MessageID,
					Payload: mustResultNAK(sc.FuncEncapsulatedNPDU)})
				continue
			}
			select {
			case h.npdus <- hubNPDU{orig: frame.Orig, dest: frame.Dest, data: frame.Payload}:
			default:
			}
		}
	}
}

func (h *testHub) send(hc *hubConn, hdr sc.Header) {
	h.t.Helper()
	if err := hc.send(hdr); err != nil {
		h.t.Fatalf("hub send: %v", err)
	}
}

func (hc *hubConn) send(hdr sc.Header) error {
	buf, err := hdr.Marshal()
	if err != nil {
		return err
	}
	return hc.c.WriteBinary(buf)
}

func (h *testHub) waitConn(t *testing.T, timeout time.Duration) *hubConn {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		h.mu.Lock()
		if len(h.conns) > 0 {
			c := h.conns[0]
			h.mu.Unlock()
			return c
		}
		h.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("hub never saw a node connect")
	return nil
}

func (h *testHub) count() (connects, hearts int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.connects, h.hearts
}

// setDropHeartbeats controls whether the hub acknowledges Heartbeat-Requests.
func (h *testHub) setDropHeartbeats(v bool) {
	h.mu.Lock()
	h.dropHeartbeats = v
	h.mu.Unlock()
}

func mustResultNAK(fn sc.Function) []byte {
	p, _ := sc.Result{Function: fn, Code: sc.ResultNAK, ErrorClass: 1, ErrorCode: 1, Details: "no"}.Encode()
	return p
}

// testNode builds a node for the test hub with fast timers and real TLS
// verification of the hub certificate.
func testNode(t *testing.T, h *testHub, cfg NodeConfig) *Node {
	t.Helper()
	if cfg.VMAC.IsZero() {
		cfg.VMAC = sc.MAC{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	}
	if cfg.UUID == (sc.UUID{}) {
		cfg.UUID = sc.UUID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	}
	cfg.Hubs = []string{h.url}
	cfg.TLS = &tls.Config{RootCAs: h.pool}
	cfg.DialTimeout = 3 * time.Second
	if cfg.HeartbeatInterval == 0 {
		cfg.HeartbeatInterval = 100 * time.Millisecond
	}
	if cfg.HeartbeatTimeout == 0 {
		cfg.HeartbeatTimeout = time.Second
	}
	cfg.ReconnectMin = 20 * time.Millisecond
	cfg.ReconnectMax = 100 * time.Millisecond
	if cfg.MaxMessage == 0 {
		cfg.MaxMessage = 4096
	}
	n, err := NewNode(cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}
	return n
}

func TestNodeConnectsSendsAndReceives(t *testing.T) {
	h := newTestHub(t)
	n := testNode(t, h, NodeConfig{})

	received := make(chan hubNPDU, 4)
	n.SetNPDUHandler(func(orig *sc.MAC, npdu []byte) {
		received <- hubNPDU{orig: orig, data: append([]byte(nil), npdu...)}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = n.Run(ctx) }()

	hc := h.waitConn(t, 3*time.Second)
	waitConnected(t, n, 3*time.Second)

	// Node -> hub. The originating VMAC must be absent: the hub stamps it
	// from the connection, and bacnet-stack's hub rejects a node that sets
	// it. Only the destination travels with the frame.
	dest := sc.MAC{0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F}
	if err := n.SendNPDU(dest, []byte{1, 4, 0, 5, 1}); err != nil {
		t.Fatalf("SendNPDU: %v", err)
	}
	select {
	case got := <-h.npdus:
		if got.orig != nil {
			t.Fatalf("orig = %v, want absent (the hub adds it)", got.orig)
		}
		if got.dest == nil || *got.dest != dest {
			t.Fatalf("dest = %v, want %v", got.dest, dest)
		}
		if string(got.data) != string([]byte{1, 4, 0, 5, 1}) {
			t.Fatalf("payload = %x", got.data)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("hub did not receive the encapsulated npdu")
	}

	// Hub -> node.
	client := sc.MAC{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01}
	destMAC := n.VMAC()
	h.send(hc, sc.Header{Function: sc.FuncEncapsulatedNPDU, MessageID: 0x100, Orig: &client, Dest: &destMAC, Payload: []byte{9, 9}})
	select {
	case got := <-received:
		if got.orig == nil || *got.orig != client {
			t.Fatalf("inbound orig = %v, want %v", got.orig, client)
		}
		if string(got.data) != string([]byte{9, 9}) {
			t.Fatalf("inbound payload = %x", got.data)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("node did not deliver the inbound npdu")
	}
}

func TestNodeStateHandler(t *testing.T) {
	h := newTestHub(t)
	n := testNode(t, h, NodeConfig{})

	type event struct {
		connected bool
		hub       string
	}
	events := make(chan event, 8)
	n.SetStateHandler(func(connected bool, hub string) {
		events <- event{connected: connected, hub: hub}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = n.Run(ctx) }()

	// Connecting must be reported exactly once, with the hub URL, so a
	// dashboard can show the SC leg up even before the first NPDU.
	select {
	case ev := <-events:
		if !ev.connected {
			t.Fatalf("first state event = %+v, want connected", ev)
		}
		if ev.hub != h.url {
			t.Fatalf("hub = %q, want %q", ev.hub, h.url)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no connected state event")
	}
	waitConnected(t, n, 3*time.Second)

	// Shutting down must report the link down, so the gauge falls back to 0
	// instead of freezing at 1.
	cancel()
	select {
	case ev := <-events:
		if ev.connected {
			t.Fatalf("second state event = %+v, want disconnected", ev)
		}
		if ev.hub != h.url {
			t.Fatalf("hub = %q, want %q", ev.hub, h.url)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no disconnected state event on shutdown")
	}
}

// TestNodeStateHandlerReconnect: a hub drop must be reported as disconnected
// and the re-attach as connected again, in order, so the connected gauge falls
// to 0 during the outage and rises again instead of sticking at 1.
func TestNodeStateHandlerReconnect(t *testing.T) {
	h := newTestHub(t)
	n := testNode(t, h, NodeConfig{})

	connected := make(chan struct{}, 8)
	disconnected := make(chan struct{}, 8)
	n.SetStateHandler(func(up bool, hub string) {
		if up {
			connected <- struct{}{}
		} else {
			disconnected <- struct{}{}
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = n.Run(ctx) }()

	hc := h.waitConn(t, 3*time.Second)
	waitState(t, connected, "initial connect")
	waitConnected(t, n, 3*time.Second)

	// The hub drops the connection. The node must report the loss...
	_ = hc.c.Close()
	waitState(t, disconnected, "disconnect after the hub dropped")
	// ...and then report the re-attach once it is serving again.
	waitState(t, connected, "reconnect")
	waitConnected(t, n, 3*time.Second)
}

func waitState(t *testing.T, ch chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(3 * time.Second):
		t.Fatalf("no state transition: %s", what)
	}
}

func TestNodeFiltersInboundNPDUs(t *testing.T) {
	h := newTestHub(t)
	n := testNode(t, h, NodeConfig{})

	received := make(chan hubNPDU, 4)
	n.SetNPDUHandler(func(orig *sc.MAC, npdu []byte) {
		received <- hubNPDU{orig: orig, data: append([]byte(nil), npdu...)}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = n.Run(ctx) }()

	hc := h.waitConn(t, 3*time.Second)
	waitConnected(t, n, 3*time.Second)

	client := sc.MAC{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01}
	other := sc.MAC{0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x02}
	we := n.VMAC()

	// Addressed to another node: not ours to deliver.
	h.send(hc, sc.Header{Function: sc.FuncEncapsulatedNPDU, MessageID: 0x201,
		Orig: &client, Dest: &other, Payload: []byte{1, 1}})
	// No origin: cannot be attributed to a client.
	h.send(hc, sc.Header{Function: sc.FuncEncapsulatedNPDU, MessageID: 0x202,
		Dest: &we, Payload: []byte{2, 2}})
	// A zero origin is the same as none.
	zero := sc.MAC{}
	h.send(hc, sc.Header{Function: sc.FuncEncapsulatedNPDU, MessageID: 0x203,
		Orig: &zero, Dest: &we, Payload: []byte{3, 3}})

	select {
	case got := <-received:
		t.Fatalf("node delivered a frame it should have dropped: %x from %v", got.data, got.orig)
	case <-time.After(200 * time.Millisecond):
	}

	// Addressed to us: delivered.
	h.send(hc, sc.Header{Function: sc.FuncEncapsulatedNPDU, MessageID: 0x204,
		Orig: &client, Dest: &we, Payload: []byte{4, 4}})
	select {
	case got := <-received:
		if got.orig == nil || *got.orig != client {
			t.Fatalf("inbound orig = %v, want %v", got.orig, client)
		}
		if string(got.data) != string([]byte{4, 4}) {
			t.Fatalf("inbound payload = %x", got.data)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("node dropped a frame addressed to it")
	}

	// A broadcast destination is delivered too: discovery is addressed to
	// every node and the proxy answers it as the one device.
	bcast := sc.BroadcastMAC
	h.send(hc, sc.Header{Function: sc.FuncEncapsulatedNPDU, MessageID: 0x205,
		Orig: &client, Dest: &bcast, Payload: []byte{5, 5}})
	select {
	case got := <-received:
		if string(got.data) != string([]byte{5, 5}) {
			t.Fatalf("broadcast payload = %x", got.data)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("node dropped a broadcast frame")
	}
}

func TestNodeHeartbeats(t *testing.T) {
	h := newTestHub(t)
	n := testNode(t, h, NodeConfig{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = n.Run(ctx) }()

	h.waitConn(t, 3*time.Second)
	waitConnected(t, n, 3*time.Second)
	time.Sleep(400 * time.Millisecond) // several heartbeat intervals
	_, hearts := h.count()
	if hearts == 0 {
		t.Fatal("node never sent a heartbeat request")
	}
	if !n.Connected() {
		t.Fatal("node dropped the connection while heartbeating")
	}
}

func TestNodeReconnectsAfterHubDrops(t *testing.T) {
	h := newTestHub(t)
	n := testNode(t, h, NodeConfig{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = n.Run(ctx) }()

	hc := h.waitConn(t, 3*time.Second)
	waitConnected(t, n, 3*time.Second)
	_ = hc.c.Close() // hub drops the connection

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if connects, _ := h.count(); connects >= 2 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	connects, _ := h.count()
	t.Fatalf("node did not reconnect, connects = %d", connects)
}

func TestNodeRunStopsOnContextCancel(t *testing.T) {
	h := newTestHub(t)
	n := testNode(t, h, NodeConfig{})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- n.Run(ctx) }()
	h.waitConn(t, 3*time.Second)
	waitConnected(t, n, 3*time.Second)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Run returned nil after cancel")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not stop after cancel")
	}
}

func TestNodeValidation(t *testing.T) {
	good := NodeConfig{
		VMAC: sc.MAC{1, 2, 3, 4, 5, 6},
		UUID: sc.UUID{1, 2, 3},
		Hubs: []string{"wss://hub.example/"},
	}
	if _, err := NewNode(good, nil); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	cases := map[string]func(*NodeConfig){
		"zero vmac":   func(c *NodeConfig) { c.VMAC = sc.MAC{} },
		"zero uuid":   func(c *NodeConfig) { c.UUID = sc.UUID{} },
		"no hubs":     func(c *NodeConfig) { c.Hubs = nil },
		"bad hub url": func(c *NodeConfig) { c.Hubs = []string{"http://hub/"} },
		"insecure ws": func(c *NodeConfig) { c.Hubs = []string{"ws://hub/"} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := good
			mutate(&cfg)
			if _, err := NewNode(cfg, nil); err == nil {
				t.Fatal("config accepted")
			}
		})
	}
	// The test-only escape hatch.
	cfg := good
	cfg.Hubs = []string{"ws://127.0.0.1:1234/"}
	cfg.AllowInsecure = true
	if _, err := NewNode(cfg, nil); err != nil {
		t.Fatalf("AllowInsecure rejected: %v", err)
	}
}

func TestNodeSendWithoutConnection(t *testing.T) {
	n, err := NewNode(NodeConfig{
		VMAC: sc.MAC{1, 2, 3, 4, 5, 6},
		UUID: sc.UUID{1, 2, 3},
		Hubs: []string{"wss://hub.example/"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := n.SendNPDU(sc.MAC{9, 9, 9, 9, 9, 9}, []byte{1}); err != ErrNotConnected {
		t.Fatalf("SendNPDU = %v, want ErrNotConnected", err)
	}
	if n.Connected() {
		t.Fatal("Connected() is true before Run")
	}
}

func TestNodeHubAdvertisement(t *testing.T) {
	h := newTestHub(t)
	n := testNode(t, h, NodeConfig{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = n.Run(ctx) }()

	hc := h.waitConn(t, 3*time.Second)
	waitConnected(t, n, 3*time.Second)
	adv, err := sc.Advertisement{HubStatus: sc.HubStatusConnectedPrimary, MaxBVLC: 1497, MaxNPDU: 1440}.Encode()
	if err != nil {
		t.Fatal(err)
	}
	h.send(hc, sc.Header{Function: sc.FuncAdvertisement, MessageID: 0x50, Payload: adv})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s, ok := n.HubStatus(); ok && s == sc.HubStatusConnectedPrimary {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	s, ok := n.HubStatus()
	t.Fatalf("hub status = %d, seen = %v", s, ok)
}

func waitConnected(t *testing.T, n *Node, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if n.Connected() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("node never reported connected")
}

// waitConnects waits until the hub has accepted at least n node connections.
func waitConnects(t *testing.T, h *testHub, n int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if connects, _ := h.count(); connects >= n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	connects, _ := h.count()
	t.Fatalf("hub saw %d connections, want at least %d", connects, n)
}

// TestNodeHeartbeatTimeoutReconnects proves a hub that stops acknowledging
// heartbeats is treated as dead: the node gives up the connection and attaches
// again rather than sitting on a black hole. This is the failure half of
// TestNodeHeartbeats, which only proves the happy path.
func TestNodeHeartbeatTimeoutReconnects(t *testing.T) {
	h := newTestHub(t)
	h.setDropHeartbeats(true)
	n := testNode(t, h, NodeConfig{
		HeartbeatInterval: 60 * time.Millisecond,
		HeartbeatTimeout:  80 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = n.Run(ctx) }()

	h.waitConn(t, 3*time.Second)
	waitConnected(t, n, 3*time.Second)
	waitConnects(t, h, 2, 4*time.Second)
}

// TestNodeSurvivesMalformedFrame proves a junk frame from the network costs
// one frame, not the connection: the node logs and continues, and the next
// good Encapsulated-NPDU is still delivered.
func TestNodeSurvivesMalformedFrame(t *testing.T) {
	h := newTestHub(t)
	n := testNode(t, h, NodeConfig{})

	received := make(chan hubNPDU, 4)
	n.SetNPDUHandler(func(orig *sc.MAC, npdu []byte) {
		received <- hubNPDU{orig: orig, data: append([]byte(nil), npdu...)}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = n.Run(ctx) }()

	hc := h.waitConn(t, 3*time.Second)
	waitConnected(t, n, 3*time.Second)

	// A binary frame that is not a valid BVLL-SC message (unknown function).
	if err := hc.c.WriteBinary([]byte{0xFF, 0x00, 0x00, 0x00}); err != nil {
		t.Fatalf("inject malformed frame: %v", err)
	}

	client := sc.MAC{0x02, 0x00, 0x00, 0x00, 0x00, 0x20}
	dest := n.VMAC()
	h.send(hc, sc.Header{Function: sc.FuncEncapsulatedNPDU, MessageID: 0x70,
		Orig: &client, Dest: &dest, Payload: []byte{1, 4, 0, 5, 1}})

	select {
	case got := <-received:
		if got.orig == nil || *got.orig != client {
			t.Fatalf("orig = %v, want %v", got.orig, client)
		}
		if string(got.data) != string([]byte{1, 4, 0, 5, 1}) {
			t.Fatalf("payload = %x", got.data)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("node dropped the connection after a malformed frame")
	}
	if !n.Connected() {
		t.Fatal("node is no longer connected after a malformed frame")
	}
}

// TestNodeRejectsNonBinaryMessage proves a text (or other non-binary) WebSocket
// message is a protocol violation that ends the connection, not something the
// node tries to parse as a BVLL-SC frame.
func TestNodeRejectsNonBinaryMessage(t *testing.T) {
	h := newTestHub(t)
	n := testNode(t, h, NodeConfig{})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = n.Run(ctx) }()

	hc := h.waitConn(t, 3*time.Second)
	waitConnected(t, n, 3*time.Second)

	if err := hc.c.writeFrame(opText, []byte("not a bacnet frame")); err != nil {
		t.Fatalf("inject text frame: %v", err)
	}

	// The node must drop the connection and reconnect, exactly as after any
	// other connection-level fault.
	waitConnects(t, h, 2, 4*time.Second)
}

// TestNodeFailsOverToSecondHub proves the node list is a real failover list,
// not decoration: when the first hub refuses the connection the node advances
// to the next one and attaches there.
func TestNodeFailsOverToSecondHub(t *testing.T) {
	down := newTestHub(t)
	up := newTestHub(t)
	_ = down.ln.Close() // the first hub is unreachable

	cfg := NodeConfig{
		VMAC:              sc.MAC{0x00, 0x11, 0x22, 0x33, 0x44, 0x66},
		UUID:              sc.UUID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 17},
		Hubs:              []string{down.url, up.url},
		TLS:               &tls.Config{RootCAs: up.pool},
		DialTimeout:       time.Second,
		HeartbeatInterval: 100 * time.Millisecond,
		HeartbeatTimeout:  time.Second,
		ReconnectMin:      20 * time.Millisecond,
		ReconnectMax:      100 * time.Millisecond,
	}
	n, err := NewNode(cfg, zap.NewNop())
	if err != nil {
		t.Fatalf("NewNode: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = n.Run(ctx) }()

	up.waitConn(t, 5*time.Second)
	waitConnected(t, n, 5*time.Second)
}
