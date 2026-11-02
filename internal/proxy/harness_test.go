package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/GalaxyGorilla/bacnet-shield/internal/access"
	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet"
	"github.com/GalaxyGorilla/bacnet-shield/internal/observ"
)

// fixture is one gateway plus the isolated registry its counters live in.
type fixture struct {
	g       *Gateway
	metrics *observ.Metrics
}

func startGateway(t *testing.T, cfg Config, pol *access.Policy) *fixture {
	t.Helper()
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:0"
	}
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = 2 * time.Second
	}
	if cfg.MaxPending == 0 {
		cfg.MaxPending = 256
	}
	m := observ.NewMetrics()
	g, err := New(cfg, pol, zap.NewNop(), m)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	// Most tests leave a request unanswered on purpose; a full two-second
	// drain on cleanup would turn the suite into a coffee break. The
	// dedicated shutdown tests keep the production default.
	g.drainTimeout = 100 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = g.Serve(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("gateway did not shut down")
		}
	})
	return &fixture{g: g, metrics: m}
}

func (f *fixture) addr() *net.UDPAddr { return f.g.ClientAddr() }

// fakeDevice is the legacy device on the clear leg. It binds a real UDP socket
// so the test exercises the production read/write path, not a mocked one.
type fakeDevice struct {
	t    *testing.T
	conn *net.UDPConn
}

func newFakeDevice(t *testing.T, ip string) *fakeDevice {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ip), Port: 0})
	if err != nil {
		t.Fatalf("fake device bind: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &fakeDevice{t: t, conn: conn}
}

func (d *fakeDevice) addr() *net.UDPAddr { return d.conn.LocalAddr().(*net.UDPAddr) }

// recv reads and decodes one datagram. A timeout is returned as-is so callers
// can distinguish "nothing arrived" from a malformed frame.
func (d *fakeDevice) recv(timeout time.Duration) (bacnet.APDU, bacnet.NPDU, *net.UDPAddr, []byte, error) {
	_ = d.conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 65535)
	n, src, err := d.conn.ReadFromUDP(buf)
	if err != nil {
		return bacnet.APDU{}, bacnet.NPDU{}, nil, nil, err
	}
	b, err := bacnet.ParseBVLC(buf[:n])
	if err != nil {
		return bacnet.APDU{}, bacnet.NPDU{}, nil, nil, fmt.Errorf("bvlc: %w", err)
	}
	np, err := bacnet.ParseNPDU(b.Data)
	if err != nil {
		return bacnet.APDU{}, bacnet.NPDU{}, nil, nil, fmt.Errorf("npdu: %w", err)
	}
	a, err := bacnet.ParseAPDU(np.APDU)
	if err != nil {
		return bacnet.APDU{}, bacnet.NPDU{}, nil, nil, fmt.Errorf("apdu: %w", err)
	}
	return a, np, src, append([]byte(nil), np.APDU...), nil
}

func (d *fakeDevice) mustRecv(t *testing.T, timeout time.Duration) (bacnet.APDU, bacnet.NPDU, *net.UDPAddr) {
	t.Helper()
	a, np, src, _, err := d.recv(timeout)
	if err != nil {
		t.Fatalf("device receive: %v", err)
	}
	return a, np, src
}

func (d *fakeDevice) expectNothing(t *testing.T, wait time.Duration) {
	t.Helper()
	_, _, _, _, err := d.recv(wait)
	if err == nil {
		t.Fatal("device received an unexpected datagram")
	}
	if !isTimeout(err) {
		t.Fatalf("device read: %v", err)
	}
}

func (d *fakeDevice) send(t *testing.T, a bacnet.APDU, to *net.UDPAddr) {
	t.Helper()
	d.sendNPDU(t, bacnet.NPDU{}, a, to)
}

func (d *fakeDevice) sendNPDU(t *testing.T, n bacnet.NPDU, a bacnet.APDU, to *net.UDPAddr) {
	t.Helper()
	n.APDU = a.Marshal()
	frame := bacnet.BVLC{Function: bacnet.BVLCOriginalUnicastNPDU, Data: n.Marshal()}.Marshal()
	if _, err := d.conn.WriteToUDP(frame, to); err != nil {
		t.Fatalf("device send: %v", err)
	}
}

// testClient is one front-leg workstation.
type testClient struct {
	t    *testing.T
	conn *net.UDPConn
}

func newTestClient(t *testing.T) *testClient {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("client bind: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &testClient{t: t, conn: conn}
}

func (c *testClient) send(a bacnet.APDU, to *net.UDPAddr) {
	c.t.Helper()
	c.sendNPDU(bacnet.NPDU{}, a, to)
}

func (c *testClient) sendNPDU(n bacnet.NPDU, a bacnet.APDU, to *net.UDPAddr) {
	c.t.Helper()
	n.APDU = a.Marshal()
	c.sendFrame(bacnet.BVLC{Function: bacnet.BVLCOriginalUnicastNPDU, Data: n.Marshal()}.Marshal(), to)
}

func (c *testClient) sendFrame(frame []byte, to *net.UDPAddr) {
	c.t.Helper()
	if _, err := c.conn.WriteToUDP(frame, to); err != nil {
		c.t.Fatalf("client send: %v", err)
	}
}

func (c *testClient) recv(timeout time.Duration) (bacnet.APDU, bacnet.NPDU, []byte, error) {
	_ = c.conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 65535)
	n, _, err := c.conn.ReadFromUDP(buf)
	if err != nil {
		return bacnet.APDU{}, bacnet.NPDU{}, nil, err
	}
	b, err := bacnet.ParseBVLC(buf[:n])
	if err != nil {
		return bacnet.APDU{}, bacnet.NPDU{}, nil, fmt.Errorf("bvlc: %w", err)
	}
	np, err := bacnet.ParseNPDU(b.Data)
	if err != nil {
		return bacnet.APDU{}, bacnet.NPDU{}, nil, fmt.Errorf("npdu: %w", err)
	}
	a, err := bacnet.ParseAPDU(np.APDU)
	if err != nil {
		return bacnet.APDU{}, bacnet.NPDU{}, nil, fmt.Errorf("apdu: %w", err)
	}
	return a, np, append([]byte(nil), np.APDU...), nil
}

func (c *testClient) mustRecv(t *testing.T, timeout time.Duration) (bacnet.APDU, bacnet.NPDU) {
	t.Helper()
	a, np, _, err := c.recv(timeout)
	if err != nil {
		t.Fatalf("client receive: %v", err)
	}
	return a, np
}

func (c *testClient) expectNothing(t *testing.T, wait time.Duration) {
	t.Helper()
	_, _, _, err := c.recv(wait)
	if err == nil {
		t.Fatal("client received an unexpected datagram")
	}
	if !isTimeout(err) {
		t.Fatalf("client read: %v", err)
	}
}

func isTimeout(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// --- APDU builders -------------------------------------------------------

func readProperty(invoke byte, oid bacnet.ObjectID, prop bacnet.PropertyID) bacnet.APDU {
	payload := append([]byte{0x0C}, oid.AppendTo(nil)...)
	payload = append(payload, 0x19, byte(prop))
	return bacnet.APDU{Type: bacnet.PDUConfirmedRequest, InvokeID: invoke, HasInvokeID: true,
		HasService: true, Service: bacnet.ServiceReadProperty, Payload: payload}
}

func readPropertyACK(invoke byte, oid bacnet.ObjectID, prop bacnet.PropertyID, value []byte) bacnet.APDU {
	payload := append([]byte{0x0C}, oid.AppendTo(nil)...)
	payload = append(payload, 0x19, byte(prop))
	payload = append(payload, 0x3E)
	payload = append(payload, value...)
	payload = append(payload, 0x3F)
	return bacnet.APDU{Type: bacnet.PDUComplexACK, InvokeID: invoke, HasInvokeID: true,
		HasService: true, Service: bacnet.ServiceReadProperty, Payload: payload}
}

func writeProperty(invoke byte, oid bacnet.ObjectID, prop bacnet.PropertyID) bacnet.APDU {
	payload := append([]byte{0x0C}, oid.AppendTo(nil)...)
	payload = append(payload, 0x19, byte(prop))
	payload = append(payload, 0x3E, 0x44, 0x3F, 0x80, 0x00, 0x00, 0x3F)
	return bacnet.APDU{Type: bacnet.PDUConfirmedRequest, InvokeID: invoke, HasInvokeID: true,
		HasService: true, Service: bacnet.ServiceWriteProperty, Payload: payload}
}

func writePropertyMultiple(invoke byte, targets []bacnet.WriteTarget) bacnet.APDU {
	payload := []byte{0x0E}
	for _, tg := range targets {
		payload = append(payload, 0x0C)
		payload = append(payload, tg.Object.AppendTo(nil)...)
		payload = append(payload, 0x1E, 0x09, byte(tg.Property))
		payload = append(payload, 0x2E, 0x44, 0x3F, 0x80, 0x00, 0x00, 0x2F, 0x1F)
	}
	payload = append(payload, 0x0F)
	return bacnet.APDU{Type: bacnet.PDUConfirmedRequest, InvokeID: invoke, HasInvokeID: true,
		HasService: true, Service: bacnet.ServiceWritePropertyMultiple, Payload: payload}
}

func simpleACK(invoke byte, service bacnet.Service) bacnet.APDU {
	return bacnet.APDU{Type: bacnet.PDUSimpleACK, InvokeID: invoke, HasInvokeID: true,
		Service: service, HasService: true}
}

func subscribeCOV(invoke byte, proc uint32, oid bacnet.ObjectID, lifetime *uint32) bacnet.APDU {
	payload := []byte{0x09, byte(proc), 0x1C}
	payload = append(payload, oid.AppendTo(nil)...)
	payload = append(payload, 0x29, 0x00)
	if lifetime != nil {
		payload = append(payload, 0x39, byte(*lifetime))
	}
	return bacnet.APDU{Type: bacnet.PDUConfirmedRequest, InvokeID: invoke, HasInvokeID: true,
		HasService: true, Service: bacnet.ServiceSubscribeCOV, Payload: payload}
}

func covNotification(proc uint32, oid bacnet.ObjectID) []byte {
	payload := []byte{0x09, byte(proc), 0x1C, 0x02, 0x00, 0x00, 0x64, 0x2C}
	payload = append(payload, oid.AppendTo(nil)...)
	payload = append(payload, 0x39, 0x00, 0x4E, 0x0F)
	return payload
}

func iam(device uint32) bacnet.APDU {
	oid := bacnet.ObjectID{Type: bacnet.ObjectDevice, Instance: device}
	payload := append([]byte{0x0C}, oid.AppendTo(nil)...)
	payload = append(payload, 0x19, 0x05, 0x29, 0x00, 0x3A, 0x00, 0x05)
	return bacnet.APDU{Type: bacnet.PDUUnconfirmedRequest, HasService: true,
		Service: bacnet.ServiceIAm, Payload: payload}
}

func whoIs() bacnet.APDU {
	return bacnet.APDU{Type: bacnet.PDUUnconfirmedRequest, HasService: true, Service: bacnet.ServiceWhoIs}
}

func segmentACK(invoke, seq byte) bacnet.APDU {
	return bacnet.APDU{Type: bacnet.PDUSegmentACK, InvokeID: invoke, HasInvokeID: true,
		SequenceNumber: seq, WindowSize: 1}
}

func segmentedACK(invoke, seq byte, more bool, payload []byte) bacnet.APDU {
	return bacnet.APDU{Type: bacnet.PDUComplexACK, Segmented: true, MoreFollows: more,
		InvokeID: invoke, HasInvokeID: true, HasService: true,
		Service: bacnet.ServiceReadProperty, SequenceNumber: seq, WindowSize: 1, Payload: payload}
}

// --- policy helpers ------------------------------------------------------

func readOnlyPolicy(t *testing.T) *access.Policy {
	t.Helper()
	wp, err := access.NewWritePolicy(true, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	return access.NewPolicy(nil, nil, wp)
}

func writePolicy(t *testing.T, def access.Action, rules []access.Rule) *access.Policy {
	t.Helper()
	wp, err := access.NewWritePolicy(false, def, rules)
	if err != nil {
		t.Fatal(err)
	}
	return access.NewPolicy(nil, nil, wp)
}
