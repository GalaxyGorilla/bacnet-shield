package proxy

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/GalaxyGorilla/bacnet-shield/internal/access"
	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet"
)

// testClient6 is one BACnet/IPv6 front-leg workstation. It sends and receives
// raw 0x82 frames so the test exercises the real IPv6 link layer, not a
// helper that agrees with the proxy by construction.
type testClient6 struct {
	t    *testing.T
	conn *net.UDPConn
	vmac bacnet.VMAC
}

func newTestClient6(t *testing.T) *testClient6 {
	t.Helper()
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Fatalf("ipv6 client bind: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return &testClient6{t: t, conn: conn, vmac: bacnet.VMAC{0x02, 0x00, 0x0a}}
}

func (c *testClient6) sendFrame(frame []byte, to *net.UDPAddr) {
	c.t.Helper()
	if _, err := c.conn.WriteToUDP(frame, to); err != nil {
		c.t.Fatalf("ipv6 client send: %v", err)
	}
}

func (c *testClient6) recv(timeout time.Duration) (bacnet.BVLC6, error) {
	_ = c.conn.SetReadDeadline(time.Now().Add(timeout))
	buf := make([]byte, 65535)
	n, _, err := c.conn.ReadFromUDP(buf)
	if err != nil {
		return bacnet.BVLC6{}, err
	}
	return bacnet.ParseBVLC6(buf[:n])
}

func (c *testClient6) mustRecv(t *testing.T, timeout time.Duration) bacnet.BVLC6 {
	t.Helper()
	b, err := c.recv(timeout)
	if err != nil {
		t.Fatalf("ipv6 client receive: %v", err)
	}
	return b
}

func (c *testClient6) expectNothing(t *testing.T, wait time.Duration) {
	t.Helper()
	if _, err := c.recv(wait); err == nil {
		t.Fatal("ipv6 client received an unexpected frame")
	} else if !isTimeout(err) {
		t.Fatalf("ipv6 client read: %v", err)
	}
}

func ipv6NPDU(a bacnet.APDU) []byte {
	return bacnet.NPDU{APDU: a.Marshal()}.Marshal()
}

// waitForMetric polls a counter: the data plane handles each datagram in its
// own goroutine, so a counter is not necessarily updated when the send
// returns.
func waitForMetric(t *testing.T, name string, get func() float64, want float64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if get() == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("%s = %v, want %v", name, get(), want)
}

// discoverProxyVMAC performs the VirtualAddressResolution exchange a real IPv6
// client uses to learn the destination virtual address.
func discoverProxyVMAC(t *testing.T, c *testClient6, to *net.UDPAddr) bacnet.VMAC {
	t.Helper()
	c.sendFrame(bacnet.BVLC6{Function: bacnet.BVLC6VirtualAddressResolution, Src: c.vmac}.Marshal(), to)
	ack := c.mustRecv(t, time.Second)
	if ack.Function != bacnet.BVLC6VirtualAddressResolutionACK {
		t.Fatalf("resolution ack function = %s", ack.Function)
	}
	if ack.Dst != c.vmac {
		t.Fatalf("resolution ack destination = %s, want %s", ack.Dst, c.vmac)
	}
	if ack.Src.IsZero() {
		t.Fatal("proxy advertised a zero virtual address")
	}
	return ack.Src
}

func TestResolveListenFamily(t *testing.T) {
	cases := []struct {
		addr    string
		network string
	}{
		{":47808", "udp4"},
		{"0.0.0.0:47808", "udp4"},
		{"127.0.0.1:47808", "udp4"},
		{"[::1]:47808", "udp6"},
		{"[::]:47808", "udp6"},
	}
	for _, tc := range cases {
		ua, network, err := resolveListen(tc.addr)
		if err != nil {
			t.Fatalf("%s: %v", tc.addr, err)
		}
		if network != tc.network {
			t.Fatalf("%s: network = %s, want %s", tc.addr, network, tc.network)
		}
		if ua == nil {
			t.Fatalf("%s: nil address", tc.addr)
		}
	}
}

func TestDeriveVMACIsStableAndNonZero(t *testing.T) {
	a, _ := net.ResolveUDPAddr("udp6", "[::1]:47808")
	v1 := deriveVMAC(a)
	v2 := deriveVMAC(a)
	if v1 != v2 || v1.IsZero() {
		t.Fatalf("derived vmac = %s / %s", v1, v2)
	}
	b, _ := net.ResolveUDPAddr("udp6", "[::2]:47808")
	if deriveVMAC(b) == v1 {
		t.Fatal("two listen addresses derived the same vmac")
	}
}

func TestGatewayIPv6Read(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{ListenAddr: "[::1]:0", DeviceAddr: dev.addr().String()}, nil)
	c := newTestClient6(t)
	proxyVMAC := discoverProxyVMAC(t, c, f.addr())

	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}
	req := readProperty(7, oid, bacnet.PropertyPresentValue)
	c.sendFrame(bacnet.BVLC6{
		Function: bacnet.BVLC6OriginalUnicastNPDU,
		Src:      c.vmac,
		Dst:      proxyVMAC,
		Data:     ipv6NPDU(req),
	}.Marshal(), f.addr())

	devReq, _, src := dev.mustRecv(t, time.Second)
	if devReq.Type != bacnet.PDUConfirmedRequest || devReq.Service != bacnet.ServiceReadProperty {
		t.Fatalf("device request = %+v", devReq)
	}
	dev.send(t, readPropertyACK(devReq.InvokeID, oid, bacnet.PropertyPresentValue,
		[]byte{0x44, 0x3F, 0x80, 0x00, 0x00}), src)

	got := c.mustRecv(t, time.Second)
	if got.Function != bacnet.BVLC6OriginalUnicastNPDU {
		t.Fatalf("answer function = %s", got.Function)
	}
	if got.Dst != c.vmac {
		t.Fatalf("answer destination = %s, want the client vmac %s", got.Dst, c.vmac)
	}
	if got.Src != proxyVMAC {
		t.Fatalf("answer source = %s, want %s", got.Src, proxyVMAC)
	}
	n, err := bacnet.ParseNPDU(got.Data)
	if err != nil {
		t.Fatalf("answer npdu: %v", err)
	}
	a, err := bacnet.ParseAPDU(n.APDU)
	if err != nil {
		t.Fatalf("answer apdu: %v", err)
	}
	if a.Type != bacnet.PDUComplexACK || a.InvokeID != 7 {
		t.Fatalf("answer = %s invoke %d", a.Type, a.InvokeID)
	}
}

func TestGatewayIPv6WhoIsBroadcast(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{ListenAddr: "[::1]:0", DeviceAddr: dev.addr().String()}, nil)
	c := newTestClient6(t)
	_ = discoverProxyVMAC(t, c, f.addr())

	c.sendFrame(bacnet.BVLC6{
		Function: bacnet.BVLC6OriginalBroadcastNPDU,
		Src:      c.vmac,
		Data:     ipv6NPDU(whoIs()),
	}.Marshal(), f.addr())

	req, _, src := dev.mustRecv(t, time.Second)
	if req.Type != bacnet.PDUUnconfirmedRequest || req.Service != bacnet.ServiceWhoIs {
		t.Fatalf("device request = %+v", req)
	}
	dev.send(t, iam(1001), src)

	got := c.mustRecv(t, time.Second)
	if got.Function != bacnet.BVLC6OriginalUnicastNPDU || got.Dst != c.vmac {
		t.Fatalf("i-am frame = %+v", got)
	}
	n, err := bacnet.ParseNPDU(got.Data)
	if err != nil {
		t.Fatalf("i-am npdu: %v", err)
	}
	a, err := bacnet.ParseAPDU(n.APDU)
	if err != nil {
		t.Fatalf("i-am apdu: %v", err)
	}
	if a.Service != bacnet.ServiceIAm {
		t.Fatalf("answer service = %s", a.ServiceName())
	}
}

func TestGatewayIPv6AddressResolution(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{ListenAddr: "[::1]:0", DeviceAddr: dev.addr().String()}, nil)
	c := newTestClient6(t)
	proxyVMAC := discoverProxyVMAC(t, c, f.addr())

	// A target that is not this node is ignored.
	c.sendFrame(bacnet.BVLC6{Function: bacnet.BVLC6AddressResolution,
		Src: c.vmac, Dst: bacnet.VMAC{0x0a, 0x0b, 0x0c}}.Marshal(), f.addr())
	c.expectNothing(t, 200*time.Millisecond)

	c.sendFrame(bacnet.BVLC6{Function: bacnet.BVLC6AddressResolution,
		Src: c.vmac, Dst: proxyVMAC}.Marshal(), f.addr())
	ack := c.mustRecv(t, time.Second)
	if ack.Function != bacnet.BVLC6AddressResolutionACK || ack.Src != proxyVMAC || ack.Dst != c.vmac {
		t.Fatalf("address resolution ack = %+v", ack)
	}
}

func TestGatewayIPv6ACL(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	list, err := access.NewList([]string{"2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	f := startGateway(t, Config{ListenAddr: "[::1]:0", DeviceAddr: dev.addr().String()},
		access.NewPolicy(list, nil, nil))
	c := newTestClient6(t)

	// An off-list IPv6 source gets no link-layer answer either: the ACL runs
	// before parsing, so the proxy does not confirm that it exists.
	c.sendFrame(bacnet.BVLC6{Function: bacnet.BVLC6VirtualAddressResolution, Src: c.vmac}.Marshal(), f.addr())
	c.expectNothing(t, 200*time.Millisecond)

	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}
	c.sendFrame(bacnet.BVLC6{Function: bacnet.BVLC6OriginalUnicastNPDU,
		Src: c.vmac, Dst: bacnet.VMAC{1, 2, 3}, Data: ipv6NPDU(readProperty(7, oid, bacnet.PropertyPresentValue))}.Marshal(), f.addr())
	c.expectNothing(t, 250*time.Millisecond)
	dev.expectNothing(t, 250*time.Millisecond)
	if n := testutil.ToFloat64(f.metrics.ACLDenied); n < 2 {
		t.Fatalf("acl_denied = %v, want at least 2", n)
	}
}

func TestGatewayIPv6WriteDenied(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{ListenAddr: "[::1]:0", DeviceAddr: dev.addr().String()}, readOnlyPolicy(t))
	c := newTestClient6(t)
	proxyVMAC := discoverProxyVMAC(t, c, f.addr())

	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}
	c.sendFrame(bacnet.BVLC6{Function: bacnet.BVLC6OriginalUnicastNPDU,
		Src: c.vmac, Dst: proxyVMAC, Data: ipv6NPDU(writeProperty(7, oid, bacnet.PropertyPresentValue))}.Marshal(), f.addr())

	got := c.mustRecv(t, time.Second)
	if got.Function != bacnet.BVLC6OriginalUnicastNPDU || got.Dst != c.vmac {
		t.Fatalf("denial frame = %+v", got)
	}
	n, err := bacnet.ParseNPDU(got.Data)
	if err != nil {
		t.Fatalf("denial npdu: %v", err)
	}
	a, err := bacnet.ParseAPDU(n.APDU)
	if err != nil {
		t.Fatalf("denial apdu: %v", err)
	}
	if a.Type != bacnet.PDUError {
		t.Fatalf("denial = %s, want an error", a.Type)
	}
	class, code, ok := bacnet.ErrorClassAndCode(a.Payload)
	if !ok || class != bacnet.ErrorClassSecurity || code != bacnet.ErrorCodeWriteAccessDenied {
		t.Fatalf("error = class %d code %d", class, code)
	}
	dev.expectNothing(t, 250*time.Millisecond)
}

func TestGatewayIPv6MalformedFrame(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{ListenAddr: "[::1]:0", DeviceAddr: dev.addr().String()}, nil)
	c := newTestClient6(t)
	proxyVMAC := discoverProxyVMAC(t, c, f.addr())

	c.sendFrame([]byte{0x82, 0x01, 0x00, 0x03}, f.addr())
	waitForMetric(t, "parse_errors", func() float64 {
		return testutil.ToFloat64(f.metrics.ParseErrors)
	}, 1)

	// The bad datagram costs one frame, not the listener.
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}
	c.sendFrame(bacnet.BVLC6{Function: bacnet.BVLC6OriginalUnicastNPDU,
		Src: c.vmac, Dst: proxyVMAC, Data: ipv6NPDU(readProperty(7, oid, bacnet.PropertyPresentValue))}.Marshal(), f.addr())
	dev.mustRecv(t, time.Second)
}

func TestGatewayIPv6UnsupportedFunction(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{ListenAddr: "[::1]:0", DeviceAddr: dev.addr().String()}, nil)
	c := newTestClient6(t)
	_ = discoverProxyVMAC(t, c, f.addr())

	c.sendFrame(bacnet.BVLC6{Function: bacnet.BVLC6ForwardedNPDU,
		Src: c.vmac, Data: bytes.Repeat([]byte{0}, 24)}.Marshal(), f.addr())

	waitForMetric(t, "unsupported", func() float64 {
		return testutil.ToFloat64(f.metrics.Unsupported)
	}, 1)
	dev.expectNothing(t, 250*time.Millisecond)
}
