package proxy

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet"
)

func TestGatewayReadProperty(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, nil)
	c := newTestClient(t)

	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}
	c.send(readProperty(7, oid, bacnet.PropertyPresentValue), f.addr())

	req, _, src := dev.mustRecv(t, time.Second)
	if req.Type != bacnet.PDUConfirmedRequest || req.Service != bacnet.ServiceReadProperty {
		t.Fatalf("device request = %+v", req)
	}
	if req.InvokeID != 0 {
		t.Fatalf("first device invoke id = %d, want 0", req.InvokeID)
	}

	ack := readPropertyACK(req.InvokeID, oid, bacnet.PropertyPresentValue,
		[]byte{0x44, 0x3F, 0x80, 0x00, 0x00})
	dev.send(t, ack, src)

	got, _ := c.mustRecv(t, time.Second)
	if got.Type != bacnet.PDUComplexACK || got.InvokeID != 7 {
		t.Fatalf("client response = %+v", got)
	}
	if !bytes.Equal(got.Payload, ack.Payload) {
		t.Fatalf("payload changed:\n got %x\nwant %x", got.Payload, ack.Payload)
	}
}

func TestGatewayInvokeIDCollision(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, nil)
	a, b := newTestClient(t), newTestClient(t)

	oidA := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}
	oidB := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 6}

	a.send(readProperty(7, oidA, bacnet.PropertyPresentValue), f.addr())
	reqA, _, srcA := dev.mustRecv(t, time.Second)
	b.send(readProperty(7, oidB, bacnet.PropertyPresentValue), f.addr())
	reqB, _, srcB := dev.mustRecv(t, time.Second)

	if reqA.InvokeID == reqB.InvokeID {
		t.Fatalf("two clients with invoke id 7 shared device invoke id %d", reqA.InvokeID)
	}
	ackA := readPropertyACK(reqA.InvokeID, oidA, bacnet.PropertyPresentValue, []byte{0x44, 0x3F, 0x80, 0x00, 0x00})
	ackB := readPropertyACK(reqB.InvokeID, oidB, bacnet.PropertyPresentValue, []byte{0x44, 0x40, 0x00, 0x00, 0x00})

	// Answer in reverse order: correlation must not depend on arrival order.
	dev.send(t, ackB, srcB)
	dev.send(t, ackA, srcA)

	gotB, _ := b.mustRecv(t, time.Second)
	if gotB.InvokeID != 7 || !bytes.Equal(gotB.Payload, ackB.Payload) {
		t.Fatalf("client B got %+v", gotB)
	}
	gotA, _ := a.mustRecv(t, time.Second)
	if gotA.InvokeID != 7 || !bytes.Equal(gotA.Payload, ackA.Payload) {
		t.Fatalf("client A got %+v", gotA)
	}
}

func TestGatewayRetransmissionInFlightDropped(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, nil)
	c := newTestClient(t)
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}

	req := readProperty(7, oid, bacnet.PropertyPresentValue)
	c.send(req, f.addr())
	got, _, src := dev.mustRecv(t, time.Second)

	// The same request while it is in flight must not reach the device: a
	// write would otherwise be applied twice.
	c.send(req, f.addr())
	dev.expectNothing(t, 250*time.Millisecond)

	ack := readPropertyACK(got.InvokeID, oid, bacnet.PropertyPresentValue, []byte{0x44, 0x3F, 0x80, 0x00, 0x00})
	dev.send(t, ack, src)
	first, _ := c.mustRecv(t, time.Second)

	// After completion the same request is answered from the replay cache.
	c.send(req, f.addr())
	second, _ := c.mustRecv(t, time.Second)
	if !bytes.Equal(first.Payload, second.Payload) {
		t.Fatalf("replayed response changed: %x vs %x", first.Payload, second.Payload)
	}
	dev.expectNothing(t, 250*time.Millisecond)
}

func TestGatewayReusedInvokeID(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, nil)
	c := newTestClient(t)

	oidA := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}
	oidB := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 6}

	c.send(readProperty(7, oidA, bacnet.PropertyPresentValue), f.addr())
	reqA, _, srcA := dev.mustRecv(t, time.Second)
	c.send(readProperty(7, oidB, bacnet.PropertyPresentValue), f.addr())
	reqB, _, srcB := dev.mustRecv(t, time.Second)

	if reqA.InvokeID == reqB.InvokeID {
		t.Fatalf("replacement reused device invoke id %d", reqA.InvokeID)
	}

	// The late answer to the abandoned request must not be delivered as the
	// answer to the new one.
	dev.send(t, readPropertyACK(reqA.InvokeID, oidA, bacnet.PropertyPresentValue, []byte{0x44, 0x3F, 0x80, 0x00, 0x00}), srcA)
	c.expectNothing(t, 250*time.Millisecond)

	ackB := readPropertyACK(reqB.InvokeID, oidB, bacnet.PropertyPresentValue, []byte{0x44, 0x40, 0x00, 0x00, 0x00})
	dev.send(t, ackB, srcB)
	got, _ := c.mustRecv(t, time.Second)
	if !bytes.Equal(got.Payload, ackB.Payload) {
		t.Fatalf("new request got the old answer: %x", got.Payload)
	}
}

func TestGatewayPendingFull(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String(), MaxPending: 1}, nil)
	a, b := newTestClient(t), newTestClient(t)
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}

	a.send(readProperty(7, oid, bacnet.PropertyPresentValue), f.addr())
	dev.mustRecv(t, time.Second)

	b.send(readProperty(7, oid, bacnet.PropertyPresentValue), f.addr())
	dev.expectNothing(t, 250*time.Millisecond)
	b.expectNothing(t, 100*time.Millisecond)
	if got := testutil.ToFloat64(f.metrics.PendingFull); got != 1 {
		t.Fatalf("pending_full = %v, want 1", got)
	}
}

func TestGatewayPendingExpires(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{
		DeviceAddr:     dev.addr().String(),
		MaxPending:     1,
		RequestTimeout: 100 * time.Millisecond,
	}, nil)
	c := newTestClient(t)
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}

	c.send(readProperty(7, oid, bacnet.PropertyPresentValue), f.addr())
	dev.mustRecv(t, time.Second)

	// The sweeper runs every second; wait for one pass past the deadline.
	time.Sleep(1500 * time.Millisecond)
	if got := testutil.ToFloat64(f.metrics.Pending); got != 0 {
		t.Fatalf("pending gauge = %v after expiry", got)
	}

	c.send(readProperty(8, oid, bacnet.PropertyPresentValue), f.addr())
	dev.mustRecv(t, time.Second)
}

func TestGatewayPendingGauge(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, nil)
	c := newTestClient(t)
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}

	c.send(readProperty(7, oid, bacnet.PropertyPresentValue), f.addr())
	req, _, src := dev.mustRecv(t, time.Second)
	if got := testutil.ToFloat64(f.metrics.Pending); got != 1 {
		t.Fatalf("pending gauge = %v, want 1", got)
	}
	dev.send(t, readPropertyACK(req.InvokeID, oid, bacnet.PropertyPresentValue, []byte{0x44, 0x3F, 0x80, 0x00, 0x00}), src)
	c.mustRecv(t, time.Second)
	if got := testutil.ToFloat64(f.metrics.Pending); got != 0 {
		t.Fatalf("pending gauge = %v after response", got)
	}
}

func TestGatewayStripsRouting(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, nil)
	c := newTestClient(t)
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}

	n := bacnet.NPDU{
		DNET:     100,
		DADR:     []byte{192, 0, 2, 10, 0xBA, 0x68},
		SNET:     200,
		SADR:     []byte{192, 0, 2, 1, 0xBA, 0x68},
		HopCount: 3,
	}
	c.sendNPDU(n, readProperty(7, oid, bacnet.PropertyPresentValue), f.addr())

	req, np, _ := dev.mustRecv(t, time.Second)
	if req.Service != bacnet.ServiceReadProperty {
		t.Fatalf("device request = %+v", req)
	}
	if np.HasDestination() || np.HasSource() || np.DNET != 0 || np.SNET != 0 || np.HopCount != 0 {
		t.Fatalf("routing survived the proxy: %+v", np)
	}
}

func TestGatewayUnsupportedBVLC(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, nil)
	c := newTestClient(t)

	frame := bacnet.BVLC{Function: bacnet.BVLCRegisterForeignDevice, TTL: 60}.Marshal()
	c.sendFrame(frame, f.addr())
	dev.expectNothing(t, 250*time.Millisecond)
	c.expectNothing(t, 100*time.Millisecond)
	if got := testutil.ToFloat64(f.metrics.Unsupported); got != 1 {
		t.Fatalf("unsupported = %v, want 1", got)
	}
}

func TestGatewayNetworkMessageDropped(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, nil)
	c := newTestClient(t)

	n := bacnet.NPDU{NetworkMessage: &bacnet.NetworkMessage{Type: bacnet.NetWhoIsRouterToNetwork}}
	c.sendNPDU(n, whoIs(), f.addr())
	dev.expectNothing(t, 250*time.Millisecond)
	if got := testutil.ToFloat64(f.metrics.Unsupported); got != 1 {
		t.Fatalf("unsupported = %v, want 1", got)
	}
}

func TestGatewayWhoIsIAm(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, nil)
	c := newTestClient(t)

	c.send(whoIs(), f.addr())
	req, _, src := dev.mustRecv(t, time.Second)
	if req.Type != bacnet.PDUUnconfirmedRequest || req.Service != bacnet.ServiceWhoIs {
		t.Fatalf("device request = %+v", req)
	}

	dev.send(t, iam(1001), src)
	got, _ := c.mustRecv(t, time.Second)
	if got.Type != bacnet.PDUUnconfirmedRequest || got.Service != bacnet.ServiceIAm {
		t.Fatalf("client response = %+v", got)
	}
}

func TestGatewayIAmRelayedToActiveClients(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, nil)
	a, b := newTestClient(t), newTestClient(t)

	a.send(whoIs(), f.addr())
	dev.mustRecv(t, time.Second)
	b.send(whoIs(), f.addr())
	_, _, src := dev.mustRecv(t, time.Second)

	dev.send(t, iam(1001), src)
	for name, c := range map[string]*testClient{"a": a, "b": b} {
		got, _ := c.mustRecv(t, time.Second)
		if got.Service != bacnet.ServiceIAm {
			t.Fatalf("client %s got %+v", name, got)
		}
	}
}

func TestGatewayRejectsUnexpectedDeviceSource(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, nil)
	c := newTestClient(t)
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}

	c.send(readProperty(7, oid, bacnet.PropertyPresentValue), f.addr())
	req, _, src := dev.mustRecv(t, time.Second)
	ack := readPropertyACK(req.InvokeID, oid, bacnet.PropertyPresentValue, []byte{0x44, 0x3F, 0x80, 0x00, 0x00})

	// A forged response from a host that is not the configured device.
	frame := bacnet.BVLC{Function: bacnet.BVLCOriginalUnicastNPDU,
		Data: bacnet.NPDU{APDU: ack.Marshal()}.Marshal()}.Marshal()
	f.g.handleDevice(frame, &net.UDPAddr{IP: net.IPv4(192, 0, 2, 99), Port: 47808})
	c.expectNothing(t, 250*time.Millisecond)

	// The real device address still works.
	dev.send(t, ack, src)
	c.mustRecv(t, time.Second)
}

func TestGatewayLearnsDeviceSourcePort(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, nil)
	c := newTestClient(t)
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}

	c.send(readProperty(7, oid, bacnet.PropertyPresentValue), f.addr())
	req, _, src := dev.mustRecv(t, time.Second)

	// Some stacks answer from a different port. The proxy must accept it
	// (same host) and send the client's SegmentACK back to that port.
	alt := newFakeDevice(t, "127.0.0.1")
	alt.send(t, segmentedACK(req.InvokeID, 1, true, []byte{0x0C, 0x00, 0x80, 0x00, 0x05}), src)
	c.mustRecv(t, time.Second)

	c.send(segmentACK(7, 1), f.addr())
	ack, _, _ := alt.mustRecv(t, time.Second)
	if ack.Type != bacnet.PDUSegmentACK || ack.InvokeID != req.InvokeID {
		t.Fatalf("alternate device port got %+v", ack)
	}
	dev.expectNothing(t, 250*time.Millisecond)
}

func TestGatewaySurvivesMalformedDatagrams(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, nil)
	c := newTestClient(t)

	for _, dg := range [][]byte{
		{},
		{0x81},
		{0x81, 0x0A, 0x00, 0x04},
		{0x81, 0x0A, 0x00, 0x07, 0x01, 0x00, 0x10},
		{0x81, 0x0A, 0x00, 0x06, 0x01, 0x00},
		{0x81, 0x0A, 0x00, 0x07, 0x01, 0x00, 0x00},
	} {
		c.sendFrame(dg, f.addr())
	}
	dev.expectNothing(t, 250*time.Millisecond)

	// The proxy is still serving.
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}
	c.send(readProperty(7, oid, bacnet.PropertyPresentValue), f.addr())
	req, _, src := dev.mustRecv(t, time.Second)
	dev.send(t, readPropertyACK(req.InvokeID, oid, bacnet.PropertyPresentValue, []byte{0x44, 0x3F, 0x80, 0x00, 0x00}), src)
	c.mustRecv(t, time.Second)
}
