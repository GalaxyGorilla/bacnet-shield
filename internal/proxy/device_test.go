package proxy

import (
	"bytes"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet"
)

func TestGatewaySegmentedResponse(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, nil)
	c := newTestClient(t)
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}

	c.send(readProperty(7, oid, bacnet.PropertyPresentValue), f.addr())
	req, _, src := dev.mustRecv(t, time.Second)

	dev.send(t, segmentedACK(req.InvokeID, 1, true, []byte{0x0C, 0x00, 0x80, 0x00, 0x05}), src)
	first, _ := c.mustRecv(t, time.Second)
	if first.Type != bacnet.PDUComplexACK || first.InvokeID != 7 || !first.Segmented || !first.MoreFollows {
		t.Fatalf("first segment = %+v", first)
	}

	c.send(segmentACK(7, 1), f.addr())
	ack, _, _ := dev.mustRecv(t, time.Second)
	if ack.Type != bacnet.PDUSegmentACK || ack.InvokeID != req.InvokeID || ack.SequenceNumber != 1 {
		t.Fatalf("device segment ack = %+v", ack)
	}

	dev.send(t, segmentedACK(req.InvokeID, 2, false, []byte{0x44, 0x3F, 0x80, 0x00, 0x00}), src)
	last, _ := c.mustRecv(t, time.Second)
	if last.Type != bacnet.PDUComplexACK || last.InvokeID != 7 || last.MoreFollows {
		t.Fatalf("last segment = %+v", last)
	}

	c.send(segmentACK(7, 2), f.addr())
	final, _, _ := dev.mustRecv(t, time.Second)
	if final.Type != bacnet.PDUSegmentACK || final.InvokeID != req.InvokeID || final.SequenceNumber != 2 {
		t.Fatalf("final device segment ack = %+v", final)
	}
}

func TestGatewaySegmentedDeviceRequest(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, nil)
	c := newTestClient(t)
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}

	zero := uint32(0)
	c.send(subscribeCOV(7, 1, oid, &zero), f.addr())
	sub, _, src := dev.mustRecv(t, time.Second)
	dev.send(t, simpleACK(sub.InvokeID, bacnet.ServiceSubscribeCOV), src)
	c.mustRecv(t, time.Second)

	first := bacnet.APDU{Type: bacnet.PDUConfirmedRequest, Segmented: true, MoreFollows: true,
		InvokeID: 42, HasInvokeID: true, HasService: true,
		Service: bacnet.ServiceConfirmedCOVNotification, SequenceNumber: 1, WindowSize: 1,
		Payload: covNotification(1, oid)}
	dev.send(t, first, src)
	got, _ := c.mustRecv(t, time.Second)
	if got.Type != bacnet.PDUConfirmedRequest || !got.Segmented || !got.MoreFollows {
		t.Fatalf("first client segment = %+v", got)
	}
	if got.InvokeID == 42 {
		t.Fatal("device invoke id was exposed to the client")
	}
	clientID := got.InvokeID

	c.send(segmentACK(clientID, 1), f.addr())
	ack, _, _ := dev.mustRecv(t, time.Second)
	if ack.Type != bacnet.PDUSegmentACK || ack.InvokeID != 42 || ack.SequenceNumber != 1 {
		t.Fatalf("device segment ack = %+v", ack)
	}

	last := first
	last.MoreFollows = false
	last.SequenceNumber = 2
	last.Payload = nil
	dev.send(t, last, src)
	got, _ = c.mustRecv(t, time.Second)
	if got.Type != bacnet.PDUConfirmedRequest || got.MoreFollows || got.InvokeID != clientID {
		t.Fatalf("last client segment = %+v", got)
	}

	c.send(segmentACK(clientID, 2), f.addr())
	final, _, _ := dev.mustRecv(t, time.Second)
	if final.Type != bacnet.PDUSegmentACK || final.InvokeID != 42 || final.SequenceNumber != 2 {
		t.Fatalf("final device segment ack = %+v", final)
	}
}

func TestGatewayDeviceErrorCompletesExchange(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, nil)
	c := newTestClient(t)
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}

	req := readProperty(7, oid, bacnet.PropertyPresentValue)
	c.send(req, f.addr())
	got, _, src := dev.mustRecv(t, time.Second)
	dev.send(t, bacnet.ErrorAPDU(got.InvokeID, bacnet.ServiceReadProperty,
		bacnet.ErrorClassObject, bacnet.ErrorCodeUnknownObject), src)

	first, _ := c.mustRecv(t, time.Second)
	if first.Type != bacnet.PDUError || first.InvokeID != 7 {
		t.Fatalf("client response = %+v", first)
	}
	if got := testutil.ToFloat64(f.metrics.Pending); got != 0 {
		t.Fatalf("pending = %v after an error", got)
	}

	// The finished error is replayed to a retransmission.
	c.send(req, f.addr())
	second, _ := c.mustRecv(t, time.Second)
	if !bytes.Equal(first.Payload, second.Payload) {
		t.Fatalf("replayed error changed: %x vs %x", first.Payload, second.Payload)
	}
	dev.expectNothing(t, 250*time.Millisecond)
}

func TestGatewayClientResponseWithoutPending(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, nil)
	c := newTestClient(t)

	c.send(simpleACK(7, bacnet.ServiceReadProperty), f.addr())
	dev.expectNothing(t, 250*time.Millisecond)

	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}
	c.send(readProperty(7, oid, bacnet.PropertyPresentValue), f.addr())
	req, _, src := dev.mustRecv(t, time.Second)
	dev.send(t, readPropertyACK(req.InvokeID, oid, bacnet.PropertyPresentValue, []byte{0x44, 0x3F, 0x80, 0x00, 0x00}), src)
	c.mustRecv(t, time.Second)
}

func TestGatewayDeviceUnconfirmedEventBroadcast(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, nil)
	a, b := newTestClient(t), newTestClient(t)

	a.send(whoIs(), f.addr())
	dev.mustRecv(t, time.Second)
	b.send(whoIs(), f.addr())
	_, _, src := dev.mustRecv(t, time.Second)

	event := bacnet.APDU{Type: bacnet.PDUUnconfirmedRequest, HasService: true,
		Service: bacnet.ServiceUnconfirmedEventNotification,
		Payload: []byte{0x09, 0x01, 0x1C, 0x02, 0x00, 0x00, 0x64, 0x2C, 0x00, 0x80, 0x00, 0x05}}
	dev.send(t, event, src)
	for name, c := range map[string]*testClient{"a": a, "b": b} {
		got, _ := c.mustRecv(t, time.Second)
		if got.Service != bacnet.ServiceUnconfirmedEventNotification {
			t.Fatalf("client %s got %+v", name, got)
		}
	}
}

func TestGatewayDeviceNetworkMessageDropped(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, nil)
	c := newTestClient(t)

	c.send(whoIs(), f.addr())
	_, _, src := dev.mustRecv(t, time.Second)

	n := bacnet.NPDU{NetworkMessage: &bacnet.NetworkMessage{Type: bacnet.NetIAmRouterToNetwork}}
	dev.sendNPDU(t, n, bacnet.APDU{}, src)
	c.expectNothing(t, 250*time.Millisecond)
	if got := testutil.ToFloat64(f.metrics.Unsupported); got != 1 {
		t.Fatalf("unsupported = %v, want 1", got)
	}
}

func TestGatewayDeviceUnknownResponseDropped(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, nil)
	c := newTestClient(t)

	// Make the device's source address known by asking a question first.
	c.send(whoIs(), f.addr())
	_, _, src := dev.mustRecv(t, time.Second)

	dev.send(t, simpleACK(99, bacnet.ServiceReadProperty), src)
	c.expectNothing(t, 250*time.Millisecond)
}
