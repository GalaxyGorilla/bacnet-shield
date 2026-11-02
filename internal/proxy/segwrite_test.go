package proxy

import (
	"bytes"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/GalaxyGorilla/bacnet-shield/internal/access"
	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet"
)

// segmentedWrite builds one segment of a segmented confirmed request. The
// service and invoke ID are the same on every segment; only the payload slice
// and the more-follows flag change.
func segmentedWrite(invoke, seq byte, more bool, service bacnet.Service, payload []byte) bacnet.APDU {
	return bacnet.APDU{
		Type: bacnet.PDUConfirmedRequest, Segmented: true, MoreFollows: more,
		MaxSegments: 2, MaxAPDU: 5,
		InvokeID: invoke, HasInvokeID: true,
		SequenceNumber: seq, WindowSize: 1,
		Service: service, HasService: true,
		Payload: payload,
	}
}

// splitWrite returns two segments covering the whole service payload.
func splitWrite(invoke byte, w bacnet.APDU) (bacnet.APDU, bacnet.APDU) {
	half := len(w.Payload) / 2
	return segmentedWrite(invoke, 0, true, w.Service, w.Payload[:half]),
		segmentedWrite(invoke, 1, false, w.Service, w.Payload[half:])
}

func TestGatewaySegmentedWriteAllowed(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, writePolicy(t, access.ActionAllow, nil))
	c := newTestClient(t)
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}

	w := writeProperty(7, oid, bacnet.PropertyPresentValue)
	first, last := splitWrite(7, w)

	c.send(first, f.addr())
	ack, _ := c.mustRecv(t, time.Second)
	if ack.Type != bacnet.PDUSegmentACK || !ack.Server || ack.InvokeID != 7 || ack.SequenceNumber != 0 {
		t.Fatalf("segment 0 ack = %+v", ack)
	}
	// Nothing is forwarded until the whole request is known.
	dev.expectNothing(t, 200*time.Millisecond)

	c.send(last, f.addr())
	req, _, src := dev.mustRecv(t, time.Second)
	if req.Type != bacnet.PDUConfirmedRequest || req.Segmented || req.Service != bacnet.ServiceWriteProperty {
		t.Fatalf("device request = %+v", req)
	}
	if req.InvokeID != 0 {
		t.Fatalf("device invoke id = %d, want 0", req.InvokeID)
	}
	if !bytes.Equal(req.Payload, w.Payload) {
		t.Fatalf("reassembled payload = %x, want %x", req.Payload, w.Payload)
	}

	dev.send(t, simpleACK(req.InvokeID, bacnet.ServiceWriteProperty), src)
	resp, _ := c.mustRecv(t, time.Second)
	if resp.Type != bacnet.PDUSimpleACK || resp.InvokeID != 7 {
		t.Fatalf("client response = %+v", resp)
	}
	if n := testutil.ToFloat64(f.metrics.SegmentedWrites); n != 1 {
		t.Fatalf("segmented_writes = %v, want 1", n)
	}
}

func TestGatewaySegmentedWriteDenied(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, readOnlyPolicy(t))
	c := newTestClient(t)
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}

	w := writeProperty(7, oid, bacnet.PropertyPresentValue)
	first, last := splitWrite(7, w)

	c.send(first, f.addr())
	ack, _ := c.mustRecv(t, time.Second)
	if ack.Type != bacnet.PDUSegmentACK {
		t.Fatalf("segment 0 ack = %+v", ack)
	}

	c.send(last, f.addr())
	got, _ := c.mustRecv(t, time.Second)
	if got.Type != bacnet.PDUError || got.InvokeID != 7 || got.Service != bacnet.ServiceWriteProperty {
		t.Fatalf("denial = %+v", got)
	}
	class, code, ok := bacnet.ErrorClassAndCode(got.Payload)
	if !ok || class != bacnet.ErrorClassSecurity || code != bacnet.ErrorCodeWriteAccessDenied {
		t.Fatalf("error = class %d code %d, want class security / write-access-denied", class, code)
	}
	if n := testutil.ToFloat64(f.metrics.WritesDenied); n != 1 {
		t.Fatalf("writes_denied = %v, want 1", n)
	}
	dev.expectNothing(t, 250*time.Millisecond)
}

// TestGatewaySegmentedWriteStraddleDenied is the bypass B5 exists to close: an
// allowed target in the first segment and a forbidden one in the last. The
// policy must see the whole request.
func TestGatewaySegmentedWriteStraddleDenied(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	pol := writePolicy(t, access.ActionDeny, []access.Rule{
		{Spec: "analog-value:5:present-value", Action: access.ActionAllow},
	})
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, pol)
	c := newTestClient(t)
	allowed := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}
	forbidden := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 6}

	w := writePropertyMultiple(7, []bacnet.WriteTarget{
		{Object: allowed, Property: bacnet.PropertyPresentValue},
		{Object: forbidden, Property: bacnet.PropertyPresentValue},
	})
	// Split at the second target so the forbidden object is only visible in
	// the final segment.
	split := bytes.Index(w.Payload, forbidden.AppendTo(nil)) - 2
	if split <= 0 || split >= len(w.Payload) {
		t.Fatalf("could not split the WritePropertyMultiple payload: %x", w.Payload)
	}
	first := segmentedWrite(7, 0, true, w.Service, w.Payload[:split])
	last := segmentedWrite(7, 1, false, w.Service, w.Payload[split:])

	c.send(first, f.addr())
	if ack, _ := c.mustRecv(t, time.Second); ack.Type != bacnet.PDUSegmentACK {
		t.Fatalf("segment 0 ack = %+v", ack)
	}
	c.send(last, f.addr())

	got, _ := c.mustRecv(t, time.Second)
	if got.Type != bacnet.PDUError {
		t.Fatalf("straddling segmented write = %+v, want an Error PDU", got)
	}
	class, code, ok := bacnet.ErrorClassAndCode(got.Payload)
	if !ok || class != bacnet.ErrorClassSecurity || code != bacnet.ErrorCodeWriteAccessDenied {
		t.Fatalf("error = class %d code %d", class, code)
	}
	dev.expectNothing(t, 250*time.Millisecond)
}

func TestGatewaySegmentedWriteOutOfOrder(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, writePolicy(t, access.ActionAllow, nil))
	c := newTestClient(t)
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}

	w := writeProperty(7, oid, bacnet.PropertyPresentValue)
	_, last := splitWrite(7, w)
	c.send(last, f.addr()) // sequence 1 without sequence 0

	c.expectNothing(t, 250*time.Millisecond)
	dev.expectNothing(t, 250*time.Millisecond)
}

func TestGatewaySegmentedWriteOversize(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, writePolicy(t, access.ActionAllow, nil))
	c := newTestClient(t)

	// Exceed the reassembly cap with ordinary-size segments; a single
	// over-cap datagram would hit the host's UDP limit before the proxy's.
	const chunk = 1500
	seq := byte(0)
	sent := 0
	for ; sent+chunk <= maxSegWriteBytes; sent, seq = sent+chunk, seq+1 {
		c.send(segmentedWrite(7, seq, true, bacnet.ServiceWriteProperty,
			make([]byte, chunk)), f.addr())
		if ack, _ := c.mustRecv(t, time.Second); ack.Type != bacnet.PDUSegmentACK {
			t.Fatalf("segment %d ack = %+v", seq, ack)
		}
	}
	// This segment crosses the cap and must be refused, not buffered.
	c.send(segmentedWrite(7, seq, false, bacnet.ServiceWriteProperty,
		make([]byte, chunk)), f.addr())

	got, _ := c.mustRecv(t, time.Second)
	if got.Type != bacnet.PDUReject {
		t.Fatalf("oversize segmented write = %+v, want a Reject", got)
	}
	if n := testutil.ToFloat64(f.metrics.SegmentedRejected); n != 1 {
		t.Fatalf("segmented_writes_rejected = %v, want 1", n)
	}
	dev.expectNothing(t, 250*time.Millisecond)
}

func TestGatewaySegmentedWriteRetransmit(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, writePolicy(t, access.ActionAllow, nil))
	c := newTestClient(t)
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}

	w := writeProperty(7, oid, bacnet.PropertyPresentValue)
	first, last := splitWrite(7, w)

	// The first ACK was lost, so the client sends segment 0 again.
	c.send(first, f.addr())
	c.mustRecv(t, time.Second)
	c.send(first, f.addr())
	ack, _ := c.mustRecv(t, time.Second)
	if ack.Type != bacnet.PDUSegmentACK || ack.SequenceNumber != 0 {
		t.Fatalf("repeat segment 0 ack = %+v", ack)
	}
	dev.expectNothing(t, 150*time.Millisecond)

	c.send(last, f.addr())
	req, _, src := dev.mustRecv(t, time.Second)
	if !bytes.Equal(req.Payload, w.Payload) {
		t.Fatalf("reassembled payload = %x, want %x", req.Payload, w.Payload)
	}
	dev.send(t, simpleACK(req.InvokeID, bacnet.ServiceWriteProperty), src)
	c.mustRecv(t, time.Second)
}

// A completed segmented write that is retransmitted end to end must be answered
// from the replay cache, not applied twice. This is the same guarantee as an
// unsegmented write, preserved across reassembly.
func TestGatewaySegmentedWriteReplay(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, writePolicy(t, access.ActionAllow, nil))
	c := newTestClient(t)
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}

	w := writeProperty(7, oid, bacnet.PropertyPresentValue)
	first, last := splitWrite(7, w)

	c.send(first, f.addr())
	c.mustRecv(t, time.Second)
	c.send(last, f.addr())
	req, _, src := dev.mustRecv(t, time.Second)
	dev.send(t, simpleACK(req.InvokeID, bacnet.ServiceWriteProperty), src)
	c.mustRecv(t, time.Second)

	// The client did not see the answer and retransmits the whole request.
	c.send(first, f.addr())
	c.mustRecv(t, time.Second)
	c.send(last, f.addr())
	got, _ := c.mustRecv(t, time.Second)
	if got.Type != bacnet.PDUSimpleACK || got.InvokeID != 7 {
		t.Fatalf("replayed segmented write = %+v", got)
	}
	dev.expectNothing(t, 250*time.Millisecond)
	if n := testutil.ToFloat64(f.metrics.Replayed); n != 1 {
		t.Fatalf("replayed = %v, want 1", n)
	}
}
