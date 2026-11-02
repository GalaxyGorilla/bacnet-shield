package proxy

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet"
)

func TestGatewayCOVUnconfirmed(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, nil)
	c := newTestClient(t)
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}
	other := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 6}

	zero := uint32(0)
	c.send(subscribeCOV(7, 1, oid, &zero), f.addr())
	sub, _, src := dev.mustRecv(t, time.Second)
	if sub.Service != bacnet.ServiceSubscribeCOV {
		t.Fatalf("device request = %+v", sub)
	}
	dev.send(t, simpleACK(sub.InvokeID, bacnet.ServiceSubscribeCOV), src)
	ack, _ := c.mustRecv(t, time.Second)
	if ack.Type != bacnet.PDUSimpleACK || ack.InvokeID != 7 {
		t.Fatalf("subscription ack = %+v", ack)
	}
	if got := testutil.ToFloat64(f.metrics.Subscriptions); got != 1 {
		t.Fatalf("subscriptions = %v, want 1", got)
	}

	// A notification for the subscribed object reaches the subscriber.
	dev.send(t, bacnet.APDU{Type: bacnet.PDUUnconfirmedRequest, HasService: true,
		Service: bacnet.ServiceUnconfirmedCOVNotification, Payload: covNotification(1, oid)}, src)
	got, _ := c.mustRecv(t, time.Second)
	if got.Service != bacnet.ServiceUnconfirmedCOVNotification {
		t.Fatalf("notification = %+v", got)
	}

	// A notification for a different object does not.
	dev.send(t, bacnet.APDU{Type: bacnet.PDUUnconfirmedRequest, HasService: true,
		Service: bacnet.ServiceUnconfirmedCOVNotification, Payload: covNotification(1, other)}, src)
	c.expectNothing(t, 250*time.Millisecond)

	// Cancellation: a SubscribeCOV with no lifetime.
	c.send(subscribeCOV(8, 1, oid, nil), f.addr())
	cancel, _, src2 := dev.mustRecv(t, time.Second)
	dev.send(t, simpleACK(cancel.InvokeID, bacnet.ServiceSubscribeCOV), src2)
	c.mustRecv(t, time.Second)
	if got := testutil.ToFloat64(f.metrics.Subscriptions); got != 0 {
		t.Fatalf("subscriptions = %v after cancel", got)
	}

	dev.send(t, bacnet.APDU{Type: bacnet.PDUUnconfirmedRequest, HasService: true,
		Service: bacnet.ServiceUnconfirmedCOVNotification, Payload: covNotification(1, oid)}, src)
	c.expectNothing(t, 250*time.Millisecond)
}

func TestGatewayCOVConfirmed(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, nil)
	c := newTestClient(t)
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}

	zero := uint32(0)
	c.send(subscribeCOV(7, 1, oid, &zero), f.addr())
	sub, _, src := dev.mustRecv(t, time.Second)
	dev.send(t, simpleACK(sub.InvokeID, bacnet.ServiceSubscribeCOV), src)
	c.mustRecv(t, time.Second)

	// The device sends a confirmed notification. The proxy must give the
	// client its own invoke ID and remember the device's ID.
	dev.send(t, bacnet.APDU{Type: bacnet.PDUConfirmedRequest, InvokeID: 42, HasInvokeID: true,
		HasService: true, Service: bacnet.ServiceConfirmedCOVNotification,
		Payload: covNotification(1, oid)}, src)
	got, _ := c.mustRecv(t, time.Second)
	if got.Type != bacnet.PDUConfirmedRequest || got.Service != bacnet.ServiceConfirmedCOVNotification {
		t.Fatalf("client notification = %+v", got)
	}
	if got.InvokeID == 42 {
		t.Fatal("device invoke id was exposed to the client")
	}

	c.send(simpleACK(got.InvokeID, bacnet.ServiceConfirmedCOVNotification), f.addr())
	ack, _, _ := dev.mustRecv(t, time.Second)
	if ack.Type != bacnet.PDUSimpleACK || ack.InvokeID != 42 || ack.Service != bacnet.ServiceConfirmedCOVNotification {
		t.Fatalf("device answer = %+v", ack)
	}
}

func TestGatewayCOVMultipleSubscribers(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, nil)
	a, b := newTestClient(t), newTestClient(t)
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}
	zero := uint32(0)

	a.send(subscribeCOV(7, 1, oid, &zero), f.addr())
	subA, _, src := dev.mustRecv(t, time.Second)
	dev.send(t, simpleACK(subA.InvokeID, bacnet.ServiceSubscribeCOV), src)
	a.mustRecv(t, time.Second)

	b.send(subscribeCOV(7, 2, oid, &zero), f.addr())
	subB, _, _ := dev.mustRecv(t, time.Second)
	dev.send(t, simpleACK(subB.InvokeID, bacnet.ServiceSubscribeCOV), src)
	b.mustRecv(t, time.Second)

	// The process identifier selects the subscriber.
	dev.send(t, bacnet.APDU{Type: bacnet.PDUUnconfirmedRequest, HasService: true,
		Service: bacnet.ServiceUnconfirmedCOVNotification, Payload: covNotification(1, oid)}, src)
	a.mustRecv(t, time.Second)
	b.expectNothing(t, 250*time.Millisecond)

	dev.send(t, bacnet.APDU{Type: bacnet.PDUUnconfirmedRequest, HasService: true,
		Service: bacnet.ServiceUnconfirmedCOVNotification, Payload: covNotification(2, oid)}, src)
	b.mustRecv(t, time.Second)
	a.expectNothing(t, 250*time.Millisecond)
}

func TestGatewayCOVExpiry(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, nil)
	c := newTestClient(t)
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}

	lifetime := uint32(1)
	c.send(subscribeCOV(7, 1, oid, &lifetime), f.addr())
	sub, _, src := dev.mustRecv(t, time.Second)
	dev.send(t, simpleACK(sub.InvokeID, bacnet.ServiceSubscribeCOV), src)
	c.mustRecv(t, time.Second)

	time.Sleep(2200 * time.Millisecond)
	if got := testutil.ToFloat64(f.metrics.Subscriptions); got != 0 {
		t.Fatalf("subscriptions = %v after expiry", got)
	}
	dev.send(t, bacnet.APDU{Type: bacnet.PDUUnconfirmedRequest, HasService: true,
		Service: bacnet.ServiceUnconfirmedCOVNotification, Payload: covNotification(1, oid)}, src)
	c.expectNothing(t, 250*time.Millisecond)
}

func TestGatewayCOVRejectedSubscriptionNotRouted(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, nil)
	c := newTestClient(t)
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}

	zero := uint32(0)
	c.send(subscribeCOV(7, 1, oid, &zero), f.addr())
	sub, _, src := dev.mustRecv(t, time.Second)
	dev.send(t, bacnet.ErrorAPDU(sub.InvokeID, bacnet.ServiceSubscribeCOV,
		bacnet.ErrorClassServices, bacnet.ErrorCodeServiceRequestDenied), src)
	got, _ := c.mustRecv(t, time.Second)
	if got.Type != bacnet.PDUError {
		t.Fatalf("client response = %+v", got)
	}
	if got := testutil.ToFloat64(f.metrics.Subscriptions); got != 0 {
		t.Fatalf("rejected subscription was installed: %v", got)
	}

	dev.send(t, bacnet.APDU{Type: bacnet.PDUUnconfirmedRequest, HasService: true,
		Service: bacnet.ServiceUnconfirmedCOVNotification, Payload: covNotification(1, oid)}, src)
	c.expectNothing(t, 250*time.Millisecond)
}

func TestGatewayCOVCancelRejectedKeepsSubscription(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, nil)
	c := newTestClient(t)
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}

	zero := uint32(0)
	c.send(subscribeCOV(7, 1, oid, &zero), f.addr())
	sub, _, src := dev.mustRecv(t, time.Second)
	dev.send(t, simpleACK(sub.InvokeID, bacnet.ServiceSubscribeCOV), src)
	c.mustRecv(t, time.Second)

	c.send(subscribeCOV(8, 1, oid, nil), f.addr())
	cancel, _, src2 := dev.mustRecv(t, time.Second)
	dev.send(t, bacnet.ErrorAPDU(cancel.InvokeID, bacnet.ServiceSubscribeCOV,
		bacnet.ErrorClassServices, bacnet.ErrorCodeServiceRequestDenied), src2)
	c.mustRecv(t, time.Second)

	// The cancel failed, so the subscription must still be live.
	dev.send(t, bacnet.APDU{Type: bacnet.PDUUnconfirmedRequest, HasService: true,
		Service: bacnet.ServiceUnconfirmedCOVNotification, Payload: covNotification(1, oid)}, src)
	c.mustRecv(t, time.Second)
}

// --- multi-object COV fixtures ------------------------------------------

// covMultipleRef builds one listOfCOVPropertyReferences element:
// [0] { [0] object-id, [1] { [0] property-id } }.
func covMultipleRef(oid bacnet.ObjectID, prop bacnet.PropertyID) []byte {
	b := []byte{0x0C}
	b = append(b, oid.AppendTo(nil)...)
	b = append(b, 0x1E, 0x0E, 0x09, byte(prop), 0x0F, 0x29, 0x00, 0x1F)
	return b
}

// covMultipleSubscribe builds a SubscribeCOVPropertyMultiple payload; a
// negative lifetime omits the optional field, which is a cancellation.
func covMultipleSubscribe(proc uint32, lifetime int, objs ...bacnet.ObjectID) []byte {
	b := []byte{0x09, byte(proc), 0x19, 0x00}
	if lifetime >= 0 {
		b = append(b, 0x29, byte(lifetime))
	}
	b = append(b, 0x39, 0x00, 0x4E)
	for _, oid := range objs {
		b = append(b, covMultipleRef(oid, bacnet.PropertyPresentValue)...)
	}
	return append(b, 0x4F)
}

// covMultipleNotification builds a COVNotificationMultiple body for objects,
// each carrying present-value.
func covMultipleNotification(proc, device uint32, objs ...bacnet.ObjectID) []byte {
	dev := bacnet.ObjectID{Type: bacnet.ObjectDevice, Instance: device}
	b := []byte{0x09, byte(proc), 0x1C}
	b = append(b, dev.AppendTo(nil)...)
	b = append(b, 0x29, 0x00, 0x3E, 0x3F, 0x4E)
	for _, oid := range objs {
		b = append(b, 0x0C)
		b = append(b, oid.AppendTo(nil)...)
		b = append(b, 0x1E, 0x09, byte(bacnet.PropertyPresentValue),
			0x2E, 0x44, 0x3F, 0x80, 0x00, 0x00, 0x2F, 0x1F)
	}
	return append(b, 0x4F)
}

func subscribeCOVMultiple(objs []bacnet.ObjectID, proc uint32, lifetime int) bacnet.APDU {
	return bacnet.APDU{Type: bacnet.PDUConfirmedRequest, HasInvokeID: true, HasService: true,
		Service: bacnet.ServiceSubscribeCOVPropertyMultiple,
		Payload: covMultipleSubscribe(proc, lifetime, objs...)}
}

func covNotificationMultiple(proc, device uint32, objs ...bacnet.ObjectID) bacnet.APDU {
	return bacnet.APDU{Type: bacnet.PDUUnconfirmedRequest, HasService: true,
		Service: bacnet.ServiceUnconfirmedCOVNotificationMultiple,
		Payload: covMultipleNotification(proc, device, objs...)}
}

func TestGatewayCOVMultipleSubscription(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, nil)
	c := newTestClient(t)
	oidA := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}
	oidB := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 6}
	other := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 7}

	sub := subscribeCOVMultiple([]bacnet.ObjectID{oidA, oidB}, 1, 0)
	sub.InvokeID = 7
	c.send(sub, f.addr())
	got, _, src := dev.mustRecv(t, time.Second)
	if got.Service != bacnet.ServiceSubscribeCOVPropertyMultiple {
		t.Fatalf("device request = %+v", got)
	}
	dev.send(t, simpleACK(got.InvokeID, bacnet.ServiceSubscribeCOVPropertyMultiple), src)
	c.mustRecv(t, time.Second)

	// Both objects are installed; the multi subscription is not one entry.
	if got := testutil.ToFloat64(f.metrics.Subscriptions); got != 2 {
		t.Fatalf("subscriptions = %v, want 2", got)
	}

	// One notification covering both objects arrives once, not twice.
	dev.send(t, covNotificationMultiple(1, 1001, oidA, oidB), src)
	c.mustRecv(t, time.Second)
	c.expectNothing(t, 200*time.Millisecond)

	// A notification for an object that is not subscribed is dropped.
	dev.send(t, covNotificationMultiple(1, 1001, other), src)
	c.expectNothing(t, 250*time.Millisecond)
	if got := testutil.ToFloat64(f.metrics.NotificationsDropped); got != 1 {
		t.Fatalf("notifications_dropped = %v, want 1", got)
	}
}

func TestGatewayCOVMultipleCancellation(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, nil)
	c := newTestClient(t)
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}
	other := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 6}

	sub := subscribeCOVMultiple([]bacnet.ObjectID{oid, other}, 1, 0)
	sub.InvokeID = 7
	c.send(sub, f.addr())
	req, _, src := dev.mustRecv(t, time.Second)
	dev.send(t, simpleACK(req.InvokeID, bacnet.ServiceSubscribeCOVPropertyMultiple), src)
	c.mustRecv(t, time.Second)

	cancel := subscribeCOVMultiple([]bacnet.ObjectID{oid, other}, 1, -1)
	cancel.InvokeID = 8
	c.send(cancel, f.addr())
	req, _, src = dev.mustRecv(t, time.Second)
	dev.send(t, simpleACK(req.InvokeID, bacnet.ServiceSubscribeCOVPropertyMultiple), src)
	c.mustRecv(t, time.Second)

	if got := testutil.ToFloat64(f.metrics.Subscriptions); got != 0 {
		t.Fatalf("subscriptions = %v after cancel, want 0", got)
	}
	dev.send(t, covNotificationMultiple(1, 1001, oid), src)
	c.expectNothing(t, 250*time.Millisecond)
}

func TestGatewayCOVMultipleRejectedSubscriptionNotRouted(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, nil)
	c := newTestClient(t)
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}

	sub := subscribeCOVMultiple([]bacnet.ObjectID{oid}, 1, 0)
	sub.InvokeID = 7
	c.send(sub, f.addr())
	req, _, src := dev.mustRecv(t, time.Second)
	dev.send(t, bacnet.ErrorAPDU(req.InvokeID, bacnet.ServiceSubscribeCOVPropertyMultiple,
		bacnet.ErrorClassServices, bacnet.ErrorCodeServiceRequestDenied), src)
	got, _ := c.mustRecv(t, time.Second)
	if got.Type != bacnet.PDUError {
		t.Fatalf("client response = %+v", got)
	}
	if got := testutil.ToFloat64(f.metrics.Subscriptions); got != 0 {
		t.Fatalf("rejected multi subscription was installed: %v", got)
	}
	dev.send(t, covNotificationMultiple(1, 1001, oid), src)
	c.expectNothing(t, 250*time.Millisecond)
}

func TestGatewayCOVMultipleUndecodableDenied(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, nil)
	c := newTestClient(t)

	c.send(bacnet.APDU{Type: bacnet.PDUConfirmedRequest, InvokeID: 9, HasInvokeID: true,
		HasService: true, Service: bacnet.ServiceSubscribeCOVPropertyMultiple,
		Payload: []byte{0x0E, 0x0F}}, f.addr())

	got, _ := c.mustRecv(t, time.Second)
	if got.Type != bacnet.PDUError {
		t.Fatalf("denial = %+v, want an Error PDU", got)
	}
	class, code, ok := bacnet.ErrorClassAndCode(got.Payload)
	if !ok || class != bacnet.ErrorClassServices || code != bacnet.ErrorCodeServiceRequestDenied {
		t.Fatalf("error payload = %x, want class services / code service-request-denied", got.Payload)
	}
	if got := testutil.ToFloat64(f.metrics.Unsupported); got != 1 {
		t.Fatalf("unsupported = %v, want 1", got)
	}
	dev.expectNothing(t, 250*time.Millisecond)
}

func TestGatewayConfirmedCOVMultiple(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, nil)
	c := newTestClient(t)
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}

	sub := subscribeCOVMultiple([]bacnet.ObjectID{oid}, 1, 0)
	sub.InvokeID = 7
	c.send(sub, f.addr())
	req, _, src := dev.mustRecv(t, time.Second)
	dev.send(t, simpleACK(req.InvokeID, bacnet.ServiceSubscribeCOVPropertyMultiple), src)
	c.mustRecv(t, time.Second)

	notif := covNotificationMultiple(1, 1001, oid)
	notif.Type = bacnet.PDUConfirmedRequest
	notif.Service = bacnet.ServiceConfirmedCOVNotificationMultiple
	notif.InvokeID = 42
	notif.HasInvokeID = true
	dev.send(t, notif, src)

	got, _ := c.mustRecv(t, time.Second)
	if got.Type != bacnet.PDUConfirmedRequest || got.Service != bacnet.ServiceConfirmedCOVNotificationMultiple {
		t.Fatalf("client notification = %+v", got)
	}
	if got.InvokeID == 42 {
		t.Fatal("device invoke id was exposed to the client")
	}
	c.send(simpleACK(got.InvokeID, bacnet.ServiceConfirmedCOVNotificationMultiple), f.addr())
	ack, _, _ := dev.mustRecv(t, time.Second)
	if ack.Type != bacnet.PDUSimpleACK || ack.InvokeID != 42 ||
		ack.Service != bacnet.ServiceConfirmedCOVNotificationMultiple {
		t.Fatalf("device answer = %+v", ack)
	}
}

func TestGatewayConfirmedCOVMultipleWithoutSubscriber(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, nil)
	c := newTestClient(t)
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}

	// Keep a client active so the failure is "no subscriber", not "no
	// clients": the proxy must answer the device either way.
	c.send(whoIs(), f.addr())
	_, _, src := dev.mustRecv(t, time.Second)

	notif := covNotificationMultiple(1, 1001, oid)
	notif.Type = bacnet.PDUConfirmedRequest
	notif.Service = bacnet.ServiceConfirmedCOVNotificationMultiple
	notif.InvokeID = 42
	notif.HasInvokeID = true
	dev.send(t, notif, src)

	answer, _, _ := dev.mustRecv(t, time.Second)
	if answer.Type != bacnet.PDUError || answer.InvokeID != 42 {
		t.Fatalf("device answer = %+v", answer)
	}
	class, code, ok := bacnet.ErrorClassAndCode(answer.Payload)
	if !ok || class != bacnet.ErrorClassServices || code != bacnet.ErrorCodeUnknownSubscription {
		t.Fatalf("error payload = %x (class %d code %d), want class services / code unknown-subscription",
			answer.Payload, class, code)
	}
}

func TestGatewayCOVNotificationWithoutSubscriber(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, nil)
	c := newTestClient(t)
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}

	// Make the client active so an unrouted notification is not simply
	// "no clients".
	c.send(whoIs(), f.addr())
	_, _, src := dev.mustRecv(t, time.Second)

	dev.send(t, bacnet.APDU{Type: bacnet.PDUUnconfirmedRequest, HasService: true,
		Service: bacnet.ServiceUnconfirmedCOVNotification, Payload: covNotification(1, oid)}, src)
	c.expectNothing(t, 250*time.Millisecond)
	if got := testutil.ToFloat64(f.metrics.NotificationsDropped); got != 1 {
		t.Fatalf("notifications_dropped = %v, want 1", got)
	}

	// A confirmed notification with no subscriber gets an Error, so the
	// device stops retransmitting.
	dev.send(t, bacnet.APDU{Type: bacnet.PDUConfirmedRequest, InvokeID: 42, HasInvokeID: true,
		HasService: true, Service: bacnet.ServiceConfirmedCOVNotification,
		Payload: covNotification(1, oid)}, src)
	answer, _, _ := dev.mustRecv(t, time.Second)
	if answer.Type != bacnet.PDUError || answer.InvokeID != 42 {
		t.Fatalf("device answer = %+v", answer)
	}
	class, code, ok := bacnet.ErrorClassAndCode(answer.Payload)
	if !ok || class != bacnet.ErrorClassServices || code != bacnet.ErrorCodeUnknownSubscription {
		t.Fatalf("error payload = %x (class %d code %d), want class services / code unknown-subscription",
			answer.Payload, class, code)
	}
}
