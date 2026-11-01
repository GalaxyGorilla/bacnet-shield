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
