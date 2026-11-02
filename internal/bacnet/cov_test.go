package bacnet

import (
	"bytes"
	"testing"
)

// The multiple-COV structures are hand-encoded here: bacpypes3 does not
// implement SubscribeCOVPropertyMultiple, so there is no independent encoder to
// borrow. The bytes below follow ASHRAE 135 clause 21 (context tags, sequence
// elements as opening/closing pairs), and the decoders must extract exactly the
// subscriber process id and the monitored objects — nothing else is routing
// state.

// covMultipleRef builds one listOfCOVPropertyReferences element:
//
//	[0] object-identifier, [1] { [0] property-reference, [2] timestamped }
//
// The element itself is an untagged SEQUENCE, so it has no wrapper; the [0]
// property reference is a CHOICE and therefore a constructed value.
func covMultipleRef(oid ObjectID, prop PropertyID) []byte {
	b := []byte{0x0C}
	b = append(b, oid.AppendTo(nil)...)
	b = append(b, 0x1E, 0x0E, 0x09, byte(prop), 0x0F, 0x29, 0x00, 0x1F)
	return b
}

// covMultipleSubscribe builds a SubscribeCOVPropertyMultiple payload. lifetime
// < 0 omits the optional lifetime (a cancellation).
func covMultipleSubscribe(procID uint32, lifetime int, refs ...[]byte) []byte {
	b := []byte{0x09, byte(procID), 0x19, 0x00}
	if lifetime >= 0 {
		b = append(b, 0x29, byte(lifetime))
	}
	b = append(b, 0x39, 0x00, 0x4E) // maxNotificationDelay 0, then [4] list
	for _, ref := range refs {
		b = append(b, ref...)
	}
	return append(b, 0x4F)
}

// covMultipleNotify builds a COVNotificationMultiple payload (confirmed and
// unconfirmed have the same body):
//
//	[0] proc, [1] device-id, [2] time-remaining, [3] timestamp, [4] list of
//	{ [0] object-id, [1] { [0] property-id, [2] value } }
func covMultipleNotify(procID uint32, device uint32, oids ...ObjectID) []byte {
	dev := ObjectID{Type: ObjectDevice, Instance: device}
	b := []byte{0x09, byte(procID), 0x1C}
	b = append(b, dev.AppendTo(nil)...)
	b = append(b, 0x29, 0x00, 0x3E, 0x3F, 0x4E)
	for _, oid := range oids {
		b = append(b, 0x0C)
		b = append(b, oid.AppendTo(nil)...)
		b = append(b, 0x1E, 0x09, 0x55, 0x2E, 0x44, 0x3F, 0x80, 0x00, 0x00, 0x2F, 0x1F)
	}
	return append(b, 0x4F)
}

func av(instance uint32) ObjectID {
	return ObjectID{Type: ObjectAnalogValue, Instance: instance}
}

func TestCOVMultipleSubscriptionDecoding(t *testing.T) {
	payload := covMultipleSubscribe(7, 60,
		covMultipleRef(av(1), PropertyPresentValue),
		covMultipleRef(av(2), PropertyPresentValue),
	)
	a := APDU{Type: PDUConfirmedRequest, HasService: true,
		Service: ServiceSubscribeCOVPropertyMultiple, Payload: payload}

	objs, proc, lifetime, hasLifetime, ok := COVMultipleSubscription(a)
	if !ok {
		t.Fatalf("did not decode a valid multiple subscription: %x", payload)
	}
	if proc != 7 || lifetime != 60 || !hasLifetime {
		t.Fatalf("proc=%d lifetime=%d hasLifetime=%v", proc, lifetime, hasLifetime)
	}
	if len(objs) != 2 || objs[0] != av(1) || objs[1] != av(2) {
		t.Fatalf("objects = %v, want [analog-value,1 analog-value,2]", objs)
	}

	// No lifetime is a cancellation and must still name its objects.
	cancel := covMultipleSubscribe(7, -1, covMultipleRef(av(1), PropertyPresentValue))
	objs, _, _, hasLifetime, ok = COVMultipleSubscription(APDU{Type: PDUConfirmedRequest,
		HasService: true, Service: ServiceSubscribeCOVPropertyMultiple, Payload: cancel})
	if !ok || hasLifetime || len(objs) != 1 || objs[0] != av(1) {
		t.Fatalf("cancellation = %v, hasLifetime=%v, ok=%v", objs, hasLifetime, ok)
	}
}

func TestCOVMultipleSubscriptionRejectsMalformed(t *testing.T) {
	valid := covMultipleSubscribe(7, 60, covMultipleRef(av(1), PropertyPresentValue))

	cases := []struct {
		name string
		a    APDU
	}{
		{"wrong service", APDU{Type: PDUConfirmedRequest, HasService: true,
			Service: ServiceSubscribeCOV, Payload: valid}},
		{"not confirmed", APDU{Type: PDUUnconfirmedRequest, HasService: true,
			Service: ServiceSubscribeCOVPropertyMultiple, Payload: valid}},
		{"truncated", APDU{Type: PDUConfirmedRequest, HasService: true,
			Service: ServiceSubscribeCOVPropertyMultiple, Payload: valid[:len(valid)-3]}},
		{"no object list", APDU{Type: PDUConfirmedRequest, HasService: true,
			Service: ServiceSubscribeCOVPropertyMultiple, Payload: []byte{0x09, 0x07, 0x19, 0x00}}},
		{"no process id", APDU{Type: PDUConfirmedRequest, HasService: true,
			Service: ServiceSubscribeCOVPropertyMultiple,
			Payload: []byte{0x19, 0x00, 0x4E, 0x0C, 0x00, 0x80, 0x00, 0x01, 0x1E, 0x0F, 0x4F}}},
		{"element without object", APDU{Type: PDUConfirmedRequest, HasService: true,
			Service: ServiceSubscribeCOVPropertyMultiple,
			Payload: []byte{0x09, 0x07, 0x19, 0x00, 0x4E, 0x09, 0x55, 0x4F}}},
		{"wrong closing tag", APDU{Type: PDUConfirmedRequest, HasService: true,
			Service: ServiceSubscribeCOVPropertyMultiple,
			Payload: []byte{0x09, 0x07, 0x19, 0x00, 0x4E, 0x0C, 0x00, 0x80, 0x00, 0x01, 0x1F, 0x4F}}},
	}
	for _, tc := range cases {
		if _, _, _, _, ok := COVMultipleSubscription(tc.a); ok {
			t.Errorf("%s: accepted a malformed request", tc.name)
		}
	}
}

func TestCOVMultipleNotificationDecoding(t *testing.T) {
	payload := covMultipleNotify(9, 1001, av(1), av(3))

	for _, a := range []APDU{
		{Type: PDUUnconfirmedRequest, HasService: true,
			Service: ServiceUnconfirmedCOVNotificationMultiple, Payload: payload},
		{Type: PDUConfirmedRequest, HasService: true,
			Service: ServiceConfirmedCOVNotificationMultiple, Payload: payload},
	} {
		objs, proc, ok := COVMultipleNotification(a)
		if !ok || proc != 9 || len(objs) != 2 || objs[0] != av(1) || objs[1] != av(3) {
			t.Fatalf("%s: objects=%v proc=%d ok=%v", a.Type, objs, proc, ok)
		}
		if !IsCOVMultipleNotification(a) {
			t.Fatalf("%s: IsCOVMultipleNotification = false", a.Type)
		}
	}

	// A single-object notification is not a multiple notification.
	single := APDU{Type: PDUUnconfirmedRequest, HasService: true,
		Service: ServiceUnconfirmedCOVNotification, Payload: payload}
	if IsCOVMultipleNotification(single) {
		t.Fatal("a single-object COV notification was treated as multiple")
	}
	if _, _, ok := COVMultipleNotification(single); ok {
		t.Fatal("COVMultipleNotification accepted a single-object notification")
	}
}

func TestCOVMultipleNotificationRejectsMalformed(t *testing.T) {
	valid := covMultipleNotify(9, 1001, av(1))

	cases := []struct {
		name string
		a    APDU
	}{
		{"empty list", APDU{Type: PDUUnconfirmedRequest, HasService: true,
			Service: ServiceUnconfirmedCOVNotificationMultiple,
			Payload: []byte{0x09, 0x09, 0x1C, 0x00, 0x80, 0x03, 0xE9, 0x29, 0x00, 0x3E, 0x3F, 0x4E, 0x4F}}},
		{"truncated", APDU{Type: PDUUnconfirmedRequest, HasService: true,
			Service: ServiceUnconfirmedCOVNotificationMultiple, Payload: valid[:len(valid)-4]}},
		{"no process id", APDU{Type: PDUUnconfirmedRequest, HasService: true,
			Service: ServiceUnconfirmedCOVNotificationMultiple, Payload: valid[2:]}},
		{"wrong service", APDU{Type: PDUUnconfirmedRequest, HasService: true,
			Service: ServiceUnconfirmedCOVNotification, Payload: valid}},
	}
	for _, tc := range cases {
		if _, _, ok := COVMultipleNotification(tc.a); ok {
			t.Errorf("%s: accepted a malformed notification", tc.name)
		}
	}
}

// A notification list that names the same object twice must not confuse the
// router: the proxy deduplicates clients, not objects, but the decoder must
// return them in wire order.
func TestCOVMultipleNotificationRepeatedObject(t *testing.T) {
	payload := covMultipleNotify(9, 1001, av(1), av(1))
	objs, _, ok := COVMultipleNotification(APDU{Type: PDUUnconfirmedRequest,
		HasService: true, Service: ServiceUnconfirmedCOVNotificationMultiple, Payload: payload})
	if !ok || len(objs) != 2 || objs[0] != av(1) || objs[1] != av(1) {
		t.Fatalf("objects = %v, ok=%v", objs, ok)
	}
}

// The decoders are structural parsers over attacker-controlled bytes; a
// payload that is valid enough to parse must not depend on trailing bytes.
func TestCOVMultipleIgnoresTrailingBytes(t *testing.T) {
	sub := append(covMultipleSubscribe(1, 30, covMultipleRef(av(1), PropertyPresentValue)), 0xFF, 0xFF)
	if _, _, _, _, ok := COVMultipleSubscription(APDU{Type: PDUConfirmedRequest,
		HasService: true, Service: ServiceSubscribeCOVPropertyMultiple, Payload: sub}); !ok {
		t.Fatal("trailing bytes broke the subscription decoder")
	}
	notify := append(covMultipleNotify(1, 1, av(1)), 0xFF)
	if _, _, ok := COVMultipleNotification(APDU{Type: PDUUnconfirmedRequest,
		HasService: true, Service: ServiceUnconfirmedCOVNotificationMultiple, Payload: notify}); !ok {
		t.Fatal("trailing bytes broke the notification decoder")
	}
}

// The encoders above are only trustworthy if the bytes are what they claim to
// be. Pin the first element of a valid subscription so a typo in the fixture
// cannot quietly make a decoder test vacuous.
func TestCOVMultipleWireShape(t *testing.T) {
	payload := covMultipleSubscribe(7, 60, covMultipleRef(av(1), PropertyPresentValue))
	want := []byte{0x09, 0x07, 0x19, 0x00, 0x29, 0x3C, 0x39, 0x00, 0x4E,
		0x0C, 0x00, 0x80, 0x00, 0x01, 0x1E, 0x0E, 0x09, 0x55, 0x0F, 0x29, 0x00, 0x1F, 0x4F}
	if !bytes.Equal(payload, want) {
		t.Fatalf("subscription bytes = %x, want %x", payload, want)
	}
}
