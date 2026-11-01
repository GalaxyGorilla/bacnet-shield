package bacnet

import (
	"bytes"
	"encoding/hex"
	"net"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestBVLCParse(t *testing.T) {
	t.Run("unicast", func(t *testing.T) {
		dg := mustHex(t, "810a000801001008")
		b, err := ParseBVLC(dg)
		if err != nil {
			t.Fatal(err)
		}
		if b.Function != BVLCOriginalUnicastNPDU {
			t.Fatalf("function = %v", b.Function)
		}
		if !bytes.Equal(b.Data, mustHex(t, "01001008")) {
			t.Fatalf("data = %x", b.Data)
		}
		if b.IsBroadcast() {
			t.Fatal("unicast reported as broadcast")
		}
	})

	t.Run("broadcast", func(t *testing.T) {
		b, err := ParseBVLC(mustHex(t, "810b000801001008"))
		if err != nil {
			t.Fatal(err)
		}
		if !b.IsBroadcast() {
			t.Fatal("original-broadcast not reported as broadcast")
		}
	})

	t.Run("forwarded", func(t *testing.T) {
		// origin 192.0.2.1:47808, then a who-is NPDU
		dg := mustHex(t, "8104000ec0000201bac001001008")
		b, err := ParseBVLC(dg)
		if err != nil {
			t.Fatal(err)
		}
		if b.Origin.String() != "192.0.2.1:47808" {
			t.Fatalf("origin = %s", b.Origin)
		}
		if !bytes.Equal(b.Data, mustHex(t, "01001008")) {
			t.Fatalf("data = %x", b.Data)
		}
		if b.IsBroadcast() {
			t.Fatal("forwarded-npdu is delivered unicast")
		}
	})

	t.Run("distribute-broadcast", func(t *testing.T) {
		dg := mustHex(t, "810900100005c0000201bac001001008")
		b, err := ParseBVLC(dg)
		if err != nil {
			t.Fatal(err)
		}
		if b.DNET != 5 {
			t.Fatalf("dnet = %d", b.DNET)
		}
		if b.Origin.String() != "192.0.2.1:47808" {
			t.Fatalf("origin = %s", b.Origin)
		}
		if !b.IsBroadcast() {
			t.Fatal("distribute-broadcast not reported as broadcast")
		}
	})

	t.Run("result", func(t *testing.T) {
		b, err := ParseBVLC(mustHex(t, "810000060000"))
		if err != nil {
			t.Fatal(err)
		}
		if b.Result != 0 {
			t.Fatalf("result = %d", b.Result)
		}
	})

	t.Run("register-foreign-device", func(t *testing.T) {
		b, err := ParseBVLC(mustHex(t, "81050006003c"))
		if err != nil {
			t.Fatal(err)
		}
		if b.TTL != 60 {
			t.Fatalf("ttl = %d", b.TTL)
		}
	})

	t.Run("rejections", func(t *testing.T) {
		cases := []struct {
			name string
			dg   string
		}{
			{"short", "810a00"},
			{"wrong type", "800a00040100"},
			{"sc frame", "820a00040100"},
			{"length mismatch", "810a00070100"},
			{"truncated origin", "81040006c000"},
		}
		for _, c := range cases {
			if _, err := ParseBVLC(mustHex(t, c.dg)); err == nil {
				t.Fatalf("%s: parsed, want error", c.name)
			}
		}
	})
}

func TestBVLCRoundTrip(t *testing.T) {
	cases := []BVLC{
		{Function: BVLCOriginalUnicastNPDU, Data: []byte{1, 0, 0x10, 0x08}},
		{Function: BVLCOriginalBroadcastNPDU, Data: []byte{1, 0, 0x10, 0x08}},
		{Function: BVLCForwardedNPDU, Origin: IPMAC{192, 0, 2, 1, 0xBA, 0xC0}, Data: []byte{1, 0}},
		{Function: BVLCDistributeBroadcastToNetwork, DNET: 7, Origin: IPMAC{10, 0, 0, 1, 0xBA, 0xC0}, Data: []byte{1, 0}},
		{Function: BVLCResult, Result: 0},
		{Function: BVLCRegisterForeignDevice, TTL: 300},
	}
	for _, want := range cases {
		got, err := ParseBVLC(want.Marshal())
		if err != nil {
			t.Fatalf("%v: %v", want.Function, err)
		}
		if got.Function != want.Function || got.DNET != want.DNET || got.Result != want.Result ||
			got.TTL != want.TTL || got.Origin != want.Origin || !bytes.Equal(got.Data, want.Data) {
			t.Fatalf("%v: round trip = %+v, want %+v", want.Function, got, want)
		}
	}
}

func TestNPDUParse(t *testing.T) {
	t.Run("plain apdu", func(t *testing.T) {
		n, err := ParseNPDU(mustHex(t, "01001008"))
		if err != nil {
			t.Fatal(err)
		}
		if n.HasDestination() || n.HasSource() || n.IsNetworkMessage() {
			t.Fatalf("unexpected routing: %+v", n)
		}
		if !bytes.Equal(n.APDU, mustHex(t, "1008")) {
			t.Fatalf("apdu = %x", n.APDU)
		}
	})

	t.Run("destination network", func(t *testing.T) {
		// control 0x20, dnet 5, dlen 6, dadr, hop 255, apdu
		n, err := ParseNPDU(mustHex(t, "0120000506c0000201bac0ff1008"))
		if err != nil {
			t.Fatal(err)
		}
		if n.DNET != 5 || len(n.DADR) != 6 || n.HopCount != 255 {
			t.Fatalf("routing = %+v", n)
		}
		if n.IsBroadcast() {
			t.Fatal("station address reported as broadcast")
		}
	})

	t.Run("broadcast to network", func(t *testing.T) {
		// dlen 0 is a broadcast to the destination network
		n, err := ParseNPDU(mustHex(t, "0120000500ff1008"))
		if err != nil {
			t.Fatal(err)
		}
		if !n.IsBroadcast() {
			t.Fatalf("dlen 0 not reported as broadcast: %+v", n)
		}
	})

	t.Run("global broadcast", func(t *testing.T) {
		n, err := ParseNPDU(mustHex(t, "0120ffff00ff1008"))
		if err != nil {
			t.Fatal(err)
		}
		if !n.IsBroadcast() || n.DNET != 0xFFFF {
			t.Fatalf("global broadcast = %+v", n)
		}
	})

	t.Run("source network", func(t *testing.T) {
		n, err := ParseNPDU(mustHex(t, "0108000506c0000201bac01008"))
		if err != nil {
			t.Fatal(err)
		}
		if n.SNET != 5 || len(n.SADR) != 6 {
			t.Fatalf("source = %+v", n)
		}
	})

	t.Run("network message", func(t *testing.T) {
		n, err := ParseNPDU(mustHex(t, "0180000005"))
		if err != nil {
			t.Fatal(err)
		}
		if n.NetworkMessage == nil || n.NetworkMessage.Type != NetWhoIsRouterToNetwork {
			t.Fatalf("network message = %+v", n.NetworkMessage)
		}
		if !bytes.Equal(n.NetworkMessage.Data, mustHex(t, "0005")) {
			t.Fatalf("data = %x", n.NetworkMessage.Data)
		}
	})

	t.Run("proprietary network message", func(t *testing.T) {
		n, err := ParseNPDU(mustHex(t, "01808003e7aabb"))
		if err != nil {
			t.Fatal(err)
		}
		if n.NetworkMessage.VendorID != 999 || !bytes.Equal(n.NetworkMessage.Data, mustHex(t, "aabb")) {
			t.Fatalf("proprietary = %+v", n.NetworkMessage)
		}
	})

	t.Run("rejections", func(t *testing.T) {
		cases := []struct {
			name string
			dg   string
		}{
			{"empty", ""},
			{"short", "01"},
			{"version", "0200"},
			{"truncated dnet", "012000"},
			{"dlen past end", "01200005ff"},
			{"zero source address", "01080005001008"},
			{"truncated hop", "0120000506c0000201bac0"},
		}
		for _, c := range cases {
			if _, err := ParseNPDU(mustHex(t, c.dg)); err == nil {
				t.Fatalf("%s: parsed, want error", c.name)
			}
		}
	})
}

func TestNPDURoundTrip(t *testing.T) {
	cases := []NPDU{
		{APDU: []byte{0x10, 0x08}},
		{DNET: 5, DADR: []byte{192, 0, 2, 1, 0xBA, 0xC0}, HopCount: 255, APDU: []byte{0x10, 0x08}},
		{DNET: 5, DADR: []byte{}, HopCount: 1, APDU: []byte{0x10, 0x08}},
		{SNET: 5, SADR: []byte{192, 0, 2, 1, 0xBA, 0xC0}, APDU: []byte{0x10, 0x08}},
		{DNET: 5, DADR: []byte{}, SNET: 5, SADR: []byte{10, 0, 0, 1, 0xBA, 0xC0}, HopCount: 9, APDU: []byte{0x10, 0x08}},
		{NetworkMessage: &NetworkMessage{Type: NetIAmRouterToNetwork, Data: []byte{0, 5}}},
		{NetworkMessage: &NetworkMessage{Type: 0x80, VendorID: 999, Data: []byte{1, 2}}},
	}
	for _, want := range cases {
		got, err := ParseNPDU(want.Marshal())
		if err != nil {
			t.Fatalf("%+v: %v", want, err)
		}
		if got.DNET != want.DNET || got.SNET != want.SNET || got.HopCount != want.HopCount ||
			!bytes.Equal(got.DADR, want.DADR) || !bytes.Equal(got.SADR, want.SADR) ||
			!bytes.Equal(got.APDU, want.APDU) {
			t.Fatalf("round trip = %+v, want %+v", got, want)
		}
		if (got.NetworkMessage == nil) != (want.NetworkMessage == nil) {
			t.Fatalf("network message presence differs")
		}
	}
}

func TestNPDUStripRouting(t *testing.T) {
	n := NPDU{
		DNET: 5, DADR: []byte{192, 0, 2, 1, 0xBA, 0xC0},
		SNET: 6, SADR: []byte{192, 0, 2, 2, 0xBA, 0xC0},
		HopCount: 9, ExpectingReply: true, Priority: 2,
		APDU: []byte{0x10, 0x08},
	}
	s := n.StripRouting()
	if s.HasDestination() || s.HasSource() || s.HopCount != 0 || s.ExpectingReply || s.Priority != 0 {
		t.Fatalf("routing not stripped: %+v", s)
	}
	if !bytes.Equal(s.APDU, n.APDU) {
		t.Fatalf("apdu changed: %x", s.APDU)
	}
	if !n.HasDestination() || !n.HasSource() {
		t.Fatal("StripRouting mutated the original")
	}
}

func TestAPDUParse(t *testing.T) {
	cases := []struct {
		name string
		hex  string
		want APDU
	}{
		{
			name: "confirmed request",
			hex:  "0005010c00",
			want: APDU{Type: PDUConfirmedRequest, MaxAPDU: 5, InvokeID: 1, HasInvokeID: true,
				Service: ServiceReadProperty, HasService: true, Payload: []byte{0}},
		},
		{
			name: "segmented confirmed request",
			hex:  "08050100020c00",
			want: APDU{Type: PDUConfirmedRequest, Segmented: true, MaxAPDU: 5, InvokeID: 1,
				HasInvokeID: true, SequenceNumber: 0, WindowSize: 2,
				Service: ServiceReadProperty, HasService: true, Payload: []byte{0}},
		},
		{
			name: "unconfirmed request",
			hex:  "1008",
			want: APDU{Type: PDUUnconfirmedRequest, Service: ServiceWhoIs, HasService: true},
		},
		{
			name: "simple ack",
			hex:  "20010f",
			want: APDU{Type: PDUSimpleACK, InvokeID: 1, HasInvokeID: true,
				Service: ServiceWriteProperty, HasService: true},
		},
		{
			name: "complex ack",
			hex:  "30010c00",
			want: APDU{Type: PDUComplexACK, InvokeID: 1, HasInvokeID: true,
				Service: ServiceReadProperty, HasService: true, Payload: []byte{0}},
		},
		{
			name: "segmented complex ack",
			hex:  "3c0101020c00",
			want: APDU{Type: PDUComplexACK, Segmented: true, MoreFollows: true, InvokeID: 1,
				HasInvokeID: true, SequenceNumber: 1, WindowSize: 2,
				Service: ServiceReadProperty, HasService: true, Payload: []byte{0}},
		},
		{
			name: "segment ack",
			hex:  "40010002",
			want: APDU{Type: PDUSegmentACK, InvokeID: 1, HasInvokeID: true, SequenceNumber: 0, WindowSize: 2},
		},
		{
			name: "error",
			hex:  "50010f91049128",
			want: APDU{Type: PDUError, InvokeID: 1, HasInvokeID: true,
				Service: ServiceWriteProperty, HasService: true, Payload: []byte{0x91, 4, 0x91, 40}},
		},
		{
			name: "reject",
			hex:  "600100",
			want: APDU{Type: PDUReject, InvokeID: 1, HasInvokeID: true, Payload: []byte{0}},
		},
		{
			name: "abort",
			hex:  "700100",
			want: APDU{Type: PDUAbort, InvokeID: 1, HasInvokeID: true, Payload: []byte{0}},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ParseAPDU(mustHex(t, c.hex))
			if err != nil {
				t.Fatal(err)
			}
			if got.Type != c.want.Type || got.InvokeID != c.want.InvokeID || got.HasInvokeID != c.want.HasInvokeID ||
				got.Service != c.want.Service || got.HasService != c.want.HasService ||
				got.Segmented != c.want.Segmented || got.MoreFollows != c.want.MoreFollows ||
				got.MaxAPDU != c.want.MaxAPDU || got.SequenceNumber != c.want.SequenceNumber ||
				got.WindowSize != c.want.WindowSize || !bytes.Equal(got.Payload, c.want.Payload) {
				t.Fatalf("parsed = %+v, want %+v", got, c.want)
			}
			if enc := got.Marshal(); !bytes.Equal(enc, mustHex(t, c.hex)) {
				t.Fatalf("marshal = %x, want %s", enc, c.hex)
			}
		})
	}
}

func TestAPDURejections(t *testing.T) {
	for _, dg := range []string{"", "08", "0005", "0805", "0f", "4f00", "5001"} {
		if _, err := ParseAPDU(mustHex(t, dg)); err == nil {
			t.Fatalf("%q: parsed, want error", dg)
		}
	}
}

func TestPatchInvokeID(t *testing.T) {
	// Confirmed request: invoke id is the third octet.
	cr := mustHex(t, "0005010c00")
	if err := PatchInvokeID(cr, 0x42); err != nil {
		t.Fatal(err)
	}
	if cr[2] != 0x42 {
		t.Fatalf("confirmed request invoke id = %x", cr[2])
	}
	// Simple ack: second octet.
	ack := mustHex(t, "20010f")
	if err := PatchInvokeID(ack, 0x42); err != nil {
		t.Fatal(err)
	}
	if ack[1] != 0x42 {
		t.Fatalf("simple ack invoke id = %x", ack[1])
	}
	// Unconfirmed requests have none.
	if err := PatchInvokeID(mustHex(t, "1008"), 1); err == nil {
		t.Fatal("patched an unconfirmed request")
	}
	if err := PatchInvokeID([]byte{0x90}, 1); err == nil {
		t.Fatal("patched an invalid pdu type")
	}
}

func TestAPDUIsWrite(t *testing.T) {
	write := APDU{Type: PDUConfirmedRequest, HasService: true, Service: ServiceWriteProperty}
	if !write.IsWrite() {
		t.Fatal("write-property not a write")
	}
	for _, s := range []Service{ServiceWritePropertyMultiple, ServiceCreateObject, ServiceDeleteObject,
		ServiceAddListElement, ServiceRemoveListElement, ServiceAtomicWriteFile,
		ServiceDeviceCommunicationControl, ServiceReinitializeDevice} {
		if !(APDU{Type: PDUConfirmedRequest, HasService: true, Service: s}).IsWrite() {
			t.Fatalf("%d not a write", s)
		}
	}
	for _, s := range []Service{ServiceReadProperty, ServiceReadPropertyMultiple, ServiceSubscribeCOV} {
		if (APDU{Type: PDUConfirmedRequest, HasService: true, Service: s}).IsWrite() {
			t.Fatalf("%d reported as write", s)
		}
	}
	if (APDU{Type: PDUUnconfirmedRequest, HasService: true, Service: ServiceWhoIs}).IsWrite() {
		t.Fatal("who-is reported as write")
	}
}

func TestObjectID(t *testing.T) {
	oid := ObjectID{Type: ObjectAnalogValue, Instance: 5}
	enc := oid.AppendTo(nil)
	got, err := ParseObjectID(enc)
	if err != nil {
		t.Fatal(err)
	}
	if got != oid {
		t.Fatalf("round trip = %v, want %v", got, oid)
	}
	if oid.String() != "analog-value,5" {
		t.Fatalf("string = %q", oid.String())
	}
	for _, s := range []string{"analog-value,5", "analog_value:5", "2,5", "2:5"} {
		got, err := ParseObjectIDString(s)
		if err != nil {
			t.Fatalf("%q: %v", s, err)
		}
		if got != oid {
			t.Fatalf("%q = %v", s, got)
		}
	}
	for _, s := range []string{"", "analog-value", "analog-value,", "nope,5", "analog-value,4194304"} {
		if _, err := ParseObjectIDString(s); err == nil {
			t.Fatalf("%q parsed, want error", s)
		}
	}
	if _, err := ParseObjectID([]byte{1, 2, 3}); err == nil {
		t.Fatal("short object id parsed")
	}
}

func TestWriteTargetsWriteProperty(t *testing.T) {
	// [0] analog-value,5  [1] present-value(85)  [3] { real 1.0 }
	payload := mustHex(t, "0c0080000519553e443f8000003f")
	a := APDU{Type: PDUConfirmedRequest, HasService: true, Service: ServiceWriteProperty, Payload: payload}
	ts, isWrite, err := WriteTargets(a)
	if err != nil {
		t.Fatal(err)
	}
	if !isWrite || len(ts) != 1 {
		t.Fatalf("targets = %+v, isWrite=%v", ts, isWrite)
	}
	want := WriteTarget{Object: ObjectID{Type: ObjectAnalogValue, Instance: 5}, Property: PropertyPresentValue}
	if ts[0] != want {
		t.Fatalf("target = %+v, want %+v", ts[0], want)
	}
	if ts[0].String() != "analog-value,5:present-value" {
		t.Fatalf("string = %q", ts[0].String())
	}
}

func TestWriteTargetsWritePropertyArrayIndex(t *testing.T) {
	// [0] analog-value,5 [1] priority-array(87) [2] 3 [3] { real 1.0 }
	payload := mustHex(t, "0c00800005195729033e443f8000003f")
	a := APDU{Type: PDUConfirmedRequest, HasService: true, Service: ServiceWriteProperty, Payload: payload}
	ts, _, err := WriteTargets(a)
	if err != nil {
		t.Fatal(err)
	}
	if len(ts) != 1 || ts[0].ArrayIndex == nil || *ts[0].ArrayIndex != 3 {
		t.Fatalf("targets = %+v", ts)
	}
}

func TestWriteTargetsWritePropertyMultiple(t *testing.T) {
	// { { [0] analog-value,5  [1] { [0] present-value, [2] { real 1.0 } } }
	//   { [0] binary-output,7 [1] { [0] present-value, [2] { enum 1 } } } }
	payload := mustHex(t,
		"0e"+
			"0c00800005"+"1e"+"0955"+"2e"+"443f800000"+"2f"+"1f"+
			"0c01000007"+"1e"+"0955"+"2e"+"9101"+"2f"+"1f"+
			"0f")
	a := APDU{Type: PDUConfirmedRequest, HasService: true, Service: ServiceWritePropertyMultiple, Payload: payload}
	ts, isWrite, err := WriteTargets(a)
	if err != nil {
		t.Fatal(err)
	}
	if !isWrite || len(ts) != 2 {
		t.Fatalf("targets = %+v, isWrite=%v", ts, isWrite)
	}
	if ts[0].Object != (ObjectID{Type: ObjectAnalogValue, Instance: 5}) || ts[0].Property != PropertyPresentValue {
		t.Fatalf("first target = %+v", ts[0])
	}
	if ts[1].Object != (ObjectID{Type: ObjectBinaryOutput, Instance: 7}) || ts[1].Property != PropertyPresentValue {
		t.Fatalf("second target = %+v", ts[1])
	}
}

func TestWriteTargetsRejectsUndecodable(t *testing.T) {
	cases := []struct {
		name    string
		service Service
		payload string
	}{
		{"empty write-property", ServiceWriteProperty, ""},
		{"missing property", ServiceWriteProperty, "0c00800005"},
		{"missing value", ServiceWriteProperty, "0c008000051955"},
		{"truncated object id", ServiceWriteProperty, "0c0080"},
		{"truncated wpm", ServiceWritePropertyMultiple, "0e"},
		{"wpm without object id", ServiceWritePropertyMultiple, "0e1e0f0f"},
	}
	for _, c := range cases {
		a := APDU{Type: PDUConfirmedRequest, HasService: true, Service: c.service, Payload: mustHex(t, c.payload)}
		_, isWrite, err := WriteTargets(a)
		if !isWrite || err == nil {
			t.Fatalf("%s: isWrite=%v err=%v, want a denial-worthy error", c.name, isWrite, err)
		}
	}
}

func TestWriteTargetsServiceLevelWrite(t *testing.T) {
	a := APDU{Type: PDUConfirmedRequest, HasService: true, Service: ServiceReinitializeDevice}
	ts, isWrite, err := WriteTargets(a)
	if err != nil || !isWrite || ts != nil {
		t.Fatalf("service-level write = %+v, %v, %v", ts, isWrite, err)
	}
	a = APDU{Type: PDUConfirmedRequest, HasService: true, Service: ServiceReadProperty}
	if _, isWrite, _ := WriteTargets(a); isWrite {
		t.Fatal("read reported as write")
	}
}

func TestCOVObjects(t *testing.T) {
	// SubscribeCOV: [0] process 1, [1] monitored object, [2] confirmed, [3] lifetime
	sub := APDU{Type: PDUConfirmedRequest, HasService: true, Service: ServiceSubscribeCOV,
		Payload: mustHex(t, "0901"+"1c00800005"+"2901"+"3900")}
	oid, ok := COVSubscriptionObject(sub)
	if !ok || oid != (ObjectID{Type: ObjectAnalogValue, Instance: 5}) {
		t.Fatalf("subscription object = %v, %v", oid, ok)
	}
	// Without the optional process identifier the object is still tag 1.
	sub.Payload = mustHex(t, "1c00800005"+"2901"+"3900")
	if oid, ok := COVSubscriptionObject(sub); !ok || oid.Instance != 5 {
		t.Fatalf("subscription without process id = %v, %v", oid, ok)
	}

	// Unconfirmed COV notification: [0] process, [1] device, [2] monitored object, ...
	notif := APDU{Type: PDUUnconfirmedRequest, HasService: true, Service: ServiceUnconfirmedCOVNotification,
		Payload: mustHex(t, "0901"+"1c02000064"+"2c00800005"+"3900"+"4e0f")}
	oid, ok = COVNotificationObject(notif)
	if !ok || oid != (ObjectID{Type: ObjectAnalogValue, Instance: 5}) {
		t.Fatalf("notification object = %v, %v", oid, ok)
	}
	if _, ok := COVNotificationObject(sub); ok {
		t.Fatal("a subscription parsed as a notification")
	}
}

func TestTagReaderExtended(t *testing.T) {
	// Extended tag number 20, length 1, value 0x2a.
	tr := &tagReader{b: mustHex(t, "f9142a")}
	tag, err := tr.next()
	if err != nil {
		t.Fatal(err)
	}
	if tag.Number != 20 || !tag.Context || !bytes.Equal(tag.Data, []byte{0x2a}) {
		t.Fatalf("tag = %+v", tag)
	}

	// Extended length: 254 escapes a 16-bit length.
	tr = &tagReader{b: append([]byte{0x0d, 254, 0x01, 0x00}, make([]byte, 256)...)}
	tag, err = tr.next()
	if err != nil {
		t.Fatal(err)
	}
	if len(tag.Data) != 256 {
		t.Fatalf("data length = %d", len(tag.Data))
	}

	// 255 escapes a 32-bit length; 4 bytes is enough to prove the path.
	tr = &tagReader{b: []byte{0x0d, 255, 0, 0, 0, 4, 1, 2, 3, 4}}
	tag, err = tr.next()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tag.Data, []byte{1, 2, 3, 4}) {
		t.Fatalf("data = %x", tag.Data)
	}

	// Application BOOLEAN carries its value in the tag and has no data.
	tr = &tagReader{b: []byte{0x11}}
	tag, err = tr.next()
	if err != nil {
		t.Fatal(err)
	}
	if !tag.Boolean || len(tag.Data) != 0 {
		t.Fatalf("boolean tag = %+v", tag)
	}

	// Truncated streams are errors, never panics.
	for _, b := range [][]byte{{0x0d}, {0x0d, 254}, {0x0d, 254, 1}, {0x0d, 255, 0, 0, 0}, {0xf0}, {0x0d, 5, 1}} {
		tr := &tagReader{b: b}
		if _, err := tr.next(); err == nil {
			t.Fatalf("%x: parsed, want error", b)
		}
	}
}

func TestIPMAC(t *testing.T) {
	a := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 47808}
	m, err := IPMACFromUDP(a)
	if err != nil {
		t.Fatal(err)
	}
	if m.String() != "192.0.2.1:47808" {
		t.Fatalf("string = %q", m.String())
	}
	if got := m.UDPAddr(); !got.IP.Equal(a.IP) || got.Port != a.Port {
		t.Fatalf("udp = %v", got)
	}
	if _, err := IPMACFromUDP(&net.UDPAddr{IP: net.ParseIP("::1"), Port: 47808}); err == nil {
		t.Fatal("IPv6 accepted as a BACnet/IPv4 address")
	}
}

func TestWriteTargetsWritePropertyMultiplePriority(t *testing.T) {
	// A priority (context tag 3) after the value must be consumed, not read
	// as the next property identifier.
	payload := mustHex(t,
		"0e"+
			"0c00800005"+"1e"+"0955"+"2e"+"443f800000"+"2f"+"3903"+"1f"+
			"0f")
	a := APDU{Type: PDUConfirmedRequest, HasService: true, Service: ServiceWritePropertyMultiple, Payload: payload}
	ts, isWrite, err := WriteTargets(a)
	if err != nil || !isWrite || len(ts) != 1 {
		t.Fatalf("targets = %+v, isWrite=%v, err=%v", ts, isWrite, err)
	}
	if ts[0].Object != (ObjectID{Type: ObjectAnalogValue, Instance: 5}) || ts[0].Property != PropertyPresentValue {
		t.Fatalf("target = %+v", ts[0])
	}
}

func TestWriteTargetsZeroLengthProperty(t *testing.T) {
	// Property identifier 0 (acked-transitions) is a zero-length context tag.
	payload := mustHex(t, "0c00800005"+"18"+"3e443f8000003f")
	a := APDU{Type: PDUConfirmedRequest, HasService: true, Service: ServiceWriteProperty, Payload: payload}
	ts, _, err := WriteTargets(a)
	if err != nil || len(ts) != 1 {
		t.Fatalf("targets = %+v, err=%v", ts, err)
	}
	if ts[0].Property != PropertyID(0) {
		t.Fatalf("property = %v", ts[0].Property)
	}
}

func TestCOVSubscriptionFields(t *testing.T) {
	// Timed subscription: process 1, object analog-value,5, confirmed, lifetime 10.
	sub := APDU{Type: PDUConfirmedRequest, HasService: true, Service: ServiceSubscribeCOV,
		Payload: mustHex(t, "0901"+"1c00800005"+"2901"+"390a")}
	obj, proc, life, hasLife, ok := COVSubscription(sub)
	if !ok || obj != (ObjectID{Type: ObjectAnalogValue, Instance: 5}) || proc != 1 || !hasLife || life != 10 {
		t.Fatalf("subscription = %v %d %d %v %v", obj, proc, life, hasLife, ok)
	}

	// Cancellation: no lifetime tag.
	sub.Payload = mustHex(t, "0901"+"1c00800005")
	if _, _, _, hasLife, ok := COVSubscription(sub); !ok || hasLife {
		t.Fatalf("cancel = hasLifetime %v, ok %v", hasLife, ok)
	}

	// A permanent subscription has lifetime 0, not "no lifetime".
	sub.Payload = mustHex(t, "0901"+"1c00800005"+"3900")
	if _, _, life, hasLife, ok := COVSubscription(sub); !ok || !hasLife || life != 0 {
		t.Fatalf("permanent = lifetime %d, hasLifetime %v, ok %v", life, hasLife, ok)
	}

	// A read is not a subscription.
	read := APDU{Type: PDUConfirmedRequest, HasService: true, Service: ServiceReadProperty}
	if _, _, _, _, ok := COVSubscription(read); ok {
		t.Fatal("a read parsed as a subscription")
	}
}

func TestCOVNotificationProcessID(t *testing.T) {
	notif := APDU{Type: PDUUnconfirmedRequest, HasService: true, Service: ServiceUnconfirmedCOVNotification,
		Payload: mustHex(t, "0901"+"1c02000064"+"2c00800005"+"3900"+"4e0f")}
	if id, ok := COVNotificationProcessID(notif); !ok || id != 1 {
		t.Fatalf("process id = %d, %v", id, ok)
	}
	sub := APDU{Type: PDUConfirmedRequest, HasService: true, Service: ServiceSubscribeCOV,
		Payload: mustHex(t, "0901"+"1c00800005")}
	if _, ok := COVNotificationProcessID(sub); ok {
		t.Fatal("a subscription parsed as a notification")
	}
}

func TestIAmDeviceID(t *testing.T) {
	iam := APDU{Type: PDUUnconfirmedRequest, HasService: true, Service: ServiceIAm,
		Payload: mustHex(t, "0c02000064"+"1905"+"2900"+"3a0005")}
	oid, ok := IAmDeviceID(iam)
	if !ok || oid != (ObjectID{Type: ObjectDevice, Instance: 100}) {
		t.Fatalf("i-am device = %v, %v", oid, ok)
	}
	if _, ok := IAmDeviceID(APDU{Type: PDUUnconfirmedRequest, HasService: true, Service: ServiceWhoIs}); ok {
		t.Fatal("who-is parsed as an i-am")
	}
}

func TestTagSkipValueRejectsMismatchedClose(t *testing.T) {
	// Opening tag 0, opening tag 1, then a closing tag 0 where tag 1 is
	// expected. Accepting it would let a crafted write move the parser's
	// cursor and hide a target from the policy.
	r := &tagReader{b: mustHex(t, "0e1e0f0f")}
	if _, err := r.next(); err != nil {
		t.Fatal(err)
	}
	if err := r.skipValue(0); err == nil {
		t.Fatal("mismatched closing tag accepted")
	}

	r = &tagReader{b: mustHex(t, "0e1e1f0f")}
	if _, err := r.next(); err != nil {
		t.Fatal(err)
	}
	if err := r.skipValue(0); err != nil {
		t.Fatalf("well-nested value rejected: %v", err)
	}
}

func TestTagUintZeroLength(t *testing.T) {
	// BACnet encodes unsigned 0 as a zero-length value.
	got, err := (Tag{Number: 0, Context: true}).uint()
	if err != nil || got != 0 {
		t.Fatalf("zero-length uint = %d, %v", got, err)
	}
	if _, err := (Tag{Number: 0, Context: true, Data: []byte{1, 2, 3, 4, 5}}).uint(); err == nil {
		t.Fatal("5-byte unsigned accepted")
	}
	if _, err := (Tag{Number: 0}).uint(); err == nil {
		t.Fatal("application tag accepted as a context unsigned")
	}
}

func TestErrorCodesAndReject(t *testing.T) {
	// These octets are wire values a client acts on; pin them.
	if ErrorClassSecurity != 4 {
		t.Fatalf("security class = %d", ErrorClassSecurity)
	}
	if ErrorCodeWriteAccessDenied != 40 || ErrorCodeServiceRequestDenied != 29 ||
		ErrorCodeUnknownObject != 31 || ErrorCodeUnknownProperty != 32 {
		t.Fatal("error code drifted from ASHRAE 135")
	}
	rej := RejectAPDU(7, RejectReasonUnrecognizedService)
	if rej.Type != PDUReject || rej.InvokeID != 7 || !rej.HasInvokeID || !bytes.Equal(rej.Payload, []byte{9}) {
		t.Fatalf("reject = %+v", rej)
	}
	if _, err := ParseAPDU(rej.Marshal()); err != nil {
		t.Fatalf("reject does not round trip: %v", err)
	}
}

// TestErrorAPDUEncoding pins the exact bytes a locally generated Error PDU
// puts on the wire. Error class and code are application-tagged ENUMERATEDs
// (tag number 9, one octet each), so class security (4) and code
// write-access-denied (40) encode as 91 04 91 28. This vector was taken from
// bacpypes3 0.0.110; a raw-octet encoding is silently dropped by a strict
// stack, which turns a denial into an apparent timeout.
func TestErrorAPDUEncoding(t *testing.T) {
	errAPDU := ErrorAPDU(1, ServiceWriteProperty, ErrorClassSecurity, ErrorCodeWriteAccessDenied)
	if got, want := errAPDU.Marshal(), mustHex(t, "50010f91049128"); !bytes.Equal(got, want) {
		t.Fatalf("error apdu = % x, want % x", got, want)
	}

	class, code, ok := ErrorClassAndCode(errAPDU.Payload)
	if !ok || class != ErrorClassSecurity || code != ErrorCodeWriteAccessDenied {
		t.Fatalf("decode = %d/%d ok=%v, want %d/%d", class, code, ok,
			ErrorClassSecurity, ErrorCodeWriteAccessDenied)
	}

	// A raw, untagged payload is refused rather than misread as class 4.
	if _, _, ok := ErrorClassAndCode([]byte{4, 40}); ok {
		t.Fatal("untagged error payload accepted")
	}
	// So is a truncated one.
	if _, _, ok := ErrorClassAndCode([]byte{0x91, 4, 0x91}); ok {
		t.Fatal("truncated error payload accepted")
	}
}
