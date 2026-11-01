package bacnet

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// seedHex is mustHex for fuzz seeds: *testing.F is not a *testing.T.
func seedHex(f *testing.F, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		f.Fatalf("bad seed %q: %v", s, err)
	}
	return b
}

// The parsers below are the only code in the proxy that touches raw
// attacker-controlled datagrams, so they are fuzzed directly. The invariants
// are deliberately weak (no panic, and a successful parse must re-encode to
// something the same parser accepts): a strong "output == input" invariant
// would be wrong, because the encoders normalize fields the wire allows to
// be redundant (reserved control bits, extended lengths).

func FuzzParseBVLC(f *testing.F) {
	for _, s := range []string{
		"810a000801001008",
		"810b000801001008",
		"8104000ec0000201bac001001008",
		"810900100005c0000201bac001001008",
		"810000060000",
		"81050006003c",
	} {
		f.Add(seedHex(f, s))
	}
	f.Fuzz(func(t *testing.T, dg []byte) {
		b, err := ParseBVLC(dg)
		if err != nil {
			return
		}
		again, err := ParseBVLC(b.Marshal())
		if err != nil {
			t.Fatalf("marshal produced an unparseable frame: %v (%x)", err, dg)
		}
		if again.Function != b.Function || !bytes.Equal(again.Data, b.Data) {
			t.Fatalf("round trip changed the frame: %+v vs %+v", again, b)
		}
	})
}

func FuzzParseNPDU(f *testing.F) {
	for _, s := range []string{
		"01001008",
		"0120000506c0000201bac0ff1008",
		"0120000500ff1008",
		"0120ffff00ff1008",
		"0108000506c0000201bac01008",
		"0180000005",
		"01808003e7aabb",
	} {
		f.Add(seedHex(f, s))
	}
	f.Fuzz(func(t *testing.T, dg []byte) {
		n, err := ParseNPDU(dg)
		if err != nil {
			return
		}
		again, err := ParseNPDU(n.Marshal())
		if err != nil {
			t.Fatalf("marshal produced an unparseable npdu: %v (%x)", err, dg)
		}
		if again.DNET != n.DNET || again.SNET != n.SNET || again.HopCount != n.HopCount ||
			!bytes.Equal(again.DADR, n.DADR) || !bytes.Equal(again.SADR, n.SADR) ||
			!bytes.Equal(again.APDU, n.APDU) {
			t.Fatalf("round trip changed the npdu: %+v vs %+v", again, n)
		}
	})
}

func FuzzParseAPDU(f *testing.F) {
	for _, s := range []string{
		"0005010c00",
		"08050100020c00",
		"1008",
		"20010f",
		"30010c00",
		"3c0101020c00",
		"40010002",
		"50010f0428",
		"600100",
		"700100",
	} {
		f.Add(seedHex(f, s))
	}
	f.Fuzz(func(t *testing.T, dg []byte) {
		a, err := ParseAPDU(dg)
		if err != nil {
			return
		}
		again, err := ParseAPDU(a.Marshal())
		if err != nil {
			t.Fatalf("marshal produced an unparseable apdu: %v (%x)", err, dg)
		}
		if again.Type != a.Type || again.InvokeID != a.InvokeID || again.Service != a.Service ||
			again.HasService != a.HasService || again.Segmented != a.Segmented ||
			again.MoreFollows != a.MoreFollows || !bytes.Equal(again.Payload, a.Payload) {
			t.Fatalf("round trip changed the apdu: %+v vs %+v", again, a)
		}
	})
}

func FuzzParseObjectID(f *testing.F) {
	f.Add([]byte{0, 0x80, 0, 5})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		oid, err := ParseObjectID(b)
		if err != nil {
			return
		}
		if oid.Instance > maxObjectInstance {
			t.Fatalf("instance %d exceeds 22 bits", oid.Instance)
		}
		back, err := ParseObjectID(oid.AppendTo(nil))
		if err != nil || back != oid {
			t.Fatalf("round trip = %v, %v", back, err)
		}
	})
}

func FuzzWriteTargets(f *testing.F) {
	// A valid WriteProperty, a valid WritePropertyMultiple, and a few
	// truncated variants.
	f.Add(byte(ServiceWriteProperty), seedHex(f, "0c0080000519553e443f8000003f"))
	f.Add(byte(ServiceWritePropertyMultiple), seedHex(f, "0e0c008000051e09552e443f8000002f1f0f"))
	f.Add(byte(ServiceWriteProperty), seedHex(f, "0c0080"))
	f.Add(byte(ServiceReinitializeDevice), []byte{})
	f.Fuzz(func(t *testing.T, service byte, payload []byte) {
		a := APDU{Type: PDUConfirmedRequest, HasService: true, Service: Service(service), Payload: payload}
		targets, _, err := WriteTargets(a)
		if err != nil {
			return
		}
		for _, tg := range targets {
			if tg.Object.Instance > maxObjectInstance {
				t.Fatalf("target instance %d exceeds 22 bits", tg.Object.Instance)
			}
		}
	})
}

func FuzzTagReader(f *testing.F) {
	f.Add(seedHex(f, "0c0080000519553e443f8000003f"))
	f.Add(seedHex(f, "f9142a"))
	f.Add(seedHex(f, "0dff00000004"))
	f.Fuzz(func(t *testing.T, b []byte) {
		r := &tagReader{b: b}
		// The reader must either error or consume the buffer; it must never
		// loop forever or read past the end.
		for i := 0; i < len(b)+1; i++ {
			if _, err := r.next(); err != nil {
				return
			}
		}
		t.Fatalf("reader consumed more tags than bytes: %x", b)
	})
}
