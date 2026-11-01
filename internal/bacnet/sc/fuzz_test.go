package sc

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func seedHex(f *testing.F, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		f.Fatalf("bad seed %q: %v", s, err)
	}
	return b
}

// FuzzParse is the fuzz target for the BVLC-SC frame parser: the only code in
// this package that touches bytes from the secure network. The invariant is
// deliberately weak, exactly as in the parent package: a successful parse must
// re-encode to something the same parser accepts with the same routing fields
// and payload. A strong input==output invariant would be wrong, because the
// encoder normalizes option markers the wire lets a peer set redundantly.
func FuzzParse(f *testing.F) {
	for _, s := range []string{
		"000c12340102030405060a0b0c0d0e0f0600",
		"000c12340102030405060a0b0c0d0e0f0601000005001d626164",
		"010c00010102030405060a0b0c0d0e0f0104000501",
		"020c00020102030405060a0b0c0d0e0f",
		"030c00030102030405060a0b0c0d0e0f7773733a2f2f6875623a34373830382f78",
		"040c00040102030405060a0b0c0d0e0f010005d905a0",
		"060c00060102030405060a0b0c0d0e0f01020304050600112233445566778899aabbccddeeff05d905a0",
		"070c00070102030405060a0b0c0d0e0f0a0b0c0d0e0f00112233445566778899aabbccddeeff05d905a0",
		"09000009",
		"0a00000a",
		"0c0c000c0102030405060a0b0c0d0e0f03e707aabb",
		"010d000d0102030405060a0b0c0d0e0f410104000501",
		"010e000e0102030405060a0b0c0d0e0f7f000503e702dead0104000501",
		"0100000f0104000501",
		// Malformed shapes the parser must survive.
		"01020001",
		"010200012100ff",
		"010200013f00020300",
	} {
		f.Add(seedHex(f, s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := Parse(b)
		if err != nil {
			return
		}
		out, err := h.Marshal()
		if err != nil {
			t.Fatalf("a parsed frame failed to re-encode: %v (%x)", err, b)
		}
		back, err := Parse(out)
		if err != nil {
			t.Fatalf("marshal produced an unparseable frame: %v (%x -> %x)", err, b, out)
		}
		if back.Function != h.Function || back.MessageID != h.MessageID ||
			!bytes.Equal(back.Payload, h.Payload) ||
			!macPtrEqual(back.Orig, h.Orig) || !macPtrEqual(back.Dest, h.Dest) ||
			!sameOptions(back.DestOptions, h.DestOptions) || !sameOptions(back.DataOptions, h.DataOptions) {
			t.Fatalf("round trip changed the frame:\n in %+v\nout %+v", h, back)
		}
	})
}

// FuzzDecodeMessage drives every typed BVLL-SC body decoder. FuzzParse covers
// the generic header; the bodies are separate parser entry points that read
// bytes straight from the secure network (Result, Connect-Request/Accept,
// Advertisement, Proprietary, Address-Resolution-ACK), so each needs its own
// crash surface. The selector byte chooses the decoder so one corpus covers
// all of them; a successful decode must re-encode to bytes that decode again
// to the same value, exactly as for the parent package's parsers.
func FuzzDecodeMessage(f *testing.F) {
	add := func(sel byte, m interface{ Encode() ([]byte, error) }) {
		b, err := m.Encode()
		if err != nil {
			f.Fatalf("seed encode: %v", err)
		}
		f.Add(sel, b)
	}
	vmac := MAC{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	uuid := UUID{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF}
	add(0, Result{Function: FuncEncapsulatedNPDU, Code: ResultACK})
	add(0, Result{Function: FuncEncapsulatedNPDU, Code: ResultNAK,
		ErrorClass: 4, ErrorCode: 40, Details: "write-access-denied"})
	add(1, ConnectRequest{VMAC: vmac, UUID: uuid, MaxBVLC: 1497, MaxNPDU: 1440})
	add(2, ConnectAccept{VMAC: vmac, UUID: uuid, MaxBVLC: 1497, MaxNPDU: 1440})
	add(3, Advertisement{HubStatus: HubStatusConnectedPrimary, MaxBVLC: 1497, MaxNPDU: 1440})
	add(4, Proprietary{VendorID: 42, Function: 7, Data: []byte{0xDE, 0xAD, 0xBE, 0xEF}})
	// Malformed and boundary shapes the decoders must reject without panic.
	f.Add(byte(0), []byte{})
	f.Add(byte(0), []byte{byte(FuncEncapsulatedNPDU), ResultNAK})
	f.Add(byte(0), []byte{byte(FuncEncapsulatedNPDU), 0x09})
	f.Add(byte(1), []byte{})
	f.Add(byte(1), []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Add(byte(3), []byte{1, 0, 5, 0xDD})
	f.Add(byte(4), []byte{0, 1})
	f.Add(byte(5), []byte("wss://node.example/"))

	f.Fuzz(func(t *testing.T, sel uint8, p []byte) {
		switch sel % 6 {
		case 0:
			r, err := DecodeResult(p)
			if err != nil {
				return
			}
			out, err := r.Encode()
			if err != nil {
				t.Fatalf("a parsed Result failed to re-encode: %v (%x)", err, p)
			}
			back, err := DecodeResult(out)
			if err != nil {
				t.Fatalf("Result re-encoded to unparseable bytes: %v (%x -> %x)", err, p, out)
			}
			if back != r {
				t.Fatalf("Result round trip changed:\n in %+v\nout %+v", r, back)
			}
		case 1:
			c, err := DecodeConnectRequest(p)
			if err != nil {
				return
			}
			out, err := c.Encode()
			if err != nil {
				t.Fatalf("a parsed ConnectRequest failed to re-encode: %v (%x)", err, p)
			}
			back, err := DecodeConnectRequest(out)
			if err != nil {
				t.Fatalf("ConnectRequest re-encoded to unparseable bytes: %v", err)
			}
			if back != c {
				t.Fatalf("ConnectRequest round trip changed:\n in %+v\nout %+v", c, back)
			}
		case 2:
			c, err := DecodeConnectAccept(p)
			if err != nil {
				return
			}
			out, err := c.Encode()
			if err != nil {
				t.Fatalf("a parsed ConnectAccept failed to re-encode: %v (%x)", err, p)
			}
			back, err := DecodeConnectAccept(out)
			if err != nil {
				t.Fatalf("ConnectAccept re-encoded to unparseable bytes: %v", err)
			}
			if back != c {
				t.Fatalf("ConnectAccept round trip changed:\n in %+v\nout %+v", c, back)
			}
		case 3:
			a, err := DecodeAdvertisement(p)
			if err != nil {
				return
			}
			out, err := a.Encode()
			if err != nil {
				t.Fatalf("a parsed Advertisement failed to re-encode: %v (%x)", err, p)
			}
			back, err := DecodeAdvertisement(out)
			if err != nil {
				t.Fatalf("Advertisement re-encoded to unparseable bytes: %v", err)
			}
			if back != a {
				t.Fatalf("Advertisement round trip changed:\n in %+v\nout %+v", a, back)
			}
		case 4:
			m, err := DecodeProprietary(p)
			if err != nil {
				return
			}
			out, err := m.Encode()
			if err != nil {
				t.Fatalf("a parsed Proprietary failed to re-encode: %v (%x)", err, p)
			}
			back, err := DecodeProprietary(out)
			if err != nil {
				t.Fatalf("Proprietary re-encoded to unparseable bytes: %v", err)
			}
			if back.VendorID != m.VendorID || back.Function != m.Function || !bytes.Equal(back.Data, m.Data) {
				t.Fatalf("Proprietary round trip changed:\n in %+v\nout %+v", m, back)
			}
		case 5:
			// Address-Resolution-ACK is a raw UTF-8 URI list: the codec is the
			// identity, and the invariant is that it never reinterprets bytes.
			if s := DecodeAddressResolutionACK(p); !bytes.Equal(EncodeAddressResolutionACK(s), p) {
				t.Fatalf("address-resolution ACK did not round trip: %x", p)
			}
		}
	})
}

// sameOptions compares parsed option lists, treating a nil and an empty data
// slice as equal (the encoder drops a redundant zero-length data flag).
func sameOptions(a, b []HeaderOption) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Type != b[i].Type || a[i].MustUnderstand != b[i].MustUnderstand {
			return false
		}
		if a[i].Type == OptionProprietary &&
			(a[i].VendorID != b[i].VendorID || a[i].ProprietaryType != b[i].ProprietaryType) {
			return false
		}
		if !bytes.Equal(a[i].Data, b[i].Data) {
			return false
		}
	}
	return true
}
