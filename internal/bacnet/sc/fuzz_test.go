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
