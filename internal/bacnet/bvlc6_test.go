package bacnet

import (
	"bytes"
	"testing"
)

func TestVMACString(t *testing.T) {
	if got := (VMAC{0x02, 0x00, 0x0a}).String(); got != "02:00:0a" {
		t.Fatalf("VMAC.String = %q", got)
	}
	if (VMAC{}).IsZero() != true || (VMAC{0, 0, 1}).IsZero() != false {
		t.Fatal("VMAC.IsZero is wrong")
	}
}

func TestBVLC6RoundTrip(t *testing.T) {
	src := VMAC{0x02, 0x00, 0x0a}
	dst := VMAC{0x02, 0x00, 0xff}
	npdu := NPDU{APDU: []byte{0x10, 0x08}}.Marshal()

	cases := []struct {
		name string
		b    BVLC6
	}{
		{"original-unicast", BVLC6{Function: BVLC6OriginalUnicastNPDU, Src: src, Dst: dst, Data: npdu}},
		{"original-broadcast", BVLC6{Function: BVLC6OriginalBroadcastNPDU, Src: src, Data: npdu}},
		{"address-resolution", BVLC6{Function: BVLC6AddressResolution, Src: src, Dst: dst}},
		{"address-resolution-ack", BVLC6{Function: BVLC6AddressResolutionACK, Src: src, Dst: dst}},
		{"virtual-address-resolution", BVLC6{Function: BVLC6VirtualAddressResolution, Src: src}},
		{"virtual-address-resolution-ack", BVLC6{Function: BVLC6VirtualAddressResolutionACK, Src: src, Dst: dst}},
		{"result", BVLC6{Function: BVLC6Result, Src: src, Dst: dst, Result: 0x0090}},
	}
	for _, tc := range cases {
		dg := tc.b.Marshal()
		if dg[0] != BVLC6Type {
			t.Fatalf("%s: type = 0x%02x", tc.name, dg[0])
		}
		got, err := ParseBVLC6(dg)
		if err != nil {
			t.Fatalf("%s: parse: %v (%x)", tc.name, err, dg)
		}
		if got.Function != tc.b.Function {
			t.Fatalf("%s: function = %s", tc.name, got.Function)
		}
		if got.Function == BVLC6Result {
			if got.Result != tc.b.Result {
				t.Fatalf("%s: result = 0x%04x", tc.name, got.Result)
			}
			continue
		}
		if got.Src != tc.b.Src {
			t.Fatalf("%s: src = %s, want %s", tc.name, got.Src, tc.b.Src)
		}
		if tc.b.Function == BVLC6VirtualAddressResolution {
			continue
		}
		if got.Dst != tc.b.Dst {
			t.Fatalf("%s: dst = %s, want %s", tc.name, got.Dst, tc.b.Dst)
		}
		if !bytes.Equal(got.Data, tc.b.Data) {
			t.Fatalf("%s: data = %x, want %x", tc.name, got.Data, tc.b.Data)
		}
	}
}

func TestBVLC6Rejections(t *testing.T) {
	src := VMAC{0x02, 0x00, 0x0a}
	unicast := BVLC6{Function: BVLC6OriginalUnicastNPDU, Src: src, Dst: VMAC{0, 0, 1}, Data: []byte{1, 2}}.Marshal()

	cases := []struct {
		name string
		dg   []byte
	}{
		{"empty", nil},
		{"short header", []byte{0x82, 0x01, 0x00}},
		{"ipv4 type", append([]byte{0x81}, unicast[1:]...)},
		{"wrong type", append([]byte{0x83}, unicast[1:]...)},
		{"length short", unicast[:len(unicast)-1]},
		{"length long", append(append([]byte(nil), unicast...), 0x00)},
		{"unicast without vmacs", []byte{0x82, 0x01, 0x00, 0x07, 1, 2, 3}},
		{"broadcast without vmac", []byte{0x82, 0x02, 0x00, 0x04}},
		{"resolution without target", []byte{0x82, 0x03, 0x00, 0x07, 1, 2, 3}},
		{"var without source", []byte{0x82, 0x06, 0x00, 0x04}},
		{"zero source", []byte{0x82, 0x01, 0x00, 0x0b, 0, 0, 0, 1, 2, 3, 9}},
	}
	for _, tc := range cases {
		if _, err := ParseBVLC6(tc.dg); err == nil {
			t.Errorf("%s: accepted %x", tc.name, tc.dg)
		}
	}
}

// A function the proxy does not serve must still be well-framed enough to
// reject by function; the codec leaves its body opaque but validates the
// declared length so a malformed frame is counted as a parse error instead.
func TestBVLC6UnsupportedFunctions(t *testing.T) {
	for _, fn := range []BVLC6Function{
		BVLC6ForwardedNPDU, BVLC6ForwardedAddressResolution,
		BVLC6RegisterForeignDevice, BVLC6DeleteForeignDeviceTableEntry,
		BVLC6DistributeBroadcastToNetwork,
	} {
		dg := BVLC6{Function: fn, Src: VMAC{1, 2, 3}, Data: []byte{0xaa, 0xbb}}.Marshal()
		got, err := ParseBVLC6(dg)
		if err != nil {
			t.Fatalf("%s: parse: %v", fn, err)
		}
		if got.Function != fn {
			t.Fatalf("%s: function = %s", fn, got.Function)
		}
	}
}

func TestBVLC6IsBroadcast(t *testing.T) {
	bc := BVLC6{Function: BVLC6OriginalBroadcastNPDU, Src: VMAC{1, 2, 3}, Data: []byte{1}}
	if !bc.IsBroadcast() {
		t.Fatal("original broadcast is not reported as broadcast")
	}
	uc := BVLC6{Function: BVLC6OriginalUnicastNPDU, Src: VMAC{1, 2, 3}, Dst: VMAC{4, 5, 6}}
	if uc.IsBroadcast() {
		t.Fatal("unicast is reported as broadcast")
	}
}

// The body of a Forwarded-NPDU is not interpreted by the proxy, but the codec
// must not let the length field disagree with the datagram.
func TestBVLC6LengthIsExact(t *testing.T) {
	dg := BVLC6{Function: BVLC6ForwardedNPDU, Src: VMAC{1, 2, 3}, Data: bytes.Repeat([]byte{0}, 30)}.Marshal()
	if _, err := ParseBVLC6(dg); err != nil {
		t.Fatalf("valid forwarded frame: %v", err)
	}
	if _, err := ParseBVLC6(append(dg, 0x00)); err == nil {
		t.Fatal("accepted a frame with a trailing byte")
	}
}
