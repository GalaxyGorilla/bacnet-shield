package sc

import (
	"bytes"
	"encoding/hex"
	"reflect"
	"strings"
	"testing"
)

// mustHex decodes a hex fixture or fails the test.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

// The fixtures in this file are golden bytes emitted by bacpypes3 0.0.110
// (the independent oracle), then cross-checked against bacnet-stack's
// bvlc-sc.c field-by-field layout. They pin the exact wire shape of BVLC-SC,
// which does not share anything with the plain BACnet/IP BVLC in the parent
// package. Regenerate with:
//
//	.venv/bin/python scripts/sc-golden.py
var (
	testOrig = MAC{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	testDest = MAC{0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
	testUUID = UUID{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}
	testNPDU = []byte{0x01, 0x04, 0x00, 0x05, 0x01}
)

// headerEqual compares two decoded headers, treating a nil and an empty byte
// slice as equal (a parsed empty payload is a zero-length sub-slice, not nil).
func headerEqual(a, b Header) bool {
	if a.Function != b.Function || a.MessageID != b.MessageID {
		return false
	}
	if !macPtrEqual(a.Orig, b.Orig) || !macPtrEqual(a.Dest, b.Dest) {
		return false
	}
	if !reflect.DeepEqual(a.DestOptions, b.DestOptions) || !reflect.DeepEqual(a.DataOptions, b.DataOptions) {
		return false
	}
	return bytes.Equal(a.Payload, b.Payload)
}

func macPtrEqual(a, b *MAC) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

// TestHeaderGolden is the oracle cross-check: every BVLC-SC message a node and
// a hub exchange is built in Go, encoded, and compared to the exact bytes
// bacpypes3 produced. It then decodes the oracle bytes back and compares the
// fields, so both directions are pinned.
func TestHeaderGolden(t *testing.T) {
	orig, dest := testOrig, testDest
	vectors := []struct {
		name string
		hex  string
		hdr  Header
	}{
		{
			name: "result-ack",
			hex:  "000c12340102030405060a0b0c0d0e0f0600",
			hdr: Header{
				Function: FuncResult, MessageID: 0x1234, Orig: &orig, Dest: &dest,
				Payload: mustHex(t, "0600"),
			},
		},
		{
			name: "result-nak",
			hex:  "000c12340102030405060a0b0c0d0e0f0601000005001d626164",
			hdr: Header{
				Function: FuncResult, MessageID: 0x1234, Orig: &orig, Dest: &dest,
				Payload: mustHex(t, "0601000005001d626164"),
			},
		},
		{
			name: "encapsulated-npdu",
			hex:  "010c00010102030405060a0b0c0d0e0f0104000501",
			hdr: Header{
				Function: FuncEncapsulatedNPDU, MessageID: 1, Orig: &orig, Dest: &dest,
				Payload: testNPDU,
			},
		},
		{
			name: "address-resolution",
			hex:  "020c00020102030405060a0b0c0d0e0f",
			hdr: Header{
				Function: FuncAddressResolution, MessageID: 2, Orig: &orig, Dest: &dest,
			},
		},
		{
			name: "address-resolution-ack",
			hex:  "030c00030102030405060a0b0c0d0e0f7773733a2f2f6875623a34373830382f78",
			hdr: Header{
				Function: FuncAddressResolutionACK, MessageID: 3, Orig: &orig, Dest: &dest,
				Payload: []byte("wss://hub:47808/x"),
			},
		},
		{
			name: "advertisement",
			hex:  "040c00040102030405060a0b0c0d0e0f010005d905a0",
			hdr: Header{
				Function: FuncAdvertisement, MessageID: 4, Orig: &orig, Dest: &dest,
				Payload: mustHex(t, "010005d905a0"),
			},
		},
		{
			name: "advertisement-solicitation",
			hex:  "050c00050102030405060a0b0c0d0e0f",
			hdr: Header{
				Function: FuncAdvertisementSolicitation, MessageID: 5, Orig: &orig, Dest: &dest,
			},
		},
		{
			name: "connect-request",
			hex:  "060c00060102030405060a0b0c0d0e0f01020304050600112233445566778899aabbccddeeff05d905a0",
			hdr: Header{
				Function: FuncConnectRequest, MessageID: 6, Orig: &orig, Dest: &dest,
				Payload: mustHex(t, "01020304050600112233445566778899aabbccddeeff05d905a0"),
			},
		},
		{
			name: "connect-accept",
			hex:  "070c00070102030405060a0b0c0d0e0f0a0b0c0d0e0f00112233445566778899aabbccddeeff05d905a0",
			hdr: Header{
				Function: FuncConnectAccept, MessageID: 7, Orig: &orig, Dest: &dest,
				Payload: mustHex(t, "0a0b0c0d0e0f00112233445566778899aabbccddeeff05d905a0"),
			},
		},
		{
			name: "disconnect-request",
			hex:  "080c00080102030405060a0b0c0d0e0f",
			hdr: Header{
				Function: FuncDisconnectRequest, MessageID: 8, Orig: &orig, Dest: &dest,
			},
		},
		{
			name: "disconnect-ack",
			hex:  "09000009",
			hdr:  Header{Function: FuncDisconnectACK, MessageID: 9},
		},
		{
			name: "heartbeat-request",
			hex:  "0a00000a",
			hdr:  Header{Function: FuncHeartbeatRequest, MessageID: 10},
		},
		{
			name: "heartbeat-ack",
			hex:  "0b00000b",
			hdr:  Header{Function: FuncHeartbeatACK, MessageID: 11},
		},
		{
			name: "proprietary",
			hex:  "0c0c000c0102030405060a0b0c0d0e0f03e707aabb",
			hdr: Header{
				Function: FuncProprietary, MessageID: 12, Orig: &orig, Dest: &dest,
				Payload: mustHex(t, "03e707aabb"),
			},
		},
		{
			name: "encapsulated-secure-path",
			hex:  "010d000d0102030405060a0b0c0d0e0f410104000501",
			hdr: Header{
				Function: FuncEncapsulatedNPDU, MessageID: 13, Orig: &orig, Dest: &dest,
				DataOptions: []HeaderOption{{Type: OptionSecurePath, MustUnderstand: true}},
				Payload:     testNPDU,
			},
		},
		{
			name: "encapsulated-proprietary-option",
			hex:  "010e000e0102030405060a0b0c0d0e0f7f000503e702dead0104000501",
			hdr: Header{
				Function: FuncEncapsulatedNPDU, MessageID: 14, Orig: &orig, Dest: &dest,
				DestOptions: []HeaderOption{{
					Type: OptionProprietary, MustUnderstand: true,
					VendorID: 999, ProprietaryType: 2, Data: []byte{0xde, 0xad},
				}},
				Payload: testNPDU,
			},
		},
		{
			name: "encapsulated-no-addresses",
			hex:  "0100000f0104000501",
			hdr: Header{
				Function: FuncEncapsulatedNPDU, MessageID: 15,
				Payload: testNPDU,
			},
		},
	}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			got, err := v.hdr.Marshal()
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			if !bytes.Equal(got, mustHex(t, v.hex)) {
				t.Fatalf("marshal mismatch\n got %x\nwant %s", got, v.hex)
			}
			back, err := Parse(mustHex(t, v.hex))
			if err != nil {
				t.Fatalf("parse: %v", err)
			}
			if !headerEqual(back, v.hdr) {
				t.Fatalf("parse mismatch\n got %+v\nwant %+v", back, v.hdr)
			}
		})
	}
}

// TestMessageGolden pins the typed payload encoders on their own, so a bug in
// a body codec is reported as a body bug rather than a header mismatch.
func TestMessageGolden(t *testing.T) {
	t.Run("result-ack", func(t *testing.T) {
		r := Result{Function: FuncConnectRequest, Code: ResultACK}
		got, err := r.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if want := mustHex(t, "0600"); !bytes.Equal(got, want) {
			t.Fatalf("got %x want %x", got, want)
		}
		back, err := DecodeResult(got)
		if err != nil || back != r {
			t.Fatalf("decode = %+v, %v", back, err)
		}
	})
	t.Run("result-nak", func(t *testing.T) {
		r := Result{
			Function: FuncConnectRequest, Code: ResultNAK,
			ErrorClass: 5, ErrorCode: 29, Details: "bad",
		}
		got, err := r.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if want := mustHex(t, "0601000005001d626164"); !bytes.Equal(got, want) {
			t.Fatalf("got %x want %x", got, want)
		}
		back, err := DecodeResult(got)
		if err != nil || back != r {
			t.Fatalf("decode = %+v, %v", back, err)
		}
	})
	t.Run("connect-request", func(t *testing.T) {
		c := ConnectRequest{VMAC: testOrig, UUID: testUUID, MaxBVLC: 1497, MaxNPDU: 1440}
		got, err := c.Encode()
		if err != nil {
			t.Fatal(err)
		}
		want := mustHex(t, "01020304050600112233445566778899aabbccddeeff05d905a0")
		if !bytes.Equal(got, want) {
			t.Fatalf("got %x want %x", got, want)
		}
		back, err := DecodeConnectRequest(got)
		if err != nil || back != c {
			t.Fatalf("decode = %+v, %v", back, err)
		}
	})
	t.Run("connect-accept", func(t *testing.T) {
		c := ConnectAccept{VMAC: testDest, UUID: testUUID, MaxBVLC: 1497, MaxNPDU: 1440}
		got, err := c.Encode()
		if err != nil {
			t.Fatal(err)
		}
		want := mustHex(t, "0a0b0c0d0e0f00112233445566778899aabbccddeeff05d905a0")
		if !bytes.Equal(got, want) {
			t.Fatalf("got %x want %x", got, want)
		}
		back, err := DecodeConnectAccept(got)
		if err != nil || back != c {
			t.Fatalf("decode = %+v, %v", back, err)
		}
	})
	t.Run("advertisement", func(t *testing.T) {
		a := Advertisement{HubStatus: HubStatusConnectedPrimary, MaxBVLC: 1497, MaxNPDU: 1440}
		got, err := a.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if want := mustHex(t, "010005d905a0"); !bytes.Equal(got, want) {
			t.Fatalf("got %x want %x", got, want)
		}
		back, err := DecodeAdvertisement(got)
		if err != nil || back != a {
			t.Fatalf("decode = %+v, %v", back, err)
		}
	})
	t.Run("address-resolution-ack", func(t *testing.T) {
		got := EncodeAddressResolutionACK("wss://hub:47808/x")
		want := mustHex(t, "7773733a2f2f6875623a34373830382f78")
		if !bytes.Equal(got, want) {
			t.Fatalf("got %x want %x", got, want)
		}
		if s := DecodeAddressResolutionACK(got); s != "wss://hub:47808/x" {
			t.Fatalf("decode = %q", s)
		}
	})
	t.Run("proprietary", func(t *testing.T) {
		m := Proprietary{VendorID: 999, Function: 7, Data: []byte{0xaa, 0xbb}}
		got, err := m.Encode()
		if err != nil {
			t.Fatal(err)
		}
		if want := mustHex(t, "03e707aabb"); !bytes.Equal(got, want) {
			t.Fatalf("got %x want %x", got, want)
		}
		back, err := DecodeProprietary(got)
		if err != nil || !reflect.DeepEqual(back, m) {
			t.Fatalf("decode = %+v, %v", back, err)
		}
	})
}

func TestMACAndUUID(t *testing.T) {
	if got := testOrig.String(); got != "01:02:03:04:05:06" {
		t.Fatalf("mac string = %q", got)
	}
	if got := BroadcastMAC.String(); got != "ff:ff:ff:ff:ff:ff" {
		t.Fatalf("broadcast string = %q", got)
	}
	for _, s := range []string{"01:02:03:04:05:06", "010203040506"} {
		m, err := ParseMAC(s)
		if err != nil {
			t.Fatalf("ParseMAC(%q): %v", s, err)
		}
		if m != testOrig {
			t.Fatalf("ParseMAC(%q) = %v", s, m)
		}
	}
	for _, s := range []string{"", "01:02:03:04:05", "01020304050607", "gg0203040506", "01:02:03:04:05:0z"} {
		if _, err := ParseMAC(s); err == nil {
			t.Fatalf("ParseMAC(%q) accepted a bad MAC", s)
		}
	}

	want := "00112233-4455-6677-8899-aabbccddeeff"
	if got := testUUID.String(); got != want {
		t.Fatalf("uuid string = %q want %q", got, want)
	}
	for _, s := range []string{want, "00112233445566778899aabbccddeeff"} {
		u, err := ParseUUID(s)
		if err != nil {
			t.Fatalf("ParseUUID(%q): %v", s, err)
		}
		if u != testUUID {
			t.Fatalf("ParseUUID(%q) = %v", s, u)
		}
	}
	for _, s := range []string{"", "00112233445566778899aabbccddee", "00112233445566778899aabbccddeeff00", "zz112233445566778899aabbccddeeff"} {
		if _, err := ParseUUID(s); err == nil {
			t.Fatalf("ParseUUID(%q) accepted a bad UUID", s)
		}
	}
	if testOrig.IsZero() || !(MAC{}).IsZero() {
		t.Fatal("IsZero is wrong")
	}
	if !BroadcastMAC.IsBroadcast() || testOrig.IsBroadcast() {
		t.Fatal("IsBroadcast is wrong")
	}
}

func TestFunctionString(t *testing.T) {
	names := map[Function]string{
		FuncResult:                    "result",
		FuncEncapsulatedNPDU:          "encapsulated-npdu",
		FuncAddressResolution:         "address-resolution",
		FuncAddressResolutionACK:      "address-resolution-ack",
		FuncAdvertisement:             "advertisement",
		FuncAdvertisementSolicitation: "advertisement-solicitation",
		FuncConnectRequest:            "connect-request",
		FuncConnectAccept:             "connect-accept",
		FuncDisconnectRequest:         "disconnect-request",
		FuncDisconnectACK:             "disconnect-ack",
		FuncHeartbeatRequest:          "heartbeat-request",
		FuncHeartbeatACK:              "heartbeat-ack",
		FuncProprietary:               "proprietary",
	}
	for f, want := range names {
		if got := f.String(); got != want {
			t.Errorf("Function(0x%02x).String() = %q want %q", byte(f), got, want)
		}
	}
	if got := Function(0x7f).String(); !strings.HasPrefix(got, "sc-function(") {
		t.Errorf("unknown function string = %q", got)
	}
}

func TestParseErrors(t *testing.T) {
	long := make([]byte, 0, 4+maxOptions+1)
	long = append(long, 0x01, 0x02, 0x00, 0x01) // EncapsulatedNPDU, dest options
	long = append(long, bytes.Repeat([]byte{0x81}, maxOptions)...)
	long = append(long, 0x01) // one option too many

	exactly := make([]byte, 0, 4+maxOptions)
	exactly = append(exactly, 0x01, 0x02, 0x00, 0x01)
	exactly = append(exactly, bytes.Repeat([]byte{0x81}, maxOptions-1)...)
	exactly = append(exactly, 0x01)

	cases := []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"too-short", mustHex(t, "000c")},
		{"unknown-function", mustHex(t, "0d000000")},
		{"orig-vmac-past-end", mustHex(t, "000c12340102")},
		{"dest-vmac-past-end", mustHex(t, "000c1234010203040506")},
		{"options-past-end", mustHex(t, "01020001")},
		{"option-length-past-end", mustHex(t, "010200012100ff")},
		{"option-length-truncated", mustHex(t, "010200012100")},
		{"option-data-past-end", mustHex(t, "0102000121ffff")},
		{"proprietary-option-too-short", mustHex(t, "010200013f00020300")},
		{"more-options-with-nothing-after", mustHex(t, "01020001a10000")},
		{"too-many-options", long},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := Parse(c.in); err == nil {
				t.Fatalf("Parse(%x) accepted a malformed frame", c.in)
			}
		})
	}

	// The bound must be exact: maxOptions options parse, one more does not.
	if _, err := Parse(exactly); err != nil {
		t.Fatalf("Parse with exactly %d options: %v", maxOptions, err)
	}
}

func TestResultErrors(t *testing.T) {
	if _, err := (Result{Function: FuncConnectRequest, Code: ResultACK, ErrorCode: 1}).Encode(); err == nil {
		t.Fatal("ACK with error fields encoded")
	}
	if _, err := (Result{Function: FuncConnectRequest, Code: 0x02}).Encode(); err == nil {
		t.Fatal("bad result code encoded")
	}
	if _, err := (Result{Function: 0x7f, Code: ResultACK}).Encode(); err == nil {
		t.Fatal("result for unknown function encoded")
	}
	for _, in := range [][]byte{{}, {0x06}, {0x06, 0x01}, {0x06, 0x01, 0, 0, 5}, {0x06, 0x02, 0, 0, 5, 0, 1}, {0x7f, 0x00}} {
		if _, err := DecodeResult(in); err == nil {
			t.Fatalf("DecodeResult(%x) accepted a bad result", in)
		}
	}
}

func TestConnectAndBodyErrors(t *testing.T) {
	if _, err := (ConnectRequest{VMAC: MAC{}, UUID: testUUID, MaxBVLC: 1, MaxNPDU: 1}).Encode(); err == nil {
		t.Fatal("connect with zero vmac encoded")
	}
	for _, in := range [][]byte{{}, make([]byte, 25), make([]byte, 26), make([]byte, 27)} {
		if _, err := DecodeConnectRequest(in); err == nil {
			t.Fatalf("DecodeConnectRequest(%d bytes) accepted a bad payload", len(in))
		}
	}
	if _, err := DecodeAdvertisement(make([]byte, 5)); err == nil {
		t.Fatal("short advertisement decoded")
	}
	if _, err := DecodeAdvertisement(make([]byte, 7)); err == nil {
		t.Fatal("long advertisement decoded")
	}
	if _, err := DecodeProprietary([]byte{0x03, 0xe7}); err == nil {
		t.Fatal("short proprietary decoded")
	}
}

// TestSecurePathOptionNormalizesData pins the one normalization the encoder is
// allowed to do: the Secure Path option is defined to carry no data, so a
// peer's stray data bytes are consumed on decode and never re-emitted. Without
// this, a decode/encode round trip would not be stable, which is exactly what
// FuzzParse caught.
func TestSecurePathOptionNormalizesData(t *testing.T) {
	in := mustHex(t, "01020001210002aabbff") // EncapsulatedNPDU, dest option SecurePath(1) + 2 data bytes
	h, err := Parse(in)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := HeaderOption{Type: OptionSecurePath}
	if len(h.DestOptions) != 1 || !reflect.DeepEqual(h.DestOptions[0], want) {
		t.Fatalf("secure path option = %+v want %+v", h.DestOptions, want)
	}
	if !bytes.Equal(h.Payload, []byte{0xff}) {
		t.Fatalf("payload = %x", h.Payload)
	}
	out, err := h.Marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if want := mustHex(t, "0102000101ff"); !bytes.Equal(out, want) {
		t.Fatalf("re-encoded %x want %x", out, want)
	}
}

func TestMarshalRejectsUnknownFunction(t *testing.T) {
	if _, err := (Header{Function: 0x7f}).Marshal(); err == nil {
		t.Fatal("unknown function marshaled")
	}
	if _, err := (Header{DataOptions: []HeaderOption{{Type: 0x20}}}).Marshal(); err == nil {
		t.Fatal("option type out of range marshaled")
	}
}

// TestParseTruncationNoPanic walks every prefix of every golden frame. A
// truncated frame must be an error or a shorter valid frame, never a panic;
// the deterministic counterpart to FuzzParse.
func TestParseTruncationNoPanic(t *testing.T) {
	frames := []string{
		"000c12340102030405060a0b0c0d0e0f0601000005001d626164",
		"010c00010102030405060a0b0c0d0e0f0104000501",
		"060c00060102030405060a0b0c0d0e0f01020304050600112233445566778899aabbccddeeff05d905a0",
		"010e000e0102030405060a0b0c0d0e0f7f000503e702dead0104000501",
		"010d000d0102030405060a0b0c0d0e0f410104000501",
	}
	for _, fh := range frames {
		full := mustHex(t, fh)
		if _, err := Parse(full); err != nil {
			t.Fatalf("full frame %s: %v", fh, err)
		}
		for i := 0; i < len(full); i++ {
			//nolint:errcheck // a panic is the failure; the error is expected.
			Parse(full[:i])
		}
	}
}
