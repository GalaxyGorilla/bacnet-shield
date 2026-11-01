// Package sc is the BACnet Secure Connect virtual link layer (BVLC-SC), the
// link layer that carries BACnet/SC frames over a WebSocket.
//
// It is deliberately separate from the plain BACnet/IP BVLC in package bacnet:
// the two share a name and a purpose, not a wire format. An SC frame is
//
//	function (1) | control flags (1) | message ID (2)
//	[originating VMAC (6)] [destination VMAC (6)]
//	[destination options] [data options]
//	payload
//
// and an SC node is addressed by a 6-octet virtual MAC (VMAC) plus a 16-octet
// device UUID, not by IP:port. This package is only the codec: it turns a
// frame into typed fields and back, with every read bounds-checked. The
// transport (TLS 1.3 + WebSocket), the connect handshake state machine and the
// address mapping live above it.
package sc

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// Function is a BVLC-SC message type (ASHRAE 135 AB.2.2).
type Function byte

const (
	FuncResult                    Function = 0x00
	FuncEncapsulatedNPDU          Function = 0x01
	FuncAddressResolution         Function = 0x02
	FuncAddressResolutionACK      Function = 0x03
	FuncAdvertisement             Function = 0x04
	FuncAdvertisementSolicitation Function = 0x05
	FuncConnectRequest            Function = 0x06
	FuncConnectAccept             Function = 0x07
	FuncDisconnectRequest         Function = 0x08
	FuncDisconnectACK             Function = 0x09
	FuncHeartbeatRequest          Function = 0x0A
	FuncHeartbeatACK              Function = 0x0B
	FuncProprietary               Function = 0x0C
)

func (f Function) String() string {
	switch f {
	case FuncResult:
		return "result"
	case FuncEncapsulatedNPDU:
		return "encapsulated-npdu"
	case FuncAddressResolution:
		return "address-resolution"
	case FuncAddressResolutionACK:
		return "address-resolution-ack"
	case FuncAdvertisement:
		return "advertisement"
	case FuncAdvertisementSolicitation:
		return "advertisement-solicitation"
	case FuncConnectRequest:
		return "connect-request"
	case FuncConnectAccept:
		return "connect-accept"
	case FuncDisconnectRequest:
		return "disconnect-request"
	case FuncDisconnectACK:
		return "disconnect-ack"
	case FuncHeartbeatRequest:
		return "heartbeat-request"
	case FuncHeartbeatACK:
		return "heartbeat-ack"
	case FuncProprietary:
		return "proprietary"
	default:
		return fmt.Sprintf("sc-function(0x%02x)", byte(f))
	}
}

// Control flags (ASHRAE 135 AB.2.2). Bits 4..7 are reserved and ignored.
const (
	ctrlDataOptions byte = 1 << 0
	ctrlDestOptions byte = 1 << 1
	ctrlDestVMAC    byte = 1 << 2
	ctrlOrigVMAC    byte = 1 << 3
)

// Header-option marker bits (ASHRAE 135 AB.2.3).
const (
	optData           byte = 1 << 5
	optMustUnderstand byte = 1 << 6
	optMore           byte = 1 << 7
	optTypeMask       byte = 0x1F
)

// Header option types.
const (
	OptionSecurePath  uint8 = 1
	OptionProprietary uint8 = 31
)

// maxOptions bounds a decoded option list. The standard does not limit the
// count; an implementation must, or a hostile frame can make the decoder spin
// through options until the frame runs out.
const maxOptions = 64

// MAC is a 6-octet BACnet/SC virtual MAC address (VMAC). The all-ones value is
// the local broadcast VMAC; the all-zero value means "unknown" and is never a
// valid node address.
type MAC [6]byte

// BroadcastMAC is the BACnet/SC local broadcast VMAC (X'FFFFFFFFFFFF').
var BroadcastMAC = MAC{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}

// IsBroadcast reports whether m is the local broadcast VMAC.
func (m MAC) IsBroadcast() bool { return m == BroadcastMAC }

// IsZero reports whether m is the uninitialized VMAC (all zero octets).
func (m MAC) IsZero() bool { return m == MAC{} }

// String renders a VMAC as lowercase colon-separated hex.
func (m MAC) String() string {
	const hex = "0123456789abcdef"
	var b [17]byte
	for i, v := range m {
		if i > 0 {
			b[i*3-1] = ':'
		}
		b[i*3] = hex[v>>4]
		b[i*3+1] = hex[v&0x0f]
	}
	return string(b[:])
}

// ParseMAC accepts "aa:bb:cc:dd:ee:ff" (colons optional) or 12 hex digits.
func ParseMAC(s string) (MAC, error) {
	var m MAC
	clean := strings.ReplaceAll(strings.TrimSpace(s), ":", "")
	if len(clean) != 12 {
		return m, fmt.Errorf("sc: mac %q: want 12 hex digits", s)
	}
	for i := 0; i < 6; i++ {
		hi, ok1 := hexVal(clean[i*2])
		lo, ok2 := hexVal(clean[i*2+1])
		if !ok1 || !ok2 {
			return m, fmt.Errorf("sc: mac %q: not hex", s)
		}
		m[i] = hi<<4 | lo
	}
	return m, nil
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// UUID is a 16-octet BACnet/SC device UUID (RFC 4122 wire form).
type UUID [16]byte

// String renders the UUID in the canonical 8-4-4-4-12 form.
func (u UUID) String() string {
	const hex = "0123456789abcdef"
	var b [36]byte
	j := 0
	for i, v := range u {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			b[j] = '-'
			j++
		}
		b[j] = hex[v>>4]
		b[j+1] = hex[v&0x0f]
		j += 2
	}
	return string(b[:])
}

// ParseUUID accepts the canonical 8-4-4-4-12 form (dashes optional).
func ParseUUID(s string) (UUID, error) {
	var u UUID
	clean := strings.ReplaceAll(strings.TrimSpace(s), "-", "")
	if len(clean) != 32 {
		return u, fmt.Errorf("sc: uuid %q: want 32 hex digits", s)
	}
	for i := 0; i < 16; i++ {
		hi, ok1 := hexVal(clean[i*2])
		lo, ok2 := hexVal(clean[i*2+1])
		if !ok1 || !ok2 {
			return u, fmt.Errorf("sc: uuid %q: not hex", s)
		}
		u[i] = hi<<4 | lo
	}
	return u, nil
}

// HeaderOption is one BVLC-SC header option.
type HeaderOption struct {
	Type           uint8
	MustUnderstand bool
	// VendorID and ProprietaryType are only meaningful for OptionProprietary.
	VendorID        uint16
	ProprietaryType uint8
	// Data is the option payload: for OptionProprietary it excludes the
	// vendor id and proprietary option type; for any other type it is the
	// raw option data.
	Data []byte
}

// Header is a decoded BVLC-SC frame. Orig and Dest are nil when the address is
// absent (the "connection peer" shorthand); that distinction is preserved
// because the wire encoding differs.
type Header struct {
	Function    Function
	MessageID   uint16
	Orig        *MAC
	Dest        *MAC
	DestOptions []HeaderOption
	DataOptions []HeaderOption
	Payload     []byte
}

// Marshal encodes the header and the payload. It is strict about what the
// standard allows: an unknown function or an empty option is refused rather
// than written as a frame a peer would reject.
func (h Header) Marshal() ([]byte, error) {
	if h.Function > FuncProprietary {
		return nil, fmt.Errorf("sc: cannot encode unknown function 0x%02x", byte(h.Function))
	}
	var flags byte
	if h.Orig != nil {
		flags |= ctrlOrigVMAC
	}
	if h.Dest != nil {
		flags |= ctrlDestVMAC
	}
	if len(h.DestOptions) > 0 {
		flags |= ctrlDestOptions
	}
	if len(h.DataOptions) > 0 {
		flags |= ctrlDataOptions
	}
	out := make([]byte, 0, 16+len(h.Payload))
	out = append(out, byte(h.Function), flags)
	out = binary.BigEndian.AppendUint16(out, h.MessageID)
	if h.Orig != nil {
		out = append(out, h.Orig[:]...)
	}
	if h.Dest != nil {
		out = append(out, h.Dest[:]...)
	}
	var err error
	if flags&ctrlDestOptions != 0 {
		if out, err = appendOptions(out, h.DestOptions); err != nil {
			return nil, err
		}
	}
	if flags&ctrlDataOptions != 0 {
		if out, err = appendOptions(out, h.DataOptions); err != nil {
			return nil, err
		}
	}
	return append(out, h.Payload...), nil
}

func appendOptions(out []byte, opts []HeaderOption) ([]byte, error) {
	if len(opts) > maxOptions {
		return nil, fmt.Errorf("sc: %d options exceeds max %d", len(opts), maxOptions)
	}
	for i, o := range opts {
		if o.Type > optTypeMask {
			return nil, fmt.Errorf("sc: option type %d out of range", o.Type)
		}
		data := o.optionData()
		marker := o.Type & optTypeMask
		if o.MustUnderstand {
			marker |= optMustUnderstand
		}
		if i < len(opts)-1 {
			marker |= optMore
		}
		if len(data) > 0 {
			marker |= optData
		}
		out = append(out, marker)
		if len(data) > 0 {
			if len(data) > 0xFFFF {
				return nil, fmt.Errorf("sc: option data %d bytes too long", len(data))
			}
			out = binary.BigEndian.AppendUint16(out, uint16(len(data)))
			out = append(out, data...)
		}
	}
	return out, nil
}

func (o HeaderOption) optionData() []byte {
	switch o.Type {
	case OptionSecurePath:
		// The Secure Path option carries no data; the marker alone is the
		// signal.
		return nil
	case OptionProprietary:
		out := make([]byte, 0, 3+len(o.Data))
		out = binary.BigEndian.AppendUint16(out, o.VendorID)
		out = append(out, o.ProprietaryType)
		return append(out, o.Data...)
	default:
		return o.Data
	}
}

// Parse decodes one BVLC-SC frame. Every field is bounds-checked; a truncated
// frame is an error, never a panic. Payload is a sub-slice of b.
func Parse(b []byte) (Header, error) {
	var h Header
	if len(b) < 4 {
		return h, fmt.Errorf("sc: frame %d bytes, need at least 4", len(b))
	}
	h.Function = Function(b[0])
	if h.Function > FuncProprietary {
		return h, fmt.Errorf("sc: unknown function 0x%02x", b[0])
	}
	flags := b[1]
	h.MessageID = binary.BigEndian.Uint16(b[2:4])
	off := 4

	readMAC := func() (*MAC, error) {
		if off+6 > len(b) {
			return nil, fmt.Errorf("sc: frame %d bytes, vmac past end", len(b))
		}
		var m MAC
		copy(m[:], b[off:off+6])
		off += 6
		return &m, nil
	}
	var err error
	if flags&ctrlOrigVMAC != 0 {
		if h.Orig, err = readMAC(); err != nil {
			return Header{}, err
		}
	}
	if flags&ctrlDestVMAC != 0 {
		if h.Dest, err = readMAC(); err != nil {
			return Header{}, err
		}
	}
	if flags&ctrlDestOptions != 0 {
		if h.DestOptions, off, err = parseOptions(b, off); err != nil {
			return Header{}, err
		}
	}
	if flags&ctrlDataOptions != 0 {
		if h.DataOptions, off, err = parseOptions(b, off); err != nil {
			return Header{}, err
		}
	}
	h.Payload = b[off:]
	return h, nil
}

func parseOptions(b []byte, off int) ([]HeaderOption, int, error) {
	var opts []HeaderOption
	for {
		if off >= len(b) {
			return nil, 0, fmt.Errorf("sc: options past end")
		}
		if len(opts) >= maxOptions {
			return nil, 0, fmt.Errorf("sc: more than %d options", maxOptions)
		}
		marker := b[off]
		off++
		o := HeaderOption{
			Type:           marker & optTypeMask,
			MustUnderstand: marker&optMustUnderstand != 0,
		}
		if marker&optData != 0 {
			if off+2 > len(b) {
				return nil, 0, fmt.Errorf("sc: option length past end")
			}
			n := int(binary.BigEndian.Uint16(b[off : off+2]))
			off += 2
			if off+n > len(b) {
				return nil, 0, fmt.Errorf("sc: option data %d bytes past end", n)
			}
			data := b[off : off+n]
			off += n
			switch o.Type {
			case OptionProprietary:
				if n < 3 {
					return nil, 0, fmt.Errorf("sc: proprietary option %d bytes, need 3", n)
				}
				o.VendorID = binary.BigEndian.Uint16(data[0:2])
				o.ProprietaryType = data[2]
				o.Data = data[3:]
			case OptionSecurePath:
				// The Secure Path option is defined to carry no data. If a
				// peer set the data flag anyway, the bytes are consumed (so
				// nothing downstream shifts) but not retained; Marshal never
				// emits them, so the decode is stable.
			default:
				o.Data = data
			}
		}
		opts = append(opts, o)
		if marker&optMore == 0 {
			return opts, off, nil
		}
	}
}
