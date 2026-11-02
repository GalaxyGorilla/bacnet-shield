package bacnet

import (
	"encoding/binary"
	"fmt"
)

// BACnet/IPv6 (ASHRAE 135 Annex U) uses its own link-layer type and function
// numbers. It is not BACnet/IP with a wider address: the frame carries 3-octet
// virtual addresses, and a node learns the mapping between a virtual address
// and an IPv6 address through the resolution messages below.
const (
	// BVLC6Type is the BACnet/IPv6 link-layer type octet.
	BVLC6Type byte = 0x82
)

// BVLC6Function is a BACnet/IPv6 BVLL function (Annex U, table U-1).
type BVLC6Function byte

const (
	BVLC6Result                        BVLC6Function = 0x00
	BVLC6OriginalUnicastNPDU           BVLC6Function = 0x01
	BVLC6OriginalBroadcastNPDU         BVLC6Function = 0x02
	BVLC6AddressResolution             BVLC6Function = 0x03
	BVLC6ForwardedAddressResolution    BVLC6Function = 0x04
	BVLC6AddressResolutionACK          BVLC6Function = 0x05
	BVLC6VirtualAddressResolution      BVLC6Function = 0x06
	BVLC6VirtualAddressResolutionACK   BVLC6Function = 0x07
	BVLC6ForwardedNPDU                 BVLC6Function = 0x08
	BVLC6RegisterForeignDevice         BVLC6Function = 0x09
	BVLC6DeleteForeignDeviceTableEntry BVLC6Function = 0x0A
	BVLC6DistributeBroadcastToNetwork  BVLC6Function = 0x0C
)

func (f BVLC6Function) String() string {
	switch f {
	case BVLC6Result:
		return "result"
	case BVLC6OriginalUnicastNPDU:
		return "original-unicast"
	case BVLC6OriginalBroadcastNPDU:
		return "original-broadcast"
	case BVLC6AddressResolution:
		return "address-resolution"
	case BVLC6ForwardedAddressResolution:
		return "forwarded-address-resolution"
	case BVLC6AddressResolutionACK:
		return "address-resolution-ack"
	case BVLC6VirtualAddressResolution:
		return "virtual-address-resolution"
	case BVLC6VirtualAddressResolutionACK:
		return "virtual-address-resolution-ack"
	case BVLC6ForwardedNPDU:
		return "forwarded-npdu"
	case BVLC6RegisterForeignDevice:
		return "register-foreign-device"
	case BVLC6DeleteForeignDeviceTableEntry:
		return "delete-fdt-entry"
	case BVLC6DistributeBroadcastToNetwork:
		return "distribute-broadcast"
	default:
		return fmt.Sprintf("bvlc6(0x%02x)", byte(f))
	}
}

// VMAC is a BACnet/IPv6 virtual address: three octets (Annex U, clause U.3).
// It is not the six-octet BACnet/SC virtual MAC, even though the abbreviation
// sounds similar.
type VMAC [3]byte

// String formats a virtual address as three colon-separated hex octets.
func (v VMAC) String() string { return fmt.Sprintf("%02x:%02x:%02x", v[0], v[1], v[2]) }

// IsZero reports whether the virtual address is unset.
func (v VMAC) IsZero() bool { return v == VMAC{} }

// BVLC6 is a parsed BACnet/IPv6 link-layer frame.
//
// Data is the NPDU for Original-Unicast/Original-Broadcast. For the
// resolution and foreign-device functions the proxy does not interpret the
// body, so Data holds the opaque payload; the proxy rejects every function it
// does not serve before looking at it.
type BVLC6 struct {
	Function BVLC6Function
	Src      VMAC // source virtual address, where the function carries one
	Dst      VMAC // destination/target virtual address, where it carries one
	Result   uint16
	Data     []byte
}

// ParseBVLC6 validates and decodes one BACnet/IPv6 frame. The declared length
// must match the datagram exactly, for the same reason as the IPv4 parser: a
// trailing byte would let a peer smuggle data past the policy parser.
func ParseBVLC6(dg []byte) (BVLC6, error) {
	if len(dg) < 4 {
		return BVLC6{}, fmt.Errorf("bacnet: bvlc6: %d bytes, need at least 4", len(dg))
	}
	if dg[0] != BVLC6Type {
		if dg[0] == BVLCTypeIP {
			return BVLC6{}, fmt.Errorf("bacnet: bvlc6: type 0x81 is BACnet/IPv4, not IPv6")
		}
		return BVLC6{}, fmt.Errorf("bacnet: bvlc6: type 0x%02x, want 0x82", dg[0])
	}
	n := int(binary.BigEndian.Uint16(dg[2:4]))
	if n != len(dg) {
		return BVLC6{}, fmt.Errorf("bacnet: bvlc6: declared length %d, datagram %d", n, len(dg))
	}
	fn := BVLC6Function(dg[1])
	payload := dg[4:]

	b := BVLC6{Function: fn}
	switch fn {
	case BVLC6OriginalUnicastNPDU:
		if len(payload) < 6 {
			return BVLC6{}, fmt.Errorf("bacnet: bvlc6: original-unicast without source/destination vmac")
		}
		copy(b.Src[:], payload[:3])
		copy(b.Dst[:], payload[3:6])
		b.Data = payload[6:]
	case BVLC6OriginalBroadcastNPDU:
		if len(payload) < 3 {
			return BVLC6{}, fmt.Errorf("bacnet: bvlc6: original-broadcast without source vmac")
		}
		copy(b.Src[:], payload[:3])
		b.Data = payload[3:]
	case BVLC6AddressResolution, BVLC6AddressResolutionACK, BVLC6VirtualAddressResolutionACK:
		if len(payload) < 6 {
			return BVLC6{}, fmt.Errorf("bacnet: bvlc6: %s without source/destination vmac", fn)
		}
		copy(b.Src[:], payload[:3])
		copy(b.Dst[:], payload[3:6])
		b.Data = payload[6:]
	case BVLC6VirtualAddressResolution:
		if len(payload) < 3 {
			return BVLC6{}, fmt.Errorf("bacnet: bvlc6: virtual-address-resolution without source vmac")
		}
		copy(b.Src[:], payload[:3])
		b.Data = payload[3:]
	case BVLC6Result:
		if len(payload) < 2 {
			return BVLC6{}, fmt.Errorf("bacnet: bvlc6: result without code")
		}
		b.Result = binary.BigEndian.Uint16(payload[:2])
		b.Data = payload[2:]
	default:
		// Forwarded-NPDU, the forwarded/foreign-device functions and
		// Distribute-Broadcast carry different bodies. The proxy rejects
		// them by function, so the codec only proves the frame is
		// well-framed and leaves the body opaque.
		b.Data = payload
	}
	if b.Src.IsZero() {
		switch fn {
		case BVLC6OriginalUnicastNPDU, BVLC6OriginalBroadcastNPDU,
			BVLC6AddressResolution, BVLC6AddressResolutionACK,
			BVLC6VirtualAddressResolution, BVLC6VirtualAddressResolutionACK:
			return BVLC6{}, fmt.Errorf("bacnet: bvlc6: %s with a zero source vmac", fn)
		}
	}
	return b, nil
}

// Marshal encodes the frame, recomputing the length field.
func (b BVLC6) Marshal() []byte {
	out := make([]byte, 4, 4+32+len(b.Data))
	out[0] = BVLC6Type
	out[1] = byte(b.Function)
	switch b.Function {
	case BVLC6OriginalUnicastNPDU:
		out = append(out, b.Src[:]...)
		out = append(out, b.Dst[:]...)
		out = append(out, b.Data...)
	case BVLC6OriginalBroadcastNPDU:
		out = append(out, b.Src[:]...)
		out = append(out, b.Data...)
	case BVLC6AddressResolution, BVLC6AddressResolutionACK, BVLC6VirtualAddressResolutionACK:
		out = append(out, b.Src[:]...)
		out = append(out, b.Dst[:]...)
		out = append(out, b.Data...)
	case BVLC6VirtualAddressResolution:
		out = append(out, b.Src[:]...)
		out = append(out, b.Data...)
	case BVLC6Result:
		out = binary.BigEndian.AppendUint16(out, b.Result)
		out = append(out, b.Data...)
	default:
		out = append(out, b.Data...)
	}
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	return out
}

// IsBroadcast reports whether the frame is an IPv6 original broadcast.
func (b BVLC6) IsBroadcast() bool { return b.Function == BVLC6OriginalBroadcastNPDU }
