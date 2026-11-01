package bacnet

import (
	"encoding/binary"
	"fmt"
)

// BVLCTypeIP is the BACnet/IP link-layer type octet. BACnet/SC uses 0x82 and
// is not a BVLC at all (it rides TLS + WebSocket); ParseBVLC rejects it with
// a message that says so rather than misreading it as a malformed IP frame.
const BVLCTypeIP byte = 0x81

// BVLCFunction is the BACnet Virtual Link Control function.
type BVLCFunction byte

const (
	BVLCResult                          BVLCFunction = 0x00
	BVLCWriteBroadcastDistributionTable BVLCFunction = 0x01
	BVLCReadBroadcastDistributionTable  BVLCFunction = 0x02
	BVLCReadBroadcastDistributionAck    BVLCFunction = 0x03
	BVLCForwardedNPDU                   BVLCFunction = 0x04
	BVLCRegisterForeignDevice           BVLCFunction = 0x05
	BVLCReadForeignDeviceTable          BVLCFunction = 0x06
	BVLCReadForeignDeviceTableAck       BVLCFunction = 0x07
	BVLCDeleteForeignDeviceTableEntry   BVLCFunction = 0x08
	BVLCDistributeBroadcastToNetwork    BVLCFunction = 0x09
	BVLCOriginalUnicastNPDU             BVLCFunction = 0x0A
	BVLCOriginalBroadcastNPDU           BVLCFunction = 0x0B
)

func (f BVLCFunction) String() string {
	switch f {
	case BVLCResult:
		return "result"
	case BVLCWriteBroadcastDistributionTable:
		return "write-bdt"
	case BVLCReadBroadcastDistributionTable:
		return "read-bdt"
	case BVLCReadBroadcastDistributionAck:
		return "read-bdt-ack"
	case BVLCForwardedNPDU:
		return "forwarded-npdu"
	case BVLCRegisterForeignDevice:
		return "register-foreign-device"
	case BVLCReadForeignDeviceTable:
		return "read-fdt"
	case BVLCReadForeignDeviceTableAck:
		return "read-fdt-ack"
	case BVLCDeleteForeignDeviceTableEntry:
		return "delete-fdt-entry"
	case BVLCDistributeBroadcastToNetwork:
		return "distribute-broadcast"
	case BVLCOriginalUnicastNPDU:
		return "original-unicast"
	case BVLCOriginalBroadcastNPDU:
		return "original-broadcast"
	default:
		return fmt.Sprintf("bvlc(0x%02x)", byte(f))
	}
}

// BVLC is a parsed BACnet/IP link-layer frame.
//
// Data is the function's payload with the fixed fields removed: for
// Original-Unicast/Original-Broadcast it is the NPDU, for Forwarded-NPDU it
// is the NPDU after the 6-byte originating station address, and for
// Distribute-Broadcast-To-Network it is the NPDU after DNET and the
// originating address.
type BVLC struct {
	Function BVLCFunction
	Origin   IPMAC  // Forwarded-NPDU / Distribute-Broadcast
	DNET     uint16 // Distribute-Broadcast-To-Network
	Result   uint16 // BVLC-Result
	TTL      uint16 // Register-Foreign-Device
	Data     []byte
}

// ParseBVLC validates and decodes one BACnet/IP frame. The declared length
// must match the datagram exactly: a frame with trailing bytes is not
// something a BACnet stack sends, and forwarding it would let a peer smuggle
// data past the policy parser.
func ParseBVLC(dg []byte) (BVLC, error) {
	if len(dg) < 4 {
		return BVLC{}, fmt.Errorf("bacnet: bvlc: %d bytes, need at least 4", len(dg))
	}
	if dg[0] != BVLCTypeIP {
		if dg[0] == 0x82 {
			return BVLC{}, fmt.Errorf("bacnet: bvlc: BACnet/SC frame (0x82) is not BACnet/IP")
		}
		return BVLC{}, fmt.Errorf("bacnet: bvlc: type 0x%02x, want 0x81", dg[0])
	}
	fn := BVLCFunction(dg[1])
	n := int(binary.BigEndian.Uint16(dg[2:4]))
	if n != len(dg) {
		return BVLC{}, fmt.Errorf("bacnet: bvlc: declared length %d, datagram %d", n, len(dg))
	}
	payload := dg[4:]

	b := BVLC{Function: fn}
	switch fn {
	case BVLCForwardedNPDU:
		if len(payload) < 6 {
			return BVLC{}, fmt.Errorf("bacnet: bvlc: forwarded npdu without origin address")
		}
		copy(b.Origin[:], payload[:6])
		b.Data = payload[6:]
	case BVLCDistributeBroadcastToNetwork:
		if len(payload) < 8 {
			return BVLC{}, fmt.Errorf("bacnet: bvlc: distribute-broadcast without dnet/origin")
		}
		b.DNET = binary.BigEndian.Uint16(payload[:2])
		copy(b.Origin[:], payload[2:8])
		b.Data = payload[8:]
	case BVLCResult:
		if len(payload) < 2 {
			return BVLC{}, fmt.Errorf("bacnet: bvlc: result without code")
		}
		b.Result = binary.BigEndian.Uint16(payload[:2])
		b.Data = payload[2:]
	case BVLCRegisterForeignDevice:
		if len(payload) < 2 {
			return BVLC{}, fmt.Errorf("bacnet: bvlc: register-foreign-device without ttl")
		}
		b.TTL = binary.BigEndian.Uint16(payload[:2])
		b.Data = payload[2:]
	default:
		b.Data = payload
	}
	return b, nil
}

// Marshal encodes the frame, recomputing the length field. The caller owns
// Function and the function-specific fields; a field that does not belong to
// the function is ignored rather than emitted.
func (b BVLC) Marshal() []byte {
	fixed := make([]byte, 0, 8)
	switch b.Function {
	case BVLCForwardedNPDU:
		fixed = append(fixed, b.Origin[:]...)
	case BVLCDistributeBroadcastToNetwork:
		fixed = binary.BigEndian.AppendUint16(fixed, b.DNET)
		fixed = append(fixed, b.Origin[:]...)
	case BVLCResult:
		fixed = binary.BigEndian.AppendUint16(fixed, b.Result)
	case BVLCRegisterForeignDevice:
		fixed = binary.BigEndian.AppendUint16(fixed, b.TTL)
	}
	out := make([]byte, 4, 4+len(fixed)+len(b.Data))
	out[0] = BVLCTypeIP
	out[1] = byte(b.Function)
	out = append(out, fixed...)
	out = append(out, b.Data...)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	return out
}

// IsBroadcast reports whether the frame is a broadcast on the IP leg:
// Original-Broadcast, or a Distribute-Broadcast-To-Network. Forwarded-NPDU
// is delivered unicast to one station even when the NPDU inside is a
// broadcast, so it is not one.
func (b BVLC) IsBroadcast() bool {
	return b.Function == BVLCOriginalBroadcastNPDU ||
		b.Function == BVLCDistributeBroadcastToNetwork
}
