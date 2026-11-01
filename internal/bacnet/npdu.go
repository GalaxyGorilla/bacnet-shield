package bacnet

import (
	"encoding/binary"
	"fmt"
)

// NPDU version 1 is the only one that exists.
const NPDUVersion byte = 0x01

// NPDU control octet bits (ASHRAE 135 clause 6.2.2).
const (
	npduNetMessage     byte = 0x80
	npduDNETPresent    byte = 0x20
	npduSNETPresent    byte = 0x08
	npduExpectingReply byte = 0x04
	npduPriorityMask   byte = 0x03
)

// NetworkMessageType is a BACnet network-layer message type.
type NetworkMessageType byte

const (
	NetWhoIsRouterToNetwork      NetworkMessageType = 0x00
	NetIAmRouterToNetwork        NetworkMessageType = 0x01
	NetICouldBeRouterToNetwork   NetworkMessageType = 0x02
	NetRejectMessageToNetwork    NetworkMessageType = 0x03
	NetRouterBusyToNetwork       NetworkMessageType = 0x04
	NetRouterAvailableToNetwork  NetworkMessageType = 0x05
	NetInitializeRoutingTable    NetworkMessageType = 0x06
	NetInitializeRoutingTableAck NetworkMessageType = 0x07
	NetEstablishConnection       NetworkMessageType = 0x08
	NetDisconnectConnection      NetworkMessageType = 0x09
	NetChallengeRequest          NetworkMessageType = 0x0A
	NetSecurityPayload           NetworkMessageType = 0x0B
	NetSecurityResponse          NetworkMessageType = 0x0C
	NetRequestKeyUpdate          NetworkMessageType = 0x0D
	NetUpdateKeySet              NetworkMessageType = 0x0E
	NetUpdateDistributionKey     NetworkMessageType = 0x0F
	NetRequestMasterKey          NetworkMessageType = 0x10
	NetSetMasterKey              NetworkMessageType = 0x11
	NetWhatIsNetworkNumber       NetworkMessageType = 0x12
	NetNetworkNumberIs           NetworkMessageType = 0x13
)

// NetworkMessage is the body of a network-layer NPDU.
type NetworkMessage struct {
	Type     NetworkMessageType
	VendorID uint16 // present for the proprietary range 0x80..0xFF
	Data     []byte
}

// NPDU is a parsed BACnet network-layer PDU.
//
// DADR/SADR use nil to mean "not present" and a non-nil (possibly empty)
// slice to mean "present": a present-but-empty DADR is a broadcast to DNET,
// which is a legal and common shape.
type NPDU struct {
	DNET           uint16
	DADR           []byte
	SNET           uint16
	SADR           []byte
	HopCount       byte
	ExpectingReply bool
	Priority       byte
	NetworkMessage *NetworkMessage
	APDU           []byte
}

// HasDestination reports whether a DNET/DADR pair is present.
func (n NPDU) HasDestination() bool { return n.DADR != nil }

// HasSource reports whether an SNET/SADR pair is present.
func (n NPDU) HasSource() bool { return n.SADR != nil }

// IsNetworkMessage reports whether the NPDU carries a network-layer message
// instead of an APDU.
func (n NPDU) IsNetworkMessage() bool { return n.NetworkMessage != nil }

// IsBroadcast reports whether the NPDU addresses a whole network: a
// destination network with a zero-length DADR, or the global broadcast
// network 0xFFFF.
func (n NPDU) IsBroadcast() bool {
	return n.HasDestination() && (len(n.DADR) == 0 || n.DNET == 0xFFFF)
}

// ParseNPDU decodes the network layer. Every length is checked against the
// datagram; a peer cannot make the parser read past its input.
func ParseNPDU(b []byte) (NPDU, error) {
	if len(b) < 2 {
		return NPDU{}, fmt.Errorf("bacnet: npdu: %d bytes, need at least 2", len(b))
	}
	if b[0] != NPDUVersion {
		return NPDU{}, fmt.Errorf("bacnet: npdu: version %d, want 1", b[0])
	}
	control := b[1]
	i := 2

	n := NPDU{
		ExpectingReply: control&npduExpectingReply != 0,
		Priority:       control & npduPriorityMask,
	}
	if control&npduDNETPresent != 0 {
		if len(b) < i+3 {
			return NPDU{}, fmt.Errorf("bacnet: npdu: truncated dnet")
		}
		n.DNET = binary.BigEndian.Uint16(b[i:])
		dlen := int(b[i+2])
		i += 3
		if len(b) < i+dlen {
			return NPDU{}, fmt.Errorf("bacnet: npdu: dlen %d past end", dlen)
		}
		n.DADR = b[i : i+dlen : i+dlen]
		i += dlen
	}
	if control&npduSNETPresent != 0 {
		if len(b) < i+3 {
			return NPDU{}, fmt.Errorf("bacnet: npdu: truncated snet")
		}
		n.SNET = binary.BigEndian.Uint16(b[i:])
		slen := int(b[i+2])
		i += 3
		if slen == 0 {
			return NPDU{}, fmt.Errorf("bacnet: npdu: zero-length source address")
		}
		if len(b) < i+slen {
			return NPDU{}, fmt.Errorf("bacnet: npdu: slen %d past end", slen)
		}
		n.SADR = b[i : i+slen : i+slen]
		i += slen
	}
	if n.HasDestination() {
		if len(b) < i+1 {
			return NPDU{}, fmt.Errorf("bacnet: npdu: truncated hop count")
		}
		n.HopCount = b[i]
		i++
	}
	if control&npduNetMessage != 0 {
		if len(b) < i+1 {
			return NPDU{}, fmt.Errorf("bacnet: npdu: network message without type")
		}
		nm := &NetworkMessage{Type: NetworkMessageType(b[i])}
		i++
		if nm.Type >= 0x80 {
			if len(b) < i+2 {
				return NPDU{}, fmt.Errorf("bacnet: npdu: proprietary network message without vendor id")
			}
			nm.VendorID = binary.BigEndian.Uint16(b[i:])
			i += 2
		}
		nm.Data = b[i:]
		n.NetworkMessage = nm
		return n, nil
	}
	n.APDU = b[i:]
	return n, nil
}

// Marshal encodes the NPDU. The control octet is derived from the fields, so
// a struct built by hand cannot claim an address it does not carry.
func (n NPDU) Marshal() []byte {
	control := n.Priority & npduPriorityMask
	if n.ExpectingReply {
		control |= npduExpectingReply
	}
	if n.HasDestination() {
		control |= npduDNETPresent
	}
	if n.HasSource() {
		control |= npduSNETPresent
	}
	if n.IsNetworkMessage() {
		control |= npduNetMessage
	}

	out := make([]byte, 0, 2+8+len(n.APDU))
	out = append(out, NPDUVersion, control)
	if n.HasDestination() {
		out = binary.BigEndian.AppendUint16(out, n.DNET)
		out = append(out, byte(len(n.DADR)))
		out = append(out, n.DADR...)
	}
	if n.HasSource() {
		out = binary.BigEndian.AppendUint16(out, n.SNET)
		out = append(out, byte(len(n.SADR)))
		out = append(out, n.SADR...)
	}
	if n.HasDestination() {
		out = append(out, n.HopCount)
	}
	if n.IsNetworkMessage() {
		out = append(out, byte(n.NetworkMessage.Type))
		if n.NetworkMessage.Type >= 0x80 {
			out = binary.BigEndian.AppendUint16(out, n.NetworkMessage.VendorID)
		}
		out = append(out, n.NetworkMessage.Data...)
		return out
	}
	return append(out, n.APDU...)
}

// StripRouting returns the NPDU as it must look on a locally attached
// network: no destination network, no source network, no hop count. The
// application bytes are untouched.
//
// This is what the proxy does when it forwards a client's request to a device
// that sits on the proxy's own IP network: the client addressed the device
// through a DNET/DADR, the device must see a plain local request.
func (n NPDU) StripRouting() NPDU {
	out := n
	out.DNET = 0
	out.DADR = nil
	out.SNET = 0
	out.SADR = nil
	out.HopCount = 0
	out.ExpectingReply = false
	out.Priority = 0
	return out
}
