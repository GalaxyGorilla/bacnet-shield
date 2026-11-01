package sc

import (
	"encoding/binary"
	"fmt"
)

// This file is the typed payload layer over the generic header in sc.go:
// the BVLC-SC messages a node and a hub exchange. Each Encode returns only the
// payload; each Decode reads only the payload. The header (addresses, message
// id, options) is built by the caller, so a decoded frame's routing fields
// stay available.

// Result codes (ASHRAE 135 AB.2.4.1).
const (
	ResultACK uint8 = 0x00
	ResultNAK uint8 = 0x01
)

// Result is a BVLC-Result: an ACK or NAK for a previously sent message,
// correlated by the header message ID.
type Result struct {
	// Function is the BVLC function this result answers.
	Function Function
	// Code is ResultACK or ResultNAK.
	Code uint8
	// ErrorMarker, ErrorClass, ErrorCode and Details are only present for a
	// NAK. ErrorClass and ErrorCode are the BACnet error datatype values.
	ErrorMarker byte
	ErrorClass  uint16
	ErrorCode   uint16
	Details     string
}

// Encode returns the Result payload.
func (r Result) Encode() ([]byte, error) {
	if r.Function > FuncProprietary {
		return nil, fmt.Errorf("sc: result for unknown function 0x%02x", byte(r.Function))
	}
	if r.Code != ResultACK && r.Code != ResultNAK {
		return nil, fmt.Errorf("sc: result code 0x%02x is not ACK or NAK", r.Code)
	}
	out := []byte{byte(r.Function), r.Code}
	if r.Code == ResultACK {
		if r.ErrorMarker != 0 || r.ErrorClass != 0 || r.ErrorCode != 0 || r.Details != "" {
			return nil, fmt.Errorf("sc: ACK result carries error fields")
		}
		return out, nil
	}
	out = append(out, r.ErrorMarker)
	out = binary.BigEndian.AppendUint16(out, r.ErrorClass)
	out = binary.BigEndian.AppendUint16(out, r.ErrorCode)
	return append(out, r.Details...), nil
}

// DecodeResult decodes a Result payload.
func DecodeResult(p []byte) (Result, error) {
	var r Result
	if len(p) < 2 {
		return r, fmt.Errorf("sc: result %d bytes, need 2", len(p))
	}
	if Function(p[0]) > FuncProprietary {
		return r, fmt.Errorf("sc: result for unknown function 0x%02x", p[0])
	}
	r.Function = Function(p[0])
	r.Code = p[1]
	switch r.Code {
	case ResultACK:
		if len(p) != 2 {
			return r, fmt.Errorf("sc: ACK result %d bytes, want 2", len(p))
		}
	case ResultNAK:
		if len(p) < 7 {
			return r, fmt.Errorf("sc: NAK result %d bytes, need 7", len(p))
		}
		r.ErrorMarker = p[2]
		r.ErrorClass = binary.BigEndian.Uint16(p[3:5])
		r.ErrorCode = binary.BigEndian.Uint16(p[5:7])
		r.Details = string(p[7:])
	default:
		return r, fmt.Errorf("sc: result code 0x%02x is not ACK or NAK", r.Code)
	}
	return r, nil
}

// ConnectRequest is sent by a node to a hub to attach (ASHRAE 135 AB.2.10).
// VMAC and UUID are the node's own identity; the hub echoes them in the
// ConnectAccept.
type ConnectRequest struct {
	VMAC    MAC
	UUID    UUID
	MaxBVLC uint16
	MaxNPDU uint16
}

// Encode returns the ConnectRequest payload.
func (c ConnectRequest) Encode() ([]byte, error) {
	return encodeConnect(c.VMAC, c.UUID, c.MaxBVLC, c.MaxNPDU)
}

// DecodeConnectRequest decodes a ConnectRequest payload.
func DecodeConnectRequest(p []byte) (ConnectRequest, error) {
	vmac, uuid, bvlc, npdu, err := decodeConnect(p)
	return ConnectRequest{VMAC: vmac, UUID: uuid, MaxBVLC: bvlc, MaxNPDU: npdu}, err
}

// ConnectAccept is the hub's answer to a ConnectRequest (ASHRAE 135 AB.2.11).
// The VMAC and UUID are the node's, confirmed; the lengths are the hub's
// limits, which may be lower than the node asked for.
type ConnectAccept struct {
	VMAC    MAC
	UUID    UUID
	MaxBVLC uint16
	MaxNPDU uint16
}

// Encode returns the ConnectAccept payload.
func (c ConnectAccept) Encode() ([]byte, error) {
	return encodeConnect(c.VMAC, c.UUID, c.MaxBVLC, c.MaxNPDU)
}

// DecodeConnectAccept decodes a ConnectAccept payload.
func DecodeConnectAccept(p []byte) (ConnectAccept, error) {
	vmac, uuid, bvlc, npdu, err := decodeConnect(p)
	return ConnectAccept{VMAC: vmac, UUID: uuid, MaxBVLC: bvlc, MaxNPDU: npdu}, err
}

func encodeConnect(vmac MAC, uuid UUID, maxBVLC, maxNPDU uint16) ([]byte, error) {
	if vmac.IsZero() {
		return nil, fmt.Errorf("sc: connect with a zero vmac")
	}
	out := make([]byte, 0, 26)
	out = append(out, vmac[:]...)
	out = append(out, uuid[:]...)
	out = binary.BigEndian.AppendUint16(out, maxBVLC)
	out = binary.BigEndian.AppendUint16(out, maxNPDU)
	return out, nil
}

func decodeConnect(p []byte) (MAC, UUID, uint16, uint16, error) {
	var vmac MAC
	var uuid UUID
	if len(p) != 26 {
		return vmac, uuid, 0, 0, fmt.Errorf("sc: connect payload %d bytes, want 26", len(p))
	}
	copy(vmac[:], p[0:6])
	copy(uuid[:], p[6:22])
	// A hub must not assign the zero VMAC; the spec reserves it as
	// "unknown".
	if vmac.IsZero() {
		return vmac, uuid, 0, 0, fmt.Errorf("sc: connect with a zero vmac")
	}
	return vmac, uuid, binary.BigEndian.Uint16(p[22:24]), binary.BigEndian.Uint16(p[24:26]), nil
}

// Hub connection status values carried in an Advertisement
// (BACNET_SC_HUB_CONNECTOR_STATE).
const (
	HubStatusNoHub             uint8 = 0x00
	HubStatusConnectedPrimary  uint8 = 0x01
	HubStatusConnectedFailover uint8 = 0x02
)

// Direct-connection support flag (ASHRAE 135 AB.2.6).
const (
	DirectConnectionUnsupported uint8 = 0x00
	DirectConnectionSupported   uint8 = 0x01
)

// Advertisement is periodically broadcast by a hub to tell nodes their
// connection state and size limits (ASHRAE 135 AB.2.6).
type Advertisement struct {
	HubStatus    uint8
	AcceptDirect uint8
	MaxBVLC      uint16
	MaxNPDU      uint16
}

// Encode returns the Advertisement payload.
func (a Advertisement) Encode() ([]byte, error) {
	out := []byte{a.HubStatus, a.AcceptDirect}
	out = binary.BigEndian.AppendUint16(out, a.MaxBVLC)
	out = binary.BigEndian.AppendUint16(out, a.MaxNPDU)
	return out, nil
}

// DecodeAdvertisement decodes an Advertisement payload.
func DecodeAdvertisement(p []byte) (Advertisement, error) {
	var a Advertisement
	if len(p) != 6 {
		return a, fmt.Errorf("sc: advertisement payload %d bytes, want 6", len(p))
	}
	a.HubStatus = p[0]
	a.AcceptDirect = p[1]
	a.MaxBVLC = binary.BigEndian.Uint16(p[2:4])
	a.MaxNPDU = binary.BigEndian.Uint16(p[4:6])
	return a, nil
}

// EncodeAddressResolutionACK returns the AddressResolutionACK payload: a
// UTF-8 list of WebSocket URIs the answering node accepts connections on.
func EncodeAddressResolutionACK(uris string) []byte { return []byte(uris) }

// DecodeAddressResolutionACK decodes an AddressResolutionACK payload.
func DecodeAddressResolutionACK(p []byte) string { return string(p) }

// Proprietary is a vendor-specific message (ASHRAE 135 AB.2.15).
type Proprietary struct {
	VendorID uint16
	Function uint8
	Data     []byte
}

// Encode returns the Proprietary payload.
func (m Proprietary) Encode() ([]byte, error) {
	out := make([]byte, 0, 3+len(m.Data))
	out = binary.BigEndian.AppendUint16(out, m.VendorID)
	out = append(out, m.Function)
	return append(out, m.Data...), nil
}

// DecodeProprietary decodes a Proprietary payload.
func DecodeProprietary(p []byte) (Proprietary, error) {
	var m Proprietary
	if len(p) < 3 {
		return m, fmt.Errorf("sc: proprietary payload %d bytes, need 3", len(p))
	}
	m.VendorID = binary.BigEndian.Uint16(p[0:2])
	m.Function = p[2]
	m.Data = p[3:]
	return m, nil
}
