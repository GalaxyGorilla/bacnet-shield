// Package bacnet implements the BACnet/IP wire format.
//
// BACnet/IP is three nested headers around an application PDU:
//
//	BVLC  link layer: type 0x81, function, total length
//	NPDU  network layer: version, control, optional DNET/DADR/SNET/SADR,
//	      hop count, then either a network message or an APDU
//	APDU  application layer: PDU type, invoke ID, service choice, service data
//
// The proxy is deliberately a *forwarder*, not a BACnet device stack: it
// parses exactly the fields it must act on (routing, invoke-ID translation,
// write policy, COV subscriptions) and forwards the APDU bytes untouched, so
// vendor quirks inside a service payload survive. That is also why the
// parsers below are total and bounds-checked: every byte here comes from the
// network.
//
// Only BACnet/IPv4 is implemented. BACnet/IPv6 uses an 18-byte station
// address and is a separate link layer; BACnet/SC (0x82) is a different
// framing entirely (TLS + WebSocket) and is rejected by ParseBVLC.
package bacnet
