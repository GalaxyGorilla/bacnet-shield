package bacnet

import (
	"encoding/binary"
	"fmt"
	"net"
)

// IPMAC is a BACnet/IP station address: 4-byte IPv4 address followed by a
// 2-byte UDP port, both big-endian. BACnet uses this 6-byte form in DADR/SADR
// fields and in the Forwarded-NPDU origin field.
type IPMAC [6]byte

// IPMACFromUDP converts a UDP address to its BACnet/IP station form.
// BACnet/IPv6 has a different (18-byte) address and is not supported.
func IPMACFromUDP(a *net.UDPAddr) (IPMAC, error) {
	var m IPMAC
	if a == nil {
		return m, fmt.Errorf("bacnet: nil udp address")
	}
	ip4 := a.IP.To4()
	if ip4 == nil {
		return m, fmt.Errorf("bacnet: %s is not IPv4 (BACnet/IPv6 uses an 18-byte address)", a)
	}
	copy(m[:4], ip4)
	binary.BigEndian.PutUint16(m[4:], uint16(a.Port))
	return m, nil
}

// UDPAddr returns the station as a UDP address.
func (m IPMAC) UDPAddr() *net.UDPAddr {
	ip := net.IPv4(m[0], m[1], m[2], m[3])
	return &net.UDPAddr{IP: ip, Port: int(binary.BigEndian.Uint16(m[4:]))}
}

func (m IPMAC) String() string {
	return m.UDPAddr().String()
}
