package proxy

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet"
)

// ProbeResult is what a device-leg probe learned. The fields are the ones a
// commissioning report needs: the device object the device claims and a
// human-readable description of the exchange.
type ProbeResult struct {
	Device bacnet.ObjectID
	Detail string
}

// probeResolutionTimeout bounds the virtual-address exchange an IPv6 probe
// needs before it can send a unicast request. It is shorter than the probe
// deadline so a device that does not answer still leaves time for the normal
// two attempts.
const probeResolutionTimeout = 750 * time.Millisecond

// probeLink is the probe's device-leg transport: plain BACnet/IPv4 or
// BACnet/IPv6. The gateway has the same split; keeping it here means selftest
// tests the same wire shape the running process uses.
type probeLink struct {
	conn       *net.UDPConn
	addr       *net.UDPAddr
	ipv6       bool
	localVMAC  bacnet.VMAC
	deviceVMAC bacnet.VMAC
}

// ProbeDevice checks the clear leg without starting a gateway. It sends one
// BACnet request directly from this host and waits for the answer:
//
//   - with a pinned instance, a ReadProperty for device,<instance>,object-name
//     (a unicast request, so it works through firewalls that drop broadcast);
//   - without one, a Who-Is, and it reports the instance from the first I-Am
//     that comes from the configured device host.
//
// An IPv4 device is addressed directly. An IPv6 device is asked for its
// 3-octet virtual address first, because an Annex U unicast frame carries it.
//
// Two attempts cover a device that drops the first query after ARP
// resolution. A BACnet Error PDU is a successful reachability result — the
// device answered — so it is reported with the error class and code instead
// of being flattened into a timeout.
func ProbeDevice(ctx context.Context, deviceAddr string, instance *uint32) (ProbeResult, error) {
	addr, network, err := resolveAddr(deviceAddr)
	if err != nil {
		return ProbeResult{}, fmt.Errorf("probe: device address %q: %w", deviceAddr, err)
	}
	if addr.Port == 0 {
		return ProbeResult{}, fmt.Errorf("probe: device address %q has no port", deviceAddr)
	}
	if addr.IP == nil {
		return ProbeResult{}, fmt.Errorf("probe: device address %q has no host", deviceAddr)
	}
	conn, err := net.ListenUDP(network, nil)
	if err != nil {
		return ProbeResult{}, fmt.Errorf("probe: bind: %w", err)
	}
	defer conn.Close()
	link := &probeLink{conn: conn, addr: addr, ipv6: network == "udp6"}
	if link.ipv6 {
		link.localVMAC = deriveVMAC(conn.LocalAddr().(*net.UDPAddr))
	}

	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return ProbeResult{}, lastErr
			}
			return ProbeResult{}, err
		}
		var res ProbeResult
		if instance != nil {
			res, err = probeRead(link, *instance, ctx)
		} else {
			res, err = probeWhoIs(link, ctx)
		}
		if err == nil {
			return res, nil
		}
		lastErr = err
		// Retry only while there is budget left. An attempt reads until the
		// probe deadline, which is the context deadline when one is set;
		// once that has passed there is nothing left to spend, and testing
		// ctx.Err() here would race the context timer and send a duplicate.
		if !time.Now().Before(probeDeadline(ctx)) {
			break
		}
	}
	return ProbeResult{}, lastErr
}

// ensureVMAC asks an IPv6 device for its virtual address. It is called before
// the first request; there is no other reader on the probe socket.
func (l *probeLink) ensureVMAC() error {
	if !l.ipv6 || !l.deviceVMAC.IsZero() {
		return nil
	}
	frame := bacnet.BVLC6{Function: bacnet.BVLC6VirtualAddressResolution, Src: l.localVMAC}.Marshal()
	if _, err := l.conn.WriteToUDP(frame, l.addr); err != nil {
		return fmt.Errorf("probe: virtual-address request: %w", err)
	}
	_ = l.conn.SetReadDeadline(time.Now().Add(probeResolutionTimeout))
	buf := make([]byte, 65535)
	for {
		n, src, err := l.conn.ReadFromUDP(buf)
		if err != nil {
			return fmt.Errorf("probe: no virtual-address answer from %s: %w", l.addr, err)
		}
		if !src.IP.Equal(l.addr.IP) {
			continue
		}
		b, err := bacnet.ParseBVLC6(buf[:n])
		if err != nil {
			continue
		}
		if b.Function == bacnet.BVLC6VirtualAddressResolutionACK && !b.Src.IsZero() {
			l.deviceVMAC = b.Src
			return nil
		}
	}
}

// probeRead sends ReadProperty(device,instance,object-name) and waits for the
// matching answer.
func probeRead(link *probeLink, instance uint32, ctx context.Context) (ProbeResult, error) {
	oid := bacnet.ObjectID{Type: bacnet.ObjectDevice, Instance: instance}
	payload := append([]byte{0x0C}, oid.AppendTo(nil)...)
	payload = append(payload, 0x19, byte(bacnet.PropertyObjectName))
	a := bacnet.APDU{
		Type:        bacnet.PDUConfirmedRequest,
		InvokeID:    1,
		HasInvokeID: true,
		HasService:  true,
		Service:     bacnet.ServiceReadProperty,
		Payload:     payload,
	}
	if err := link.send(a); err != nil {
		return ProbeResult{}, err
	}
	_ = link.conn.SetReadDeadline(probeDeadline(ctx))
	buf := make([]byte, 65535)
	for {
		got, src, err := link.read(buf)
		if err != nil {
			return ProbeResult{}, fmt.Errorf("probe: no answer to ReadProperty from %s: %w", link.addr, err)
		}
		if !src.IP.Equal(link.addr.IP) {
			continue
		}
		if got.Type != bacnet.PDUComplexACK && got.Type != bacnet.PDUError {
			continue
		}
		if got.InvokeID != 1 || got.Service != bacnet.ServiceReadProperty {
			continue
		}
		if got.Type == bacnet.PDUError {
			class, code := probeError(got)
			return ProbeResult{Device: oid,
				Detail: fmt.Sprintf("device answered ReadProperty with error class %d code %d", class, code)}, nil
		}
		return ProbeResult{Device: oid,
			Detail: fmt.Sprintf("ReadProperty(device,%d,object-name) ok from %s", instance, src)}, nil
	}
}

// probeWhoIs sends a Who-Is from this host and reports the first I-Am from the
// configured device address.
func probeWhoIs(link *probeLink, ctx context.Context) (ProbeResult, error) {
	a := bacnet.APDU{Type: bacnet.PDUUnconfirmedRequest, HasService: true, Service: bacnet.ServiceWhoIs}
	if err := link.send(a); err != nil {
		return ProbeResult{}, err
	}
	_ = link.conn.SetReadDeadline(probeDeadline(ctx))
	buf := make([]byte, 65535)
	for {
		got, src, err := link.read(buf)
		if err != nil {
			return ProbeResult{}, fmt.Errorf("probe: no I-Am from %s: %w", link.addr, err)
		}
		if !src.IP.Equal(link.addr.IP) {
			// Another device on the network answered the Who-Is. It is not
			// the device this proxy is configured for; keep waiting.
			continue
		}
		oid, ok := bacnet.IAmDeviceID(got)
		if !ok {
			continue
		}
		return ProbeResult{Device: oid,
			Detail: fmt.Sprintf("Who-Is answered by device,%d from %s", oid.Instance, src)}, nil
	}
}

func (l *probeLink) send(a bacnet.APDU) error {
	if err := l.ensureVMAC(); err != nil {
		return err
	}
	npdu := bacnet.NPDU{APDU: a.Marshal()}.Marshal()
	var frame []byte
	if l.ipv6 {
		frame = bacnet.BVLC6{
			Function: bacnet.BVLC6OriginalUnicastNPDU,
			Src:      l.localVMAC,
			Dst:      l.deviceVMAC,
			Data:     npdu,
		}.Marshal()
	} else {
		frame = bacnet.BVLC{
			Function: bacnet.BVLCOriginalUnicastNPDU,
			Data:     npdu,
		}.Marshal()
	}
	if _, err := l.conn.WriteToUDP(frame, l.addr); err != nil {
		return fmt.Errorf("probe: send: %w", err)
	}
	return nil
}

func (l *probeLink) read(buf []byte) (bacnet.APDU, *net.UDPAddr, error) {
	n, src, err := l.conn.ReadFromUDP(buf)
	if err != nil {
		return bacnet.APDU{}, nil, err
	}
	var data []byte
	if l.ipv6 {
		b, err := bacnet.ParseBVLC6(buf[:n])
		if err != nil {
			return bacnet.APDU{}, nil, err
		}
		switch b.Function {
		case bacnet.BVLC6OriginalUnicastNPDU, bacnet.BVLC6OriginalBroadcastNPDU:
		default:
			return bacnet.APDU{}, nil, fmt.Errorf("probe: unexpected ipv6 function %s", b.Function)
		}
		if l.deviceVMAC.IsZero() {
			l.deviceVMAC = b.Src
		}
		data = b.Data
	} else {
		b, err := bacnet.ParseBVLC(buf[:n])
		if err != nil {
			return bacnet.APDU{}, nil, err
		}
		data = b.Data
	}
	np, err := bacnet.ParseNPDU(data)
	if err != nil {
		return bacnet.APDU{}, nil, err
	}
	a, err := bacnet.ParseAPDU(np.APDU)
	if err != nil {
		return bacnet.APDU{}, nil, err
	}
	return a, src, nil
}

// probeError returns the class and code of an Error PDU. The parameters are
// tagged ENUMERATEDs, so they are decoded through the shared tag reader; a
// malformed or truncated payload is reported as class/code device/other
// rather than panicking.
func probeError(a bacnet.APDU) (bacnet.ErrorClass, bacnet.ErrorCode) {
	class, code, ok := bacnet.ErrorClassAndCode(a.Payload)
	if !ok {
		return bacnet.ErrorClassDevice, bacnet.ErrorCodeOther
	}
	return class, code
}

func probeDeadline(ctx context.Context) time.Time {
	deadline := time.Now().Add(2 * time.Second)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	return deadline
}
