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

// ProbeDevice checks the clear leg without starting a gateway. It sends one
// BACnet request directly from this host and waits for the answer:
//
//   - with a pinned instance, a ReadProperty for device,<instance>,object-name
//     (a unicast request, so it works through firewalls that drop broadcast);
//   - without one, a Who-Is, and it reports the instance from the first I-Am
//     that comes from the configured device host.
//
// Two attempts cover a device that drops the first query after ARP
// resolution. A BACnet Error PDU is a successful reachability result — the
// device answered — so it is reported with the error class and code instead
// of being flattened into a timeout.
func ProbeDevice(ctx context.Context, deviceAddr string, instance *uint32) (ProbeResult, error) {
	addr, err := net.ResolveUDPAddr("udp4", deviceAddr)
	if err != nil {
		return ProbeResult{}, fmt.Errorf("probe: device address %q: %w", deviceAddr, err)
	}
	if addr.IP == nil || addr.IP.To4() == nil {
		return ProbeResult{}, fmt.Errorf("probe: device address %q is not IPv4", deviceAddr)
	}
	if addr.Port == 0 {
		return ProbeResult{}, fmt.Errorf("probe: device address %q has no port", deviceAddr)
	}
	conn, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return ProbeResult{}, fmt.Errorf("probe: bind: %w", err)
	}
	defer conn.Close()

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
			res, err = probeRead(conn, addr, *instance, ctx)
		} else {
			res, err = probeWhoIs(conn, addr, ctx)
		}
		if err == nil {
			return res, nil
		}
		lastErr = err
	}
	return ProbeResult{}, lastErr
}

// probeRead sends ReadProperty(device,instance,object-name) and waits for the
// matching answer.
func probeRead(conn *net.UDPConn, addr *net.UDPAddr, instance uint32, ctx context.Context) (ProbeResult, error) {
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
	if err := sendProbe(conn, addr, a); err != nil {
		return ProbeResult{}, err
	}
	_ = conn.SetReadDeadline(probeDeadline(ctx))
	buf := make([]byte, 65535)
	for {
		got, src, err := readProbe(conn, buf)
		if err != nil {
			return ProbeResult{}, fmt.Errorf("probe: no answer to ReadProperty from %s: %w", addr, err)
		}
		if !src.IP.Equal(addr.IP) {
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

// probeWhoIs broadcasts a Who-Is from this host and reports the first I-Am
// from the configured device address.
func probeWhoIs(conn *net.UDPConn, addr *net.UDPAddr, ctx context.Context) (ProbeResult, error) {
	a := bacnet.APDU{Type: bacnet.PDUUnconfirmedRequest, HasService: true, Service: bacnet.ServiceWhoIs}
	if err := sendProbe(conn, addr, a); err != nil {
		return ProbeResult{}, err
	}
	_ = conn.SetReadDeadline(probeDeadline(ctx))
	buf := make([]byte, 65535)
	for {
		got, src, err := readProbe(conn, buf)
		if err != nil {
			return ProbeResult{}, fmt.Errorf("probe: no I-Am from %s: %w", addr, err)
		}
		if !src.IP.Equal(addr.IP) {
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

func sendProbe(conn *net.UDPConn, addr *net.UDPAddr, a bacnet.APDU) error {
	frame := bacnet.BVLC{
		Function: bacnet.BVLCOriginalUnicastNPDU,
		Data:     bacnet.NPDU{APDU: a.Marshal()}.Marshal(),
	}.Marshal()
	if _, err := conn.WriteToUDP(frame, addr); err != nil {
		return fmt.Errorf("probe: send: %w", err)
	}
	return nil
}

func readProbe(conn *net.UDPConn, buf []byte) (bacnet.APDU, *net.UDPAddr, error) {
	n, src, err := conn.ReadFromUDP(buf)
	if err != nil {
		return bacnet.APDU{}, nil, err
	}
	b, err := bacnet.ParseBVLC(buf[:n])
	if err != nil {
		return bacnet.APDU{}, nil, err
	}
	np, err := bacnet.ParseNPDU(b.Data)
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
