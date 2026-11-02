package proxy

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet"
)

func TestProbeDeviceReadProperty(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	instance := uint32(1001)

	type outcome struct {
		res ProbeResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := ProbeDevice(context.Background(), dev.addr().String(), &instance)
		done <- outcome{res, err}
	}()

	req, _, src := dev.mustRecv(t, 2*time.Second)
	if req.Type != bacnet.PDUConfirmedRequest || req.Service != bacnet.ServiceReadProperty {
		t.Fatalf("probe request = %+v", req)
	}
	oid := bacnet.ObjectID{Type: bacnet.ObjectDevice, Instance: instance}
	dev.send(t, readPropertyACK(req.InvokeID, oid, bacnet.PropertyObjectName,
		[]byte{0x75, 0x04, 't', 'e', 's', 't'}), src)

	got := <-done
	if got.err != nil {
		t.Fatalf("ProbeDevice: %v", got.err)
	}
	if got.res.Device != oid {
		t.Fatalf("device = %v, want %v", got.res.Device, oid)
	}
	if !strings.Contains(got.res.Detail, "ReadProperty(device,1001,object-name) ok") {
		t.Fatalf("detail = %q", got.res.Detail)
	}
}

func TestProbeDeviceIPv6WhoIs(t *testing.T) {
	dev := newFakeDevice6(t)

	done := make(chan ProbeResult, 1)
	go func() {
		res, err := ProbeDevice(context.Background(), dev.addr().String(), nil)
		if err != nil {
			t.Errorf("ProbeDevice: %v", err)
		}
		done <- res
	}()

	req, src, proxyVMAC := dev.mustRecv(t, 3*time.Second)
	if req.Type != bacnet.PDUUnconfirmedRequest || req.Service != bacnet.ServiceWhoIs {
		t.Fatalf("probe request = %+v", req)
	}
	dev.send(t, iam(1001), src, proxyVMAC)

	res := <-done
	if res.Device != (bacnet.ObjectID{Type: bacnet.ObjectDevice, Instance: 1001}) {
		t.Fatalf("device = %v", res.Device)
	}
	if !strings.Contains(res.Detail, "Who-Is answered by device,1001") {
		t.Fatalf("detail = %q", res.Detail)
	}
}

func TestProbeDeviceIPv6TimesOut(t *testing.T) {
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback, Port: 0})
	if err != nil {
		t.Fatalf("silent ipv6 device bind: %v", err)
	}
	defer conn.Close()

	instance := uint32(1)
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := ProbeDevice(ctx, conn.LocalAddr().String(), &instance); err == nil {
		t.Fatal("ProbeDevice succeeded with no device answer")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("ProbeDevice took %s to give up", elapsed)
	}
}

func TestProbeDeviceErrorIsReachable(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	instance := uint32(7)

	done := make(chan error, 1)
	go func() {
		res, err := ProbeDevice(context.Background(), dev.addr().String(), &instance)
		if err == nil && !strings.Contains(res.Detail, "error class 1 code 31") {
			t.Errorf("detail = %q, want the device error", res.Detail)
		}
		done <- err
	}()

	req, _, src := dev.mustRecv(t, 2*time.Second)
	dev.send(t, bacnet.ErrorAPDU(req.InvokeID, bacnet.ServiceReadProperty,
		bacnet.ErrorClassObject, bacnet.ErrorCodeUnknownObject), src)

	// A device that answers with an Error is alive; that is a successful
	// probe, not a timeout.
	if err := <-done; err != nil {
		t.Fatalf("ProbeDevice returned %v for a device that answered with an error", err)
	}
}

func TestProbeDeviceWhoIs(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")

	done := make(chan ProbeResult, 1)
	go func() {
		res, err := ProbeDevice(context.Background(), dev.addr().String(), nil)
		if err != nil {
			t.Errorf("ProbeDevice: %v", err)
		}
		done <- res
	}()

	req, _, src := dev.mustRecv(t, 2*time.Second)
	if req.Type != bacnet.PDUUnconfirmedRequest || req.Service != bacnet.ServiceWhoIs {
		t.Fatalf("probe request = %+v", req)
	}
	dev.send(t, iam(1001), src)

	res := <-done
	if res.Device != (bacnet.ObjectID{Type: bacnet.ObjectDevice, Instance: 1001}) {
		t.Fatalf("device = %v", res.Device)
	}
	if !strings.Contains(res.Detail, "Who-Is answered by device,1001") {
		t.Fatalf("detail = %q", res.Detail)
	}
}

func TestProbeDeviceTimesOut(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	instance := uint32(1)
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err := ProbeDevice(ctx, dev.addr().String(), &instance)
	if err == nil {
		t.Fatal("ProbeDevice succeeded with no device answer")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("ProbeDevice took %s to give up", elapsed)
	}
	// The request reached the device even though it never answered. The
	// cancelled context ends the retry loop, so exactly one copy is sent.
	dev.mustRecv(t, 2*time.Second)
	dev.expectNothing(t, 150*time.Millisecond)
}

func TestProbeDeviceIPv6ReadProperty(t *testing.T) {
	dev := newFakeDevice6(t)
	instance := uint32(1001)

	type outcome struct {
		res ProbeResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		res, err := ProbeDevice(context.Background(), dev.addr().String(), &instance)
		done <- outcome{res, err}
	}()

	// mustRecv answers the probe's VirtualAddressResolution on the way, then
	// returns the ReadProperty.
	req, src, proxyVMAC := dev.mustRecv(t, 3*time.Second)
	if req.Type != bacnet.PDUConfirmedRequest || req.Service != bacnet.ServiceReadProperty {
		t.Fatalf("probe request = %+v", req)
	}
	oid := bacnet.ObjectID{Type: bacnet.ObjectDevice, Instance: instance}
	dev.send(t, readPropertyACK(req.InvokeID, oid, bacnet.PropertyObjectName,
		[]byte{0x75, 0x04, 't', 'e', 's', 't'}), src, proxyVMAC)

	got := <-done
	if got.err != nil {
		t.Fatalf("ProbeDevice: %v", got.err)
	}
	if got.res.Device != oid {
		t.Fatalf("device = %v, want %v", got.res.Device, oid)
	}
	if !strings.Contains(got.res.Detail, "ReadProperty(device,1001,object-name) ok") {
		t.Fatalf("detail = %q", got.res.Detail)
	}
}

func TestProbeDeviceBadAddress(t *testing.T) {
	instance := uint32(1)
	for _, addr := range []string{"not-an-address", "127.0.0.1", ":47808"} {
		if _, err := ProbeDevice(context.Background(), addr, &instance); err == nil {
			t.Errorf("ProbeDevice(%q) succeeded", addr)
		}
	}
}

func TestProbeErrorTruncated(t *testing.T) {
	class, code := probeError(bacnet.APDU{Type: bacnet.PDUError, Payload: []byte{4}})
	if class != bacnet.ErrorClassDevice || code != bacnet.ErrorCodeOther {
		t.Fatalf("truncated error = %d/%d", class, code)
	}
}
