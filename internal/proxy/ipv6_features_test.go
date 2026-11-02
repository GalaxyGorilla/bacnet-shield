package proxy

import (
	"context"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"go.uber.org/zap"

	"github.com/GalaxyGorilla/bacnet-shield/internal/access"
	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet"
	"github.com/GalaxyGorilla/bacnet-shield/internal/observ"
)

// The IPv6 tests below deliberately combine the new link layer with features
// that already work on IPv4: COV, segmentation, replay, rate limiting, audit
// and multi-device co-hosting. A leg-neutral data plane only earns that name
// when these paths are exercised on the leg.

func startIPv6DeviceGateway(t *testing.T, dev *fakeDevice6, pol *access.Policy) *fixture {
	t.Helper()
	f := startGateway(t, Config{ListenAddr: "127.0.0.1:0", DeviceAddr: dev.addr().String()}, pol)
	dev.answerResolution(t)
	waitDeviceVMAC(t, f)
	return f
}

func TestGatewayIPv6DeviceCOV(t *testing.T) {
	dev := newFakeDevice6(t)
	f := startIPv6DeviceGateway(t, dev, nil)
	c := newTestClient(t)
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}
	zero := uint32(0)

	c.send(subscribeCOV(7, 1, oid, &zero), f.addr())
	sub, src, proxyVMAC := dev.mustRecv(t, 2*time.Second)
	if sub.Service != bacnet.ServiceSubscribeCOV {
		t.Fatalf("device request = %+v", sub)
	}
	dev.send(t, simpleACK(sub.InvokeID, bacnet.ServiceSubscribeCOV), src, proxyVMAC)
	c.mustRecv(t, time.Second)

	dev.send(t, bacnet.APDU{Type: bacnet.PDUUnconfirmedRequest, HasService: true,
		Service: bacnet.ServiceUnconfirmedCOVNotification, Payload: covNotification(1, oid)}, src, proxyVMAC)
	got, _ := c.mustRecv(t, time.Second)
	if got.Service != bacnet.ServiceUnconfirmedCOVNotification {
		t.Fatalf("client notification = %+v", got)
	}
	if n := testutil.ToFloat64(f.metrics.Subscriptions); n != 1 {
		t.Fatalf("subscriptions = %v, want 1", n)
	}
}

func TestGatewayIPv6DeviceSegmentedWrite(t *testing.T) {
	dev := newFakeDevice6(t)
	f := startIPv6DeviceGateway(t, dev, writePolicy(t, access.ActionAllow, nil))
	c := newTestClient(t)
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}

	w := writeProperty(7, oid, bacnet.PropertyPresentValue)
	first, last := splitWrite(7, w)
	c.send(first, f.addr())
	if ack, _ := c.mustRecv(t, time.Second); ack.Type != bacnet.PDUSegmentACK {
		t.Fatalf("segment 0 ack = %+v", ack)
	}
	dev.expectNothing(t, 150*time.Millisecond)

	c.send(last, f.addr())
	req, src, proxyVMAC := dev.mustRecv(t, 2*time.Second)
	if req.Segmented || req.Service != bacnet.ServiceWriteProperty {
		t.Fatalf("device request = %+v", req)
	}
	dev.send(t, simpleACK(req.InvokeID, bacnet.ServiceWriteProperty), src, proxyVMAC)
	resp, _ := c.mustRecv(t, time.Second)
	if resp.Type != bacnet.PDUSimpleACK || resp.InvokeID != 7 {
		t.Fatalf("client answer = %+v", resp)
	}
}

func TestGatewayIPv6DeviceSegmentedResponse(t *testing.T) {
	dev := newFakeDevice6(t)
	f := startIPv6DeviceGateway(t, dev, nil)
	c := newTestClient(t)
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}

	c.send(readProperty(7, oid, bacnet.PropertyPresentValue), f.addr())
	req, src, proxyVMAC := dev.mustRecv(t, 2*time.Second)

	dev.send(t, segmentedACK(req.InvokeID, 1, true, []byte{0x0C, 0x00, 0x80, 0x00, 0x05}), src, proxyVMAC)
	first, _ := c.mustRecv(t, time.Second)
	if first.Type != bacnet.PDUComplexACK || !first.Segmented || !first.MoreFollows {
		t.Fatalf("first segment = %+v", first)
	}
	c.send(segmentACK(7, 1), f.addr())
	ack, _, _ := dev.mustRecv(t, 2*time.Second)
	if ack.Type != bacnet.PDUSegmentACK || ack.SequenceNumber != 1 {
		t.Fatalf("device segment ack = %+v", ack)
	}

	dev.send(t, segmentedACK(req.InvokeID, 2, false, []byte{0x44, 0x3F, 0x80, 0x00, 0x00}), src, proxyVMAC)
	last, _ := c.mustRecv(t, time.Second)
	if last.Type != bacnet.PDUComplexACK || last.MoreFollows {
		t.Fatalf("last segment = %+v", last)
	}
	c.send(segmentACK(7, 2), f.addr())
	if final, _, _ := dev.mustRecv(t, 2*time.Second); final.Type != bacnet.PDUSegmentACK || final.SequenceNumber != 2 {
		t.Fatalf("final device segment ack = %+v", final)
	}
}

func TestGatewayIPv6DeviceReplay(t *testing.T) {
	dev := newFakeDevice6(t)
	f := startIPv6DeviceGateway(t, dev, nil)
	c := newTestClient(t)
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}

	c.send(readProperty(7, oid, bacnet.PropertyPresentValue), f.addr())
	req, src, proxyVMAC := dev.mustRecv(t, 2*time.Second)
	dev.send(t, readPropertyACK(req.InvokeID, oid, bacnet.PropertyPresentValue,
		[]byte{0x44, 0x3F, 0x80, 0x00, 0x00}), src, proxyVMAC)
	c.mustRecv(t, time.Second)

	// The retransmission must come from the cache, not the device.
	c.send(readProperty(7, oid, bacnet.PropertyPresentValue), f.addr())
	replayed, _ := c.mustRecv(t, time.Second)
	if replayed.Type != bacnet.PDUComplexACK || replayed.InvokeID != 7 {
		t.Fatalf("replayed answer = %+v", replayed)
	}
	dev.expectNothing(t, 200*time.Millisecond)
	if n := testutil.ToFloat64(f.metrics.Replayed); n != 1 {
		t.Fatalf("replayed = %v, want 1", n)
	}
}

func TestGatewayIPv6RateLimit(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	limit := access.NewLimit(1)
	f := startGateway(t, Config{
		ListenAddr: "[::1]:0",
		DeviceAddr: dev.addr().String(),
	}, access.NewPolicy(nil, limit, nil))
	c := newTestClient6(t)
	proxyVMAC := discoverProxyVMAC(t, c, f.addr())
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}

	send := func(invoke byte) {
		c.sendFrame(bacnet.BVLC6{Function: bacnet.BVLC6OriginalUnicastNPDU,
			Src: c.vmac, Dst: proxyVMAC, Data: ipv6NPDU(readProperty(invoke, oid, bacnet.PropertyPresentValue))}.Marshal(), f.addr())
	}
	send(7)
	req, _, src := dev.mustRecv(t, time.Second)
	dev.send(t, readPropertyACK(req.InvokeID, oid, bacnet.PropertyPresentValue,
		[]byte{0x44, 0x3F, 0x80, 0x00, 0x00}), src)
	c.mustRecv(t, time.Second)

	// The bucket's burst is one, so the second request is dropped silently.
	send(8)
	c.expectNothing(t, 250*time.Millisecond)
	dev.expectNothing(t, 250*time.Millisecond)
	waitForMetric(t, "rate_limited", func() float64 {
		return testutil.ToFloat64(f.metrics.RateLimited)
	}, 1)
}

func TestGatewayIPv6AuditWriteDenied(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	audit, r := newAuditPipe(t)
	f := startGateway(t, Config{
		ListenAddr: "[::1]:0",
		DeviceAddr: dev.addr().String(),
		Audit:      audit,
	}, readOnlyPolicy(t))
	c := newTestClient6(t)
	proxyVMAC := discoverProxyVMAC(t, c, f.addr())
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}

	c.sendFrame(bacnet.BVLC6{Function: bacnet.BVLC6OriginalUnicastNPDU,
		Src: c.vmac, Dst: proxyVMAC, Data: ipv6NPDU(writeProperty(7, oid, bacnet.PropertyPresentValue))}.Marshal(), f.addr())

	ev := readAuditEvent(t, r)
	if ev.Event != "write_denied" || ev.Leg != "ip" || ev.Reason != "read_only" {
		t.Fatalf("audit event = %+v", ev)
	}
	if len(ev.Targets) != 1 || ev.Targets[0] != "analog-value,5:present-value" {
		t.Fatalf("audit targets = %v", ev.Targets)
	}
	dev.expectNothing(t, 200*time.Millisecond)
}

// TestGatewayIPv6DeviceRecovery: a device that is slow to answer address
// resolution drops the first request, then works once the answer arrives. The
// proxy must not cache "unresolved" forever.
func TestGatewayIPv6DeviceRecovery(t *testing.T) {
	dev := newFakeDevice6(t)
	f := startGateway(t, Config{ListenAddr: "127.0.0.1:0", DeviceAddr: dev.addr().String()}, nil)
	c := newTestClient(t)
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}

	c.send(readProperty(7, oid, bacnet.PropertyPresentValue), f.addr())
	c.expectNothing(t, 250*time.Millisecond)
	if n := testutil.ToFloat64(f.metrics.Forwarded); n != 0 {
		t.Fatalf("forwarded = %v while unresolved", n)
	}

	dev.answerResolution(t)
	waitDeviceVMAC(t, f)

	c.send(readProperty(8, oid, bacnet.PropertyPresentValue), f.addr())
	req, src, proxyVMAC := dev.mustRecv(t, 2*time.Second)
	dev.send(t, readPropertyACK(req.InvokeID, oid, bacnet.PropertyPresentValue,
		[]byte{0x44, 0x3F, 0x80, 0x00, 0x00}), src, proxyVMAC)
	got, _ := c.mustRecv(t, time.Second)
	if got.Type != bacnet.PDUComplexACK || got.InvokeID != 8 {
		t.Fatalf("answer after recovery = %+v", got)
	}
}

// TestGatewayIPv6DeviceLearnsFromBroadcast: a device that does not answer
// resolution still reveals its virtual address in any frame it sends, so the
// next client request can be forwarded.
func TestGatewayIPv6DeviceLearnsFromBroadcast(t *testing.T) {
	dev := newFakeDevice6(t)
	f := startGateway(t, Config{ListenAddr: "127.0.0.1:0", DeviceAddr: dev.addr().String()}, nil)
	src, _ := dev.captureResolution(t)

	// An unsolicited I-Am (device -> proxy) teaches the address without an
	// explicit resolution ACK.
	dev.sendBroadcast(t, iam(1001), src)
	waitDeviceVMAC(t, f)

	c := newTestClient(t)
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}
	c.send(readProperty(7, oid, bacnet.PropertyPresentValue), f.addr())
	req, deviceAddr, proxyVMAC := dev.mustRecv(t, 2*time.Second)
	dev.send(t, readPropertyACK(req.InvokeID, oid, bacnet.PropertyPresentValue,
		[]byte{0x44, 0x3F, 0x80, 0x00, 0x00}), deviceAddr, proxyVMAC)
	c.mustRecv(t, time.Second)
}

func TestGatewayIPv6DeviceZeroSourceIgnored(t *testing.T) {
	dev := newFakeDevice6(t)
	f := startGateway(t, Config{ListenAddr: "127.0.0.1:0", DeviceAddr: dev.addr().String()}, nil)
	src, _ := dev.captureResolution(t)

	// A zero source virtual address cannot be attributed; the device leg must
	// count it as a parse error and not learn a bogus address.
	frame := bacnet.BVLC6{Function: bacnet.BVLC6OriginalUnicastNPDU,
		Src: bacnet.VMAC{}, Dst: bacnet.VMAC{1, 2, 3},
		Data: bacnet.NPDU{APDU: iam(1001).Marshal()}.Marshal()}.Marshal()
	if _, err := dev.conn.WriteToUDP(frame, src); err != nil {
		t.Fatalf("device send: %v", err)
	}
	waitForMetric(t, "parse_errors", func() float64 {
		return testutil.ToFloat64(f.metrics.ParseErrors)
	}, 1)
	if f.g.deviceVMAC.Load() != nil {
		t.Fatal("a zero-source frame set the device virtual address")
	}
}

// TestRunnerMixedFamilies exercises the Runner directly with one IPv4 and one
// IPv6 device, and proves both gateways stop together.
func TestRunnerMixedFamilies(t *testing.T) {
	dev4 := newFakeDevice(t, "127.0.0.1")
	dev6 := newFakeDevice6(t)
	m4, m6 := observ.NewMetrics(), observ.NewMetrics()

	g4, err := New(Config{ListenAddr: "127.0.0.1:0", DeviceAddr: dev4.addr().String(),
		MaxPending: 256, RequestTimeout: 2 * time.Second}, nil, zap.NewNop(), m4)
	if err != nil {
		t.Fatalf("ipv4 gateway: %v", err)
	}
	g6, err := New(Config{ListenAddr: "127.0.0.1:0", DeviceAddr: dev6.addr().String(),
		MaxPending: 256, RequestTimeout: 2 * time.Second}, nil, zap.NewNop(), m6)
	if err != nil {
		t.Fatalf("ipv6 gateway: %v", err)
	}
	dev6.answerResolution(t)

	runner := NewRunner([]*Gateway{g4, g6})
	if got := runner.Gateways(); len(got) != 2 || got[0] != g4 || got[1] != g6 {
		t.Fatalf("Gateways() = %v", got)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = runner.Serve(ctx) }()
	waitDeviceVMAC(t, &fixture{g: g6, metrics: m6})

	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}
	c4 := newTestClient(t)
	c4.send(readProperty(7, oid, bacnet.PropertyPresentValue), g4.ClientAddr())
	req, _, src := dev4.mustRecv(t, 2*time.Second)
	dev4.send(t, readPropertyACK(req.InvokeID, oid, bacnet.PropertyPresentValue,
		[]byte{0x44, 0x3F, 0x80, 0x00, 0x00}), src)
	c4.mustRecv(t, time.Second)

	c6 := newTestClient(t)
	c6.send(readProperty(8, oid, bacnet.PropertyPresentValue), g6.ClientAddr())
	req6, src6, proxyVMAC := dev6.mustRecv(t, 2*time.Second)
	dev6.send(t, readPropertyACK(req6.InvokeID, oid, bacnet.PropertyPresentValue,
		[]byte{0x44, 0x40, 0x00, 0x00, 0x00}), src6, proxyVMAC)
	c6.mustRecv(t, time.Second)

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("runner did not stop")
	}
}
