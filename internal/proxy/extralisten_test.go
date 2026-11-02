package proxy

import (
	"net"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet"
)

// TestExtraListenSharedState is the alignment check with modbus-shield's
// extra_listen: two front doors for one device share one device leg, one
// policy and one set of routing tables. Each door still delivers answers to
// the client that used it.
func TestExtraListenSharedState(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{
		ListenAddr:  "127.0.0.1:0",
		ExtraListen: []string{"127.0.0.1:0"},
		DeviceAddr:  dev.addr().String(),
	}, nil)
	addrs := f.g.ClientAddrs()
	if len(addrs) != 2 {
		t.Fatalf("listeners = %d, want 2", len(addrs))
	}
	a, b := newTestClient(t), newTestClient(t)
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}

	// Same invoke ID through both doors: the shared pending table must still
	// allocate separate device IDs and route each answer back to its door.
	a.send(readProperty(7, oid, bacnet.PropertyPresentValue), addrs[0])
	b.send(readProperty(7, oid, bacnet.PropertyPresentValue), addrs[1])

	devID := map[byte]bool{}
	var deviceAddr *net.UDPAddr
	for i := 0; i < 2; i++ {
		req, _, src := dev.mustRecv(t, time.Second)
		if devID[req.InvokeID] {
			t.Fatalf("both doors got device invoke id %d", req.InvokeID)
		}
		devID[req.InvokeID] = true
		deviceAddr = src
		dev.send(t, readPropertyACK(req.InvokeID, oid, bacnet.PropertyPresentValue,
			[]byte{0x44, 0x3F, 0x80, 0x00, 0x00}), src)
	}
	for _, c := range []*testClient{a, b} {
		got, _ := c.mustRecv(t, time.Second)
		if got.Type != bacnet.PDUComplexACK || got.InvokeID != 7 {
			t.Fatalf("answer = %+v, want a complex ack for invoke 7", got)
		}
	}

	// A completed request is replayed even when the retransmission arrives on
	// the other door: the cache is shared, and the key is the client's
	// address, not the listener it used.
	a.send(readProperty(9, oid, bacnet.PropertyPresentValue), addrs[0])
	req, _, _ := dev.mustRecv(t, time.Second)
	dev.send(t, readPropertyACK(req.InvokeID, oid, bacnet.PropertyPresentValue,
		[]byte{0x44, 0x40, 0x00, 0x00, 0x00}), deviceAddr)
	a.mustRecv(t, time.Second)

	a.send(readProperty(9, oid, bacnet.PropertyPresentValue), addrs[1])
	replayed, _ := a.mustRecv(t, time.Second)
	if replayed.Type != bacnet.PDUComplexACK || replayed.InvokeID != 9 {
		t.Fatalf("replayed answer = %+v", replayed)
	}
	dev.expectNothing(t, 200*time.Millisecond)
	if n := testutil.ToFloat64(f.metrics.Replayed); n != 1 {
		t.Fatalf("replayed = %v, want 1", n)
	}
}

// TestExtraListenMixedFamilies: one gateway may have an IPv4 and an IPv6 front
// door. Both share the same device leg and policy.
func TestExtraListenMixedFamilies(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{
		ListenAddr:  "127.0.0.1:0",
		ExtraListen: []string{"[::1]:0"},
		DeviceAddr:  dev.addr().String(),
	}, nil)
	addrs := f.g.ClientAddrs()
	if len(addrs) != 2 {
		t.Fatalf("listeners = %d, want 2", len(addrs))
	}
	var v4, v6 *net.UDPAddr
	for _, a := range addrs {
		if a.IP.To4() != nil {
			v4 = a
		} else {
			v6 = a
		}
	}
	if v4 == nil || v6 == nil {
		t.Fatalf("addresses = %v, want one IPv4 and one IPv6", addrs)
	}

	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}
	c4 := newTestClient(t)
	c4.send(readProperty(7, oid, bacnet.PropertyPresentValue), v4)
	req, _, src := dev.mustRecv(t, time.Second)
	dev.send(t, readPropertyACK(req.InvokeID, oid, bacnet.PropertyPresentValue,
		[]byte{0x44, 0x3F, 0x80, 0x00, 0x00}), src)
	c4.mustRecv(t, time.Second)

	c6 := newTestClient6(t)
	proxyVMAC := discoverProxyVMAC(t, c6, v6)
	c6.sendFrame(bacnet.BVLC6{Function: bacnet.BVLC6OriginalUnicastNPDU,
		Src: c6.vmac, Dst: proxyVMAC,
		Data: ipv6NPDU(readProperty(8, oid, bacnet.PropertyPresentValue))}.Marshal(), v6)
	req, _, src = dev.mustRecv(t, time.Second)
	dev.send(t, readPropertyACK(req.InvokeID, oid, bacnet.PropertyPresentValue,
		[]byte{0x44, 0x40, 0x00, 0x00, 0x00}), src)
	if got := c6.mustRecv(t, time.Second); got.Dst != c6.vmac {
		t.Fatalf("IPv6 answer destination = %s, want %s", got.Dst, c6.vmac)
	}
}

// TestExtraListenClosedWithGateway: every front door is closed on shutdown, so
// a restart can bind the same addresses again.
func TestExtraListenClosedWithGateway(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{
		ListenAddr:  "127.0.0.1:0",
		ExtraListen: []string{"127.0.0.1:0"},
		DeviceAddr:  dev.addr().String(),
	}, nil)
	addrs := f.g.ClientAddrs()

	if err := f.g.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	for _, a := range addrs {
		conn, err := net.ListenUDP("udp4", a)
		if err != nil {
			t.Fatalf("listen %s after close: %v", a, err)
		}
		_ = conn.Close()
	}
}
