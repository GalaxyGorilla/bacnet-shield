package proxy

import (
	"bytes"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/GalaxyGorilla/bacnet-shield/internal/access"
	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet"
	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet/sc"
)

// fakeSCLeg is an in-memory BACnet/SC front leg. It records what the data
// plane sends (destination VMAC plus NPDU) and lets a test inject an inbound
// NPDU as if the hub had delivered it from a node.
type fakeSCLeg struct {
	mu      sync.Mutex
	handler func(*sc.MAC, []byte)
	sent    []scSend
}

type scSend struct {
	dest sc.MAC
	npdu []byte
}

func (f *fakeSCLeg) SetNPDUHandler(fn func(orig *sc.MAC, npdu []byte)) {
	f.mu.Lock()
	f.handler = fn
	f.mu.Unlock()
}

func (f *fakeSCLeg) SendNPDU(dest sc.MAC, npdu []byte) error {
	f.mu.Lock()
	f.sent = append(f.sent, scSend{dest: dest, npdu: append([]byte(nil), npdu...)})
	f.mu.Unlock()
	return nil
}

func (f *fakeSCLeg) deliver(t *testing.T, orig sc.MAC, n bacnet.NPDU, a bacnet.APDU) {
	t.Helper()
	n.APDU = a.Marshal()
	f.mu.Lock()
	h := f.handler
	f.mu.Unlock()
	if h == nil {
		t.Fatal("SC handler not attached")
	}
	h(&orig, n.Marshal())
}

func (f *fakeSCLeg) wait(t *testing.T, count int, timeout time.Duration) []scSend {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		if len(f.sent) >= count {
			out := append([]scSend(nil), f.sent...)
			f.mu.Unlock()
			return out
		}
		f.mu.Unlock()
		time.Sleep(5 * time.Millisecond)
	}
	f.mu.Lock()
	n := len(f.sent)
	f.mu.Unlock()
	t.Fatalf("SC leg received %d messages, want %d", n, count)
	return nil
}

func (f *fakeSCLeg) expectNothing(t *testing.T, wait time.Duration) {
	t.Helper()
	time.Sleep(wait)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sent) != 0 {
		t.Fatalf("SC leg received an unexpected message: %+v", f.sent)
	}
}

func (f *fakeSCLeg) expectNoMore(t *testing.T, count int, wait time.Duration) {
	t.Helper()
	time.Sleep(wait)
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.sent) != count {
		t.Fatalf("SC leg received %d messages, want exactly %d", len(f.sent), count)
	}
}

func decodeSCNPDU(t *testing.T, npdu []byte) bacnet.APDU {
	t.Helper()
	n, err := bacnet.ParseNPDU(npdu)
	if err != nil {
		t.Fatalf("SC npdu parse: %v", err)
	}
	a, err := bacnet.ParseAPDU(n.APDU)
	if err != nil {
		t.Fatalf("SC apdu parse: %v", err)
	}
	return a
}

// readObjectID decodes the object id from a ReadProperty payload built by the
// test helper: 0x0C | object id | 0x19 | property.
func readObjectID(t *testing.T, a bacnet.APDU) bacnet.ObjectID {
	t.Helper()
	if len(a.Payload) < 5 || a.Payload[0] != 0x0C {
		t.Fatalf("read-property payload = %x", a.Payload)
	}
	oid, err := bacnet.ParseObjectID(a.Payload[1:5])
	if err != nil {
		t.Fatal(err)
	}
	return oid
}

// TestGatewaySCMultiClientInvokeIDs is the SC counterpart of the IP leg's
// concurrent-client test: two SC nodes use the same invoke ID at the same time
// and each must get its own answer, addressed to its own VMAC.
func TestGatewaySCMultiClientInvokeIDs(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, nil)
	leg := &fakeSCLeg{}
	f.g.AttachSC(leg)

	clientA := sc.MAC{0x02, 0x00, 0x00, 0x00, 0x00, 0x0A}
	clientB := sc.MAC{0x02, 0x00, 0x00, 0x00, 0x00, 0x0B}
	oidA := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 1}
	oidB := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 2}

	// Same invoke ID (7) from both clients. The proxy must allocate distinct
	// device-leg IDs and keep the reverse mapping per client.
	leg.deliver(t, clientA, bacnet.NPDU{}, readProperty(7, oidA, bacnet.PropertyPresentValue))
	leg.deliver(t, clientB, bacnet.NPDU{}, readProperty(7, oidB, bacnet.PropertyPresentValue))

	devID := map[bacnet.ObjectID]byte{}
	var deviceAddr *net.UDPAddr
	for i := 0; i < 2; i++ {
		a, _, src, _, err := dev.recv(2 * time.Second)
		if err != nil {
			t.Fatalf("device receive %d: %v", i, err)
		}
		if a.Type != bacnet.PDUConfirmedRequest {
			t.Fatalf("device got %s, want a confirmed request", a.Type)
		}
		devID[readObjectID(t, a)] = a.InvokeID
		deviceAddr = src
	}
	if len(devID) != 2 {
		t.Fatalf("device saw %d distinct objects, want 2", len(devID))
	}
	if devID[oidA] == devID[oidB] {
		t.Fatalf("both clients got device invoke id %d; they must not share one", devID[oidA])
	}

	// The value echoes the device-leg invoke ID so each client's answer can
	// be traced without reading the proxy's tables.
	for oid, id := range devID {
		dev.send(t, readPropertyACK(id, oid, bacnet.PropertyPresentValue, []byte{id}), deviceAddr)
	}

	sent := leg.wait(t, 2, 2*time.Second)
	byDest := map[sc.MAC]scSend{}
	for _, s := range sent {
		byDest[s.dest] = s
	}
	check := func(client sc.MAC, oid bacnet.ObjectID) {
		s, ok := byDest[client]
		if !ok {
			t.Fatalf("no answer for %s", client)
		}
		a := decodeSCNPDU(t, s.npdu)
		if a.Type != bacnet.PDUComplexACK {
			t.Fatalf("%s got %s, want a complex ack", client, a.Type)
		}
		if a.InvokeID != 7 {
			t.Fatalf("%s invoke id = %d, want 7 (the client's own)", client, a.InvokeID)
		}
		if got := readObjectID(t, a); got != oid {
			t.Fatalf("%s answer for %v, want %v", client, got, oid)
		}
		if len(a.Payload) < 2 {
			t.Fatalf("%s empty payload", client)
		}
		// readPropertyACK puts the value between the opening 0x3E and the
		// closing 0x3F; one octet here is the device invoke ID.
		if value := a.Payload[8 : len(a.Payload)-1]; !bytes.Equal(value, []byte{devID[oid]}) {
			t.Fatalf("%s value = %x, want device id %d", client, value, devID[oid])
		}
	}
	check(clientA, oidA)
	check(clientB, oidB)

	if got := testutil.ToFloat64(f.metrics.Pending); got != 0 {
		t.Fatalf("pending = %v after both answers, want 0", got)
	}
}

// TestGatewaySCWritePolicyDenied proves the SC leg reuses the same write
// policy and the same Error PDU shape as the IP leg.
func TestGatewaySCWritePolicyDenied(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, readOnlyPolicy(t))
	leg := &fakeSCLeg{}
	f.g.AttachSC(leg)

	client := sc.MAC{0x02, 0x00, 0x00, 0x00, 0x00, 0x0C}
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 3}
	leg.deliver(t, client, bacnet.NPDU{}, writeProperty(9, oid, bacnet.PropertyPresentValue))

	sent := leg.wait(t, 1, 2*time.Second)
	if sent[0].dest != client {
		t.Fatalf("denial sent to %s, want %s", sent[0].dest, client)
	}
	a := decodeSCNPDU(t, sent[0].npdu)
	if a.Type != bacnet.PDUError {
		t.Fatalf("denial pdu = %s, want error", a.Type)
	}
	if a.InvokeID != 9 || a.Service != bacnet.ServiceWriteProperty {
		t.Fatalf("denial echoed invoke=%d service=%d, want 9/%d", a.InvokeID, a.Service, bacnet.ServiceWriteProperty)
	}
	class, code, ok := bacnet.ErrorClassAndCode(a.Payload)
	if !ok || class != bacnet.ErrorClassSecurity || code != bacnet.ErrorCodeWriteAccessDenied {
		t.Fatalf("denial class/code = %v/%v ok=%v, want security/write-access-denied", class, code, ok)
	}

	dev.expectNothing(t, 300*time.Millisecond)
	if got := testutil.ToFloat64(f.metrics.WritesDenied); got != 1 {
		t.Fatalf("denied writes = %v, want 1", got)
	}
}

// TestGatewaySCAllowList proves the opt-in VMAC allow-list gates before the
// NPDU is parsed: an off-list node is silent and never reaches the device.
func TestGatewaySCAllowList(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	allowed := sc.MAC{0x02, 0x00, 0x00, 0x00, 0x00, 0x0D}
	denied := sc.MAC{0x02, 0x00, 0x00, 0x00, 0x00, 0x0E}
	list, err := access.NewMACList([]string{allowed.String()})
	if err != nil {
		t.Fatal(err)
	}
	pol := access.NewPolicy(nil, nil, nil).WithSCAllow(list)
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, pol)
	leg := &fakeSCLeg{}
	f.g.AttachSC(leg)

	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 4}
	leg.deliver(t, denied, bacnet.NPDU{}, readProperty(1, oid, bacnet.PropertyPresentValue))
	dev.expectNothing(t, 300*time.Millisecond)
	leg.expectNothing(t, 100*time.Millisecond)
	if got := testutil.ToFloat64(f.metrics.ACLDenied); got != 1 {
		t.Fatalf("acl denials = %v, want 1", got)
	}

	leg.deliver(t, allowed, bacnet.NPDU{}, readProperty(1, oid, bacnet.PropertyPresentValue))
	dev.mustRecv(t, 2*time.Second)
}

// TestGatewaySCRateLimitIsPerVMAC proves the SC leg charges a bucket per
// virtual MAC, exactly as the IP leg charges per source IP.
func TestGatewaySCRateLimitIsPerVMAC(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()},
		access.NewPolicy(nil, access.NewLimit(1), nil))
	leg := &fakeSCLeg{}
	f.g.AttachSC(leg)

	noisy := sc.MAC{0x02, 0x00, 0x00, 0x00, 0x00, 0x0F}
	quiet := sc.MAC{0x02, 0x00, 0x00, 0x00, 0x00, 0x10}
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}

	leg.deliver(t, noisy, bacnet.NPDU{}, readProperty(1, oid, bacnet.PropertyPresentValue))
	dev.mustRecv(t, 2*time.Second)
	leg.deliver(t, noisy, bacnet.NPDU{}, readProperty(2, oid, bacnet.PropertyPresentValue))
	dev.expectNothing(t, 300*time.Millisecond)

	// A different VMAC still has its own token.
	leg.deliver(t, quiet, bacnet.NPDU{}, readProperty(3, oid, bacnet.PropertyPresentValue))
	dev.mustRecv(t, 2*time.Second)

	if got := testutil.ToFloat64(f.metrics.RateLimited); got != 1 {
		t.Fatalf("rate-limited = %v, want 1", got)
	}
}

// TestGatewaySCIAmReachesActiveSCClients proves the active-client table, not
// just correlated replies, works for SC peers.
func TestGatewaySCIAmReachesActiveSCClients(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, nil)
	leg := &fakeSCLeg{}
	f.g.AttachSC(leg)

	a := sc.MAC{0x02, 0x00, 0x00, 0x00, 0x00, 0x11}
	b := sc.MAC{0x02, 0x00, 0x00, 0x00, 0x00, 0x12}
	leg.deliver(t, a, bacnet.NPDU{}, whoIs())
	leg.deliver(t, b, bacnet.NPDU{}, whoIs())
	_, _, deviceAddr := dev.mustRecv(t, 2*time.Second)
	dev.mustRecv(t, 2*time.Second)

	dev.send(t, iam(42), deviceAddr)

	sent := leg.wait(t, 2, 2*time.Second)
	seen := map[sc.MAC]bool{}
	for _, s := range sent {
		if s.dest != a && s.dest != b {
			t.Fatalf("I-Am sent to unknown peer %s", s.dest)
		}
		seen[s.dest] = true
		if p := decodeSCNPDU(t, s.npdu); p.Service != bacnet.ServiceIAm {
			t.Fatalf("notification service = %d, want I-Am", p.Service)
		}
	}
	if !seen[a] || !seen[b] {
		t.Fatalf("I-Am reached %v, want both SC clients", seen)
	}
}

// TestGatewaySCCovNotificationRoutesToSubscriber proves COV routing is
// peer-agnostic: an SC subscriber receives the notification addressed to its
// VMAC, and an unrelated node does not.
func TestGatewaySCCovNotificationRoutesToSubscriber(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, nil)
	leg := &fakeSCLeg{}
	f.g.AttachSC(leg)

	subscriber := sc.MAC{0x02, 0x00, 0x00, 0x00, 0x00, 0x13}
	other := sc.MAC{0x02, 0x00, 0x00, 0x00, 0x00, 0x14}
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 6}

	// Both nodes are active, so a broken filter would visible fan out to both.
	leg.deliver(t, subscriber, bacnet.NPDU{}, readProperty(1, bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 7}, bacnet.PropertyPresentValue))
	leg.deliver(t, other, bacnet.NPDU{}, readProperty(2, bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 8}, bacnet.PropertyPresentValue))
	_, _, deviceAddr := dev.mustRecv(t, 2*time.Second)
	dev.mustRecv(t, 2*time.Second)

	lifetime := uint32(0)
	leg.deliver(t, subscriber, bacnet.NPDU{}, subscribeCOV(3, 1, oid, &lifetime))
	sub, _, _ := dev.mustRecv(t, 2*time.Second)
	dev.send(t, simpleACK(sub.InvokeID, bacnet.ServiceSubscribeCOV), deviceAddr)

	// The SimpleACK is relayed to the subscriber; wait for it before sending
	// the notification so the two sends cannot be confused.
	if ack := leg.wait(t, 1, 2*time.Second); ack[0].dest != subscriber {
		t.Fatalf("SimpleACK sent to %s, want subscriber %s", ack[0].dest, subscriber)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && testutil.ToFloat64(f.metrics.Subscriptions) != 1 {
		time.Sleep(5 * time.Millisecond)
	}
	if got := testutil.ToFloat64(f.metrics.Subscriptions); got != 1 {
		t.Fatalf("subscriptions = %v, want 1", got)
	}

	// The device's unconfirmed notification must reach only the subscriber.
	note := bacnet.APDU{Type: bacnet.PDUUnconfirmedRequest, HasService: true,
		Service: bacnet.ServiceUnconfirmedCOVNotification, Payload: covNotification(1, oid)}
	dev.send(t, note, deviceAddr)

	sent := leg.wait(t, 2, 2*time.Second)
	last := sent[len(sent)-1]
	if last.dest != subscriber {
		t.Fatalf("notification sent to %s, want subscriber %s", last.dest, subscriber)
	}
	a := decodeSCNPDU(t, last.npdu)
	if a.Service != bacnet.ServiceUnconfirmedCOVNotification {
		t.Fatalf("last service = %d, want unconfirmed COV notification", a.Service)
	}
	leg.expectNoMore(t, 2, 200*time.Millisecond)
}
