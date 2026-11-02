package proxy

import (
	"bufio"
	"encoding/json"
	"io"
	"testing"
	"time"

	"github.com/GalaxyGorilla/bacnet-shield/internal/access"
	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet"
	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet/sc"
	"github.com/GalaxyGorilla/bacnet-shield/internal/observ"
)

// newAuditPipe builds an audit stream the test can read line by line. The
// pipe reader is closed before the audit is closed (LIFO cleanup), so a writer
// blocked on the pipe unblocks and Close does not hang.
func newAuditPipe(t *testing.T) (*observ.Audit, *bufio.Reader) {
	t.Helper()
	pr, pw := io.Pipe()
	a := observ.NewAuditWriter(pw, nil)
	t.Cleanup(func() {
		_ = pr.Close()
		_ = a.Close()
	})
	return a, bufio.NewReader(pr)
}

// readAuditEvent reads and decodes the next audit line. The read runs in a
// goroutine so a missing event fails the test instead of hanging it.
func readAuditEvent(t *testing.T, r *bufio.Reader) observ.AuditEvent {
	t.Helper()
	type result struct {
		line string
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		line, err := r.ReadString('\n')
		ch <- result{line, err}
	}()
	select {
	case res := <-ch:
		if res.err != nil {
			t.Fatalf("audit read: %v", res.err)
		}
		var ev observ.AuditEvent
		if err := json.Unmarshal([]byte(res.line), &ev); err != nil {
			t.Fatalf("audit json: %v (%q)", err, res.line)
		}
		return ev
	case <-time.After(2 * time.Second):
		t.Fatal("no audit event arrived")
		return observ.AuditEvent{}
	}
}

// TestGatewayAuditWriteDenied proves a refused write produces one structured
// record naming the client, the service and the decoded object/property target
// (the thing the human log could not say before).
func TestGatewayAuditWriteDenied(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	audit, r := newAuditPipe(t)
	f := startGateway(t, Config{DeviceAddr: dev.addr().String(), DeviceName: "boiler", Audit: audit}, readOnlyPolicy(t))

	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}
	c := newTestClient(t)
	c.send(writeProperty(7, oid, bacnet.PropertyPresentValue), f.addr())

	ev := readAuditEvent(t, r)
	if ev.Event != "write_denied" || ev.Leg != "ip" {
		t.Fatalf("event = %q leg = %q", ev.Event, ev.Leg)
	}
	// In a co-hosted process the record must name the device it concerns, so
	// two devices' denials can be told apart in one stream.
	if ev.Device != "boiler" {
		t.Fatalf("device = %q, want boiler", ev.Device)
	}
	if ev.Service != "write-property" {
		t.Fatalf("service = %q, want write-property", ev.Service)
	}
	if len(ev.Targets) != 1 || ev.Targets[0] != "analog-value,5:present-value" {
		t.Fatalf("targets = %v, want [analog-value,5:present-value]", ev.Targets)
	}
	if ev.Reason != "read_only" {
		t.Fatalf("reason = %q, want read_only", ev.Reason)
	}
	if ev.Client == "" || ev.Time == "" {
		t.Fatalf("client/time not filled: %+v", ev)
	}
	dev.expectNothing(t, 200*time.Millisecond)
}

// TestGatewayAuditACLDenied proves an off-list client still leaves an audit
// record even though it gets no reply at all.
func TestGatewayAuditACLDenied(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	audit, r := newAuditPipe(t)
	denyList, err := access.NewList([]string{"192.0.2.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	f := startGateway(t, Config{DeviceAddr: dev.addr().String(), Audit: audit},
		access.NewPolicy(denyList, nil, nil))

	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}
	c := newTestClient(t)
	c.send(readProperty(7, oid, bacnet.PropertyPresentValue), f.addr())

	ev := readAuditEvent(t, r)
	if ev.Event != "acl_denied" || ev.Leg != "ip" {
		t.Fatalf("event = %q leg = %q", ev.Event, ev.Leg)
	}
	if ev.Client == "" {
		t.Fatal("client not recorded")
	}
	dev.expectNothing(t, 200*time.Millisecond)
}

// TestGatewayAuditSCACLDenied proves the SC leg is labelled and keyed by VMAC,
// so an operator can tell the two doors apart in one stream.
func TestGatewayAuditSCACLDenied(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	audit, r := newAuditPipe(t)
	allowed := sc.MAC{0x02, 0x00, 0x00, 0x00, 0x00, 0x0D}
	denied := sc.MAC{0x02, 0x00, 0x00, 0x00, 0x00, 0x0E}
	list, err := access.NewMACList([]string{allowed.String()})
	if err != nil {
		t.Fatal(err)
	}
	pol := access.NewPolicy(nil, nil, nil).WithSCAllow(list)
	f := startGateway(t, Config{DeviceAddr: dev.addr().String(), Audit: audit}, pol)
	leg := &fakeSCLeg{}
	f.g.AttachSC(leg)

	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}
	leg.deliver(t, denied, bacnet.NPDU{}, readProperty(1, oid, bacnet.PropertyPresentValue))

	ev := readAuditEvent(t, r)
	if ev.Event != "acl_denied" || ev.Leg != "sc" {
		t.Fatalf("event = %q leg = %q", ev.Event, ev.Leg)
	}
	if ev.Client != "sc:"+denied.String() {
		t.Fatalf("client = %q, want sc:%s", ev.Client, denied.String())
	}
	dev.expectNothing(t, 200*time.Millisecond)
}

// TestGatewayAuditUnsupportedSubscription records the service the proxy itself
// refuses to forward.
func TestGatewayAuditUnsupportedSubscription(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	audit, r := newAuditPipe(t)
	f := startGateway(t, Config{DeviceAddr: dev.addr().String(), Audit: audit}, nil)

	c := newTestClient(t)
	c.send(bacnet.APDU{Type: bacnet.PDUConfirmedRequest, HasService: true, Segmented: true,
		Service: bacnet.ServiceSubscribeCOV, InvokeID: 3}, f.addr())

	ev := readAuditEvent(t, r)
	if ev.Event != "unsupported_subscription" {
		t.Fatalf("event = %q, want unsupported_subscription", ev.Event)
	}
	if ev.Service != "subscribe-cov" {
		t.Fatalf("service = %q", ev.Service)
	}
	dev.expectNothing(t, 200*time.Millisecond)
}
