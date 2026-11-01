package proxy

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/GalaxyGorilla/bacnet-shield/internal/access"
	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet"
)

func TestGatewayACL(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}

	denyList, err := access.NewList([]string{"192.0.2.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, access.NewPolicy(denyList, nil, nil))
	c := newTestClient(t)

	c.send(readProperty(7, oid, bacnet.PropertyPresentValue), f.addr())
	dev.expectNothing(t, 250*time.Millisecond)
	c.expectNothing(t, 100*time.Millisecond)
	if got := testutil.ToFloat64(f.metrics.ACLDenied); got != 1 {
		t.Fatalf("acl_denied = %v, want 1", got)
	}
}

func TestGatewayACLAllowsListedClient(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}
	list, err := access.NewList([]string{"127.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, access.NewPolicy(list, nil, nil))
	c := newTestClient(t)

	c.send(readProperty(7, oid, bacnet.PropertyPresentValue), f.addr())
	req, _, src := dev.mustRecv(t, time.Second)
	dev.send(t, readPropertyACK(req.InvokeID, oid, bacnet.PropertyPresentValue, []byte{0x44, 0x3F, 0x80, 0x00, 0x00}), src)
	c.mustRecv(t, time.Second)
	if got := testutil.ToFloat64(f.metrics.ACLDenied); got != 0 {
		t.Fatalf("acl_denied = %v, want 0", got)
	}
}

func TestGatewayRateLimit(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()},
		access.NewPolicy(nil, access.NewLimit(1), nil))
	c := newTestClient(t)

	c.send(readProperty(7, oid, bacnet.PropertyPresentValue), f.addr())
	dev.mustRecv(t, time.Second)
	c.send(readProperty(8, oid, bacnet.PropertyPresentValue), f.addr())
	dev.expectNothing(t, 250*time.Millisecond)
	if got := testutil.ToFloat64(f.metrics.RateLimited); got != 1 {
		t.Fatalf("rate_limited = %v, want 1", got)
	}
}

func TestGatewayWriteDeniedReadOnly(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, readOnlyPolicy(t))
	c := newTestClient(t)
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}

	c.send(writeProperty(7, oid, bacnet.PropertyPresentValue), f.addr())
	got, _ := c.mustRecv(t, time.Second)
	if got.Type != bacnet.PDUError || got.InvokeID != 7 || got.Service != bacnet.ServiceWriteProperty {
		t.Fatalf("denial = %+v", got)
	}
	class, code, ok := bacnet.ErrorClassAndCode(got.Payload)
	if !ok {
		t.Fatalf("error payload = %x, want class security / code write-access-denied", got.Payload)
	}
	if class != bacnet.ErrorClassSecurity || code != bacnet.ErrorCodeWriteAccessDenied {
		t.Fatalf("error = class %d code %d, want %d/%d", class, code,
			bacnet.ErrorClassSecurity, bacnet.ErrorCodeWriteAccessDenied)
	}
	dev.expectNothing(t, 250*time.Millisecond)
	if got := testutil.ToFloat64(f.metrics.WritesDenied); got != 1 {
		t.Fatalf("writes_denied = %v, want 1", got)
	}
}

func TestGatewayWriteAllowed(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, writePolicy(t, access.ActionAllow, nil))
	c := newTestClient(t)
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}

	c.send(writeProperty(7, oid, bacnet.PropertyPresentValue), f.addr())
	req, _, src := dev.mustRecv(t, time.Second)
	if req.Service != bacnet.ServiceWriteProperty {
		t.Fatalf("device request = %+v", req)
	}
	dev.send(t, simpleACK(req.InvokeID, bacnet.ServiceWriteProperty), src)
	got, _ := c.mustRecv(t, time.Second)
	if got.Type != bacnet.PDUSimpleACK || got.InvokeID != 7 {
		t.Fatalf("client response = %+v", got)
	}
}

func TestGatewayWritePolicyAllowRule(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	pol := writePolicy(t, access.ActionDeny, []access.Rule{
		{Spec: "analog-value:5:present-value", Action: access.ActionAllow},
	})
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, pol)
	c := newTestClient(t)

	allowed := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}
	c.send(writeProperty(7, allowed, bacnet.PropertyPresentValue), f.addr())
	req, _, src := dev.mustRecv(t, time.Second)
	dev.send(t, simpleACK(req.InvokeID, bacnet.ServiceWriteProperty), src)
	c.mustRecv(t, time.Second)

	other := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 6}
	c.send(writeProperty(8, other, bacnet.PropertyPresentValue), f.addr())
	got, _ := c.mustRecv(t, time.Second)
	if got.Type != bacnet.PDUError {
		t.Fatalf("uncovered write = %+v", got)
	}
	dev.expectNothing(t, 250*time.Millisecond)
}

func TestGatewayWriteMultipleStraddleDenied(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	pol := writePolicy(t, access.ActionDeny, []access.Rule{
		{Spec: "analog-value:5:present-value", Action: access.ActionAllow},
	})
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, pol)
	c := newTestClient(t)

	targets := []bacnet.WriteTarget{
		{Object: bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}, Property: bacnet.PropertyPresentValue},
		{Object: bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 6}, Property: bacnet.PropertyPresentValue},
	}
	c.send(writePropertyMultiple(7, targets), f.addr())
	got, _ := c.mustRecv(t, time.Second)
	if got.Type != bacnet.PDUError {
		t.Fatalf("straddling write = %+v", got)
	}
	dev.expectNothing(t, 250*time.Millisecond)
}

func TestGatewayUndecodableWriteDenied(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, writePolicy(t, access.ActionAllow, nil))
	c := newTestClient(t)

	bad := bacnet.APDU{Type: bacnet.PDUConfirmedRequest, InvokeID: 7, HasInvokeID: true,
		HasService: true, Service: bacnet.ServiceWriteProperty, Payload: []byte{0x0C, 0x00, 0x80}}
	c.send(bad, f.addr())
	got, _ := c.mustRecv(t, time.Second)
	if got.Type != bacnet.PDUError {
		t.Fatalf("undecodable write = %+v", got)
	}
	dev.expectNothing(t, 250*time.Millisecond)
}

func TestGatewaySegmentedWriteDenied(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, writePolicy(t, access.ActionAllow, nil))
	c := newTestClient(t)
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}

	w := writeProperty(7, oid, bacnet.PropertyPresentValue)
	w.Segmented = true
	w.SequenceNumber = 1
	w.WindowSize = 1
	c.send(w, f.addr())

	got, _ := c.mustRecv(t, time.Second)
	if got.Type != bacnet.PDUError {
		t.Fatalf("segmented write = %+v", got)
	}
	dev.expectNothing(t, 250*time.Millisecond)
}

func TestGatewayUnconfirmedWriteDenied(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, writePolicy(t, access.ActionDeny, nil))
	c := newTestClient(t)

	wg := bacnet.APDU{Type: bacnet.PDUUnconfirmedRequest, HasService: true,
		Service: bacnet.ServiceWriteGroup, Payload: []byte{0x0E, 0x0F}}
	c.send(wg, f.addr())
	dev.expectNothing(t, 250*time.Millisecond)
	c.expectNothing(t, 100*time.Millisecond)
	if got := testutil.ToFloat64(f.metrics.WritesDenied); got != 1 {
		t.Fatalf("writes_denied = %v, want 1", got)
	}
}

func TestGatewayUnconfirmedWriteAllowed(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, writePolicy(t, access.ActionAllow, nil))
	c := newTestClient(t)

	wg := bacnet.APDU{Type: bacnet.PDUUnconfirmedRequest, HasService: true,
		Service: bacnet.ServiceWriteGroup, Payload: []byte{0x0E, 0x0F}}
	c.send(wg, f.addr())
	req, _, _ := dev.mustRecv(t, time.Second)
	if req.Service != bacnet.ServiceWriteGroup {
		t.Fatalf("device request = %+v", req)
	}
}

func TestGatewaySubscribeCOVPropertyMultipleDenied(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, nil)
	c := newTestClient(t)

	sub := bacnet.APDU{Type: bacnet.PDUConfirmedRequest, InvokeID: 7, HasInvokeID: true,
		HasService: true, Service: bacnet.ServiceSubscribeCOVPropertyMultiple,
		Payload: []byte{0x0E, 0x0F}}
	c.send(sub, f.addr())

	got, _ := c.mustRecv(t, time.Second)
	if got.Type != bacnet.PDUError || got.Service != bacnet.ServiceSubscribeCOVPropertyMultiple {
		t.Fatalf("denial = %+v", got)
	}
	class, code, ok := bacnet.ErrorClassAndCode(got.Payload)
	if !ok {
		t.Fatalf("error payload = %x, want class services / code service-request-denied", got.Payload)
	}
	if class != bacnet.ErrorClassServices || code != bacnet.ErrorCodeServiceRequestDenied {
		t.Fatalf("error = class %d code %d, want %d/%d", class, code,
			bacnet.ErrorClassServices, bacnet.ErrorCodeServiceRequestDenied)
	}
	dev.expectNothing(t, 250*time.Millisecond)
}

func TestGatewayDeniedWriteDoesNotConsumeInvokeID(t *testing.T) {
	dev := newFakeDevice(t, "127.0.0.1")
	f := startGateway(t, Config{DeviceAddr: dev.addr().String()}, readOnlyPolicy(t))
	c := newTestClient(t)
	oid := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}

	c.send(writeProperty(7, oid, bacnet.PropertyPresentValue), f.addr())
	c.mustRecv(t, time.Second)

	c.send(readProperty(8, oid, bacnet.PropertyPresentValue), f.addr())
	req, _, _ := dev.mustRecv(t, time.Second)
	if req.InvokeID != 0 {
		t.Fatalf("read got device invoke id %d; the denied write leaked an id", req.InvokeID)
	}
}
