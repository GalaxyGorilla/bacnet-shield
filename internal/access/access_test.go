package access

import (
	"net"
	"testing"
	"time"

	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet"
	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet/sc"
)

// writeProperty builds a WriteProperty APDU for one object/property.
func writeProperty(t *testing.T, oid bacnet.ObjectID, prop bacnet.PropertyID) bacnet.APDU {
	t.Helper()
	payload := append([]byte{0x0C}, oid.AppendTo(nil)...)
	payload = append(payload, 0x19, byte(prop))
	payload = append(payload, 0x3E, 0x44, 0x3F, 0x80, 0x00, 0x00, 0x3F)
	return bacnet.APDU{Type: bacnet.PDUConfirmedRequest, HasService: true,
		Service: bacnet.ServiceWriteProperty, Payload: payload}
}

// writePropertyMultiple builds a WritePropertyMultiple APDU for the targets.
func writePropertyMultiple(t *testing.T, targets []bacnet.WriteTarget) bacnet.APDU {
	t.Helper()
	payload := []byte{0x0E}
	for _, tg := range targets {
		payload = append(payload, 0x0C)
		payload = append(payload, tg.Object.AppendTo(nil)...)
		payload = append(payload, 0x1E, 0x09, byte(tg.Property))
		payload = append(payload, 0x2E, 0x44, 0x3F, 0x80, 0x00, 0x00, 0x2F, 0x1F)
	}
	payload = append(payload, 0x0F)
	return bacnet.APDU{Type: bacnet.PDUConfirmedRequest, HasService: true,
		Service: bacnet.ServiceWritePropertyMultiple, Payload: payload}
}

func TestList(t *testing.T) {
	l, err := NewList([]string{"10.0.0.0/8", "192.0.2.7", "  ", "2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"10.1.2.3", "192.0.2.7", "2001:db8::1"} {
		if !l.Allowed(net.ParseIP(ip)) {
			t.Fatalf("%s not allowed", ip)
		}
	}
	for _, ip := range []string{"11.0.0.1", "192.0.2.8", "2001:db9::1"} {
		if l.Allowed(net.ParseIP(ip)) {
			t.Fatalf("%s allowed", ip)
		}
	}
	if !(*List)(nil).Allowed(net.ParseIP("203.0.113.1")) {
		t.Fatal("nil list must allow everyone")
	}
	empty, err := NewList(nil)
	if err != nil || !empty.Allowed(net.ParseIP("203.0.113.1")) {
		t.Fatalf("empty list = %v, %v", empty, err)
	}
	if _, err := NewList([]string{"not-an-ip"}); err == nil {
		t.Fatal("invalid entry accepted")
	}
}

func TestLimit(t *testing.T) {
	ip := net.ParseIP("192.0.2.1")
	now := time.Unix(1000, 0)
	l := NewLimit(2) // burst 2
	for i := 0; i < 2; i++ {
		if !l.Allow(ip, now) {
			t.Fatalf("request %d refused inside the burst", i)
		}
	}
	if l.Allow(ip, now) {
		t.Fatal("third request admitted with an empty bucket")
	}
	if !l.Allow(ip, now.Add(500*time.Millisecond)) {
		t.Fatal("half a second at 2/s did not refill one token")
	}
	if l.Allow(ip, now.Add(500*time.Millisecond)) {
		t.Fatal("second request admitted from one refilled token")
	}
	// A different client has its own bucket.
	if !l.Allow(net.ParseIP("192.0.2.2"), now) {
		t.Fatal("a new client was charged for another client's traffic")
	}
	// A zero rate disables the limiter.
	if !NewLimit(0).Allow(ip, now) {
		t.Fatal("rate 0 limited")
	}
}

func TestLimitTableCapAndSweep(t *testing.T) {
	now := time.Unix(2000, 0)
	l := NewLimit(1)
	for i := 0; i < maxBuckets; i++ {
		ip := net.IPv4(10, byte(i>>8), byte(i), 1)
		if !l.Allow(ip, now) {
			t.Fatalf("bucket %d refused before the cap", i)
		}
	}
	fresh := net.ParseIP("203.0.113.9")
	if l.Allow(fresh, now) {
		t.Fatal("a new client was admitted with the table at its cap (must fail closed)")
	}
	// After the idle horizon the sweep must make room again.
	if !l.Allow(fresh, now.Add(bucketIdleTime+gcInterval)) {
		t.Fatal("sweep did not free idle buckets")
	}
}

func TestMACList(t *testing.T) {
	a := sc.MAC{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	b := sc.MAC{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}

	empty, err := NewMACList(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !empty.Allowed(a) {
		t.Fatal("empty list did not admit everything (protection must be opt-in)")
	}
	if _, err := NewMACList([]string{"not-a-mac"}); err == nil {
		t.Fatal("invalid entry accepted")
	}
	for _, bad := range []string{sc.MAC{}.String(), sc.BroadcastMAC.String()} {
		if _, err := NewMACList([]string{bad}); err == nil {
			t.Fatalf("%q accepted as a unicast allow-list entry", bad)
		}
	}

	l, err := NewMACList([]string{a.String()})
	if err != nil {
		t.Fatal(err)
	}
	if !l.Allowed(a) {
		t.Fatal("listed VMAC refused")
	}
	if l.Allowed(b) {
		t.Fatal("unlisted VMAC admitted")
	}
}

func TestPolicyCheckSC(t *testing.T) {
	a := sc.MAC{0x02, 0x00, 0x00, 0x00, 0x00, 0x01}
	b := sc.MAC{0x02, 0x00, 0x00, 0x00, 0x00, 0x02}
	now := time.Unix(3000, 0)

	list, err := NewMACList([]string{a.String()})
	if err != nil {
		t.Fatal(err)
	}
	p := NewPolicy(nil, NewLimit(1), nil).WithSCAllow(list)

	if d := p.CheckSC(a, now); d != Allow {
		t.Fatalf("listed VMAC = %v, want allow", d)
	}
	if d := p.CheckSC(a, now); d != DenyRate {
		t.Fatalf("second request from the same VMAC = %v, want rate", d)
	}
	// Off-list is checked before the rate limit, so it never consumes a
	// token (and, importantly, cannot exhaust another node's budget).
	if d := p.CheckSC(b, now); d != DenyACL {
		t.Fatalf("unlisted VMAC = %v, want acl", d)
	}
	if d := p.CheckSC(b, now); d != DenyACL {
		t.Fatalf("unlisted VMAC is still not a rate denial: %v", d)
	}
	// A different listed VMAC has its own bucket.
	list2, err := NewMACList([]string{a.String(), b.String()})
	if err != nil {
		t.Fatal(err)
	}
	p2 := NewPolicy(nil, NewLimit(1), nil).WithSCAllow(list2)
	if d := p2.CheckSC(b, now); d != Allow {
		t.Fatalf("second listed VMAC = %v, want allow", d)
	}

	// The SC allow-list does not leak into the IP leg, and vice versa.
	if d := p.Check(net.ParseIP("192.0.2.1"), now); d != Allow {
		t.Fatalf("IP leg = %v, want allow (no IP list configured)", d)
	}
	if d := (*Policy)(nil).CheckSC(b, now); d != Allow {
		t.Fatalf("nil policy = %v, want allow", d)
	}
}

func TestWritePolicyReadOnly(t *testing.T) {
	p, err := NewWritePolicy(true, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Allowed(writeProperty(t, bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}, bacnet.PropertyPresentValue)) {
		t.Fatal("read_only allowed a write")
	}
	if !p.Allowed(bacnet.APDU{Type: bacnet.PDUConfirmedRequest, HasService: true, Service: bacnet.ServiceReadProperty}) {
		t.Fatal("read_only refused a read")
	}
	if _, err := NewWritePolicy(true, ActionDeny, nil); err == nil {
		t.Fatal("read_only + write_policy accepted")
	}
}

func TestWritePolicyDefaultDeny(t *testing.T) {
	p, err := NewWritePolicy(false, ActionDeny, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.Allowed(writeProperty(t, bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}, bacnet.PropertyPresentValue)) {
		t.Fatal("default deny allowed a write")
	}
	if !p.Allowed(bacnet.APDU{Type: bacnet.PDUConfirmedRequest, HasService: true, Service: bacnet.ServiceReadProperty}) {
		t.Fatal("default deny refused a read")
	}
}

func TestWritePolicyAllowRule(t *testing.T) {
	p, err := NewWritePolicy(false, ActionDeny, []Rule{
		{Spec: "analog-value:5:present-value", Action: ActionAllow},
	})
	if err != nil {
		t.Fatal(err)
	}
	allowed := bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}
	if !p.Allowed(writeProperty(t, allowed, bacnet.PropertyPresentValue)) {
		t.Fatal("allow rule did not cover the target")
	}
	if p.Allowed(writeProperty(t, allowed, bacnet.PropertyRelinquishDefault)) {
		t.Fatal("allow rule covered a property it does not name")
	}
	if p.Allowed(writeProperty(t, bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 6}, bacnet.PropertyPresentValue)) {
		t.Fatal("allow rule covered another instance")
	}
}

func TestWritePolicyDenyOverrides(t *testing.T) {
	p, err := NewWritePolicy(false, ActionAllow, []Rule{
		{Spec: "analog-value:*:present-value", Action: ActionAllow},
		{Spec: "analog-value:5:*", Action: ActionDeny},
	})
	if err != nil {
		t.Fatal(err)
	}
	if p.Allowed(writeProperty(t, bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}, bacnet.PropertyPresentValue)) {
		t.Fatal("deny rule did not override the allow rule")
	}
	if !p.Allowed(writeProperty(t, bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 6}, bacnet.PropertyPresentValue)) {
		t.Fatal("allow rule refused an un-denied object")
	}
}

func TestWritePolicyAllowMustCover(t *testing.T) {
	p, err := NewWritePolicy(false, ActionDeny, []Rule{
		{Spec: "analog-value:*:present-value", Action: ActionAllow},
	})
	if err != nil {
		t.Fatal(err)
	}
	covered := []bacnet.WriteTarget{
		{Object: bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}, Property: bacnet.PropertyPresentValue},
		{Object: bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 6}, Property: bacnet.PropertyPresentValue},
	}
	if !p.Allowed(writePropertyMultiple(t, covered)) {
		t.Fatal("one rule covering both targets was refused")
	}
	straddling := append(covered, bacnet.WriteTarget{
		Object:   bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 7},
		Property: bacnet.PropertyRelinquishDefault,
	})
	if p.Allowed(writePropertyMultiple(t, straddling)) {
		t.Fatal("a multi-property write straddled the allow rule")
	}
}

func TestWritePolicyWildcardAndShorthand(t *testing.T) {
	for _, spec := range []string{"*", "analog-value", "analog-value:*", "analog-value:*:*", "2:*:*"} {
		p, err := NewWritePolicy(false, ActionDeny, []Rule{{Spec: spec, Action: ActionAllow}})
		if err != nil {
			t.Fatalf("%q: %v", spec, err)
		}
		if !p.Allowed(writeProperty(t, bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 5}, bacnet.PropertyPresentValue)) {
			t.Fatalf("%q did not cover the target", spec)
		}
	}
}

func TestWritePolicyServiceLevelWrite(t *testing.T) {
	deny, _ := NewWritePolicy(false, ActionDeny, []Rule{{Spec: "*", Action: ActionAllow}})
	reinit := bacnet.APDU{Type: bacnet.PDUConfirmedRequest, HasService: true, Service: bacnet.ServiceReinitializeDevice}
	if deny.Allowed(reinit) {
		t.Fatal("default deny allowed ReinitializeDevice just because an object allow rule exists")
	}
	allow, _ := NewWritePolicy(false, ActionAllow, nil)
	if !allow.Allowed(reinit) {
		t.Fatal("default allow refused ReinitializeDevice")
	}
}

func TestWritePolicyUndecodableWriteDenied(t *testing.T) {
	p, err := NewWritePolicy(false, ActionAllow, nil)
	if err != nil {
		t.Fatal(err)
	}
	bad := bacnet.APDU{Type: bacnet.PDUConfirmedRequest, HasService: true,
		Service: bacnet.ServiceWriteProperty, Payload: []byte{0x0C, 0x00}}
	if p.Allowed(bad) {
		t.Fatal("an undecodable write was allowed by a default-allow policy")
	}
	emptyWPM := bacnet.APDU{Type: bacnet.PDUConfirmedRequest, HasService: true,
		Service: bacnet.ServiceWritePropertyMultiple, Payload: []byte{0x0E, 0x0F}}
	if p.Allowed(emptyWPM) {
		t.Fatal("an empty WritePropertyMultiple was allowed")
	}
}

func TestWritePolicyUnconfirmedWrites(t *testing.T) {
	p, err := NewWritePolicy(false, ActionDeny, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []bacnet.Service{bacnet.ServiceWriteGroup, bacnet.ServiceUnconfirmedPrivateTransfer} {
		a := bacnet.APDU{Type: bacnet.PDUUnconfirmedRequest, HasService: true, Service: s}
		if p.Allowed(a) {
			t.Fatalf("unconfirmed service %d bypassed a default-deny policy", s)
		}
	}
}

func TestWritePolicyInvalidConfig(t *testing.T) {
	cases := []struct {
		name string
		def  Action
		rule []Rule
	}{
		{"missing default", "", nil},
		{"bad default", "maybe", nil},
		{"bad action", ActionDeny, []Rule{{Spec: "*", Action: "maybe"}}},
		{"empty spec", ActionDeny, []Rule{{Spec: "", Action: ActionAllow}}},
		{"bad type", ActionDeny, []Rule{{Spec: "nope:1:1", Action: ActionAllow}}},
		{"bad instance", ActionDeny, []Rule{{Spec: "analog-value:4194304:*", Action: ActionAllow}}},
		{"too many parts", ActionDeny, []Rule{{Spec: "analog-value:1:present-value:x", Action: ActionAllow}}},
		{"bad property", ActionDeny, []Rule{{Spec: "analog-value:1:nope", Action: ActionAllow}}},
	}
	for _, c := range cases {
		if _, err := NewWritePolicy(false, c.def, c.rule); err == nil {
			t.Fatalf("%s: accepted", c.name)
		}
	}
}

func TestPolicyACLShortCircuitsBeforeRate(t *testing.T) {
	// Fill the rate table to its cap, so any token request would fail
	// closed. An off-list client must still be reported as an ACL denial:
	// that is the proof that the ACL check runs first and never touches the
	// limiter.
	now := time.Unix(3000, 0)
	limit := NewLimit(1)
	for i := 0; i < maxBuckets; i++ {
		limit.Allow(net.IPv4(10, byte(i>>8), byte(i), 1), now)
	}
	list, err := NewList([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	p := NewPolicy(list, limit, nil)
	if d := p.Check(net.ParseIP("203.0.113.5"), now); d != DenyACL {
		t.Fatalf("off-list client = %v, want ACL denial", d)
	}
	if d := p.Check(net.ParseIP("10.9.9.9"), now); d != DenyRate {
		t.Fatalf("in-list client with a full table = %v, want rate denial", d)
	}
	if d := (*Policy)(nil).Check(net.ParseIP("203.0.113.5"), now); d != Allow {
		t.Fatalf("nil policy = %v", d)
	}
}

func TestPolicyAllowWritePassthrough(t *testing.T) {
	if !(*Policy)(nil).AllowWrite(writeProperty(t, bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 1}, bacnet.PropertyPresentValue)) {
		t.Fatal("nil policy denied a write")
	}
	// A policy without a write part allows writes.
	p := NewPolicy(nil, nil, nil)
	if !p.AllowWrite(writeProperty(t, bacnet.ObjectID{Type: bacnet.ObjectAnalogValue, Instance: 1}, bacnet.PropertyPresentValue)) {
		t.Fatal("policy without write rules denied a write")
	}
}
