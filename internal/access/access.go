// Package access is the front-leg request policy: which clients may talk to
// the proxy at all, how often, and which writes they may perform.
//
// The vocabulary is deliberately the one modbus-shield and snmp-shield use
// (allow / rate_per_sec / read_only / write_policy with default + rules), so
// an operator who has configured one Shield appliance already knows this one.
// Only the rule address is protocol-specific: a BACnet write names an
// object, an instance and a property.
package access

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet"
	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet/sc"
)

// Decision is the outcome of the per-datagram client check. The two denials
// are separate so the metrics can tell an off-list client from a flooding
// one.
type Decision int

const (
	Allow Decision = iota
	DenyACL
	DenyRate
	DenyDevice
)

func (d Decision) String() string {
	switch d {
	case Allow:
		return "allow"
	case DenyACL:
		return "acl"
	case DenyRate:
		return "rate"
	case DenyDevice:
		return "device"
	default:
		return "unknown"
	}
}

// List is a client IP/CIDR allow-list. A nil or empty list allows every
// client; that is the documented "no ACL configured" state.
type List struct {
	nets []*net.IPNet
}

// NewList compiles entries. A bare IP becomes a single-host network; a CIDR
// is used as given. An invalid entry is an error, never a silent skip: a
// typo in an allow-list must not quietly widen or narrow access.
func NewList(entries []string) (*List, error) {
	l := &List{}
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(e); err == nil {
			l.nets = append(l.nets, n)
			continue
		}
		ip := net.ParseIP(e)
		if ip == nil {
			return nil, fmt.Errorf("access: %q is not an IP address or CIDR", e)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		l.nets = append(l.nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return l, nil
}

// Allowed reports whether ip is on the list. An empty list allows everyone.
func (l *List) Allowed(ip net.IP) bool {
	if l == nil || len(l.nets) == 0 {
		return true
	}
	for _, n := range l.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// MACList is a BACnet/SC virtual-MAC allow-list. A nil or empty list admits
// every node the hub delivers; that is the same documented "no ACL configured"
// state as the IP leg, and it keeps the SC leg's protection opt-in.
type MACList struct {
	macs []sc.MAC
}

// NewMACList compiles VMAC entries ("aa:bb:cc:dd:ee:ff"). An invalid entry is
// an error, never a silent skip. The all-zero VMAC and the broadcast VMAC are
// refused: neither identifies one node, so accepting either as an allow-list
// entry would not mean what the operator thinks.
func NewMACList(entries []string) (*MACList, error) {
	l := &MACList{}
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		m, err := sc.ParseMAC(e)
		if err != nil {
			return nil, fmt.Errorf("access: %q is not a BACnet/SC VMAC: %w", e, err)
		}
		if m.IsZero() || m.IsBroadcast() {
			return nil, fmt.Errorf("access: %q is not a unicast VMAC", e)
		}
		l.macs = append(l.macs, m)
	}
	return l, nil
}

// Allowed reports whether vmac is on the list. An empty list allows everyone.
func (l *MACList) Allowed(vmac sc.MAC) bool {
	if l == nil || len(l.macs) == 0 {
		return true
	}
	for _, m := range l.macs {
		if m == vmac {
			return true
		}
	}
	return false
}

// Policy is the complete front-leg request policy.
type Policy struct {
	list   *List
	scs    *MACList
	limit  *Limit
	budget *Budget
	write  *WritePolicy
}

// NewPolicy compiles the three IP-leg parts. Any of them may be nil/empty.
func NewPolicy(list *List, limit *Limit, write *WritePolicy) *Policy {
	return &Policy{list: list, limit: limit, write: write}
}

// WithSCAllow returns a copy of the policy that also admits only the listed
// BACnet/SC VMACs. An empty list admits every node the hub delivers. The copy
// keeps a reload from mutating a policy that in-flight requests are using.
func (p *Policy) WithSCAllow(list *MACList) *Policy {
	if p == nil {
		return &Policy{scs: list}
	}
	cp := *p
	cp.scs = list
	return &cp
}

// WithDeviceBudget returns a copy of the policy with a shared per-device
// budget. The budget bounds the total request rate toward the one device; the
// per-client Limit is the fairness control. A nil budget disables it. Like
// WithSCAllow, the copy keeps a reload from mutating an in-use policy.
func (p *Policy) WithDeviceBudget(b *Budget) *Policy {
	if p == nil {
		return &Policy{budget: b}
	}
	cp := *p
	cp.budget = b
	return &cp
}

// Check runs the IP-leg client checks in order: an off-list client never
// consumes a rate-limit token, so a spoofed-source flood cannot drain another
// client's budget (and cannot grow the bucket table for clients that may not
// talk to us at all). The per-client limit is charged before the shared device
// budget, so a client already over its own limit cannot spend the budget the
// other clients need.
func (p *Policy) Check(ip net.IP, now time.Time) Decision {
	if p == nil {
		return Allow
	}
	if !p.list.Allowed(ip) {
		return DenyACL
	}
	if !p.limit.Allow(ip, now) {
		return DenyRate
	}
	if !p.budget.Allow(now) {
		return DenyDevice
	}
	return Allow
}

// CheckSC runs the BACnet/SC client checks. SC nodes are addressed by VMAC,
// not by IP, so the IP allow-list does not apply; the VMAC allow-list takes
// its place and the rate bucket is keyed by VMAC. An SC allow-list entry and
// an IP entry can never share a bucket because the SC key is prefixed. The
// shared device budget is the same one the IP leg charges.
func (p *Policy) CheckSC(vmac sc.MAC, now time.Time) Decision {
	if p == nil {
		return Allow
	}
	if !p.scs.Allowed(vmac) {
		return DenyACL
	}
	if !p.limit.AllowKey("sc:"+vmac.String(), now) {
		return DenyRate
	}
	if !p.budget.Allow(now) {
		return DenyDevice
	}
	return Allow
}

// AllowWrite decides a write APDU. Non-write APDUs always pass.
func (p *Policy) AllowWrite(a bacnet.APDU) bool {
	ok, _ := p.WriteVerdict(a)
	return ok
}

// WriteVerdict decides a write APDU and returns the denial reason. It is the
// audit-facing form of AllowWrite: the reason distinguishes a read-only policy
// from a matching deny rule from an undecodable write, which a bare bool cannot.
func (p *Policy) WriteVerdict(a bacnet.APDU) (bool, string) {
	if p == nil || p.write == nil {
		return true, ""
	}
	return p.write.Decide(a)
}

// Limit is a per-client token bucket table.
//
// The table is capped and fails closed when full: an unbounded map driven by
// spoofed UDP sources is itself the denial of service. A client that has not
// been seen for five minutes is swept, so the table tracks active clients
// rather than every address that ever appeared.
type Limit struct {
	rate  float64
	burst float64

	mu      sync.Mutex
	buckets map[string]*bucket
	lastGC  time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

const (
	maxBuckets     = 4096
	bucketIdleTime = 5 * time.Minute
	gcInterval     = time.Minute
)

// NewLimit returns nil for a non-positive rate, meaning "no rate limit".
func NewLimit(ratePerSec float64) *Limit {
	if ratePerSec <= 0 {
		return nil
	}
	return &Limit{
		rate:    ratePerSec,
		burst:   ratePerSec,
		buckets: make(map[string]*bucket),
	}
}

// Allow charges one token to the client at ip.
func (l *Limit) Allow(ip net.IP, now time.Time) bool {
	return l.AllowKey(ip.String(), now)
}

// AllowKey charges one token to an arbitrary client identity. The IP leg uses
// the address string; the SC leg uses a prefixed VMAC. Keeping the key opaque
// lets both legs share one bounded bucket table without teaching the limiter
// about either address family.
func (l *Limit) AllowKey(key string, now time.Time) bool {
	if l == nil {
		return true
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	if l.lastGC.IsZero() {
		l.lastGC = now
	} else if now.Sub(l.lastGC) >= gcInterval {
		for k, b := range l.buckets {
			if now.Sub(b.last) > bucketIdleTime {
				delete(l.buckets, k)
			}
		}
		l.lastGC = now
	}

	b, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= maxBuckets {
			return false
		}
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * l.rate
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// Budget is a single shared token bucket that bounds the total request rate
// toward the one device, no matter how many clients poll it. It complements
// the per-client Limit: the Limit is the fairness control, the Budget protects
// a fragile device from the sum of many individually-reasonable pollers.
//
// Because the proxy has exactly one device, there is one bucket and no table;
// unlike Limit it cannot grow, so it needs no cap or sweep.
type Budget struct {
	rate  float64
	burst float64

	mu     sync.Mutex
	tokens float64
	last   time.Time
}

// NewBudget returns nil for a non-positive rate, meaning "no device budget".
func NewBudget(ratePerSec float64) *Budget {
	if ratePerSec <= 0 {
		return nil
	}
	return &Budget{rate: ratePerSec, burst: ratePerSec}
}

// Allow charges one token to the shared device budget. A fresh budget starts
// full, so the very first request is admitted rather than delayed a full
// interval.
func (b *Budget) Allow(now time.Time) bool {
	if b == nil {
		return true
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.last.IsZero() {
		b.last = now
		b.tokens = b.burst
	} else {
		elapsed := now.Sub(b.last).Seconds()
		if elapsed > 0 {
			b.tokens += elapsed * b.rate
			if b.tokens > b.burst {
				b.tokens = b.burst
			}
			b.last = now
		}
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}
