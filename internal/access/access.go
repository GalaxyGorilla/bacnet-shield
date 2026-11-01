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
)

// Decision is the outcome of the per-datagram client check. The two denials
// are separate so the metrics can tell an off-list client from a flooding
// one.
type Decision int

const (
	Allow Decision = iota
	DenyACL
	DenyRate
)

func (d Decision) String() string {
	switch d {
	case Allow:
		return "allow"
	case DenyACL:
		return "acl"
	case DenyRate:
		return "rate"
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

// Policy is the complete front-leg request policy.
type Policy struct {
	list  *List
	limit *Limit
	write *WritePolicy
}

// NewPolicy compiles the three parts. Any of them may be nil/empty.
func NewPolicy(list *List, limit *Limit, write *WritePolicy) *Policy {
	return &Policy{list: list, limit: limit, write: write}
}

// Check runs the client checks in order: an off-list client never consumes a
// rate-limit token, so a spoofed-source flood cannot drain another client's
// budget (and cannot grow the bucket table for clients that may not talk to
// us at all).
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
	return Allow
}

// AllowWrite decides a write APDU. Non-write APDUs always pass.
func (p *Policy) AllowWrite(a bacnet.APDU) bool {
	if p == nil || p.write == nil {
		return true
	}
	return p.write.Allowed(a)
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
	if l == nil {
		return true
	}
	key := ip.String()

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
