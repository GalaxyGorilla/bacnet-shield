package proxy

import (
	"crypto/sha256"
	"net"
	"time"

	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet"
)

// clientKey identifies one client's invoke-ID space. BACnet's invoke ID is
// one octet and belongs to the client, so the key must include the client
// address: two clients may both have request 7 outstanding.
type clientKey struct {
	addr string
	id   byte
}

// pendingReq is a client request in flight toward the device.
type pendingReq struct {
	client    *net.UDPAddr
	clientID  byte
	devID     byte
	devAddr   *net.UDPAddr // learned from the device's first response
	service   bacnet.Service
	hash      [32]byte // hash of the first request APDU, for retransmission dedupe
	segmented bool
	complete  bool // a segmented response finished; only the final SegmentACK is still expected
	fwd       []byte
	deadline  time.Time
	cov       *covIntent
}

// covIntent is the subscription state a SubscribeCOV will install if the
// device answers with a SimpleACK. It is applied on the positive response, not
// on the request: a rejected subscription must not route notifications.
type covIntent struct {
	object      bacnet.ObjectID
	procID      uint32
	lifetime    uint32
	hasLifetime bool
}

// completed is a finished response replayed to a retransmitted request. BACnet
// clients retransmit when an answer is lost; forwarding the retransmission
// would ask the device to do the work twice.
type completed struct {
	hash     [32]byte
	frame    []byte
	deadline time.Time
}

// deviceExchange is a confirmed request the device initiated (a confirmed COV
// or event notification). The proxy answers as the client's server and must
// remember the device's invoke ID to route the client's answer back. One
// exchange may fan out to several subscribers, each with its own client-side
// invoke ID; the first answer the device gets is enough, because the device
// sent one request.
type deviceExchange struct {
	devID     byte
	devAddr   *net.UDPAddr
	service   bacnet.Service
	hash      [32]byte
	segmented bool
	deadline  time.Time
	targets   []*clientForward
}

// clientForward is one client's copy of a device-initiated request.
type clientForward struct {
	client   *net.UDPAddr
	clientID byte
	frame    []byte
}

// allocDevID reserves the lowest free device-leg invoke ID. Caller holds mu.
func (g *Gateway) allocDevID() (byte, bool) {
	for i := 0; i < 256; i++ {
		if g.usedIDs[i/64]&(1<<(i%64)) == 0 {
			g.usedIDs[i/64] |= 1 << (i % 64)
			return byte(i), true
		}
	}
	return 0, false
}

// freeDevID releases a device-leg invoke ID. Caller holds mu.
func (g *Gateway) freeDevID(id byte) {
	g.usedIDs[id/64] &^= 1 << (id % 64)
}

// detachPendingLocked removes a pending request and its reverse mapping and
// decrements the Pending gauge, but keeps the device invoke ID reserved. A
// caller that is replacing the request uses this so the allocator cannot hand
// the same ID to the replacement while the old response is still on the wire.
// Caller holds mu.
func (g *Gateway) detachPendingLocked(id byte) {
	p := g.pending[id]
	if p == nil {
		return
	}
	delete(g.pending, id)
	key := clientKey{p.client.String(), p.clientID}
	if cur, ok := g.byClient[key]; ok && cur == id {
		delete(g.byClient, key)
	}
	g.metrics.Pending.Dec()
}

// dropPendingLocked detaches a pending request and releases its invoke ID.
// Caller holds mu.
func (g *Gateway) dropPendingLocked(id byte) {
	if _, ok := g.pending[id]; !ok {
		return
	}
	g.detachPendingLocked(id)
	g.freeDevID(id)
}

// allocClientID reserves an invoke ID for a device-initiated request sent to
// one client. It must not collide with the client's own outstanding requests
// (byClient) or with another device request to the same client (toDevice).
// Caller holds mu.
func (g *Gateway) allocClientID(addr string) (byte, bool) {
	for i := 0; i < 256; i++ {
		id := byte(i)
		key := clientKey{addr, id}
		if _, ok := g.byClient[key]; ok {
			continue
		}
		if _, ok := g.toDevice[key]; ok {
			continue
		}
		return id, true
	}
	return 0, false
}

// cacheLocked stores a finished response for replay. At the cap an expired
// entry is dropped first; if none is expired, an arbitrary entry is evicted.
// Losing a replay entry only costs one extra device round trip, so this is
// deliberately simpler than a true LRU. Caller holds mu.
func (g *Gateway) cacheLocked(key clientKey, hash [32]byte, frame []byte, now time.Time) {
	if len(g.done) >= maxCompleted {
		for k, c := range g.done {
			if now.After(c.deadline) {
				delete(g.done, k)
			}
		}
		if len(g.done) >= maxCompleted {
			for k := range g.done {
				delete(g.done, k)
				break
			}
		}
	}
	g.done[key] = &completed{hash: hash, frame: frame, deadline: now.Add(completedTTL)}
}

// apduHash identifies a request APDU for retransmission dedupe. The invoke ID
// is included: two different requests that reuse an ID must not be confused.
func apduHash(apdu []byte) [32]byte {
	return sha256.Sum256(apdu)
}

// covSubKey identifies one client's subscription to one monitored object.
type covSubKey struct {
	client string
	procID uint32
}

// subscription is one active COV subscription. expires is zero for an
// indefinite subscription (lifetime 0 in the request).
type subscription struct {
	client  *net.UDPAddr
	procID  uint32
	expires time.Time
}

// addSubLocked installs a subscription. Caller holds mu.
func (g *Gateway) addSubLocked(obj bacnet.ObjectID, procID uint32, client *net.UDPAddr, expires time.Time) {
	subs := g.cov[obj]
	if subs == nil {
		subs = make(map[covSubKey]*subscription)
		g.cov[obj] = subs
	}
	key := covSubKey{client.String(), procID}
	if _, ok := subs[key]; !ok {
		if g.subCount >= maxSubscriptions {
			return
		}
		g.subCount++
		g.metrics.Subscriptions.Inc()
	}
	subs[key] = &subscription{client: client, procID: procID, expires: expires}
}

// removeSubLocked removes a subscription. Caller holds mu.
func (g *Gateway) removeSubLocked(obj bacnet.ObjectID, procID uint32, client string) {
	subs := g.cov[obj]
	if subs == nil {
		return
	}
	key := covSubKey{client, procID}
	if _, ok := subs[key]; ok {
		delete(subs, key)
		g.subCount--
		g.metrics.Subscriptions.Dec()
	}
	if len(subs) == 0 {
		delete(g.cov, obj)
	}
}

// subscribersLocked returns the clients subscribed to obj. It prefers an exact
// process-identifier match; if the notification's identifier does not match any
// subscription (some devices echo a different one), it falls back to every
// subscriber of the object rather than dropping the notification. Caller holds
// mu.
func (g *Gateway) subscribersLocked(obj bacnet.ObjectID, procID uint32) []*net.UDPAddr {
	subs := g.cov[obj]
	if len(subs) == 0 {
		return nil
	}
	var out []*net.UDPAddr
	for k, s := range subs {
		if k.procID == procID {
			out = append(out, s.client)
		}
	}
	if len(out) == 0 {
		for _, s := range subs {
			out = append(out, s.client)
		}
	}
	return out
}
