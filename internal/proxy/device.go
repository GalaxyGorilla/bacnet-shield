package proxy

import (
	"net"
	"time"

	"go.uber.org/zap"

	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet"
)

// handleDevice is the clear-leg entry point. The device leg is the trusted
// side, but it is still parsed strictly: a legacy device is exactly the kind of
// peer that sends a truncated or non-conforming frame, and a panic here would
// take down the only path to the device.
func (g *Gateway) handleDevice(dg []byte, src *net.UDPAddr) {
	if !src.IP.Equal(g.deviceIP) {
		g.log.Debug("device leg datagram from an unexpected source",
			zap.Stringer("source", src), zap.Stringer("device", g.deviceAddr))
		return
	}

	b, err := bacnet.ParseBVLC(dg)
	if err != nil {
		g.metrics.ParseErrors.Inc()
		g.log.Debug("device bvlc parse", zap.Error(err), zap.Stringer("device", src))
		return
	}
	switch b.Function {
	case bacnet.BVLCOriginalUnicastNPDU, bacnet.BVLCOriginalBroadcastNPDU:
	default:
		g.metrics.Unsupported.Inc()
		g.log.Debug("device sent an unsupported bvlc function",
			zap.String("function", b.Function.String()), zap.Stringer("device", src))
		return
	}
	n, err := bacnet.ParseNPDU(b.Data)
	if err != nil {
		g.metrics.ParseErrors.Inc()
		g.log.Debug("device npdu parse", zap.Error(err), zap.Stringer("device", src))
		return
	}
	if n.IsNetworkMessage() {
		g.metrics.Unsupported.Inc()
		g.log.Debug("device sent a network message", zap.Stringer("device", src))
		return
	}
	a, err := bacnet.ParseAPDU(n.APDU)
	if err != nil {
		g.metrics.ParseErrors.Inc()
		g.log.Debug("device apdu parse", zap.Error(err), zap.Stringer("device", src))
		return
	}

	switch {
	case a.IsResponse():
		g.handleDeviceResponse(a, n, src, time.Now())
	case a.Type == bacnet.PDUConfirmedRequest:
		if !a.HasService {
			g.metrics.ParseErrors.Inc()
			g.log.Debug("device confirmed request without a service choice", zap.Stringer("device", src))
			return
		}
		g.handleDeviceRequest(a, n, src, time.Now())
	case a.Type == bacnet.PDUUnconfirmedRequest:
		g.handleDeviceUnconfirmed(a, n)
	default:
		g.metrics.Unsupported.Inc()
		g.log.Debug("device sent an unexpected apdu type",
			zap.String("pdu", a.Type.String()), zap.Stringer("device", src))
	}
}

// handleDeviceResponse correlates an answer with the client request that caused
// it and rewrites the invoke ID back to the client's.
func (g *Gateway) handleDeviceResponse(a bacnet.APDU, n bacnet.NPDU, src *net.UDPAddr, now time.Time) {
	g.mu.Lock()
	p := g.pending[a.InvokeID]
	if p == nil {
		g.mu.Unlock()
		g.log.Debug("device response for an unknown invoke id",
			zap.Uint8("invoke_id", a.InvokeID), zap.Stringer("device", src))
		return
	}
	// Remember the device's actual source address: some stacks answer from a
	// port other than the configured one, and a SegmentACK must go back to
	// the same place the response came from.
	p.devAddr = src

	apdu := append([]byte(nil), n.APDU...)
	if err := bacnet.PatchInvokeID(apdu, p.clientID); err != nil {
		g.mu.Unlock()
		g.metrics.ParseErrors.Inc()
		g.log.Debug("device response patch", zap.Error(err), zap.Stringer("device", src))
		return
	}
	npdu := buildNPDU(n, apdu)

	complete := true
	switch {
	case a.Type == bacnet.PDUSegmentACK:
		complete = false
		p.deadline = now.Add(g.cfg.RequestTimeout)
	case a.Type == bacnet.PDUComplexACK && a.Segmented && a.MoreFollows:
		complete = false
		p.deadline = now.Add(g.cfg.RequestTimeout)
	case a.Type == bacnet.PDUComplexACK && a.Segmented && !a.MoreFollows:
		// The data is complete, but the client still owes a final
		// SegmentACK. Keep the mapping briefly so that ACK reaches the
		// device; a retransmitted request during the window is treated as
		// a new exchange (see forwardConfirmed).
		p.complete = true
		p.deadline = now.Add(segmentGrace)
		p.fwd = nil
		complete = false
	}
	if complete {
		g.applyCOVLocked(p, a)
		key := clientKey{p.client.Key(), p.clientID}
		hash := p.hash
		g.dropPendingLocked(a.InvokeID)
		if !a.Segmented {
			g.cacheLocked(key, hash, npdu, now)
		}
	}
	client := p.client
	g.mu.Unlock()

	g.metrics.Responses.Inc()
	g.sendClientNPDU(npdu, client)
}

// applyCOVLocked installs or removes a subscription when the device accepts the
// SubscribeCOV. A rejected subscription never enters the routing table.
func (g *Gateway) applyCOVLocked(p *pendingReq, a bacnet.APDU) {
	if p.cov == nil || a.Type != bacnet.PDUSimpleACK {
		return
	}
	if !p.cov.hasLifetime {
		// A SubscribeCOV with no lifetime is a cancellation.
		g.removeSubLocked(p.cov.object, p.cov.procID, p.client.Key())
		return
	}
	var expires time.Time
	if p.cov.lifetime > 0 {
		expires = time.Now().Add(time.Duration(p.cov.lifetime) * time.Second)
	}
	g.addSubLocked(p.cov.object, p.cov.procID, p.client, expires)
}

// handleDeviceRequest forwards a confirmed request the device initiated (a
// confirmed COV or event notification) to the clients that should see it. One
// device request may fan out to several subscribers; each gets its own
// client-side invoke ID, and the first client answer is relayed back as the
// single answer the device expects.
func (g *Gateway) handleDeviceRequest(a bacnet.APDU, n bacnet.NPDU, src *net.UDPAddr, now time.Time) {
	hash := apduHash(n.APDU)

	g.mu.Lock()
	if ex := g.fromDevice[a.InvokeID]; ex != nil {
		switch {
		case ex.hash == hash:
			// A device retransmission: replay the exact frames already sent.
			targets := make([]*clientForward, len(ex.targets))
			copy(targets, ex.targets)
			g.mu.Unlock()
			g.metrics.Replayed.Inc()
			for _, t := range targets {
				g.sendClientNPDU(t.npdu, t.client)
			}
			return
		case a.Segmented && ex.segmented && ex.service == a.Service:
			// A later segment of a segmented notification.
			for _, t := range ex.targets {
				apdu := append([]byte(nil), n.APDU...)
				if err := bacnet.PatchInvokeID(apdu, t.clientID); err != nil {
					continue
				}
				t.npdu = buildNPDU(n, apdu)
			}
			ex.deadline = now.Add(g.cfg.RequestTimeout)
			targets := make([]*clientForward, len(ex.targets))
			copy(targets, ex.targets)
			g.mu.Unlock()
			for _, t := range targets {
				g.sendClientNPDU(t.npdu, t.client)
			}
			return
		default:
			g.dropExchangeLocked(a.InvokeID)
		}
	}

	var targets []peer
	if obj, ok := bacnet.COVNotificationObject(a); ok {
		procID, _ := bacnet.COVNotificationProcessID(a)
		targets = g.subscribersLocked(obj, procID)
	} else {
		targets = g.activeClientsLocked(now)
	}
	if len(targets) == 0 {
		g.mu.Unlock()
		g.metrics.NotificationsDropped.Inc()
		g.log.Warn("device confirmed request has no recipient",
			zap.Uint8("service", uint8(a.Service)), zap.Stringer("device", src))
		g.answerUnroutable(a, src)
		return
	}

	ex := &deviceExchange{
		devID:     a.InvokeID,
		devAddr:   src,
		service:   a.Service,
		hash:      hash,
		segmented: a.Segmented,
		deadline:  now.Add(g.cfg.RequestTimeout),
	}
	for _, client := range targets {
		cid, ok := g.allocClientID(client.Key())
		if !ok {
			g.log.Warn("no free client invoke id for a device request",
				zap.Stringer("client", client))
			continue
		}
		apdu := append([]byte(nil), n.APDU...)
		if err := bacnet.PatchInvokeID(apdu, cid); err != nil {
			continue
		}
		ex.targets = append(ex.targets, &clientForward{
			client:   client,
			clientID: cid,
			npdu:     buildNPDU(n, apdu),
		})
		g.toDevice[clientKey{client.Key(), cid}] = a.InvokeID
	}
	if len(ex.targets) == 0 {
		g.mu.Unlock()
		g.metrics.NotificationsDropped.Inc()
		g.log.Warn("no client could receive a device request",
			zap.Uint8("service", uint8(a.Service)), zap.Stringer("device", src))
		g.answerUnroutable(a, src)
		return
	}
	g.fromDevice[a.InvokeID] = ex
	frames := make([]*clientForward, len(ex.targets))
	copy(frames, ex.targets)
	g.mu.Unlock()

	for _, t := range frames {
		g.sendClientNPDU(t.npdu, t.client)
	}
}

// handleDeviceUnconfirmed relays an unconfirmed notification.
//
// COV notifications follow their subscriber map. I-Am/I-Have and every other
// notification are broadcast-shaped: on a normal BACnet network they are
// broadcast, so every active client sees them.
func (g *Gateway) handleDeviceUnconfirmed(a bacnet.APDU, n bacnet.NPDU) {
	switch a.Service {
	case bacnet.ServiceIAm:
		g.checkDeviceInstance(a)
		g.relayToActive(n)
	case bacnet.ServiceIHave:
		g.relayToActive(n)
	case bacnet.ServiceUnconfirmedCOVNotification:
		obj, ok := bacnet.COVNotificationObject(a)
		if !ok {
			g.metrics.ParseErrors.Inc()
			g.log.Debug("cov notification without a monitored object")
			return
		}
		procID, _ := bacnet.COVNotificationProcessID(a)
		g.mu.Lock()
		targets := g.subscribersLocked(obj, procID)
		g.mu.Unlock()
		if len(targets) == 0 {
			g.metrics.NotificationsDropped.Inc()
			g.log.Debug("cov notification without a subscriber", zap.Stringer("object", obj))
			return
		}
		npdu := buildNPDU(n, n.APDU)
		for _, t := range targets {
			g.sendClientNPDU(npdu, t)
		}
	default:
		g.relayToActive(n)
	}
}

func (g *Gateway) relayToActive(n bacnet.NPDU) {
	targets := g.activeClients()
	if len(targets) == 0 {
		g.metrics.NotificationsDropped.Inc()
		return
	}
	npdu := buildNPDU(n, n.APDU)
	for _, t := range targets {
		g.sendClientNPDU(npdu, t)
	}
}

// checkDeviceInstance warns when the device's I-Am contradicts the pinned
// instance. It never gates traffic: the proxy forwards what the device says,
// and selftest turns the warning into a failure.
func (g *Gateway) checkDeviceInstance(a bacnet.APDU) {
	if g.cfg.DeviceInstance == nil {
		return
	}
	oid, ok := bacnet.IAmDeviceID(a)
	if !ok {
		return
	}
	if oid.Instance != *g.cfg.DeviceInstance {
		g.log.Warn("device instance does not match device_instance",
			zap.Uint32("configured", *g.cfg.DeviceInstance),
			zap.Uint32("reported", oid.Instance))
	}
}

// answerUnroutable tells the device that the proxy cannot deliver a confirmed
// request. A COV notification gets an Error (unknown subscription); anything
// else gets an Error with service-request-denied, which is more specific than
// a Reject because the service itself is understood, it just has no recipient.
// Answering is required: a silent drop makes the device retransmit until its
// TSM gives up.
func (g *Gateway) answerUnroutable(a bacnet.APDU, src *net.UDPAddr) {
	var out bacnet.APDU
	switch a.Service {
	case bacnet.ServiceConfirmedCOVNotification, bacnet.ServiceConfirmedCOVNotificationMultiple:
		out = bacnet.ErrorAPDU(a.InvokeID, a.Service, bacnet.ErrorClassServices, bacnet.ErrorCodeUnknownSubscription)
	default:
		out = bacnet.ErrorAPDU(a.InvokeID, a.Service, bacnet.ErrorClassServices, bacnet.ErrorCodeServiceRequestDenied)
	}
	g.sendDeviceTo(buildFrame(bacnet.NPDU{}, out.Marshal()), src)
}

// dropExchangeLocked removes a device-initiated exchange and every reverse
// mapping it created. Caller holds mu.
func (g *Gateway) dropExchangeLocked(devID byte) {
	ex := g.fromDevice[devID]
	if ex == nil {
		return
	}
	delete(g.fromDevice, devID)
	for _, t := range ex.targets {
		delete(g.toDevice, clientKey{t.client.Key(), t.clientID})
	}
}

// activeClientsLocked is activeClients for a caller that already holds mu.
func (g *Gateway) activeClientsLocked(now time.Time) []peer {
	out := make([]peer, 0, len(g.clients))
	for _, c := range g.clients {
		if now.Sub(c.last) <= clientIdle {
			out = append(out, c.peer)
		}
	}
	return out
}

// sendDeviceTo sends to a learned device address, falling back to the
// configured one before any response has been seen.
func (g *Gateway) sendDeviceTo(frame []byte, addr *net.UDPAddr) {
	if addr == nil {
		g.sendDevice(frame)
		return
	}
	if _, err := g.deviceConn.WriteToUDP(frame, addr); err != nil {
		g.log.Warn("device leg write", zap.Error(err), zap.Stringer("device", addr))
	}
}
