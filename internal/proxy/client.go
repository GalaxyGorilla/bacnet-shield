package proxy

import (
	"net"
	"time"

	"go.uber.org/zap"

	"github.com/GalaxyGorilla/bacnet-shield/internal/access"
	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet"
)

// handleClient is the front-leg entry point for one datagram. It runs under
// safego.Dispatch, so a decoder panic costs one datagram, not the gateway.
func (g *Gateway) handleClient(dg []byte, src *net.UDPAddr) {
	g.metrics.Requests.Inc()
	now := time.Now()
	pol := g.policy.Load()

	// The client checks run before any parsing: an off-list or flooding
	// source must not make the proxy decode its datagram, and an off-list
	// source must never consume another client's rate budget.
	switch pol.Check(src.IP, now) {
	case access.DenyACL:
		g.metrics.ACLDenied.Inc()
		g.log.Debug("client denied by acl", zap.Stringer("client", src))
		return
	case access.DenyRate:
		g.metrics.RateLimited.Inc()
		g.log.Debug("client denied by rate limit", zap.Stringer("client", src))
		return
	}
	g.touchClient(src, now)

	b, err := bacnet.ParseBVLC(dg)
	if err != nil {
		g.metrics.ParseErrors.Inc()
		g.log.Debug("client bvlc parse", zap.Error(err), zap.Stringer("client", src))
		return
	}
	switch b.Function {
	case bacnet.BVLCOriginalUnicastNPDU, bacnet.BVLCOriginalBroadcastNPDU:
	default:
		// BBMD functions (Register-Foreign-Device, Forwarded-NPDU, ...) are
		// not a single-device gateway's job. Rejecting them is honest: a
		// client behind a BBMD needs the proxy on its own network, not a
		// silently mangled frame.
		g.metrics.Unsupported.Inc()
		g.log.Debug("client sent an unsupported bvlc function",
			zap.String("function", b.Function.String()), zap.Stringer("client", src))
		return
	}
	n, err := bacnet.ParseNPDU(b.Data)
	if err != nil {
		g.metrics.ParseErrors.Inc()
		g.log.Debug("client npdu parse", zap.Error(err), zap.Stringer("client", src))
		return
	}
	if n.IsNetworkMessage() {
		// Who-Is-Router-To-Network and friends belong to a router. The
		// proxy is not one, and answering would advertise a network it does
		// not route.
		g.metrics.Unsupported.Inc()
		g.log.Debug("client sent a network message", zap.Stringer("client", src))
		return
	}
	a, err := bacnet.ParseAPDU(n.APDU)
	if err != nil {
		g.metrics.ParseErrors.Inc()
		g.log.Debug("client apdu parse", zap.Error(err), zap.Stringer("client", src))
		return
	}

	switch a.Type {
	case bacnet.PDUConfirmedRequest:
		if !a.HasService {
			g.metrics.ParseErrors.Inc()
			g.log.Debug("client confirmed request without a service choice", zap.Stringer("client", src))
			return
		}
		g.handleClientConfirmed(a, n, src, now, pol)
	case bacnet.PDUUnconfirmedRequest:
		g.handleClientUnconfirmed(a, n, src, pol)
	default:
		g.handleClientResponse(a, n, src, now)
	}
}

// handleClientConfirmed gates and forwards a confirmed request.
func (g *Gateway) handleClientConfirmed(a bacnet.APDU, n bacnet.NPDU, src *net.UDPAddr, now time.Time, pol *access.Policy) {
	// SubscribeCOVPropertyMultiple carries a list of subscriptions. v1
	// tracks one monitored object per subscription, so it cannot route the
	// notifications of a multiple subscription. Denying it with a BACnet
	// error is better than forwarding it and silently losing notifications.
	// A segmented subscription is denied for the same reason: the proxy
	// would see only the first segment.
	if a.Service == bacnet.ServiceSubscribeCOVPropertyMultiple ||
		(a.Segmented && (a.Service == bacnet.ServiceSubscribeCOV || a.Service == bacnet.ServiceSubscribeCOVProperty)) {
		g.metrics.Unsupported.Inc()
		g.log.Info("unsupported subscription request",
			zap.Stringer("client", src), zap.Uint8("service", uint8(a.Service)))
		g.sendClientError(src, a, bacnet.ErrorClassServices, bacnet.ErrorCodeServiceRequestDenied)
		return
	}

	if !pol.AllowWrite(a) {
		g.metrics.WritesDenied.Inc()
		g.log.Info("write denied by policy",
			zap.Stringer("client", src),
			zap.Uint8("service", uint8(a.Service)),
			zap.Uint8("invoke_id", a.InvokeID))
		g.sendClientError(src, a, bacnet.ErrorClassSecurity, bacnet.ErrorCodeWriteAccessDenied)
		return
	}

	var intent *covIntent
	if obj, procID, lifetime, hasLifetime, ok := bacnet.COVSubscription(a); ok {
		intent = &covIntent{object: obj, procID: procID, lifetime: lifetime, hasLifetime: hasLifetime}
	}
	g.forwardConfirmed(a, n, src, now, intent)
}

// forwardConfirmed allocates a device-leg invoke ID (or reuses the one already
// assigned to this client/invoke-ID pair), rewrites the octet, and sends the
// request to the device.
func (g *Gateway) forwardConfirmed(a bacnet.APDU, n bacnet.NPDU, src *net.UDPAddr, now time.Time, intent *covIntent) {
	key := clientKey{src.String(), a.InvokeID}
	hash := apduHash(n.APDU)

	g.mu.Lock()
	var staleID byte
	var haveStale bool
	if devID, ok := g.byClient[key]; ok {
		if p := g.pending[devID]; p != nil {
			switch {
			case p.complete:
				// The response finished; a request with the same invoke ID
				// is a new exchange, not a retransmission.
				g.detachPendingLocked(devID)
				staleID, haveStale = devID, true
				delete(g.done, key)
			case p.hash == hash:
				// A BACnet retransmission while the request is still in
				// flight. It is dropped, not forwarded: the device already
				// has the request, and re-sending a write would apply it
				// twice. If the first copy was lost, the client times out —
				// the safe failure for a building controller.
				g.mu.Unlock()
				g.metrics.Retransmits.Inc()
				g.log.Debug("dropping a retransmission already in flight",
					zap.Stringer("client", src), zap.Uint8("invoke_id", a.InvokeID))
				return
			case a.Segmented && p.segmented && p.service == a.Service:
				// A later segment of a segmented request. It shares the
				// device-leg invoke ID; only the sequence number changes.
				devID := p.devID
				apdu := append([]byte(nil), n.APDU...)
				if err := bacnet.PatchInvokeID(apdu, devID); err != nil {
					g.mu.Unlock()
					g.metrics.ParseErrors.Inc()
					g.log.Debug("client segment patch", zap.Error(err), zap.Stringer("client", src))
					return
				}
				frame := buildFrame(n, apdu)
				p.fwd = frame
				p.deadline = now.Add(g.cfg.RequestTimeout)
				g.mu.Unlock()
				g.metrics.Forwarded.Inc()
				g.sendDevice(frame)
				return
			default:
				// The client reused an invoke ID for a different request
				// before the first finished. Keep the old device ID
				// reserved until the replacement has a different one, so a
				// late answer cannot be delivered as the new answer.
				g.detachPendingLocked(devID)
				staleID, haveStale = devID, true
				delete(g.done, key)
			}
		}
	}
	if c, ok := g.done[key]; ok {
		if c.hash == hash {
			frame := c.frame
			g.mu.Unlock()
			g.metrics.Replayed.Inc()
			g.sendClient(frame, src)
			return
		}
		delete(g.done, key)
	}

	if len(g.pending) >= g.cfg.MaxPending {
		if haveStale {
			g.freeDevID(staleID)
		}
		g.mu.Unlock()
		g.metrics.PendingFull.Inc()
		g.log.Warn("pending table full",
			zap.Stringer("client", src), zap.Uint8("invoke_id", a.InvokeID))
		return
	}
	devID, ok := g.allocDevID()
	if !ok {
		if haveStale {
			g.freeDevID(staleID)
		}
		g.mu.Unlock()
		g.metrics.PendingFull.Inc()
		g.log.Warn("no free device invoke id",
			zap.Stringer("client", src), zap.Uint8("invoke_id", a.InvokeID))
		return
	}
	if haveStale {
		g.freeDevID(staleID)
	}
	apdu := append([]byte(nil), n.APDU...)
	if err := bacnet.PatchInvokeID(apdu, devID); err != nil {
		g.freeDevID(devID)
		g.mu.Unlock()
		g.metrics.ParseErrors.Inc()
		g.log.Debug("client request patch", zap.Error(err), zap.Stringer("client", src))
		return
	}
	frame := buildFrame(n, apdu)
	g.pending[devID] = &pendingReq{
		client:    src,
		clientID:  a.InvokeID,
		devID:     devID,
		service:   a.Service,
		hash:      hash,
		segmented: a.Segmented,
		fwd:       frame,
		deadline:  now.Add(g.cfg.RequestTimeout),
		cov:       intent,
	}
	g.byClient[key] = devID
	g.mu.Unlock()

	g.metrics.Pending.Inc()
	g.metrics.Forwarded.Inc()
	g.sendDevice(frame)
}

// handleClientUnconfirmed forwards an unconfirmed request (Who-Is, Who-Has,
// WriteGroup, TimeSynchronization, ...). Unconfirmed writes still change the
// device, so the policy gates them before anything leaves the box.
func (g *Gateway) handleClientUnconfirmed(a bacnet.APDU, n bacnet.NPDU, src *net.UDPAddr, pol *access.Policy) {
	if !pol.AllowWrite(a) {
		g.metrics.WritesDenied.Inc()
		g.log.Info("unconfirmed write denied by policy",
			zap.Stringer("client", src), zap.Uint8("service", uint8(a.Service)))
		return
	}
	frame := buildFrame(n, n.APDU)
	g.metrics.Forwarded.Inc()
	g.sendDevice(frame)
}

// handleClientResponse routes a response-shaped APDU from a client. There are
// two cases:
//
//   - a response to a device-initiated request (a confirmed COV/event
//     notification): toDevice maps it back to the device's invoke ID;
//   - a SegmentACK for a segmented response to the client's own request:
//     byClient maps the client's invoke ID to the device-leg one.
func (g *Gateway) handleClientResponse(a bacnet.APDU, n bacnet.NPDU, src *net.UDPAddr, now time.Time) {
	key := clientKey{src.String(), a.InvokeID}

	g.mu.Lock()
	if devID, ok := g.toDevice[key]; ok {
		ex := g.fromDevice[devID]
		if ex == nil {
			delete(g.toDevice, key)
			g.mu.Unlock()
			return
		}
		apdu := append([]byte(nil), n.APDU...)
		if err := bacnet.PatchInvokeID(apdu, devID); err != nil {
			g.mu.Unlock()
			g.metrics.ParseErrors.Inc()
			g.log.Debug("client answer patch", zap.Error(err), zap.Stringer("client", src))
			return
		}
		frame := buildFrame(n, apdu)
		devAddr := ex.devAddr
		if a.Type == bacnet.PDUSegmentACK {
			ex.deadline = now.Add(g.cfg.RequestTimeout)
		} else {
			g.dropExchangeLocked(devID)
		}
		g.mu.Unlock()
		g.sendDeviceTo(frame, devAddr)
		return
	}
	if devID, ok := g.byClient[key]; ok {
		p := g.pending[devID]
		if p == nil {
			g.mu.Unlock()
			return
		}
		apdu := append([]byte(nil), n.APDU...)
		if err := bacnet.PatchInvokeID(apdu, devID); err != nil {
			g.mu.Unlock()
			g.metrics.ParseErrors.Inc()
			g.log.Debug("client segment-ack patch", zap.Error(err), zap.Stringer("client", src))
			return
		}
		frame := buildFrame(n, apdu)
		p.deadline = now.Add(g.cfg.RequestTimeout)
		devAddr := p.devAddr
		g.mu.Unlock()
		g.sendDeviceTo(frame, devAddr)
		return
	}
	g.mu.Unlock()
	g.log.Debug("client sent a response with no pending request",
		zap.Stringer("client", src), zap.String("pdu", a.Type.String()), zap.Uint8("invoke_id", a.InvokeID))
}

// sendClientError answers a denied request with a locally generated Error PDU.
// The invoke ID and service choice echo the request: a client correlates the
// answer by them, and a mismatch looks like a timeout.
func (g *Gateway) sendClientError(src *net.UDPAddr, a bacnet.APDU, class bacnet.ErrorClass, code bacnet.ErrorCode) {
	errAPDU := bacnet.ErrorAPDU(a.InvokeID, a.Service, class, code)
	g.sendClient(buildFrame(bacnet.NPDU{}, errAPDU.Marshal()), src)
}
