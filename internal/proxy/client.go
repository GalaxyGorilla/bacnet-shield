package proxy

import (
	"net"
	"time"

	"go.uber.org/zap"

	"github.com/GalaxyGorilla/bacnet-shield/internal/access"
	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet"
	"github.com/GalaxyGorilla/bacnet-shield/internal/observ"
)

// handleClient is the BACnet/IP front-leg entry point for one datagram. It
// runs under safego.Dispatch, so a decoder panic costs one datagram, not the
// gateway.
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
		g.recordAudit(observ.AuditEvent{Event: "acl_denied", Leg: "ip", Client: src.String()})
		g.log.Debug("client denied by acl", zap.Stringer("client", src))
		return
	case access.DenyRate:
		g.metrics.RateLimited.Inc()
		g.recordAudit(observ.AuditEvent{Event: "rate_limited", Leg: "ip", Client: src.String(), Reason: "per_client_rate"})
		g.log.Debug("client denied by rate limit", zap.Stringer("client", src))
		return
	case access.DenyDevice:
		g.metrics.DeviceRateLimited.Inc()
		g.recordAudit(observ.AuditEvent{Event: "device_budget_denied", Leg: "ip", Client: src.String(), Reason: "device_budget"})
		g.log.Debug("client denied by the shared device budget", zap.Stringer("client", src))
		return
	}

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
		// not a forwarder's job. Rejecting them is honest: a client behind a
		// BBMD needs the proxy on its own network, not a silently mangled
		// frame.
		g.metrics.Unsupported.Inc()
		g.log.Debug("client sent an unsupported bvlc function",
			zap.String("function", b.Function.String()), zap.Stringer("client", src))
		return
	}

	p := &udpPeer{addr: src, conn: g.clientConn}
	g.touchClient(p, now)
	g.handleClientNPDU(b.Data, p, now, pol)
}

// handleClientNPDU is the leg-independent half of the front leg: parse the
// network and application layers, then dispatch. Both the BACnet/IP and
// BACnet/SC handlers reach this method, so policy and routing cannot drift
// between the two.
func (g *Gateway) handleClientNPDU(npdu []byte, p peer, now time.Time, pol *access.Policy) {
	n, err := bacnet.ParseNPDU(npdu)
	if err != nil {
		g.metrics.ParseErrors.Inc()
		g.log.Debug("client npdu parse", zap.Error(err), zap.Stringer("client", p))
		return
	}
	if n.IsNetworkMessage() {
		// Who-Is-Router-To-Network and friends belong to a router. The
		// proxy is not one, and answering would advertise a network it does
		// not route.
		g.metrics.Unsupported.Inc()
		g.log.Debug("client sent a network message", zap.Stringer("client", p))
		return
	}
	a, err := bacnet.ParseAPDU(n.APDU)
	if err != nil {
		g.metrics.ParseErrors.Inc()
		g.log.Debug("client apdu parse", zap.Error(err), zap.Stringer("client", p))
		return
	}

	switch a.Type {
	case bacnet.PDUConfirmedRequest:
		if !a.HasService {
			g.metrics.ParseErrors.Inc()
			g.log.Debug("client confirmed request without a service choice", zap.Stringer("client", p))
			return
		}
		g.handleClientConfirmed(a, n, p, now, pol)
	case bacnet.PDUUnconfirmedRequest:
		g.handleClientUnconfirmed(a, n, p, pol)
	default:
		g.handleClientResponse(a, n, p, now)
	}
}

// handleClientConfirmed gates and forwards a confirmed request.
func (g *Gateway) handleClientConfirmed(a bacnet.APDU, n bacnet.NPDU, p peer, now time.Time, pol *access.Policy) {
	// SubscribeCOVPropertyMultiple carries a list of subscriptions. v1
	// tracks one monitored object per subscription, so it cannot route the
	// notifications of a multiple subscription. Denying it with a BACnet
	// error is better than forwarding it and silently losing notifications.
	// A segmented subscription is denied for the same reason: the proxy
	// would see only the first segment.
	if a.Service == bacnet.ServiceSubscribeCOVPropertyMultiple ||
		(a.Segmented && (a.Service == bacnet.ServiceSubscribeCOV || a.Service == bacnet.ServiceSubscribeCOVProperty)) {
		g.metrics.Unsupported.Inc()
		g.recordAudit(observ.AuditEvent{
			Event: "unsupported_subscription", Leg: peerLeg(p), Client: p.String(),
			Service: a.ServiceName(), Reason: "unsupported_subscription",
		})
		g.log.Info("unsupported subscription request",
			zap.Stringer("client", p), zap.String("service", a.ServiceName()))
		g.sendClientError(p, a, bacnet.ErrorClassServices, bacnet.ErrorCodeServiceRequestDenied)
		return
	}

	if allowed, reason := pol.WriteVerdict(a); !allowed {
		g.metrics.WritesDenied.Inc()
		targets := writeTargetStrings(a)
		g.recordAudit(observ.AuditEvent{
			Event: "write_denied", Leg: peerLeg(p), Client: p.String(),
			Service: a.ServiceName(), Targets: targets, Reason: reason,
		})
		g.log.Info("write denied by policy",
			zap.Stringer("client", p),
			zap.String("service", a.ServiceName()),
			zap.Strings("targets", targets),
			zap.String("reason", reason),
			zap.Uint8("invoke_id", a.InvokeID))
		g.sendClientError(p, a, bacnet.ErrorClassSecurity, bacnet.ErrorCodeWriteAccessDenied)
		return
	}

	var intent *covIntent
	if obj, procID, lifetime, hasLifetime, ok := bacnet.COVSubscription(a); ok {
		intent = &covIntent{object: obj, procID: procID, lifetime: lifetime, hasLifetime: hasLifetime}
	}
	g.forwardConfirmed(a, n, p, now, intent)
}

// forwardConfirmed allocates a device-leg invoke ID (or reuses the one already
// assigned to this client/invoke-ID pair), rewrites the octet, and sends the
// request to the device.
func (g *Gateway) forwardConfirmed(a bacnet.APDU, n bacnet.NPDU, p peer, now time.Time, intent *covIntent) {
	key := clientKey{p.Key(), a.InvokeID}
	hash := apduHash(n.APDU)

	g.mu.Lock()
	var staleID byte
	var haveStale bool
	if devID, ok := g.byClient[key]; ok {
		if pending := g.pending[devID]; pending != nil {
			switch {
			case pending.complete:
				// The response finished; a request with the same invoke ID
				// is a new exchange, not a retransmission.
				g.detachPendingLocked(devID)
				staleID, haveStale = devID, true
				delete(g.done, key)
			case pending.hash == hash:
				// A BACnet retransmission while the request is still in
				// flight. It is dropped, not forwarded: the device already
				// has the request, and re-sending a write would apply it
				// twice. If the first copy was lost, the client times out —
				// the safe failure for a building controller.
				g.mu.Unlock()
				g.metrics.Retransmits.Inc()
				g.log.Debug("dropping a retransmission already in flight",
					zap.Stringer("client", p), zap.Uint8("invoke_id", a.InvokeID))
				return
			case a.Segmented && pending.segmented && pending.service == a.Service:
				// A later segment of a segmented request. It shares the
				// device-leg invoke ID; only the sequence number changes.
				devID := pending.devID
				apdu := append([]byte(nil), n.APDU...)
				if err := bacnet.PatchInvokeID(apdu, devID); err != nil {
					g.mu.Unlock()
					g.metrics.ParseErrors.Inc()
					g.log.Debug("client segment patch", zap.Error(err), zap.Stringer("client", p))
					return
				}
				frame := buildFrame(n, apdu)
				pending.fwd = frame
				pending.deadline = now.Add(g.cfg.RequestTimeout)
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
			npdu := c.npdu
			g.mu.Unlock()
			g.metrics.Replayed.Inc()
			g.sendClientNPDU(npdu, p)
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
			zap.Stringer("client", p), zap.Uint8("invoke_id", a.InvokeID))
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
			zap.Stringer("client", p), zap.Uint8("invoke_id", a.InvokeID))
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
		g.log.Debug("client request patch", zap.Error(err), zap.Stringer("client", p))
		return
	}
	frame := buildFrame(n, apdu)
	g.pending[devID] = &pendingReq{
		client:    p,
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
func (g *Gateway) handleClientUnconfirmed(a bacnet.APDU, n bacnet.NPDU, p peer, pol *access.Policy) {
	if allowed, reason := pol.WriteVerdict(a); !allowed {
		g.metrics.WritesDenied.Inc()
		targets := writeTargetStrings(a)
		g.recordAudit(observ.AuditEvent{
			Event: "write_denied", Leg: peerLeg(p), Client: p.String(),
			Service: a.ServiceName(), Targets: targets, Reason: reason,
		})
		g.log.Info("unconfirmed write denied by policy",
			zap.Stringer("client", p),
			zap.String("service", a.ServiceName()),
			zap.Strings("targets", targets),
			zap.String("reason", reason))
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
func (g *Gateway) handleClientResponse(a bacnet.APDU, n bacnet.NPDU, p peer, now time.Time) {
	key := clientKey{p.Key(), a.InvokeID}

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
			g.log.Debug("client answer patch", zap.Error(err), zap.Stringer("client", p))
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
		pending := g.pending[devID]
		if pending == nil {
			g.mu.Unlock()
			return
		}
		apdu := append([]byte(nil), n.APDU...)
		if err := bacnet.PatchInvokeID(apdu, devID); err != nil {
			g.mu.Unlock()
			g.metrics.ParseErrors.Inc()
			g.log.Debug("client segment-ack patch", zap.Error(err), zap.Stringer("client", p))
			return
		}
		frame := buildFrame(n, apdu)
		pending.deadline = now.Add(g.cfg.RequestTimeout)
		devAddr := pending.devAddr
		g.mu.Unlock()
		g.sendDeviceTo(frame, devAddr)
		return
	}
	g.mu.Unlock()
	g.log.Debug("client sent a response with no pending request",
		zap.Stringer("client", p), zap.String("pdu", a.Type.String()), zap.Uint8("invoke_id", a.InvokeID))
}

// sendClientError answers a denied request with a locally generated Error PDU.
// The invoke ID and service choice echo the request: a client correlates the
// answer by them, and a mismatch looks like a timeout.
func (g *Gateway) sendClientError(p peer, a bacnet.APDU, class bacnet.ErrorClass, code bacnet.ErrorCode) {
	errAPDU := bacnet.ErrorAPDU(a.InvokeID, a.Service, class, code)
	g.sendClientNPDU(buildNPDU(bacnet.NPDU{}, errAPDU.Marshal()), p)
}
