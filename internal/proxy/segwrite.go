package proxy

import (
	"time"

	"go.uber.org/zap"

	"github.com/GalaxyGorilla/bacnet-shield/internal/access"
	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet"
	"github.com/GalaxyGorilla/bacnet-shield/internal/observ"
)

// Segmented writes (B5). The policy can only authorize a write it can decode,
// and a segmented APDU carries one slice of the service payload per datagram.
// Forwarding the segments as they arrive would let a client put an allowed
// target in the first segment and a forbidden one in a later segment: the
// policy would authorize what it saw and the device would apply the rest.
//
// The proxy therefore acts as the server for the client's segment transfer:
// it acknowledges each non-final segment itself, reassembles the APDU, and
// authorizes the complete request. A denied write gets the same tagged Error
// PDU as an unsegmented one and never reaches the device. An allowed write is
// forwarded as one unsegmented request, so the device never sees the client's
// segmentation and its own SegmentACKs cannot be confused with the proxy's.
//
// This is deliberately limited to writes. Every other segmented request keeps
// the original relay behavior: the proxy forwards each segment and carries the
// device's SegmentACKs back unchanged.

const (
	// maxSegWriteBytes bounds the reassembly buffer. A write larger than
	// this is not a reasonable building-automation payload, and an
	// unbounded buffer would be a memory attack from one on-list client.
	maxSegWriteBytes = 16 << 10
	// maxSegWrites bounds concurrent reassemblies across all clients. A
	// partial exchange that the client abandons is swept after the request
	// timeout.
	maxSegWrites = 64
)

// segWrite is one in-progress segmented write, keyed by the client's
// invoke-ID space. The first segment's hash identifies a retransmission of
// segment 0; a later segment with the same key but a different first hash is a
// new exchange that replaced the old one.
type segWrite struct {
	firstHash   [32]byte
	buffer      []byte
	nextSeq     byte
	maxSegments byte
	maxAPDU     byte
	client      peer
	clientID    byte
	deadline    time.Time
}

// handleSegmentedWrite buffers one segment of a segmented write and either
// acknowledges it or, on the final segment, authorizes and forwards the
// reassembled request. It is called instead of the normal write verdict,
// which would deny every segmented APDU by design.
func (g *Gateway) handleSegmentedWrite(a bacnet.APDU, n bacnet.NPDU, p peer, now time.Time, pol *access.Policy) {
	key := clientKey{p.Key(), a.InvokeID}
	hash := apduHash(n.APDU)

	g.mu.Lock()
	sw := g.segWrites[key]
	if a.SequenceNumber == 0 {
		if sw != nil && sw.firstHash == hash {
			// The client retransmitted segment 0 because our ACK was
			// lost. Acknowledge it again; keep the bytes we already have.
			g.mu.Unlock()
			g.ackSegment(p, a)
			return
		}
		if sw == nil && len(g.segWrites) >= maxSegWrites {
			g.mu.Unlock()
			g.rejectSegmentedWrite(p, a, "too many concurrent segmented requests")
			return
		}
		if len(a.Payload) > maxSegWriteBytes {
			delete(g.segWrites, key)
			g.mu.Unlock()
			g.rejectSegmentedWrite(p, a, "segmented request too large")
			return
		}
		// A new segment 0 (or a request that reused the invoke ID)
		// replaces any partial reassembly under the same key.
		sw = &segWrite{
			firstHash:   hash,
			buffer:      append([]byte(nil), a.Payload...),
			nextSeq:     1,
			maxSegments: a.MaxSegments,
			maxAPDU:     a.MaxAPDU,
			client:      p,
			clientID:    a.InvokeID,
			deadline:    now.Add(g.cfg.RequestTimeout),
		}
		g.segWrites[key] = sw
	} else {
		if sw == nil {
			// A middle segment without its first one. There is nothing to
			// authorize and nothing safe to forward; let the client
			// retransmit from the last acknowledged segment.
			g.mu.Unlock()
			g.log.Debug("segmented write without a first segment",
				zap.Stringer("client", p), zap.Uint8("invoke_id", a.InvokeID),
				zap.Uint8("sequence", a.SequenceNumber))
			return
		}
		if a.SequenceNumber < sw.nextSeq {
			// A duplicate of a segment already received and ACKed.
			g.mu.Unlock()
			g.ackSegment(p, a)
			return
		}
		if a.SequenceNumber != sw.nextSeq {
			// Out of order. Drop it; the client resends from the last
			// sequence we acknowledged, which keeps the buffer exact.
			g.mu.Unlock()
			g.log.Debug("segmented write out of order",
				zap.Stringer("client", p), zap.Uint8("want", sw.nextSeq),
				zap.Uint8("got", a.SequenceNumber))
			return
		}
		if len(sw.buffer)+len(a.Payload) > maxSegWriteBytes {
			delete(g.segWrites, key)
			g.mu.Unlock()
			g.rejectSegmentedWrite(p, a, "segmented request too large")
			return
		}
		sw.buffer = append(sw.buffer, a.Payload...)
		sw.nextSeq++
		sw.deadline = now.Add(g.cfg.RequestTimeout)
	}

	if a.MoreFollows {
		g.mu.Unlock()
		g.ackSegment(p, a)
		return
	}

	// Final segment: the complete service payload is in the buffer. Build
	// the unsegmented APDU the client would have sent in one datagram and
	// authorize that, so the policy sees every target.
	full := bacnet.APDU{
		Type:                      bacnet.PDUConfirmedRequest,
		SegmentedResponseAccepted: a.SegmentedResponseAccepted,
		MaxSegments:               sw.maxSegments,
		MaxAPDU:                   sw.maxAPDU,
		InvokeID:                  a.InvokeID,
		HasInvokeID:               true,
		Service:                   a.Service,
		HasService:                true,
		Payload:                   sw.buffer,
	}
	delete(g.segWrites, key)
	g.mu.Unlock()

	g.metrics.SegmentedWrites.Inc()
	if allowed, reason := pol.WriteVerdict(full); !allowed {
		g.metrics.WritesDenied.Inc()
		targets := writeTargetStrings(full)
		g.recordAudit(observ.AuditEvent{
			Event: "write_denied", Leg: peerLeg(p), Client: p.String(),
			Service: full.ServiceName(), Targets: targets, Reason: reason,
		})
		g.log.Info("segmented write denied by policy",
			zap.Stringer("client", p),
			zap.String("service", full.ServiceName()),
			zap.Strings("targets", targets),
			zap.String("reason", reason),
			zap.Uint8("invoke_id", full.InvokeID))
		g.sendClientError(p, full, bacnet.ErrorClassSecurity, bacnet.ErrorCodeWriteAccessDenied)
		return
	}

	// Forward the reassembled APDU in place of the segments. The normal
	// invoke-ID allocation, pending table and replay cache then apply, so a
	// retransmitted segmented request is deduplicated exactly like an
	// unsegmented one.
	n2 := n
	n2.APDU = full.Marshal()
	g.forwardConfirmed(full, n2, p, now, nil)
}

// ackSegment tells the client that one non-final segment was received. The
// server flag is set because the proxy is the server for this transfer; the
// device never sees the segment.
func (g *Gateway) ackSegment(p peer, a bacnet.APDU) {
	ack := bacnet.APDU{
		Type: bacnet.PDUSegmentACK, Server: true,
		InvokeID: a.InvokeID, HasInvokeID: true,
		SequenceNumber: a.SequenceNumber, WindowSize: 1,
	}
	g.sendClientNPDU(buildNPDU(bacnet.NPDU{}, ack.Marshal()), p)
}

// rejectSegmentedWrite refuses a segmented write whose reassembly cannot be
// bounded or ordered. A Reject is the honest answer: the service is understood,
// the transfer failed, and a silent drop would only make the client retry.
func (g *Gateway) rejectSegmentedWrite(p peer, a bacnet.APDU, why string) {
	g.metrics.SegmentedRejected.Inc()
	g.log.Info("segmented write rejected",
		zap.Stringer("client", p), zap.String("reason", why),
		zap.Uint8("invoke_id", a.InvokeID))
	g.sendClientNPDU(buildNPDU(bacnet.NPDU{},
		bacnet.RejectAPDU(a.InvokeID, bacnet.RejectReasonOther).Marshal()), p)
}

// sweepSegWrites drops partial reassemblies the client abandoned. Caller holds
// mu.
func (g *Gateway) sweepSegWritesLocked(now time.Time) {
	for key, sw := range g.segWrites {
		if now.After(sw.deadline) {
			delete(g.segWrites, key)
			g.log.Debug("segmented write expired",
				zap.Stringer("client", sw.client), zap.Uint8("invoke_id", sw.clientID))
		}
	}
}
