package proxy

import (
	"net"
	"time"

	"go.uber.org/zap"

	"github.com/GalaxyGorilla/bacnet-shield/internal/access"
	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet"
	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet/sc"
	"github.com/GalaxyGorilla/bacnet-shield/internal/safego"
)

// peer is one front-leg client. The correlation tables care about identity
// (Key) and the transport that delivers a frame back (SendNPDU); they must not
// care whether the client arrived over BACnet/IP or BACnet/SC. Keeping that
// boundary here is what lets both legs share the pending table, the replay
// cache, COV routing and the write policy.
type peer interface {
	// Key is the stable identity used in every correlation table. It must be
	// unique for the lifetime of the client's one-octet invoke-ID space.
	Key() string
	// String is the log form.
	String() string
	// SendNPDU delivers one network-layer PDU to the client, wrapped in the
	// link layer that leg speaks.
	SendNPDU(npdu []byte) error
}

// udpPeer is a BACnet/IP client. A datagram's source address is its identity,
// which is exactly what the v1 gateway already used.
type udpPeer struct {
	addr *net.UDPAddr
	conn *net.UDPConn
}

func (p *udpPeer) Key() string    { return p.addr.String() }
func (p *udpPeer) String() string { return p.addr.String() }

func (p *udpPeer) SendNPDU(npdu []byte) error {
	frame := bacnet.BVLC{Function: bacnet.BVLCOriginalUnicastNPDU, Data: npdu}.Marshal()
	_, err := p.conn.WriteToUDP(frame, p.addr)
	return err
}

// scPeer is one BACnet/SC node, identified by its virtual MAC. The SC link
// layer already delimits the NPDU, so SendNPDU passes it through untouched.
type scPeer struct {
	vmac sc.MAC
	leg  SCLeg
}

func (p *scPeer) Key() string    { return "sc:" + p.vmac.String() }
func (p *scPeer) String() string { return "sc:" + p.vmac.String() }

func (p *scPeer) SendNPDU(npdu []byte) error {
	return p.leg.SendNPDU(p.vmac, npdu)
}

// SCLeg is the BACnet/SC front-leg transport the data plane drives.
// *scnet.Node implements it; tests supply an in-memory leg. The gateway does
// not own the node's lifecycle: the command runs it, so a hub outage is a
// reconnect loop, not a gateway that stops serving the IP leg.
type SCLeg interface {
	SendNPDU(dest sc.MAC, npdu []byte) error
	SetNPDUHandler(fn func(orig *sc.MAC, npdu []byte))
}

// AttachSC binds a BACnet/SC front leg to the data plane. Every inbound
// Encapsulated-NPDU is attributed to the sender's VMAC, so each SC client gets
// its own invoke-ID space, COV subscriptions and rate bucket. It must be
// called before Serve.
func (g *Gateway) AttachSC(leg SCLeg) {
	if leg == nil {
		return
	}
	g.scLeg = leg
	leg.SetNPDUHandler(g.handleSCNPDU)
}

// handleSCNPDU is the SC front-leg entry point for one NPDU. The hub has
// already authenticated the connection; what remains is the same front-leg
// gate the IP leg applies, keyed by VMAC instead of IP.
func (g *Gateway) handleSCNPDU(orig *sc.MAC, npdu []byte) {
	if orig == nil || orig.IsZero() {
		// An Encapsulated-NPDU with no originating VMAC cannot be attributed
		// to a client, so it cannot be gated, correlated or answered. Drop
		// it rather than invent an identity.
		g.metrics.Unsupported.Inc()
		g.log.Debug("sc npdu without an origin vmac")
		return
	}

	g.metrics.Requests.Inc()
	now := time.Now()
	pol := g.policy.Load()
	switch pol.CheckSC(*orig, now) {
	case access.DenyACL:
		g.metrics.ACLDenied.Inc()
		g.log.Debug("sc client denied by allow-list", zap.Stringer("client", &scPeer{vmac: *orig}))
		return
	case access.DenyRate:
		g.metrics.RateLimited.Inc()
		g.log.Debug("sc client denied by rate limit", zap.Stringer("client", &scPeer{vmac: *orig}))
		return
	case access.DenyDevice:
		g.metrics.DeviceRateLimited.Inc()
		g.log.Debug("sc client denied by the shared device budget", zap.Stringer("client", &scPeer{vmac: *orig}))
		return
	}

	p := &scPeer{vmac: *orig, leg: g.scLeg}
	g.touchClient(p, now)
	// Same panic isolation as the IP datagram path: one malformed SC NPDU
	// must not take down the node's read loop.
	safego.Dispatch(g.log, "gateway sc npdu", func() {
		g.handleClientNPDU(npdu, p, now, pol)
	})
}
