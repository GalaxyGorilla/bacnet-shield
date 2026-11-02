package proxy

import (
	"crypto/sha256"
	"net"
	"time"

	"go.uber.org/zap"

	"github.com/GalaxyGorilla/bacnet-shield/internal/access"
	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet"
	"github.com/GalaxyGorilla/bacnet-shield/internal/observ"
)

// resolveAddr chooses the socket family from a configured address. An empty
// host (":47808") keeps the historical IPv4 wildcard; an IPv6 literal
// ("[::1]:47808" or "[::]:47808") selects IPv6. A hostname is resolved as IPv4
// for compatibility; use a literal when an IPv6 leg is intended.
func resolveAddr(addr string) (*net.UDPAddr, string, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, "", err
	}
	network := "udp4"
	if host != "" {
		if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
			network = "udp6"
		}
	}
	ua, err := net.ResolveUDPAddr(network, addr)
	if err != nil {
		return nil, "", err
	}
	return ua, network, nil
}

// deriveVMAC gives an IPv6 listener a stable 3-octet virtual address. The
// proxy's own address is not configured: a client discovers it with
// VirtualAddressResolution, and it only has to stay the same across restarts.
// Deriving it from the bound listen address gives that stability without
// another config knob; two proxies on one IPv6 link use different listen
// addresses (and therefore different virtual addresses).
func deriveVMAC(addr *net.UDPAddr) bacnet.VMAC {
	sum := sha256.Sum256([]byte(addr.String()))
	var v bacnet.VMAC
	copy(v[:], sum[:3])
	if v.IsZero() {
		v[2] = 1
	}
	return v
}

// handleClientIPv6 is the BACnet/IPv6 front-leg entry point. The ACL, rate
// limit and device budget were already charged by handleClient against the UDP
// source; what remains is the IPv6 link layer. The device leg stays plain
// BACnet/IPv4, so the frame is reduced to its NPDU here and wrapped for the
// device by the normal forwarding path.
func (g *Gateway) handleClientIPv6(dg []byte, src *net.UDPAddr, l clientListener, now time.Time, pol *access.Policy) {
	b, err := bacnet.ParseBVLC6(dg)
	if err != nil {
		// An undecodable frame cannot be a link-layer resolution request, so
		// it is charged like data even though it never reaches the device.
		_ = pol.CheckData(src.IP, now)
		g.metrics.ParseErrors.Inc()
		g.log.Debug("client bvlc6 parse", zap.Error(err), zap.Stringer("client", src))
		return
	}

	switch b.Function {
	case bacnet.BVLC6VirtualAddressResolution:
		// The requester wants this node's virtual address. Answering is a
		// link-layer service, but it is still gated by the ACL above so an
		// off-list peer cannot confirm that a proxy is present.
		g.sendLinkFrame(l, bacnet.BVLC6{
			Function: bacnet.BVLC6VirtualAddressResolutionACK,
			Src:      l.vmac,
			Dst:      b.Src,
		}.Marshal(), src)
		return
	case bacnet.BVLC6AddressResolution:
		// A peer that already knows the virtual address asks for the IPv6
		// station behind it. Only answer when the target is this node.
		if b.Dst == l.vmac {
			g.sendLinkFrame(l, bacnet.BVLC6{
				Function: bacnet.BVLC6AddressResolutionACK,
				Src:      l.vmac,
				Dst:      b.Src,
			}.Marshal(), src)
		}
		return
	}

	switch pol.CheckData(src.IP, now) {
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

	switch b.Function {
	case bacnet.BVLC6OriginalUnicastNPDU, bacnet.BVLC6OriginalBroadcastNPDU:
		// The data path.
	default:
		g.metrics.Unsupported.Inc()
		g.log.Debug("client sent an unsupported IPv6 bvlc function",
			zap.String("function", b.Function.String()), zap.Stringer("client", src))
		return
	}

	p := &udpPeer{
		addr:      src,
		conn:      l.conn,
		ipv6:      true,
		vmac:      b.Src,
		localVMAC: l.vmac,
	}
	g.touchClient(p, now)
	g.handleClientNPDU(b.Data, p, now, pol)
}

// sendLinkFrame writes one link-layer frame (not an NPDU) to a client on the
// listener it arrived on. It is used only by the IPv6 address-resolution
// exchange.
func (g *Gateway) sendLinkFrame(l clientListener, frame []byte, src *net.UDPAddr) {
	if _, err := l.conn.WriteToUDP(frame, src); err != nil {
		g.log.Debug("client leg write", zap.Error(err), zap.Stringer("client", src))
	}
}
