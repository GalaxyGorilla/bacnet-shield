package proxy

import (
	"github.com/GalaxyGorilla/bacnet-shield/internal/bacnet"
)

// The audit stream records every front-leg security decision as a structured
// event. The proxy stays a strict forwarder: auditing observes the decision, it
// never changes it. Events are emitted only where the policy already decided
// something (allow-list, rate limit, device budget, write policy, unsupported
// subscription), so the audit adds no new traffic path.

// peerLeg names the front leg a peer arrived on, for the audit record. The
// data plane treats both legs identically; only the audit labels which door the
// client used.
func peerLeg(p peer) string {
	if _, ok := p.(*scPeer); ok {
		return "sc"
	}
	return "ip"
}

// writeTargetStrings decodes the object/property targets of a denied write for
// the audit record. It is best-effort: an undecodable write yields nil, and the
// audit reason ("undecodable_write") already records that the target could not
// be read. It is only called on a denial, so the extra decode is off the hot
// path.
func writeTargetStrings(a bacnet.APDU) []string {
	targets, isWrite, err := bacnet.WriteTargets(a)
	if !isWrite || err != nil {
		return nil
	}
	out := make([]string, 0, len(targets))
	for _, t := range targets {
		out = append(out, t.String())
	}
	return out
}
