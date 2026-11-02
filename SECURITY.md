# BACnet Shield security model

BACnet Shield is a security boundary in front of one or more legacy BACnet/IP
devices. It reduces exposure; it does not make an untrusted device, host, or
clear network segment trustworthy.

## Protected assets

- Availability of each fragile legacy device and its single upstream socket.
- Isolation between co-hosted devices: a client of one device's listener can
  never reach another device, and one device's policy never gates another's.
- Object/property writes governed by read-only or scoped write policy.
- COV subscriptions, so a client only receives notifications for objects it
  subscribed to.
- Integrity of the running policy across configuration reloads.
- The client↔device mapping: an answer is delivered to the client that asked,
  never to a third party.
- SC client admission: the opt-in VMAC allow-list and the per-VMAC mapping.

## Trust boundaries

The appliance host, configuration file and administrators are trusted. The
deployment leaves each proxy-to-device BACnet/IP leg clear; physically protect
or isolate those segments.

The BACnet/SC front leg (TLS 1.3 + WebSocket, BVLC-SC `0x82`) secures the
client side only. The proxy is a **node** of an existing hub; it is not a hub.
The hub is the trust anchor for the SC side: it terminates TLS, admits nodes and
is responsible for attributing a frame to the VMAC it claims. The proxy's
`access.sc_allow` is a second, opt-in gate for that authenticated identity, not
a replacement for hub admission. Use a hub whose node authentication matches the
site's identity requirements.

Client IP allow-lists are network policy, not cryptographic identity: BACnet/IP
is unauthenticated, so any host on an allowed network can claim any device
instance. BACnet/SC gives cryptographic transport identity up to the hub, but a
compromised hub or node is still inside that boundary. The legacy device and all
wire input are treated as malformed or hostile, but a compromised device can
still return plausible false process data.

## Enforced controls

- Strict BVLC/NPDU/APDU framing with bounded lengths; only Original-Unicast and
  Original-Broadcast are accepted, and routing fields are stripped. The IPv6
  front leg applies the same rule to link type `0x82`: the frame family must
  match the listener, and the NPDU is the only part that crosses into the data
  plane.
- Client allow-list and a per-client token-bucket rate limit; an off-list
  source never consumes another client's budget. The same list and limiter
  apply to IPv6 sources, and an off-list IPv6 peer gets no link-layer answer
  either. The SC leg has a VMAC allow-list and a VMAC-keyed bucket; an IP
  allow-list entry and a VMAC entry never share a bucket.
- SC transport is TLS 1.3 only, with hub certificate verification (system roots
  or a configured CA) and an optional client certificate. A plaintext `ws://`
  hub is rejected outside tests.
- The SC node drops an `Encapsulated-NPDU` addressed to another VMAC and one
  without a nonzero origin, even if the hub delivered it.
- Read-only mode or an `<object-type>:<instance>:<property>` write policy with
  deny-overrides and allow-must-cover semantics.
- Undecodable writes are denied fail-closed, before forwarding. A segmented
  write is acknowledged segment by segment, reassembled, authorized as a whole
  and only then forwarded as one request; over-limit and out-of-order transfers
  are refused.
- Invoke-ID translation per client, a bounded pending table, retransmission
  dedupe and a completed-response replay cache; a resent request never reaches
  the device twice while it is in flight.
- COV routing installed only after the device answers with a SimpleACK;
  a rejected subscription is never routed. A confirmed notification with no
  subscriber is answered with an Error PDU so the device stops retransmitting.
- Atomic runtime-policy snapshots on `SIGHUP`; an invalid reload keeps the last
  valid policy.
- An opt-in structured audit stream records every ACL, rate, device-budget,
  write and unsupported-subscription decision with the client, the service and
  the decoded object/property target, and a closed-set reason for a refused
  write. It observes the decision the policy already made and never changes it.
- Hardened systemd service, readiness ordering, watchdog, graceful shutdown,
  structured logs, a metrics endpoint and policy counters.

Policy denials are enforced before the device sees a write. ACL and rate
denials are silent by design; write and unsupported-subscription denials are
answered with a BACnet Error PDU (see [README.md](README.md)).

## Deliberate limits

- BACnet Shield is not a firewall, an IDS, a BACnet device stack, a router or a
  BBMD. It forwards each device's traffic over its own isolated listener↔device
  pair and gates that pair's client leg; no traffic crosses between co-hosted
  devices.
- The deployment does not encrypt or authenticate the legacy device legs; those
  legs are trusted at the network layer.
- The proxy does not authenticate SC nodes itself; it trusts the hub to do so.
  `access.sc_allow` can narrow that set by VMAC, but it cannot detect a hub
  that misattributes a frame.
- SC admission is VMAC-only today. UUID-keyed admission requires
  Address-Resolution, which the node does not implement; a UUID entry in
  `sc_allow` is rejected rather than silently unenforced.
- The proxy is not an SC hub and does not accept SC direct connections.
- SC per-client state is keyed by VMAC and outlives a hub reconnect for its
  normal expiry window (pending timeout, 30 s replay cache, 5 min idle). A hub
  that lets a different node reuse a VMAC would inherit that state; VMAC
  uniqueness across the hub's lifetime is a hub responsibility.
- Rate limits reduce abuse but cannot guarantee availability under host,
  network or upstream-device exhaustion.
- Write protection is opt-in: with neither `read_only` nor `write_policy`
  configured, writes pass through unchanged.
- The proxy does not reassemble segmented payloads and refuses segmented
  writes; segment-boundary behavior is tracked, not validated end to end.
- Real hardware, external review and formal BACnet conformance testing remain
  separate validation work (see [CONFORMANCE.md](CONFORMANCE.md) and
  [BACKLOG.md](BACKLOG.md)).

## Release security gate

```sh
make verify       # format, race suite, build and vet
make acceptance   # verify + independent bacpypes3 client/device
make security     # verify + staticcheck + govulncheck + SBOM + HIGH+ gate
```

`make sbom` writes SPDX and CycloneDX documents to `dist/`.

## Reporting vulnerabilities

Please use GitHub's private **Report a vulnerability** function for this
repository. Include the affected deployment shape, configuration, a
reproduction, the expected policy and the observed wire behavior. Do not attach
production credentials, keys, or packet captures containing building process
data.
