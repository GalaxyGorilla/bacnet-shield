# BACnet Shield security model

BACnet Shield is a security boundary in front of one legacy BACnet/IP device.
It reduces exposure; it does not make an untrusted device, host, or clear
network segment trustworthy.

## Protected assets

- Availability of a fragile legacy device and its single upstream socket.
- Object/property writes governed by read-only or scoped write policy.
- COV subscriptions, so a client only receives notifications for objects it
  subscribed to.
- Integrity of the running policy across configuration reloads.
- The client↔device mapping: an answer is delivered to the client that asked,
  never to a third party.

## Trust boundaries

The appliance host, configuration file and administrators are trusted. A
one-box gateway leaves the final proxy-to-device BACnet/IP leg clear;
physically protect or isolate that segment. BACnet/SC (TLS 1.3 + WebSocket) is
the planned standard secure front leg for a later milestone and is not present
in v1.

Client IP allow-lists are network policy, not cryptographic identity: BACnet/IP
is unauthenticated, so any host on an allowed network can claim any device
instance. Use BACnet/SC, and identity-aware network controls, when identity
must survive NAT or a shared client network. The legacy device and all wire
input are treated as malformed or hostile, but a compromised device can still
return plausible false process data.

## Enforced controls

- Strict BVLC/NPDU/APDU framing with bounded lengths; only Original-Unicast and
  Original-Broadcast are accepted, and routing fields are stripped.
- Client allow-list and a per-client token-bucket rate limit; an off-list
  source never consumes another client's budget.
- Read-only mode or an `<object-type>:<instance>:<property>` write policy with
  deny-overrides and allow-must-cover semantics.
- Undecodable and segmented writes are denied fail-closed, before forwarding.
- Invoke-ID translation per client, a bounded pending table, retransmission
  dedupe and a completed-response replay cache; a resent request never reaches
  the device twice while it is in flight.
- COV routing installed only after the device answers with a SimpleACK;
  a rejected subscription is never routed. A confirmed notification with no
  subscriber is answered with an Error PDU so the device stops retransmitting.
- Atomic runtime-policy snapshots on `SIGHUP`; an invalid reload keeps the last
  valid policy.
- Hardened systemd service, readiness ordering, watchdog, graceful shutdown,
  structured logs, a metrics endpoint and policy counters.

Policy denials are enforced before the device sees a write. ACL and rate
denials are silent by design; write and unsupported-subscription denials are
answered with a BACnet Error PDU (see [README.md](README.md)).

## Deliberate limits

- BACnet Shield is not a firewall, an IDS, a BACnet device stack, a router or a
  BBMD. It forwards one device's traffic and gates the client leg.
- The one-box deployment does not encrypt or authenticate the legacy device
  leg; that leg is trusted at the network layer.
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
