# What bacnet-shield is trying to solve

## The problem

A building controller can sit in a wall for twenty years. It speaks BACnet/IP,
a protocol with no authentication, no encryption and no notion of "who may
change this setpoint". Replacing it means a commissioning project, a new
object model and a supplier relationship; changing its firmware is usually not
possible. The device stays.

That leaves the network as the security boundary. A firewall or VLAN can say
"this subnet may reach that controller", but it cannot say:

- this BMS may read everything, that dashboard may only read temperatures, and
  nobody may write the chiller setpoint;
- one runaway poller must not spend the controller's capacity for everyone
  else;
- a write that is refused must fail immediately with a BACnet error, not time
  out;
- a COV subscription must deliver the device's notifications back to the client
  that asked, not to the whole broadcast domain;
- clients on an untrusted or remote network must authenticate with TLS instead
  of plain UDP.

## What the proxy does

`bacnet-shield` is a small, transparent gate in front of the legacy device.
Clients are repointed to it once. The device keeps speaking plain BACnet/IP
(IPv4 or IPv6) and does not know the proxy exists.

It adds exactly the decisions a building network needs:

- **Who** may connect: IP/CIDR allow-list (and a VMAC allow-list for BACnet/SC).
- **How hard**: per-client token bucket and an optional shared budget toward
  the device, so a fragile controller survives a polling storm.
- **What may be written**: read-only, or rules scoped to
  `<object-type>:<instance>:<property>`, with deny-overrides and
  allow-must-cover semantics. Segmented writes are reassembled and authorized
  as a whole, so a target cannot hide in a later segment.
- **How the answer travels**: invoke-ID translation, retransmission dedupe,
  a completed-response replay cache, and COV routing to the right subscriber.
- **How a client authenticates** (optional): BACnet/SC through an existing hub,
  TLS 1.3 + WebSocket, with the same policy keyed by virtual MAC.
- **What happened**: an opt-in JSON audit stream naming the client, the service,
  the decoded write target and a closed-set reason; Prometheus metrics per
  device.

The proxy is deliberately a **strict forwarder**: the service payload goes in
and out byte for byte; only link/network headers and the invoke ID are rewritten.
It is not a BACnet device stack, a router, a BBMD or an SC hub, and it never
caches property values.

## Who it is for

- **Building/HVAC integrators and BMS owners** with a controller they cannot
  replace, and several clients that need different rights.
- **OT security teams** that need a compensating control in front of a legacy
  BACnet segment without touching the device.
- **Multi-protocol appliance builders**: the same shape (one process, several
  devices, one metrics/audit surface) exists in the Modbus and SNMP Shield
  projects, so a single box can protect a mixed building/industrial site.

It is a poor fit when a VLAN/firewall already provides enough isolation, when
the device itself supports BACnet/SC and can be enabled, or when the site needs
protocol translation, routing/BBMD, or state-syncing high availability.

## What it does not solve

- **It is a gate, not authentication on the IP leg.** An attacker on an allowed
  L2 segment can spoof a source address. Only the BACnet/SC front leg gives
  cryptographic client identity.
- **The device leg is still clear.** The proxy does not encrypt or authenticate
  the last hop to the legacy device; protect that segment physically or with a
  VLAN.
- **No physical commissioning yet.** The software is race-tested and driven by
  two independent BACnet stacks, but it has not been commissioned against real
  controllers. Timing, vendor quirks and device reboots remain a site task.
- **No router/BBMD/translation.** Clients behind a BBMD (`Forwarded-NPDU`) are
  rejected by design; see [b3-bbmd.md](b3-bbmd.md).
- **No state-syncing HA.** Active/passive behind a virtual IP is documented in
  [ha.md](ha.md); pending requests, the replay cache and COV subscriptions do
  not follow a failover.
- **No property cache.** A read always reaches the device; a stale setpoint is
  worse than a slow one.

## Why a proxy rather than an upgrade

| Option | What it gives you | What it costs |
|---|---|---|
| Replace the controller | New firmware, maybe native BACnet/SC | Capital project, commissioning, object-model migration |
| VLAN / firewall | Network isolation | Cannot express per-object writes, per-client pacing, COV routing or a clean BACnet refusal |
| BACnet router with ACLs | Routing plus coarse filtering | Still no write policy per object/property, no audit of the target |
| Native BACnet/SC on the device | Real authentication and encryption | Requires a device that supports it and can be reconfigured |
| **bacnet-shield** | Allow-list, rate/budget, scoped writes, COV routing, optional SC, audit | One more box and a one-time client repoint; the device and its object model stay |

The value is the **retrofit boundary**: security decisions without replacing the
installed asset, matching its object model, or changing the vendor.

## Proof status

- Codecs for BVLC/BVLC6/NPDU/APDU/tags/object IDs/write targets/COV, with 11
  native fuzz targets.
- Race suite on real loopback sockets: invoke-ID collisions, retransmission
  dedupe, pending expiry, segmented writes/responses, COV, multi-device
  co-hosting, IPv4/IPv6/SC legs.
- Independent peers: bacpypes3 0.0.110 on both IP legs (read, write, denial,
  COV, segmented response and write, reload) and bacnet-stack 1.6.1's
  `sc-hub` + BSC clients for BACnet/SC.
- Honest gaps: no physical commissioning; no independent IPv6 application
  peer; multi-object COV is wire-tested only (both peers mark it TODO).

## What a pilot should prove

1. The real controller accepts the forwarded reads/writes and its vendor client
   sees the same values.
2. A denied write returns the expected BACnet error, and the device never sees
   it.
3. A COV subscriber receives the device's notification after a write.
4. The device survives the site's polling pattern under the configured limits.
5. A restart/failover does not silently lose a write, and operators know that
   COV clients must resubscribe.
6. The audit log answers "who tried to write what, and why was it refused".
