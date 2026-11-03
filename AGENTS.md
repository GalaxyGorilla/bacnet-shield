# AGENTS.md — bacnet-shield

> **Read this file first. Update it at the end of every task** — behavior,
> layout, commands, decisions. Treat it as documentation-as-code.

## 1. Mission

This project is a **BACnet/IP security proxy** for retrofit installations.
From the original motivation:

> "Retrofitting — adding security capabilities to legacy devices by adding a
> box in front of them, or even inside their casing."

Deployment model (co-hosting, one process, N independent pairs):

```
[N clients]    --BACnet/IP--> [bacnet-shield] --BACnet/IP--> [legacy device A]
[N clients]    --BACnet/IP--> [bacnet-shield] --BACnet/IP--> [legacy device B]
[N SC nodes] --BACnet/SC--> [existing hub] --> [bacnet-shield] --BACnet/IP-->
```

Clients are repointed to the proxy once; the devices stay unchanged and keep
speaking plain BACnet/IP (IPv4 or IPv6). Each `devices:` entry is its own front
leg, device leg and policy; no datagram crosses between entries. The proxy is
each device's security gate: client allow-list, per-client rate limit, and
object/property-scoped write protection. It is **not** a BACnet device stack, a
BBMD, a router, or an SC hub.

The v1 essence: a **strict forwarder** — the service payload goes in and out
byte for byte; only the link/network headers and the APDU invoke ID are
rewritten, and only the front-leg policy can reject a request.

## 2. Decisions (do not re-litigate without strong reason)

| Topic | Decision |
|---|---|
| Language | **Go** — static single binary for appliance use, goroutines for the two UDP legs, race detector + native fuzzing for the test bar |
| Scope | **One or more co-hosted devices per instance**, each an independent listener↔device pair. BBMD, routing and cross-device traffic are backlog; the proxy never pretends to be a router |
| Forwarding level | Parse BVLC/NPDU/APDU enough to route and gate; forward the **service payload opaquely**. No re-encoding, no property cache |
| Correlation | **Rewrite the invoke ID**, not the payload. Per-client ↔ device-leg translation with a 256-entry pending table and a 30 s completed-response cache |
| Retransmissions | A retransmission of an in-flight request is **dropped** (re-sending a write applies it twice). A finished response is replayed from cache |
| Security v1 | IP/CIDR allow-list + per-client token bucket + optional shared per-device budget + `read_only` **or** `<object-type>:<instance>:<property>` write policy. Write protection is opt-in: with neither configured, writes pass through. Deny-overrides, allow-must-cover, fail-closed on undecodable writes; a segmented write is reassembled and authorized as a whole before it is forwarded |
| Denial shape | ACL/rate denials are silent. A refused write gets Error class `security` (4) / code `write-access-denied` (40). Unsupported subscriptions get class `services` (5) / code `service-request-denied` (29). An unroutable confirmed COV gets code `unknown-subscription` (79) |
| COV | Track `SubscribeCOV`, `SubscribeCOVProperty` and `SubscribeCOVPropertyMultiple`. Install only after a SimpleACK; a multiple subscription installs one entry per monitored object, and a notification-multiple routes to the union of subscribers (each client once). Segmented subscriptions are refused |
| Config changes | `SIGHUP` re-reads `--config` and swaps only the access policy (including `access.sc_allow`). Listener/device/timeout/log/metrics and the whole `sc` block are reported as restart-only warnings. Invalid reload keeps the running policy |
| Secure front leg | BACnet/SC (TLS 1.3 + WebSocket, BVLC-SC `0x82`). The proxy is an SC **node** that attaches to an existing hub (primary + failover), not a hub itself. A private PSK tunnel is explicitly rejected |
| Front-leg identity | One `peer` abstraction (`Key`, `IP`, `SendNPDU`) keyed by `ip:port` on the IP leg and `sc:<vmac>` on the SC leg. The data plane and its replay cache hold **NPDUs**, not link frames, so both legs share pending, replay, COV and write policy. Never key SC state by connection |
| Front doors | A device entry has one required `listen_addr` and optional `extra_listen` sockets. Every door shares one device leg, policy and pending/replay/COV tables; the client identity is still its `ip:port`, so a retransmission on another door hits the same replay entry. Each door has its own family and IPv6 virtual address |
| SC client admission | Opt-in SC allow-list keyed by **VMAC** (`access.sc_allow`). With none configured, any node the hub delivers is accepted and only the write policy gates it (same "protection is opt-in" shape as the IP leg). UUID-keyed rules cannot be enforced through a hub; a UUID entry is rejected rather than silently ignored |
| SC transport | TLS 1.3 (`crypto/tls`) + a small, fuzzed WebSocket frame parser we own, not a WebSocket dependency. The proxy is always the WebSocket client. The hub is trusted to attribute frames to their originating VMAC; the node still drops a frame addressed to another VMAC or with a zero/missing origin |
| Device leg | Plain BACnet/IPv4 or BACnet/IPv6 over UDP, independent of the front leg. The SC front leg is additive. An IPv6 device leg discovers the device's 3-octet virtual address with `VirtualAddressResolution` (and learns it from any frame the device sends); requests are dropped until it is known, never sent with a guessed address |
| IPv6 legs | Opt-in by using an IPv6 literal in `listen_addr` and/or `device_addr`. Parse/serve BACnet/IPv6 (Annex U, link type `0x82`, 3-octet virtual addresses, address resolution) on either leg, reduce a frame to its NPDU, and use the same data plane. `device_local_addr` must match the device's family. All four v4/v6 combinations are supported. Address-resolution frames are ACL-gated but never spend a data token or the device budget: they do not reach the device |
| Ground truth | ASHRAE 135 wire formats, cross-checked against **bacpypes3 0.0.110** in `.venv`. Vendor divergence is reported in [CONFORMANCE.md](CONFORMANCE.md), never silently adapted away in the proxy |
| Audit | Opt-in structured stream (`audit.file`), one JSON object per security decision (ACL, rate, device budget, write policy, unsupported subscription), with the decoded target and a closed-set reason for a refused write. Bounded stream: a rotating file (one backup) plus a bounded non-blocking queue that drops-and-counts. Observes decisions; never changes them |
| No CI | Deliberate user decision across the Shield projects. Gates are local `make` targets |

## 3. Architecture and code map

```
cmd/bacnet-shield/     CLI: gateway | validate | selftest | version | help
internal/bacnet/       Wire codecs (BVLC, BVLC6, NPDU, APDU, tags, object IDs, services)
internal/bacnet/sc/    BACnet/SC virtual link layer (BVLL-SC) codec
internal/scnet/        SC transport: TLS 1.3, WebSocket framing, node↔hub state machine
internal/access/       Allow-list, per-client token bucket, shared device budget, write policy
internal/config/       YAML + flags, validation, access-policy compilation
internal/proxy/        Data plane: one Gateway per device, Runner over all gateways, invoke IDs, COV, probe
internal/observ/       zap logger, shared Prometheus registry (per-device `device` label), /metrics listener, audit stream
internal/safego/       Panic isolation for per-datagram handlers
internal/watchdog/     sd_notify READY/WATCHDOG
internal/testkit/      Soak-duration helper shared by test suites
configs/gateway.yaml   Annotated example
deploy/                Hardened systemd unit
examples/              Deployment walkthroughs (gateway, access control, SC, operations)
docs/assets/           README logo
scripts/               bacpypes3 peer provisioning and interop drivers
```

### Data path

Each `devices:` entry builds its own `Gateway` (its own client socket, device
socket, policy, pending table, replay cache and COV table). A `Runner` merely
starts every gateway and stops them together; it never moves a datagram between
them. Inside one gateway:

1. `clientLoop` reads a datagram, applies `Policy.Check` (ACL first, then the
   per-client rate limit, then the shared device budget; an off-list source
   never consumes another client's token, and a rate-denied request never spends
   the shared budget), parses BVLC, wraps the source in a `udpPeer`, and calls
   `handleClientNPDU`.
   The SC leg's `handleSCNPDU` applies `Policy.CheckSC` (VMAC allow-list, then a
   VMAC-keyed rate limit, then the same shared device budget) before parsing,
   wraps the sender VMAC in an `scPeer`, and calls the same `handleClientNPDU`.
2. `handleClientConfirmed` refuses unsupported subscription services, applies
   `AllowWrite`, and calls `forwardConfirmed`.
3. `forwardConfirmed` allocates a device invoke ID, patches the octet, records
   `pending[devID]` and `byClient[(peer key, clientInvokeID)]`, and sends the
   frame to the device.
4. `deviceLoop` accepts datagrams only from the configured device **IP**
   (the port is learned from the response, because stacks reply from a
   different port). A response is correlated through `pending`, patched back
   to the client's invoke ID, cached as an NPDU if complete, and sent through
   that peer's link layer.
5. The sweeper expires pending requests, replay entries, device exchanges,
   COV subscriptions and idle clients once per second. An expired request that
   was never answered increments `bacnet_shield_request_timeouts_total`.
6. On shutdown the gateway stops reading the client leg, keeps the device leg
   and the client socket open for a bounded drain (2 s), and only then closes
   both. A request already at the device still gets its answer; a datagram that
   arrives after cancellation does not start a new exchange. The command keeps
   the SC nodes alive until that drain finishes, so an SC client's answer can
   still travel through the hub.

### State tables (all bounded, one set per device)

| Table | Key | Bound / lifetime |
|---|---|---|
| `pending` | device invoke ID | `max_pending` (1..256), `request_timeout_secs` |
| `byClient` | peer key + client invoke ID | one entry per pending request |
| `done` | peer key + client invoke ID | 2048 entries, 30 s |
| `segWrites` | peer key + client invoke ID | 64 in-progress writes, 16 KiB each, `request_timeout_secs` |
| `fromDevice` / `toDevice` | device invoke ID / peer key | `request_timeout_secs`, plus 10 s segment grace |
| `clients` | peer key (`ip:port` or `sc:<vmac>`) | 1024 entries, 5 min idle |
| `cov` | monitored object + subscriber process ID + peer key | 4096 subscriptions, optional device lifetime |
| rate buckets | IP string or `sc:<vmac>` | 4096 entries, 5 min idle sweep |

### Wire invariants pinned by tests

- BVLC length includes the 4-byte header. Only `0x0A` (Original-Unicast) and
  `0x0B` (Original-Broadcast) are accepted from a client; other functions are
  counted unsupported.
- BACnet/IPv6 frames use link type `0x82`, not `0x81`: Original-Unicast is
  function `0x01` with a 3-octet source and destination virtual address,
  Original-Broadcast is `0x02` with a source only. A frame of the wrong family
  is a parse error, never guessed at. On the front leg, VirtualAddressResolution
  (`0x06`) and AddressResolution (`0x03`) are answered for an admitted client.
  On an IPv6 device leg the proxy is the requester: it sends
  VirtualAddressResolution and uses the ACK's source virtual address; until that
  is known, requests are dropped rather than sent with a guessed address. Every
  other IPv6 function (Forwarded-NPDU, foreign-device, Distribute-Broadcast) is
  counted unsupported. The NPDU inside is the same network/application payload,
  which is why both legs share one data plane.
- A client broadcast is forwarded to **that listener's device** as unicast. Each
  listener has exactly one device, so a broadcast is a discovery request aimed
  at it; it is never routed to another co-hosted device.
- NPDU routing fields (DNET/SNET/hop count) are stripped on the way to the
  device and never invented on the way back.
- APDU invoke ID is at octet 2 for a confirmed request and octet 1 for every
  other type. `PatchInvokeID` rewrites exactly that octet.
- Error PDU parameters are **application-tagged ENUMERATEDs**, not raw
  octets: class `security`, code `write-access-denied` is `91 04 91 28`. A
  raw-octet payload is dropped by a strict stack, which turns a denial into a
  timeout. Pinned by `TestErrorAPDUEncoding`.
- COV notification object is context tag 2; subscription object is context
  tag 1; subscriber process ID is context tag 0. A notification with no
  subscriber is never broadcast to everyone.
- A COVNotificationMultiple (confirmed `31`, unconfirmed `11`) and a
  SubscribeCOVPropertyMultiple (`30`) carry their object list under tag 4. A
  BACnet SEQUENCE element has no tag of its own: each element is `[0] object
  id` followed by the constructed `[1]` list, so the decoder must not expect an
  opening tag around an element. A property reference inside `[1]` is itself a
  constructed CHOICE (`[0]` opening/closing). The decoders extract one object
  per element and skip the rest structurally; a list with no object is
  rejected, never treated as "everyone". Pinned by `TestCOVMultiple*`.
- A segmented write is reassembled before the policy sees it: the proxy is the
  server for the client's segment transfer, so it acknowledges each non-final
  segment itself and forwards the complete request as one unsegmented APDU.
  The policy decodes every target, including one that only appeared in a later
  segment. A reassembly over 16 KiB or an out-of-order segment is refused, not
  guessed at. A non-segmented WritePropertyMultiple is decoded far enough to
  authorize every target.
- The data plane and the replay cache hold **NPDUs**. The IP leg wraps one in
  `BVLC Original-Unicast` on the way out; the SC leg hands it to
  `Encapsulated-NPDU`. A cached frame tied to one link layer would break the
  other leg.
- An SC node drops an `Encapsulated-NPDU` whose destination is a different
  VMAC and one with no (or a zero) origin VMAC, even though the hub should
  have routed it. Pinned by `TestNodeFiltersInboundNPDUs`.
- An SC node sending an `Encapsulated-NPDU` sets **only** the destination
  VMAC. Setting its own originating VMAC is an identity it must not assert:
  bacnet-stack's hub NAKs it (`'Originating Virtual Address' field must be
  absent`). Pinned by `TestNodeConnectsSendsAndReceives` (the fake hub now
  enforces the rule) and by `make interop-sc`.
- SC peer state is keyed by `sc:<vmac>`; two SC nodes using invoke ID 7 at the
  same time must each get their own answer. Pinned by
  `TestGatewaySCMultiClientInvokeIDs`.

## 4. CLI and configuration contract

Commands: `gateway`, `validate [--json]`, `selftest [--json]
[--probe=false]`, `version`, `help`.

Every command accepts either `--config <file>` or the gateway flags. Flags
mode is for a two-line paste install and always builds exactly one device;
YAML mode is the appliance shape and may list several. Both compile to the same
`config.Config`, so validation and the daemon cannot drift.

A YAML file has process-wide `log_level`, `metrics`, `audit`, and a `devices:`
list. Each entry carries its own `listen_addr`, optional `extra_listen`,
`device_addr`, `device_local_addr`, `device_instance`, `request_timeout_secs`,
`max_pending`, `access` block and optional `sc` block. `name` (default:
`device_addr`) labels the device in logs, metrics and the audit, and is the
reload match key; it, every listener address and `sc.vmac` must be unique
across the process.

Reloadable on `SIGHUP` (per device, matched by `name`): `access.allow`,
`access.sc_allow`, `access.rate_per_sec`, `access.device_rate_per_sec`,
`access.read_only`, `access.write_policy`.

Restart-only (reported, never silently ignored): adding or removing a device,
and `listen_addr`, `extra_listen`, `device_addr`, `device_local_addr`,
`device_instance`, `request_timeout_secs`, `max_pending`, `log_level`,
`metrics.addr`, `audit.*`, and the whole `sc` block (`vmac`, `uuid`, `hubs`,
`ca_file`, `cert_file`, `key_file`).

The SC leg is configured per device, either as an `sc:` YAML block or with
`--sc-vmac/--sc-uuid/--sc-hub/--sc-ca/--sc-cert/--sc-key`; `sc_allow` is
`--sc-allow`. Each device with an `sc` block is its own SC node (its own
VMAC/UUID), so give each a distinct VMAC. A partially configured block is a
validation error, never a silently disabled leg.

A reload with an invalid file or policy logs an error and keeps the running
configuration. In flags mode a SIGHUP is ignored with a warning: there is no
file to re-read and the flags came from the command line.

## 5. Testing expectations

- **No CI.** Do not add workflows. `make verify` is the local gate.
- **Adversarial coverage is required**, not just happy paths: malformed and
  truncated frames, spoofed sources, invoke-ID collisions, retransmissions,
  write-policy straddles, segmented bypasses, unknown subscriptions.
- **Test volume is fine** — 10× the operational code is acceptable when the
  suite is structured and maintainable. Share fixtures (`harness_test.go`)
  instead of copying them.
- **Fuzz targets** live in `internal/bacnet/fuzz_test.go` (including
  `FuzzParseBVLC6` for the IPv6 link layer), the SC codec
  (`internal/bacnet/sc/fuzz_test.go`: `FuzzParse` for the header and
  `FuzzDecodeMessage` for every typed body decoder), and the WebSocket frame
  parser (`internal/scnet` `FuzzParseFrame`). Every parser entry point has one;
  a crash is a bug, not a corpus entry to hide.
- **SC tests** run a real in-process TLS 1.3 hub (`internal/scnet/node_test.go`)
  for connect/heartbeat/reconnect, heartbeat timeout, hub-list failover,
  malformed/non-binary frame survival and destination filtering, and drive the
  proxy data plane through an in-memory SC leg (`internal/proxy/sc_test.go`)
  for two clients with the same invoke ID, an IP and an SC client sharing an
  invoke ID, per-VMAC ACL/rate, per-leg rate isolation, write denial, replay
  across the leg boundary, COV fan-out and I-Am fan-out. Keep those two seams
  separate: the fake leg proves the data plane, the TLS hub proves the
  transport.
- **Oracle golden bytes** for the SC codec come from bacpypes3
  (`scripts/sc-golden.py`, cross-checked against bacnet-stack's `bvlc-sc.c`).
  Regenerate and compare with `internal/bacnet/sc/sc_test.go` when a peer
  reports a divergence; record it in `CONFORMANCE.md`.
- **Soak tests** are opt-in: `make soak` sets `BACNET_SHIELD_SOAK=1` and
  `BACNET_SHIELD_SOAK_DURATION` (default 10m). They assert bounded tables,
  flat goroutines/heap and zero unanswered requests for the single-device
  steady state, the multi-device co-hosting shape, and the spoofed-source
  rate-limit flood.
- **Independent peer**: `make peers` provisions bacpypes3 0.0.110 in `.venv`;
  `make interop` drives the built binary on both IP legs, including a COV
  subscription whose notification is triggered by a write, a segmented
  response the client forces with a small max APDU, and the on-disk audit
  record of a refused write. `make sc-hub-image` builds bacnet-stack 1.6.1's
  `sc-hub` + BSC clients in Docker; `make interop-sc` drives the built binary
  as a node of that hub, including a bacnet-stack COV subscriber and the
  SC-leg audit record of a refusal. Exit 77 means the peer is absent, not that
  the product failed.
- Do not run two full test suites concurrently; fixed ports in the interop
  scripts will collide and look like a product bind error (`interop-sc` also
  binds host port 50050).

## 6. Current state

Done in v1:

- Codecs for BVLC, NPDU, APDU, tags, object IDs, properties, write targets,
  COV subscription/notification fields, I-Am, error/reject builders.
- Codec fuzzing (6 targets, all green).
- Allow-list, per-client token bucket, optional shared per-device rate budget,
  read-only and scoped write policies.
- Invoke-ID translation, pending cap/expiry, completed-response replay,
  in-flight retransmission drop, segmented response/request tracking.
- Write denial with the correct tagged Error PDU; unsupported subscription
  denial; unroutable confirmed COV answer.
- COV subscriber mapping, cancellation, expiry, multi-client fan-out and
  multi-object subscriptions (`SubscribeCOVPropertyMultiple` / the two
  `COVNotificationMultiple` services), with per-client dedupe.
- Authorized segmented writes (B5): the proxy acknowledges the client's
  segments, reassembles the APDU, authorizes every target, and forwards one
  unsegmented request; denial, oversize and out-of-order paths are pinned by
  tests.
- Device source validation with a learned source port.
- CLI, config validation, `SIGHUP` reload, systemd watchdog, selftest probe.
- Metrics, logger, panic isolation, soak tests.
- Forward-latency histogram (`bacnet_shield_forward_latency_seconds`, measured
  from forwarding to the answering response, with SegmentACKs and intermediate
  segments excluded) and `bacnet_shield_request_timeouts_total`.
- Graceful shutdown: the front leg stops accepting, already-forwarded requests
  drain for up to 2 s (the device leg and client socket stay open), and the SC
  transport outlives that drain. A new datagram after cancellation is dropped.
- Opt-in structured audit stream (`internal/observ`): one JSON record per
  security decision with the decoded write target and a closed-set reason,
  bounded by a rotating audit file and a non-blocking drop-and-count queue.
- BVLL-SC codec (`internal/bacnet/sc`): header/options and all node↔hub
  message bodies, golden-byte cross-checked against bacpypes3, with a fuzz
  target for the header (`FuzzParse`) and one for every typed body decoder
  (`FuzzDecodeMessage`).
- SC transport (`internal/scnet`): TLS 1.3 + a fuzzed RFC 6455 frame parser,
  a node state machine (connect handshake, heartbeats + heartbeat timeout,
  reconnect/failover across a hub list), and inbound filtering (destination
  VMAC and origin required). A malformed or non-binary frame drops the
  connection but not the process. Tested against a real in-process TLS hub.
- SC front leg in the data plane: the `peer` abstraction, VMAC-keyed client
  identity, opt-in `access.sc_allow`, per-VMAC rate bucket, and the shared
  pending/replay/COV/write-policy path. Config (`sc:` block and flags),
  `sc_allow` reload, and an opt-in VMAC list.
- IPv6 legs (B10): BACnet/IPv6 link type `0x82` with 3-octet virtual
  addresses, original unicast/broadcast, and the two address-resolution
  exchanges on either leg. Selected by using an IPv6 literal in `listen_addr`
  and/or `device_addr`; the proxy derives its own virtual addresses from the
  bound sockets and discovers the device's. The data plane, ACL, rate limit,
  COV and write policy are shared with the IPv4 leg, and all four v4/v6 leg
  combinations are supported.
- Extra front doors (`extra_listen`): a device may have several client-facing
  sockets, including mixed IPv4/IPv6, sharing one device leg, policy and
  pending/replay/COV state. The client identity remains `ip:port`, so a
  retransmission on another door hits the same replay entry.
- Operational health: `/healthz` and `/readyz` on the metrics listener, plus an
  active/passive HA design in `docs/ha.md` (no state replication).
- SC data-plane tests: two clients with the same invoke ID, an IP and an SC
  client sharing an invoke ID, per-VMAC ACL and rate, per-leg rate isolation,
  write denial with the tagged Error PDU, replay across the leg boundary, COV
  notification routing and I-Am fan-out.
- bacpypes3 interop: read, Who-Is, denied write, SIGHUP reload to an allowed
  write, uncovered write still denied, read-back of the written value, a COV
  subscription that receives the notification from the client's write, a
  segmented response reassembled through the proxy, and the audit file
  recording the refused write with its decoded target and reason.
- bacnet-stack SC interop (`make interop-sc`): the proxy joins bacnet-stack
  1.6.1's `sc-hub` in Docker as a node, and bacnet-stack's own BSC clients
  drive Who-Is, a read, a denied write (tagged Error PDU over SC, recorded in
  the audit with its SC leg and target), a SIGHUP reload to a scoped policy, an
  allowed write, a read-back, and a COV subscriber that receives the initial
  and the change-triggered notification.
  This found the originating-VMAC defect recorded in `CONFORMANCE.md`.
- SC connection-state observability: the node reports attach/detach through a
  state handler, exposed as the `bacnet_shield_sc_connected` gauge and
  `bacnet_shield_sc_reconnects_total` counter, so a hub outage is visible on
  `/metrics`. `make interop-sc` scrapes both across a hub restart.
- Multi-device co-hosting: a `devices:` list builds one `Gateway` per
  listener↔device pair (own sockets, policy, pending/replay/COV tables), a
  `Runner` serves them together, and a shared registry carries a per-device
  `device` label on every counter and gauge. Each entry has its own access
  policy and optional SC node. `SIGHUP` reloads every device's policy, matched
  by `name`; adding/removing a device and any socket/SC change is a
  restart-only warning. `TestMultiDeviceCoHosting` proves each listener reaches
  its own device, policies do not cross, and both device labels appear on one
  scrape; `TestBuildDevicesPortConflict` proves a bind conflict fails startup.

Known boundaries:

- No physical-device commissioning yet (see README).
- SC admission is VMAC-only. UUID-keyed admission cannot be enforced for
  hub-delivered traffic (the hub attributes a frame to a VMAC; Address-
  Resolution returns a direct-connection URI, not a UUID, and SC direct is out
  of scope); `access.sc_allow` rejects a UUID entry rather than pretending to
  enforce it.
- No SC hub role and no SC direct (node-to-node) connections; the proxy is
  always a WebSocket client of a hub.
- No independent IPv6 application peer is available to drive either leg yet
  (bacpypes3's application layer raises `NotImplementedError` for IPv6), so the
  IPv6 paths are pinned by wire-level Go tests and a fuzz target.
- No state-syncing HA. An active/passive pair behind a virtual IP is documented
  in [docs/ha.md](docs/ha.md); pending requests, the replay cache, COV
  subscriptions and rate buckets do not follow a failover. There is no
  consensus/state-replication protocol.
- No request pacing (`request_delay_ms`) or configurable client idle timeout;
  the rate limit is a ceiling, not spacing (modbus-shield parity, backlog).
- No BBMD/router and no traffic between co-hosted devices; each entry is an
  isolated listener↔device pair. `Forwarded-NPDU` and foreign-device frames
  are rejected: accepting them would replace a verified source address with an
  address the BBMD claims, changing the allow-list's meaning. A future explicit
  `trusted_bbmd` mode and its trust trade-off are designed in
  [docs/b3-bbmd.md](docs/b3-bbmd.md).
- Segmented *write* reassembly: the proxy acknowledges the client's segments,
  authorizes the complete request, and forwards one unsegmented APDU. A
  forbidden target in a later segment is still seen, a denied write gets the
  tagged Error PDU, and a completed segmented write is replayed from the cache
  on an end-to-end retransmission. Out-of-order segments are dropped and an
  over-16-KiB reassembly is rejected.
- Segmented subscriptions are refused (the proxy does not reassemble a
  subscription and would otherwise install something the client did not ask
  for).
- Outside the segmented-write path, the proxy does not reassemble segmented
  payloads; it tracks and relays them.
- `ListenAddr` on macOS cannot use `127.0.0.2`/`127.0.0.3`; tests use separate
  ports on `127.0.0.1`. This is a host limitation, not a product one.

## 7. Maintenance rules

1. Forward bytes; do not normalize vendor payloads. If a vendor disagrees with
   the spec, record it in `CONFORMANCE.md` and keep the proxy transparent.
2. Every new denial needs a wire-level test that proves the device (or client)
   saw the documented result, not just a log line.
3. Every new table must have a bound and a sweep, and the soak test must still
   pass.
4. A retransmission must never be forwarded while the original is in flight.
   Replaying a completed response is the only duplicate-tolerant path.
5. Do not add a property cache. Reads always reach the device; a stale
   setpoint is worse than a slow one.
6. Keep `read_only` and `write_policy` mutually exclusive. A config that looks
   restrictive and is not is worse than a config error.
7. Update this file and the README when behavior or the config surface
   changes. Update `CONFORMANCE.md` when a peer finds a divergence, and
   `SECURITY.md` when a protected asset, trust boundary or enforced control
   changes.
8. Do not push unless the user asks. Commits stay local by default across the
   Shield projects.
