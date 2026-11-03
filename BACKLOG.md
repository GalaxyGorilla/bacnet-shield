# BACKLOG — bacnet-shield

The v1 proxy scope is complete. The items below are the next deliberate
steps, not missing pieces of the documented co-hosting gateway.

## Done — v1 (kept for reference)

- BVLC, NPDU, APDU, tag, object-ID and service-payload codecs, with six
  fuzz targets.
- Client allow-list, per-client token bucket, read-only mode and
  `<object-type>:<instance>:<property>` write policy with `*` wildcards.
- Invoke-ID translation, pending cap/expiry, completed-response replay,
  in-flight retransmission drop, segmented response/request tracking.
- Correct tagged Error PDU denials; unsupported subscription denial;
  unroutable confirmed COV answer.
- COV subscription mapping, cancellation, expiry and multi-client fan-out.
- Device source validation with a learned source port.
- CLI (`gateway`, `validate`, `selftest`, `version`), YAML/flags config,
  `SIGHUP` policy reload, systemd watchdog, Prometheus metrics.
- bacpypes3 0.0.110 interop on both legs, including reload and read-back,
  a segmented response, a client-segmented write, and a device-initiated
  segmented confirmed COV notification.
- Soak tests for the spoofed-source rate-limit flood, single-device
  steady-state forwarding, multi-device co-hosting, and multi-client fan-in.

## Done — post-v1 (kept for reference)

- Global device budget (B8): an optional shared token bucket
  (`access.device_rate_per_sec` / `--device-rate-per-sec`) bounds the total
  request rate toward each device across all clients, complementing the
  per-client `rate_per_sec` fairness control. The per-client bucket is charged
  first, so a rate-denied request never spends the shared budget; both front
  legs charge the same budget. Denials are silent and counted as
  `bacnet_shield_device_rate_limited_total`. Reloadable.
- Structured denial audit (B9): an opt-in (`audit.file`) JSON-lines stream with
  one record per security decision (ACL, per-client rate, device budget, write
  policy, unsupported subscription). A refused write carries its decoded
  object/property target and a closed-set reason. Bounded by a rotating file
  (one backup) and a non-blocking queue that drops-and-counts
  (`bacnet_shield_audit_dropped_total`). Restart-only.
- Service names (`bacnet.APDU.ServiceName`) for the two service-number spaces,
  used by the audit and the human log.
- Multi-device co-hosting (B2): a `devices:` list builds one independent
  listener↔device `Gateway` per entry (own sockets, access policy, pending /
  replay / COV tables) and a `Runner` serves them together. Each entry has its
  own optional SC node (own VMAC/UUID). Every counter and gauge carries a
  `device` label on one shared registry; the audit names the device. `SIGHUP`
  reloads each device's policy, matched by `name`; adding/removing a device is
  restart-only. Not a router: no BBMD and no traffic between devices.
- Multi-object COV (B4): `SubscribeCOVPropertyMultiple` installs one
  subscription per monitored object, cancellation removes every listed object,
  and both `COVNotificationMultiple` services route to the union of subscribers
  with per-client dedupe. A malformed object list is refused, never broadcast.
- Authorized segmented writes (B5): the proxy acknowledges the client's
  segments, reassembles and authorizes the whole request, and forwards one
  unsegmented write; denial, oversize, out-of-order and replay paths are
  covered by tests.
- Extra front doors (`extra_listen`): one device may have several client-facing
  sockets (including mixed IPv4/IPv6) sharing one device leg, policy and
  pending/replay/COV state, matching modbus-shield's multi-listener shape.
- Bounded HA: `/healthz` and `/readyz` on the metrics listener plus an
  active/passive VRRP/keepalived design in [docs/ha.md](docs/ha.md). No state
  replication; the failover caveats (pending, replay, COV) are explicit.
- Graceful shutdown drain and forward-latency/timeout metrics: a request
  already at the device is answered after `SIGTERM` (bounded 2 s), and the
  latency histogram plus `request_timeouts_total` make a slow device visible
  before clients time out.

## Open — remaining limits

### B1 — BACnet/SC front leg — implemented, one admission limit

The standard secure connect front leg is implemented: TLS 1.3, WebSocket,
BVLC-SC (`0x82`), hub/route handling. This is the reason the project does not
grow a private PSK tunnel: the secure leg should be a standard boundary that
other BACnet stacks can join.

Implemented:

- BVLL-SC codec (`internal/bacnet/sc`), golden-byte cross-checked against
  bacpypes3 and bacnet-stack, with a fuzz target.
- Transport (`internal/scnet`): TLS 1.3, a fuzzed RFC 6455 WebSocket parser,
  and the node state machine (Connect handshake, heartbeat, reconnect/failover
  across a hub list). The node drops a frame addressed to another VMAC and one
  with no origin.
- Front-leg abstraction (`internal/proxy`): a `peer` keyed by `ip:port` or
  `sc:<vmac>`, NPDU-based replay cache, and SC clients reusing the pending
  table, COV routing and write policy. Multi-client by construction.
- Configuration: `sc:` YAML block, flags, CA/client-certificate files, and the
  reloadable `access.sc_allow` VMAC allow-list (empty = accept what the hub
  delivers). Tests cover two SC clients with the same invoke ID, per-VMAC ACL
  and rate, denial shape, COV and I-Am fan-out.
- Independent-peer interop: `make interop-sc` runs the proxy as a node of
  bacnet-stack 1.6.1's hub (Docker) and drives it with bacnet-stack's own BSC
  clients — Who-Is, ReadProperty, a denied write with the tagged Error PDU,
  `SIGHUP` reload, an allowed write and read-back. See
  [CONFORMANCE.md](CONFORMANCE.md).
- Connection-state observability: the node reports attach/detach through a
  state handler, exposed as `bacnet_shield_sc_connected` (gauge) and
  `bacnet_shield_sc_reconnects_total` (counter). `make interop-sc` scrapes
  both across the hub restart, so a hub outage is visible on `/metrics`.

Remaining limitation:

- UUID-keyed admission is not implementable for hub-delivered traffic. The
  hub attributes a frame to a VMAC only; the spec's Address-Resolution returns
  a direct-connection WebSocket URI, not a UUID, and the only place a peer's
  UUID is carried is a direct Connect-Accept. SC direct (node-to-node) is out
  of scope, so a UUID rule would not be enforceable today. `access.sc_allow`
  accepts VMAC entries only and rejects a UUID entry rather than pretending to
  enforce it. A future direct-connection mode could add UUID admission.

The clear device leg is its own BACnet/IP (IPv4 or IPv6) link, independent of
the front leg.

### B2 — Multi-device instance

DONE. A config file lists one or more listener↔device pairs under `devices:`,
each with its own access policy and optional `sc:` node. Each pair is a separate
`Gateway` (own client/device sockets, pending, replay and COV tables), so a
client can only reach the device whose listener it used; a `Runner` starts and
stops them together. Metrics carry a `device` label on one shared registry, the
audit names the device, and `SIGHUP` reloads each device's policy by `name`.
Adding/removing a device is restart-only. Flags mode stays single-device. See
[README.md](README.md#deployment-shape) and `internal/proxy/runner.go`.

### B3 — BBMD / forwarded-NPDU clients

**Decision: not implemented.** A client behind a BBMD sends `Forwarded-NPDU`
(BVLC `0x04`) or registers as a foreign device (`0x05`); the proxy counts these
as unsupported. Accepting the frame would replace a kernel-verified source
address with a client address the BBMD *claims* in the payload, so it changes
the allow-list from a source-IP guarantee to a trust statement about the
BBMD. The only honest shape is an explicit per-device `trusted_bbmd` mode,
checked against the claimed origin, with audit marked as `bbmd`-attested — and
that is a security-model decision, not a parser change. It is deliberately
deferred until a deployment requires it. The full reasoning, the required
guarantees and the deployment shapes that avoid B3 are in
[docs/b3-bbmd.md](docs/b3-bbmd.md).

### B4 — Multi-object COV subscriptions

DONE. `SubscribeCOVPropertyMultiple` installs one subscription per monitored
object after a SimpleACK, cancellation removes every object it names, and both
`COVNotificationMultiple` services (confirmed `31`, unconfirmed `11`) fan out
to the union of subscribers with each client receiving one copy. A malformed
object list is refused rather than forwarded. Pinned by wire-level Go tests;
neither bacpypes3 0.0.110 nor bacnet-stack 1.6.1 implements the service, so
there is no independent-peer drive yet.

### B5 — Authorized segmented writes

DONE. The proxy acts as the server for the client's segment transfer: it
acknowledges each non-final segment, reassembles the APDU, authorizes every
target (including one that only appears in a later segment), and forwards one
unsegmented request. A denied segmented write gets the same tagged Error PDU as
an unsegmented one and never reaches the device; a completed one is replayed
from the finish cache on an end-to-end retransmission. Reassembly is bounded to
16 KiB, out-of-order segments are dropped, and an over-limit transfer is
rejected.

### B6 — Segmented-request interop

DONE. Segmented *responses* have an interop scenario (the Python client
advertises a small max APDU and reads a large property). The driver now also
forces a device-initiated segmented *request*: the client subscribes with
confirmed notifications and a 50-byte APDU, and the fixture's COV criteria
report the 120-character `description`, so the device sends a segmented
`ConfirmedCOVNotification` through the proxy. The client asserts it received
the full description (impossible without segmentation) and answers with the
SimpleACK; the interop script fails if the notification is not relayed. See
[CONFORMANCE.md](CONFORMANCE.md).

### B7 — Physical commissioning matrix

Commission against real controllers and vendor clients: timing and
retransmission behavior, COV lifetimes, segmented responses, source-port
changes, device reboots, network interruption and appliance resource
exhaustion. Record findings per device family. This is validation work, not
new functionality.

### B8 — Global device budget

DONE. The per-client `rate_per_sec` remains the fairness control; an optional
shared `access.device_rate_per_sec` bounds the total rate toward each device.
See [README.md](README.md#security-controls) and
[examples/access-control.md](examples/access-control.md).

### B9 — Structured denial audit

DONE. Denials are counted, logged and now recorded as a bounded, opt-in JSON
stream naming the client, the service and the decoded write target with a
closed-set reason. See [README.md](README.md#audit-trail),
[examples/operations.md](examples/operations.md#audit-trail) and
`internal/observ/audit.go`.

### B10 — BACnet/IPv6

DONE. Either leg may be BACnet/IPv6 (Annex U, link type `0x82`): original
unicast/broadcast, the two address-resolution exchanges, derived 3-octet
virtual addresses, and the same ACL, rate limit, COV and write policy as IPv4.
All four v4/v6 leg combinations work, including the common retrofit shapes
(IPv6 clients in front of an IPv4 controller, or an IPv4 front leg in front of
an IPv6 device). On an IPv6 device leg the proxy discovers the device's virtual
address with `VirtualAddressResolution` (and learns it from any frame the device
sends); a request is dropped while the address is unknown rather than sent to a
guess. `device_local_addr` must match the device's family.

Open only for validation: no independent IPv6 application peer exists
(bacpypes3's `Application` raises `NotImplementedError("IPv6")`), so both legs
are pinned by Go wire tests and `FuzzParseBVLC6`.

### B11 — HA state replication

**Deliberately not implemented.** The supported shape is an active/passive pair
behind a virtual IP (VRRP/keepalived) with `/readyz` as the health check; the
design and failover caveats are in [docs/ha.md](docs/ha.md). Pending requests,
the replay cache, COV subscriptions and rate buckets are in-memory and do not
follow a failover: clients retransmit, and COV clients must resubscribe. State
replication would add a consensus/data-sync protocol to a strict forwarder and
is not planned.

### B12 — Request pacing (`request_delay_ms`)

Open, modbus-shield parity. modbus-shield can enforce a minimum gap between
requests toward a picky device; bacnet-shield has a rate ceiling but no spacing
control. A correct implementation needs a send queue or a per-device pacer
rather than sleeping inside a per-datagram handler, so it is deferred until a
device needs it.

### B13 — Configurable client idle timeout (`idle_timeout_ms`)

Open, modbus-shield parity. The client table used for unsolicited notifications
(Who-Is/I-Am, events) is fixed at 5 minutes. Making it configurable is small,
but no deployment has needed it yet.

## Open — appliance management integration

bacnet-shield is one protocol module of a planned multi-protocol appliance.
The sibling Shield projects carry the same list. These items are the contract
between an unprivileged management UI and the daemon; they are not protocol
work and are tracked here so the module does not have to be rediscovered later.
Completion means an unprivileged management UI can safely configure and operate
the service without duplicating undocumented daemon behavior.

- **A1 Versioned configuration schema:** expose a stable JSON Schema for every
  YAML field, default, constraint, description, secret, and restart/reload
  behavior. Generate or test it against the Go configuration types so UI forms
  cannot silently drift from the daemon.
- **A2 Restricted local management API:** provide a Unix-socket interface (or a
  small shared management sidecar) for validate, self-test, apply, reload,
  restart, status, and rollback. The web process must not run arbitrary shell
  commands or require unrestricted root access. Keep the protocol data plane
  independent from the management plane.
- **A3 Transactional configuration:** stage a revision, run `validate --json`
  and optional `selftest --json`, install it atomically, reload or restart as
  required, verify health, and automatically restore the previous known-good
  revision on failure. Preserve an auditable revision history.
- **A4 Unified structured status:** expose the active configuration revision
  and hash, readiness, configured and connected devices, reload result,
  restart-required fields, and relevant counters as a stable JSON response.
  Never include credentials or private-key material.
- **A5 Secret and certificate lifecycle:** define safe upload, ownership,
  permissions, validation, rotation, expiry reporting, backup, and redaction
  behavior for the SC CA/client-certificate files. Encryption at rest and
  master-key custody belong to the appliance layer, not the protocol daemon.
- **A6 Appliance-level acceptance tests:** exercise the complete web UI/API →
  staged YAML → validation/self-test → systemd reload/restart → real BACnet
  traffic path. Cover invalid configuration, interrupted apply, failed
  self-test, rollback, secret rotation, power loss, and all supported appliance
  architectures.

## Non-goals

- A full BACnet device stack, object database or application service.
- Protocol translation, object/property remapping or value normalization.
- A property-value cache. Reads always reach the device.
- A private encrypted tunnel between two Shield boxes instead of BACnet/SC.
- CI. The gates are `make` targets run locally.
- Backwards compatibility between unreleased config shapes. v1 is allowed to
  break its own draft config when the cleaner shape is known.