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
- bacpypes3 0.0.110 interop on both legs, including reload and read-back.
- Soak tests for the spoofed-source rate-limit flood and steady-state
  forwarding.

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

## Open

### B1 — BACnet/SC front leg

Implement the standard secure connect front leg: TLS 1.3, WebSocket,
BVLC-SC (`0x82`), hub/route handling. This is the reason the project does not
grow a private PSK tunnel: the secure leg should be a standard boundary that
other BACnet stacks can join.

Done:

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

Remaining:

- UUID-keyed admission. The BVLL-SC data path carries the sender's VMAC but
  not its UUID; a UUID rule needs Address-Resolution and a bounded VMAC→UUID
  cache. `access.sc_allow` currently accepts VMAC entries only and rejects a
  UUID entry rather than pretending to enforce it.

The clear device leg stays plain BACnet/IP.

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

A client behind a BBMD sends `Forwarded-NPDU` (BVLC `0x04`) or registers as a
foreign device (`0x05`). v1 counts these as unsupported. Supporting them means
trusting a BBMD identity, handling the 6-byte original source, and deciding
whether the proxy itself should register with a BBMD. This is network
infrastructure, not a device property; design it explicitly or leave it out.

### B4 — Multi-object COV subscriptions

`SubscribeCOVPropertyMultiple` (and the confirmed notification-multiple
service) are refused in v1 because the proxy tracks one monitored object per
subscription. Supporting them requires a routing table keyed by a list of
objects and a notification decoder that can fan out per object.

### B5 — Authorized segmented writes

v1 denies every segmented write because the policy would see only the first
segment. A later version could reassemble the APDU, authorize all targets,
and forward the original segments unchanged. Until then, fail-closed is the
correct behavior and the cost is the rare large segmented write.

### B6 — Segmented-request interop

Segmented *responses* now have an interop scenario (the Python client advertises
a small max APDU and reads a large property). Extend the driver to force a
device-initiated segmented *request* (a segmented confirmed COV/event
notification) so that direction is peer-verified too; today it is pinned by
in-process tests only. See [CONFORMANCE.md](CONFORMANCE.md).

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

v1 resolves and binds IPv4 only, and rejects non-IPv4 device addresses
explicitly. IPv6 support needs its own address handling, ACL semantics and
tests; it is not a flag flip.

## Non-goals

- A full BACnet device stack, object database or application service.
- Protocol translation, object/property remapping or value normalization.
- A property-value cache. Reads always reach the device.
- A private encrypted tunnel between two Shield boxes instead of BACnet/SC.
- CI. The gates are `make` targets run locally.
- Backwards compatibility between unreleased config shapes. v1 is allowed to
  break its own draft config when the cleaner shape is known.