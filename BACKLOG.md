# BACKLOG — bacnet-shield

The v1 proxy scope is complete. The items below are the next deliberate
steps, not missing pieces of the documented single-device gateway.

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

## Open

### B1 — BACnet/SC front leg

Implement the standard secure connect front leg: TLS 1.3, WebSocket,
BVLC-SC (`0x82`), hub/route handling. This is the reason the project does not
grow a private PSK tunnel: the secure leg should be a standard boundary that
other BACnet stacks can join.

Work includes certificate/CA configuration, SC hub connection state,
address-to-client mapping (SC nodes are not identified by IP:port), and an
interop scenario against an independent SC implementation. The clear device
leg stays plain BACnet/IP.

### B2 — Multi-device instance

One listener/device pair per config entry, with per-device policy and metrics
labels. This is not a small loop change: broadcast semantics, active-client
tracking and the pending tables must become per-device, and a client must not
be able to reach a device whose listener it did not use.

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

### B6 — Real segmented and COV interop

Extend the bacpypes3 driver to force a segmented response and to originate
COV notifications from the Python device. Today those paths are pinned by
in-process tests only; see [CONFORMANCE.md](CONFORMANCE.md).

### B7 — Physical commissioning matrix

Commission against real controllers and vendor clients: timing and
retransmission behavior, COV lifetimes, segmented responses, source-port
changes, device reboots, network interruption and appliance resource
exhaustion. Record findings per device family. This is validation work, not
new functionality.

### B8 — Global device budget

The current token bucket is per client. Add an optional shared budget so the
total request rate toward one fragile device is bounded even when many
legitimate clients poll at once. The per-client limit remains the fairness
control; the shared limit protects the device.

### B9 — Structured denial audit

Denials are counted and logged, but there is no stable audit record of
"client X tried to write object/property Y at time Z". Add a bounded,
structured audit stream (or an opt-in file) without turning the proxy into a
general logging system.

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