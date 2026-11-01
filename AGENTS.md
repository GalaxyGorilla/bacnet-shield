# AGENTS.md — bacnet-shield

> **Read this file first. Update it at the end of every task** — behavior,
> layout, commands, decisions. Treat it as documentation-as-code.

## 1. Mission

This project is a **BACnet/IP security proxy** for retrofit installations.
From the original motivation:

> "Retrofitting — adding security capabilities to legacy devices by adding a
> box in front of them, or even inside their casing."

Deployment model (v1, single-device gateway):

```
[N clients] --BACnet/IP--> [bacnet-shield] --BACnet/IP--> [one legacy device]
```

Clients are repointed to the proxy once; the device stays unchanged and keeps
speaking plain BACnet/IP. The proxy is the device's security gate: client
allow-list, per-client rate limit, and object/property-scoped write
protection. It is **not** a BACnet device stack, a BBMD, or a router.

The v1 essence: a **strict forwarder** — the service payload goes in and out
byte for byte; only the link/network headers and the APDU invoke ID are
rewritten, and only the front-leg policy can reject a request.

## 2. Decisions (do not re-litigate without strong reason)

| Topic | Decision |
|---|---|
| Language | **Go** — static single binary for appliance use, goroutines for the two UDP legs, race detector + native fuzzing for the test bar |
| Scope | **One device per instance.** Multi-device, BBMD and routing are backlog; the proxy does not pretend to be a router |
| Forwarding level | Parse BVLC/NPDU/APDU enough to route and gate; forward the **service payload opaquely**. No re-encoding, no property cache |
| Correlation | **Rewrite the invoke ID**, not the payload. Per-client ↔ device-leg translation with a 256-entry pending table and a 30 s completed-response cache |
| Retransmissions | A retransmission of an in-flight request is **dropped** (re-sending a write applies it twice). A finished response is replayed from cache |
| Security v1 | IP/CIDR allow-list + per-client token bucket + `read_only` **or** `<object-type>:<instance>:<property>` write policy. Write protection is opt-in: with neither configured, writes pass through. Deny-overrides, allow-must-cover, fail-closed on undecodable/segmented writes |
| Denial shape | ACL/rate denials are silent. A refused write gets Error class `security` (4) / code `write-access-denied` (40). Unsupported subscriptions get class `services` (5) / code `service-request-denied` (29). An unroutable confirmed COV gets code `unknown-subscription` (79) |
| COV | Track `SubscribeCOV` and `SubscribeCOVProperty` (one monitored object each). Install only after a SimpleACK. `SubscribeCOVPropertyMultiple` is refused |
| Config changes | `SIGHUP` re-reads `--config` and swaps only the access policy. Listener/device/timeout/log/metrics changes are reported as restart-only warnings. Invalid reload keeps the running policy |
| Secure front leg | BACnet/SC (TLS 1.3 + WebSocket, BVLC-SC `0x82`). The proxy is an SC **node** that attaches to an existing hub (primary + failover), not a hub itself. A private PSK tunnel is explicitly rejected |
| SC client admission | Opt-in SC allow-list keyed by VMAC/UUID. With none configured, any node the hub delivers is accepted and only the write policy gates it (same "protection is opt-in" shape as the IP leg) |
| Ground truth | ASHRAE 135 wire formats, cross-checked against **bacpypes3 0.0.110** in `.venv`. Vendor divergence is reported in [CONFORMANCE.md](CONFORMANCE.md), never silently adapted away in the proxy |
| No CI | Deliberate user decision across the Shield projects. Gates are local `make` targets |

## 3. Architecture and code map

```
cmd/bacnet-shield/     CLI: gateway | validate | selftest | version | help
internal/bacnet/       Wire codecs (BVLC, NPDU, APDU, tags, object IDs, services)
internal/bacnet/sc/    BACnet/SC virtual link layer (BVLL-SC) codec
internal/access/       Allow-list, token bucket, write policy
internal/config/       YAML + flags, validation, access-policy compilation
internal/proxy/        Data plane: routing, invoke IDs, COV, firmware probe
internal/observ/       zap logger, Prometheus registry, /metrics listener
internal/safego/       Panic isolation for per-datagram handlers
internal/watchdog/     sd_notify READY/WATCHDOG
internal/testkit/      Soak-duration helper shared by test suites
configs/gateway.yaml   Annotated example
deploy/                Hardened systemd unit
scripts/               bacpypes3 peer provisioning and interop drivers
```

### Data path

1. `clientLoop` reads a datagram, applies `Policy.Check` (ACL first, then the
   rate limit; an off-list source never consumes another client's token), and
   parses BVLC → NPDU → APDU.
2. `handleClientConfirmed` refuses unsupported subscription services, applies
   `AllowWrite`, and calls `forwardConfirmed`.
3. `forwardConfirmed` allocates a device invoke ID, patches the octet, records
   `pending[devID]` and `byClient[(client, clientInvokeID)]`, and sends the
   frame to the device.
4. `deviceLoop` accepts datagrams only from the configured device **IP**
   (the port is learned from the response, because stacks reply from a
   different port). A response is correlated through `pending`, patched back
   to the client's invoke ID, cached if complete, and sent.
5. The sweeper expires pending requests, replay entries, device exchanges,
   COV subscriptions and idle clients once per second.

### State tables (all bounded)

| Table | Key | Bound / lifetime |
|---|---|---|
| `pending` | device invoke ID | `max_pending` (1..256), `request_timeout_secs` |
| `byClient` | client addr + client invoke ID | one entry per pending request |
| `done` | client addr + client invoke ID | 2048 entries, 30 s |
| `fromDevice` / `toDevice` | device invoke ID / client key | `request_timeout_secs`, plus 10 s segment grace |
| `clients` | client IP:port | 1024 entries, 5 min idle |
| `cov` | monitored object + subscriber process ID + client | 4096 subscriptions, optional device lifetime |
| rate buckets | client IP string | 4096 entries, 5 min idle sweep |

### Wire invariants pinned by tests

- BVLC length includes the 4-byte header. Only `0x0A` (Original-Unicast) and
  `0x0B` (Original-Broadcast) are accepted from a client; other functions are
  counted unsupported.
- A client broadcast is forwarded to the one device as **unicast**. The proxy
  has exactly one device, so a broadcast is a discovery request aimed at it.
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
- A segmented write is denied before decoding. A non-segmented
  WritePropertyMultiple is decoded far enough to authorize every target.

## 4. CLI and configuration contract

Commands: `gateway`, `validate [--json]`, `selftest [--json]
[--probe=false]`, `version`, `help`.

Every command accepts either `--config <file>` or the gateway flags. Flags
mode is for a two-line paste install; YAML mode is the appliance shape. Both
compile to the same `config.Config`, so validation and the daemon cannot
drift.

Reloadable on `SIGHUP`: `access.allow`, `access.rate_per_sec`,
`access.read_only`, `access.write_policy`.

Restart-only (reported, never silently ignored): `listen_addr`,
`device_addr`, `device_local_addr`, `device_instance`,
`request_timeout_secs`, `max_pending`, `log_level`, `metrics.addr`.

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
- **Fuzz targets** live in `internal/bacnet/fuzz_test.go` and, for the SC
  codec, `internal/bacnet/sc/fuzz_test.go`. Every parser entry point has one; a
  crash is a bug, not a corpus entry to hide.
- **Oracle golden bytes** for the SC codec come from bacpypes3
  (`scripts/sc-golden.py`, cross-checked against bacnet-stack's `bvlc-sc.c`).
  Regenerate and compare with `internal/bacnet/sc/sc_test.go` when a peer
  reports a divergence; record it in `CONFORMANCE.md`.
- **Soak tests** are opt-in: `make soak` sets `BACNET_SHIELD_SOAK=1` and
  `BACNET_SHIELD_SOAK_DURATION` (default 10m). They assert bounded tables,
  flat goroutines/heap and zero unanswered requests.
- **Independent peer**: `make peers` provisions bacpypes3 0.0.110 in `.venv`;
  `make interop` drives the built binary on both legs. Exit 77 means the peer
  is absent, not that the product failed.
- Do not run two full test suites concurrently; fixed ports in the interop
  script will collide and look like a product bind error.

## 6. Current state

Done in v1:

- Codecs for BVLC, NPDU, APDU, tags, object IDs, properties, write targets,
  COV subscription/notification fields, I-Am, error/reject builders.
- Codec fuzzing (6 targets, all green).
- Allow-list, per-client token bucket, read-only and scoped write policies.
- Invoke-ID translation, pending cap/expiry, completed-response replay,
  in-flight retransmission drop, segmented response/request tracking.
- Write denial with the correct tagged Error PDU; unsupported subscription
  denial; unroutable confirmed COV answer.
- COV subscriber mapping, cancellation, expiry and multi-client fan-out.
- Device source validation with a learned source port.
- CLI, config validation, `SIGHUP` reload, systemd watchdog, selftest probe.
- Metrics, logger, panic isolation, soak tests.
- BVLL-SC codec (`internal/bacnet/sc`): header/options and all node↔hub
  message bodies, golden-byte cross-checked against bacpypes3, own fuzz target.
  The transport (TLS 1.3 + WebSocket) and the connect/heartbeat state machine
  are the next step; see [BACKLOG.md](BACKLOG.md) B1.
- bacpypes3 interop: read, Who-Is, denied write, SIGHUP reload to an allowed
  write, uncovered write still denied, read-back of the written value.

Known boundaries:

- No physical-device commissioning yet (see README).
- No BACnet/SC yet; no BBMD/router; one device per instance.
- Segmented writes are refused; SubscribeCOVPropertyMultiple is refused.
- The proxy does not reassemble segmented payloads; it tracks and relays them.
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
