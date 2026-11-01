# BACnet Shield

A **BACnet/IP security proxy** for one legacy building device. One static
binary. The device keeps speaking plain BACnet/IP; the proxy does the
shielding work between it and the building's clients.

**Status:** v1 software scope complete. The protocol codecs are fuzzed, the
data plane is race-tested, and an independent stack (bacpypes3) drives reads,
writes, COV routing and policy denials through the built binary. Physical
device commissioning is still required; see [Production readiness](#production-readiness).

```
[N clients] --BACnet/IP--> [bacnet-shield] --BACnet/IP--> [legacy device]
```

Clients keep using their existing BACnet tools. They point at the proxy instead
of the device; that repointing is the whole migration. The proxy forwards the
service payload byte for byte and rewrites only what routing requires: the
link/network headers and the APDU invoke ID.

## Why

BACnet/IP is a clear, unauthenticated protocol designed for building
automation. A controller that has been in a wall for fifteen years cannot be
given authentication, an ACL or a write policy. Replacing it is expensive, and
its firmware is not yours to change.

bacnet-shield is the boundary instead:

- **Zero-touch on the device** — no firmware change, no object or property
  remapping. Vendor quirks inside service payloads pass through untouched.
- **Client allow-list** — only the BMS/SCADA segment reaches the device.
- **Per-client rate limit** — one runaway poller cannot spend the device's
  capacity for everyone else.
- **Write protection** — either all-or-nothing read-only, or rules scoped to
  `<object-type>:<instance>:<property>` with `*` wildcards.
- **Honest refusals** — a denied write is answered with a BACnet Error PDU
  (class `security`, code `write-access-denied`), so the client fails
  immediately instead of timing out.
- **COV routing** — a client's SubscribeCOV is remembered, and the device's
  notifications are delivered back to that client.
- **Config reload without downtime** — `SIGHUP` swaps the front-leg policy in
  place; clients and the device socket stay up.

## Scope

This is a **single-device gateway**, not a BACnet device stack and not a
router.

| Supported | Deliberately not supported (v1) |
|---|---|
| One legacy BACnet/IP device per instance | BBMD, foreign-device registration, routing between networks |
| Unicast and broadcast client frames to that device | BACnet/SC (secure connect) front leg |
| Confirmed and unconfirmed services, payload opaque | Service translation or object/property remapping |
| SubscribeCOV and SubscribeCOVProperty (one object each) | SubscribeCOVPropertyMultiple |
| Segmented requests and responses (except segmented writes) | Segmented writes (denied fail-closed) |
| IPv4 BACnet/IP | BACnet/IPv6 |

BACnet/SC is the planned standard secure front leg for a later milestone
(TLS 1.3 + WebSocket, BVLC-SC `0x82`). It is deliberately not replaced by a
private tunnel: the point is a standard boundary, not another proprietary one.

## Quick start

Build with the plain Go toolchain (no other build dependency):

```bash
make            # or: go build -o bin/bacnet-shield ./cmd/bacnet-shield
```

### Flags only

```bash
# everybody may read; nobody may write; only the BMS segment may connect
bacnet-shield gateway \
  --listen :47808 \
  --device 10.0.0.42:47808 \
  --read-only \
  --allow 10.8.0.0/24 \
  --rate-per-sec 50
```

Point the clients at the proxy address instead of the device. If the proxy and
device share a host, give the proxy a different client port (for example
`:47809`).

### YAML

One file describes one proxy instance. Start from
[`configs/gateway.yaml`](configs/gateway.yaml):

```bash
bacnet-shield gateway --config /etc/bacnet-shield/gateway.yaml
```

Reload the ACL, rate limit and write policy in place:

```bash
kill -HUP "$(cat /run/bacnet-shield.pid)"
# or: systemctl reload bacnet-shield-gateway
```

`listen_addr`, `device_addr`, `device_local_addr`, `device_instance`,
`request_timeout_secs`, `max_pending`, `log_level` and `metrics.addr` need a
restart; a reload reports them as warnings instead of silently keeping the old
value.

### Write policy

Read-only is the coarse switch. The fine-grained form answers *which* writes
may pass:

```yaml
access:
  write_policy:
    default: deny
    rules:
      - oid: "analog-value:5:present-value"
        action: allow        # one writable setpoint
      - oid: "analog-value:*:present-value"
        action: deny         # deny wins over allow
```

Rule vocabulary is `<object-type>:<instance>:<property>`, with `*` in any
part. `analog-value:5` means every property of that object; `*` means every
write. An object type or property may be a name (`analog-value`,
`present-value`) or its ASHRAE 135 number.

The evaluation rules are intentionally the same as the other Shield proxies:

- **Deny overrides.** One matching deny rejects the whole request, so a
  WritePropertyMultiple can never straddle a forbidden object.
- **Allow must cover.** An allow authorizes a request only if it matches
  every object/property the request touches.
- **Uncovered requests take the default.** `default: deny` is an allow-list;
  `default: allow` is a deny-list.
- **Fail closed on the undecodable.** A write whose target cannot be decoded
  is denied, never forwarded "because we could not tell".
- **Segmented writes are denied.** The policy would see only the first
  segment, so a client could hide a forbidden target in a later one.
- **Service-level writes need the default.** CreateObject, DeleteObject,
  ReinitializeDevice, DeviceCommunicationControl, file writes, list edits and
  the other state-changing services have no object target to match, so only
  `default: allow` authorizes them.

`read_only` and `write_policy` are mutually exclusive; both at once is a
config error. The same rules are available as flags:
`--write-default`, `--write-allow` and `--write-deny`.

If neither `read_only` nor `write_policy` is configured, writes are forwarded
unchanged: like the other Shield proxies, write protection is opt-in. The
example config sets `read_only: true`, and a deployment that only means to
filter reads should set it explicitly.

## How it works

The proxy is a strict forwarder with three pieces of state:

1. **Invoke-ID translation.** Every client has its own one-octet invoke-ID
   space, so two clients may both have request 7 in flight. The proxy allocates
   a device-leg ID per client request (up to `max_pending`, default 256),
   rewrites the octet on the way out, and patches it back on the answer. Two
   answers for the same client/invoke pair cannot be swapped.
2. **Retransmission handling.** A retransmission of a request still in flight
   is **dropped**, not forwarded: re-sending a write would apply it twice.
   After a response completes, a short-lived cache (30 s) replays that exact
   answer to a client retransmission. A client that reuses an invoke ID for a
   *different* request is treated as a new exchange.
3. **COV subscriber tracking.** A SubscribeCOV or SubscribeCOVProperty is
   installed only after the device answers with a SimpleACK. A rejected
   subscription is never routed. Notifications are mapped back by monitored
   object and subscriber-process identifier. A confirmed notification with no
   subscriber is answered with an Error PDU so the device stops retransmitting.

Segmented responses and device-initiated segmented requests are tracked per
invoke ID and relayed; the proxy does not reassemble the payload.

Denials are explicit per policy class:

| Situation | Wire result |
|---|---|
| Off-list client, or over the rate limit | Silent drop (never advertise the proxy) |
| Write refused by policy | Error PDU, class `security` (4), code `write-access-denied` (40) |
| Unsupported subscription service | Error PDU, class `services` (5), code `service-request-denied` (29) |
| Confirmed COV notification with no subscriber | Error PDU, class `services` (5), code `unknown-subscription` (79) |
| Malformed frame, unsupported BVLC function, network message | Dropped and counted; never guessed at |

## Metrics

Set `metrics.addr` (or `--metrics-addr`) to expose a Prometheus scrape at
`/metrics`. An empty address disables the listener.

| Metric | Meaning |
|---|---|
| `bacnet_shield_requests_total` | Client-leg datagrams received |
| `bacnet_shield_forwarded_total` | Requests forwarded to the device leg |
| `bacnet_shield_responses_total` | Device answers relayed to a client |
| `bacnet_shield_acl_denied_total` | Datagrams dropped by the allow-list |
| `bacnet_shield_rate_limited_total` | Datagrams dropped by the per-client rate limit |
| `bacnet_shield_writes_denied_total` | Writes refused by the write policy |
| `bacnet_shield_parse_errors_total` | Undecodable datagrams dropped |
| `bacnet_shield_pending_full_total` | Requests dropped because every invoke ID was in flight |
| `bacnet_shield_unsupported_total` | Frames or services the single-device gateway cannot serve |
| `bacnet_shield_replayed_total` | Retransmissions answered from the finished-response cache |
| `bacnet_shield_retransmits_dropped_total` | Retransmissions dropped while the request is in flight |
| `bacnet_shield_notifications_dropped_total` | Device notifications with no client to receive them |
| `bacnet_shield_pending` | Requests currently in flight toward the device |
| `bacnet_shield_cov_subscriptions` | Active COV subscriptions routed by the proxy |

## Tools

```bash
bacnet-shield validate --config gateway.yaml        # check a config, do not run
bacnet-shield validate --config gateway.yaml --json # machine-readable
bacnet-shield selftest --config gateway.yaml         # validate + probe the device
bacnet-shield selftest --config gateway.yaml --probe=false
bacnet-shield version
```

`selftest` sends one real request from this host to the device leg. With a
pinned `device_instance` it reads `device,<instance>,object-name`; without one
it sends a Who-Is and reports the first I-Am from the configured address. A
BACnet Error PDU counts as reachability (the device answered) and is reported
with its class and code.

## Appliance deployment

- **Static binary** — `make release` builds a stripped, CGO-free binary for
  Linux; `make release-all` cross-builds linux-amd64, linux-arm64 and
  linux-armv7 into `dist/`.
- **systemd** — [`deploy/bacnet-shield-gateway.service`](deploy/bacnet-shield-gateway.service)
  is a hardened `Type=notify` unit with a 30 s watchdog, `Restart=on-failure`
  and a restricted address-family list (`AF_UNIX` is included for sd_notify).
  The binary sends `READY=1` only after both sockets bind and pings
  `WATCHDOG=1` while running.
- **Supply chain** — `make sbom` produces SPDX + CycloneDX documents for the
  release binary (`syft`); `make vulnscan` scans them with `grype` and fails on
  HIGH or worse. Both exit 77 when the tool is missing.
- **No CI by design.** The gates are `make` targets run locally; see
  [TESTING.md](TESTING.md).

## Production readiness

The documented v1 scope is implemented and tested as software. The suite
covers the codecs (including fuzz targets), policy semantics, invoke-ID
translation, retransmission dedupe, COV routing, segmented exchanges, reload,
shutdown, systemd readiness and an independent client/device pair.

**Validation boundary:** the project has not yet been commissioned against
physical BACnet devices. Before relying on an installation, test it with the
real controller and the real vendor client: frame timing, retransmission
behaviour, COV lifetimes, segmented responses, device source-port changes and
network interruption. This is deployment validation, not unfinished
functionality in the documented scope. External security review and formal
BACnet conformance testing are separate work.

## Testing

```bash
make test        # gofmt gate + full race suite
make verify      # build + race suite + vet
make acceptance  # verify + independent bacpypes3 peer
make soak        # long-running leak and spoofed-source floods (opt-in)
make security    # verify + staticcheck + govulncheck + SBOM scan
make interop     # built binary against bacpypes3 on both legs
```

The interop suite needs the peer provisioned once:

```bash
make peers       # creates .venv and installs bacpypes3 0.0.110
```

It exits 77 when Python or the peer is missing, so a bare machine stays green;
a release run treats that as a failure. See [TESTING.md](TESTING.md) for the
layers and [CONFORMANCE.md](CONFORMANCE.md) for what the independent stack
found.

## Documentation

- [`AGENTS.md`](AGENTS.md) — architecture, wire-level invariants and
  maintenance rules.
- [`TESTING.md`](TESTING.md) — test layers, commands and security regressions.
- [`CONFORMANCE.md`](CONFORMANCE.md) — independent-peer results, divergences
  and deliberate limits.
- [`BACKLOG.md`](BACKLOG.md) — what is planned and what is explicitly out of
  scope.
- [`configs/gateway.yaml`](configs/gateway.yaml) — annotated configuration.
- [`deploy/`](deploy/) — systemd unit.

## License

[MIT](LICENSE)