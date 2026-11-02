# Testing BACnet Shield

The suite is organized around security properties and failure modes, not only
successful request forwarding. There is no CI by design; every gate below is a
local `make` target.

| Layer | Evidence |
|---|---|
| Codecs | BVLC, NPDU, APDU, tags, object IDs and write targets; malformed, truncated, extended-tag and segmented vectors |
| Fuzzing | Eleven native targets: `FuzzParseBVLC`, `FuzzParseBVLC6`, `FuzzParseNPDU`, `FuzzParseAPDU`, `FuzzParseObjectID`, `FuzzWriteTargets`, `FuzzTagReader`, `FuzzCOVMultiple`, `FuzzParse` and `FuzzDecodeMessage` (BVLL-SC), and `FuzzParseFrame` (WebSocket) |
| Policy | Allow-list, per-client rate limit, optional shared per-device budget, read-only, scoped write rules, deny-overrides, allow-must-cover, service-level writes; SC VMAC allow-list and per-VMAC bucket |
| Audit | JSON-lines writer with time-stamping and omitted empty fields; rotation cap and one-backup bound; drop-and-count under a blocked sink; served end-to-end for a refused write (with decoded target and reason), an ACL denial on each leg, and an unsupported subscription; `ServiceName` for both service-number spaces |
| Data plane | Real loopback UDP sockets, invoke-ID collision and reuse, retransmission dedupe, pending cap/expiry, routing strip, device source validation, forward-latency histogram, request-timeout counting |
| IPv6 front leg | Real `[::1]` sockets: VirtualAddressResolution discovers the proxy's 3-octet virtual address, a unicast read round-trips, a broadcast Who-Is reaches the IPv4 device and the I-Am returns to the client's virtual address, address resolution only answers for this proxy, an off-list IPv6 source gets no link-layer answer, a write is refused with the tagged Error PDU, a malformed frame costs one datagram, and a Forwarded-NPDU is counted unsupported |
| Co-hosting | Two listener↔device pairs in one process: each listener reaches its own device (Who-Is/I-Am), a read-only policy on one device does not gate the other, both `device` labels appear on one shared scrape, and a bind conflict fails startup |
| SC transport | Real in-process TLS 1.3 hub: connect handshake, heartbeat and heartbeat *timeout* (a hub that stops ACKing is dropped), reconnect and failover across a hub list, hostname verification, destination/origin filtering, attach/detach state reporting, and survival of a malformed frame and a non-binary WebSocket message |
| SC data plane | In-memory SC leg: two clients with the same invoke ID, an IP and an SC client sharing an invoke ID, per-VMAC ACL/rate, per-leg rate isolation, write denial shape, segmented-write reassembly over the SC leg, COV routing, I-Am fan-out, replay served across the leg boundary, shared pending |
| COV | Subscription install after ACK, rejected subscription not routed, cancellation, expiry, multi-client fan-out, unroutable confirmed notification; multi-object subscribe/notify decoding (request, confirmed and unconfirmed notification), per-client dedupe, cancellation of every listed object |
| Segments | Segmented responses and device requests relayed with per-invoke tracking; segmented writes acknowledged by the proxy, reassembled, authorized as a whole, forwarded unsegmented, denied with the tagged Error PDU, replayed after completion, and bounded/rejected when oversize or out of order; a real peer's multi-segment response is reassembled through the proxy (`make interop`) |
| Lifecycle | Config validation, reload, restart-only warnings, invalid reload, shutdown drain (an already-forwarded request still gets its answer, a new datagram after cancellation does not), systemd readiness and watchdog; SC config validation and TLS file errors |
| Independent peer | bacpypes3 0.0.110 drives the built binary as both client and device, including a segmented response and a segmented write; BVLL-SC golden bytes come from the same peer; bacnet-stack 1.6.1's `sc-hub` + BSC clients drive the built binary over BACnet/SC (`make interop-sc`), including a COV subscriber |
| Soak | Spoofed-source rate-limit flood; steady-state forwarding with flat goroutines/heap and zero unanswered requests |

## Commands

```sh
make test        # gofmt gate + go test ./... -race -timeout 180s
make verify      # build + race suite + vet
make acceptance  # verify + bacpypes3 interop
make interop     # built binary against bacpypes3 on both legs
make interop-sc  # built binary over BACnet/SC against bacnet-stack's hub
make soak        # opt-in long run; SOAK_DURATION=90s for a quick pass
make security    # verify + staticcheck + govulncheck + SBOM vulnerability gate
make peers       # provision .venv + bacpypes3 0.0.110 (exit 77 without Python)
make sc-hub-image # build the bacnet-stack sc-hub Docker image (once)
```

`make sbom` and `make vulnscan` are also available individually; they exit 77
when `syft`/`grype` are not installed. `make interop` exits 77 when the peer is
missing and `make interop-sc` exits 77 when Docker, the `sc-hub` image or
bacpypes3 is missing, so a bare machine stays green. A release run treats both
as failures.

## Security regressions pinned explicitly

- A denied write never reaches the device; the client receives an Error PDU
  with class `security` and code `write-access-denied`.
- A refused write is recorded in the opt-in audit stream with the client, the
  service, the decoded object/property target and a closed-set reason; an ACL
  denial on either leg and an unsupported subscription are recorded too; a full
  audit queue drops-and-counts rather than blocking the data plane.
- A denied write does not consume a device invoke ID.
- A WritePropertyMultiple that mixes an allowed and a forbidden target is
  denied as a unit.
- An undecodable write is denied.
- A segmented write is reassembled and authorized as one request: a forbidden
  target hidden in a later segment is still denied, the device never sees it,
  and the client gets the tagged Error PDU. A denied segmented write does not
  consume a device invoke ID.
- A completed segmented write that is retransmitted end to end is answered from
  the replay cache, not applied twice.
- An out-of-order segment is dropped and an over-16-KiB reassembly is rejected;
  neither reaches the device.
- An unconfirmed write (`WriteGroup`, `UnconfirmedPrivateTransfer`) is gated
  by the same policy even though it has no reply.
- A rejected COV subscription is not routed; only a SimpleACK installs it.
- A `SubscribeCOVPropertyMultiple` installs one subscription per listed object;
  cancelling it removes every object it names, and a notification-multiple is
  delivered once per client even when it names several objects that client
  watches.
- A notification-multiple with no subscriber is never broadcast; a confirmed
  one is answered with `unknown-subscription` so the device stops retransmitting.
- A multi-object subscription whose object list cannot be decoded is refused
  rather than forwarded, so it can never silently lose notifications.
- An unroutable confirmed COV notification is answered, so the device stops
  retransmitting.
- An in-flight retransmission is dropped (a write must not be applied twice);
  a completed response is replayed once.
- Two clients using the same invoke ID get their own answers; a reused invoke
  ID is not confused with the old exchange.
- A device response from an unexpected source is rejected; a changed source
  port is learned only after a legitimate response.
- A malformed datagram costs one datagram, not the process.
- A request already at the device when `SIGTERM` arrives is still answered
  (bounded by a two-second drain); a datagram that arrives after cancellation
  is dropped, so polling cannot keep the process alive.
- A request that expires without an answer increments
  `bacnet_shield_request_timeouts_total`; a response that answers it feeds the
  `bacnet_shield_forward_latency_seconds` histogram with the client's wait, and
  a SegmentACK or intermediate segment is not counted as an answer.
- Two SC nodes using the same invoke ID get their own answers addressed to
  their own VMAC; a node's frame addressed to another VMAC or with no origin is
  dropped.
- An off-list SC VMAC is silent and never reaches the device; a noisy node
  cannot spend another VMAC's rate tokens.
- An off-list IPv6 source is silent even for virtual-address resolution, so the
  proxy never confirms its presence to a denied client.
- A BACnet/IPv4 frame arriving on an IPv6 listener (or the reverse) is a parse
  error, not a frame that is guessed at or forwarded.
- A denied SC write gets the same tagged Error PDU as the IP leg, and the
  device never sees it.
- An IP client and an SC node using the same invoke ID at the same time each
  get their own answer; draining one leg's rate bucket does not spend the
  other's token.
- A hub that stops acknowledging heartbeats is dropped and re-attached, and an
  unreachable first hub makes the node fail over to the next one.
- A malformed or non-binary WebSocket message from the hub costs the
  connection, not the process, and does not desync the node.
- An invalid reload keeps the running policy.
- A bind failure exits without advertising systemd readiness.

## Soak

`make soak` runs `TestSoakRateLimiterSpoofedSources` and
`TestSoakSteadyState`. Both are skipped in the normal suite (a ten-minute test
would make `go test ./...` useless as an edit loop). Override the budget for a
quick check:

```sh
SOAK_DURATION=30s make soak
```

The rate-limit soak floods distinct 10/8 source addresses past the 4096-entry
cap and asserts the table never exceeds it and a never-seen source is refused
while full. The steady-state soak keeps a real request/response loop running
and asserts zero unanswered requests, bounded goroutines, bounded live heap
and a pending gauge back at zero.

## Independent peer

`scripts/peers-setup.sh` creates `.venv` and installs `bacpypes3==0.0.110`.
`scripts/interop-bacnet.sh` then starts a real bacpypes3 device and the built
gateway, and drives:

1. a read through the proxy (value checked);
2. a Who-Is through the proxy (I-Am returned);
3. a write refused by a read-only policy (Error 4/40), which the on-disk audit
   trail records with its decoded object/property target and the reason
   `read_only`;
4. a `SIGHUP` policy reload;
5. the same write now allowed (ACK and read-back of the new value);
6. an uncovered write still denied and audited as `default_deny`;
7. a COV subscription that receives the initial notification and then the
   change from the client's own write, proving the device-originated
   notification is routed back to the subscriber;
8. a segmented response: the client advertises a 50-byte max APDU and reads a
   120-byte description, so the proxy must relay every segment and the
   SegmentACKs;
9. a segmented write: the same client writes a 256-byte description with a
   50-byte max APDU, so the proxy acknowledges the segments, reassembles and
   authorizes the write, forwards one unsegmented request, and the value is read
   back; `/metrics` confirms `bacnet_shield_segmented_writes_total` advanced.

`scripts/interop_client.py` and `scripts/interop_device.py` are real
bacpypes3 applications, not protocol mocks. See
[CONFORMANCE.md](CONFORMANCE.md) for what this found.

Multi-object COV (`SubscribeCOVPropertyMultiple` and the two
`COVNotificationMultiple` services) is pinned by wire-level Go tests only:
bacpypes3 0.0.110 and bacnet-stack 1.6.1 both mark the service as TODO, so no
independent peer can drive it yet. The encoding the tests use was checked
against bacpypes3's `COVMultipleSubscriptionList` / `PropertyValue` encoders.

The IPv6 front leg has no independent application peer either: bacpypes3
0.0.110 ships the Annex U link layer, but its `Application` raises
`NotImplementedError("IPv6")`. The IPv6 path is therefore pinned by the Go
wire tests and `FuzzParseBVLC6`; the IPv4 interop remains the third-party check
for the shared data plane, policy and write path.

### Independent SC peer

The secure front leg has its own independent peer. `scripts/sc-hub/Dockerfile`
builds bacnet-stack 1.6.1's hub (`bacschub`) and BSC clients (`bacwi`, `bacrp`,
`bacwp`) on libwebsockets; `make sc-hub-image` builds it once.
`scripts/interop-sc.sh` then:

1. generates a small PKI with SAN `127.0.0.1` (`scripts/sc-certs.sh`), so the
   Go node's real TLS 1.3 verification is exercised;
2. starts a bacpypes3 device on the clear leg;
3. starts the bacnet-stack hub in Docker and the built gateway as a node of it;
4. drives a Who-Is, a read, a device error (unknown object) relayed opaquely,
   a denied write (the audit trail records the SC leg, the target and the
   reason), a `SIGHUP` reload, an allowed write, an uncovered sibling write and
   a read-back over BACnet/SC with a bacnet-stack client that is a second node
   of the same hub;
5. restarts the hub container and checks the node re-attaches and keeps
   serving, scraping `/metrics` to confirm `bacnet_shield_sc_connected` is 1
   both before and after the restart and `bacnet_shield_sc_reconnects_total`
   advances;
6. subscribes a bacnet-stack COV client to the device over SC and asserts it
   receives both the initial notification and the one triggered by a write —
   device-originated routing to the subscriber's VMAC through the hub.

This is the one run where the SC transport (which this project owns) talks to a
third-party implementation. It found the originating-VMAC defect recorded in
[CONFORMANCE.md](CONFORMANCE.md); do not run it concurrently with another
interop run — host port `50050` and the `127.0.0.1:4781x` ports collide.

## Remaining hardware boundary

The single-machine suite cannot reproduce every controller, gateway or target
kernel. Physical commissioning must still cover vendor timing and
retransmission behavior, COV lifetimes, segmented responses, source-port
changes, device reboots, network interruption and appliance resource
exhaustion. Missing hardware is documented as a validation boundary, not
converted into a passing test.