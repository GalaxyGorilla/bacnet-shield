# Testing BACnet Shield

The suite is organized around security properties and failure modes, not only
successful request forwarding. There is no CI by design; every gate below is a
local `make` target.

| Layer | Evidence |
|---|---|
| Codecs | BVLC, NPDU, APDU, tags, object IDs and write targets; malformed, truncated, extended-tag and segmented vectors |
| Fuzzing | Eight native targets: `FuzzParseBVLC`, `FuzzParseNPDU`, `FuzzParseAPDU`, `FuzzParseObjectID`, `FuzzWriteTargets`, `FuzzTagReader`, `FuzzParse` (BVLL-SC) and `FuzzParseFrame` (WebSocket) |
| Policy | Allow-list, per-client rate limit, read-only, scoped write rules, deny-overrides, allow-must-cover, service-level writes; SC VMAC allow-list and per-VMAC bucket |
| Data plane | Real loopback UDP sockets, invoke-ID collision and reuse, retransmission dedupe, pending cap/expiry, routing strip, device source validation |
| SC transport | Real in-process TLS 1.3 hub: connect handshake, heartbeat, reconnect/failover, hostname verification, destination/origin filtering |
| SC data plane | In-memory SC leg: two clients with the same invoke ID, per-VMAC ACL/rate, write denial shape, COV routing, I-Am fan-out, shared replay/pending |
| COV | Subscription install after ACK, rejected subscription not routed, cancellation, expiry, multi-client fan-out, unroutable confirmed notification |
| Segments | Segmented responses and device requests relayed with per-invoke tracking; segmented writes denied |
| Lifecycle | Config validation, reload, restart-only warnings, invalid reload, shutdown, systemd readiness and watchdog; SC config validation and TLS file errors |
| Independent peer | bacpypes3 0.0.110 drives the built binary as both client and device; BVLL-SC golden bytes come from the same peer |
| Soak | Spoofed-source rate-limit flood; steady-state forwarding with flat goroutines/heap and zero unanswered requests |

## Commands

```sh
make test        # gofmt gate + go test ./... -race -timeout 180s
make verify      # build + race suite + vet
make acceptance  # verify + bacpypes3 interop
make interop     # built binary against bacpypes3 on both legs
make soak        # opt-in long run; SOAK_DURATION=90s for a quick pass
make security    # verify + staticcheck + govulncheck + SBOM vulnerability gate
make peers       # provision .venv + bacpypes3 0.0.110 (exit 77 without Python)
```

`make sbom` and `make vulnscan` are also available individually; they exit 77
when `syft`/`grype` are not installed. `make interop` exits 77 when the peer is
missing, so a bare machine stays green. A release run treats both as failures.

## Security regressions pinned explicitly

- A denied write never reaches the device; the client receives an Error PDU
  with class `security` and code `write-access-denied`.
- A denied write does not consume a device invoke ID.
- A WritePropertyMultiple that mixes an allowed and a forbidden target is
  denied as a unit.
- An undecodable or segmented write is denied.
- An unconfirmed write (`WriteGroup`, `UnconfirmedPrivateTransfer`) is gated
  by the same policy even though it has no reply.
- A rejected COV subscription is not routed; only a SimpleACK installs it.
- An unroutable confirmed COV notification is answered, so the device stops
  retransmitting.
- An in-flight retransmission is dropped (a write must not be applied twice);
  a completed response is replayed once.
- Two clients using the same invoke ID get their own answers; a reused invoke
  ID is not confused with the old exchange.
- A device response from an unexpected source is rejected; a changed source
  port is learned only after a legitimate response.
- A malformed datagram costs one datagram, not the process.
- Two SC nodes using the same invoke ID get their own answers addressed to
  their own VMAC; a node's frame addressed to another VMAC or with no origin is
  dropped.
- An off-list SC VMAC is silent and never reaches the device; a noisy node
  cannot spend another VMAC's rate tokens.
- A denied SC write gets the same tagged Error PDU as the IP leg, and the
  device never sees it.
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
3. a write refused by a read-only policy (Error 4/40);
4. a `SIGHUP` policy reload;
5. the same write now allowed (ACK and read-back of the new value);
6. an uncovered write still denied.

`scripts/interop_client.py` and `scripts/interop_device.py` are real
bacpypes3 applications, not protocol mocks. See
[CONFORMANCE.md](CONFORMANCE.md) for what this found.

## Remaining hardware boundary

The single-machine suite cannot reproduce every controller, gateway or target
kernel. Physical commissioning must still cover vendor timing and
retransmission behavior, COV lifetimes, segmented responses, source-port
changes, device reboots, network interruption and appliance resource
exhaustion. Missing hardware is documented as a validation boundary, not
converted into a passing test.