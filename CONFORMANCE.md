# Conformance: bacnet-shield against another BACnet stack

The Go tests are written against our own encoders and decoders, so they can
only prove self-consistency. If the proxy and the test fixture mis-encode the
same field the same way, every unit test still passes. An independent stack
has no such symmetry with us.

This file records what that independence found, what the peer disagrees with,
and what cannot be verified on this host.

## Peer

| Peer | Stack | Version | Provisioning |
|---|---|---|---|
| `bacpypes3` | pure Python BACnet stack | 0.0.110 | `make peers` (creates `.venv`) |

`scripts/peers-setup.sh` exits 77 when no Python is available, so a bare
machine can run `make test` without the peer. `make interop` and
`make acceptance` treat a missing peer as a failure, not a skip: a green
acceptance run must have actually used the independent stack.

The peer applications are real `bacpypes3` applications:

- `scripts/interop_device.py` — a device object plus two `AnalogValueObject`s.
  It answers Who-Is, ReadProperty and WriteProperty through the normal
  bacpypes3 application service.
- `scripts/interop_client.py` — a normal bacpypes3 client. It sends
  ReadProperty and WriteProperty, decodes the answers (including Error PDUs)
  and exits non-zero when the observed behavior differs from the policy.

`scripts/interop-bacnet.sh` starts both around the built
`bin/bacnet-shield` binary, so the proxy is exercised on both legs:

```
[bacpypes3 client] --BACnet/IP--> [bacnet-shield] --BACnet/IP--> [bacpypes3 device]
```

## Covered today

| Scenario | What it proves |
|---|---|
| ReadProperty through the proxy | A third-party client accepts our forward path and a third-party device accepts the rewritten request; the value survives both directions |
| Who-Is / I-Am through the proxy | A client broadcast is delivered to the one device as unicast, and the I-Am is routed back to the active client |
| Write refused by `read_only` | The client receives a BACnet Error PDU (class `security` 4, code `write-access-denied` 40) instead of timing out |
| `SIGHUP` policy reload | A real client observes the policy change in place; the gateway does not restart |
| Write allowed after reload | The write is acknowledged by the third-party device and the new value is read back |
| Write still denied for an uncovered object | The allow rule covers exactly one target; a sibling object is still refused |

Wire formats were cross-checked against the bacpypes3 source for the parts
the proxy parses or emits: BVLC functions and length semantics, NPDU control
bits and routing fields, APDU headers and invoke-ID offsets, and the tagged
Error PDU parameter encoding.

### BACnet/SC codec oracle

The BVLL-SC codec has its own golden-vector oracle. `scripts/sc-golden.py`
uses bacpypes3's `sc` package to encode every node↔hub body (Result,
Encapsulated-NPDU, Address-Resolution(+ACK), Advertisement(+solicitation),
Connect-Request/Accept, Disconnect-Request/ACK, Heartbeat-Request/ACK,
Proprietary) and the header/option combinations the proxy emits.
`internal/bacnet/sc/sc_test.go` pins those bytes and was cross-checked against
bacnet-stack's `src/bacnet/datalink/bsc/bvlc-sc.c`. The transport and node
state machine are **not** covered by this oracle yet; that is the Docker
`sc-hub` interop step.

## Findings

### 1. Error PDU parameters are tagged ENUMERATEDs

The first interop run refused writes correctly at the proxy but the client
never surfaced the denial: it waited until the test harness killed it.

The cause was ours. `ErrorAPDU` initially encoded the error class and code as
raw octets (`04 28`). ASHRAE 135 encodes them as **application-tagged
ENUMERATEDs**: tag number 9, one octet, so class `security` and code
`write-access-denied` become `91 04 91 28`. bacpypes3 decodes the payload as
a sequence of tags; a raw pair is not a valid Error sequence, so the answer
was not delivered as an error at all.

Fixed in `internal/bacnet/apdu.go` and pinned by
`TestErrorAPDUEncoding`, which asserts the exact wire bytes and the decode
round trip. This is exactly the class of bug the independent peer exists to
find: our own decoder happily round-tripped the same wrong bytes.

### 2. Client-side oracle details (not product behavior)

- bacpypes3 raises `ErrorRejectAbortNack` from `app.request` rather than
  returning an `ErrorPDU`. The interop client normalizes both paths before
  asserting class and code.
- `ReadPropertyACK.propertyValue` is an `Any` whose tag list includes the
  context-3 opening/closing tags around the application REAL. The client
  unwraps the application tags and decodes the REAL; this is a property of the
  oracle's object model, not a difference in the wire format.

No vendor divergence was adapted away in the proxy. Service payloads remain
opaque; the proxy never rewrites a value to satisfy a peer.

## Deliberate limits of this layer

- **One peer only.** bacpypes3 is a current, specification-minded stack. A
  legacy controller may disagree with it; the response is to report the
  divergence here, not to normalize it inside the proxy.
- **No segmented interop scenario yet.** Segmented responses and
  device-initiated segmented requests are pinned by in-process tests, not by
  the Python peer. Generating a genuinely segmented answer from a real
  bacpypes3 device needs a payload large enough to force segmentation; that is
  backlog work.
- **No COV interop scenario yet.** COV subscription, cancellation, expiry and
  fan-out are pinned by in-process tests. The Python device could originate
  notifications, but the current interop driver does not exercise them.
- **No BACnet/SC transport interop yet.** The BVLL-SC codec is golden-byte
  cross-checked against bacpypes3 and bacnet-stack, and the node is tested
  against an in-process TLS 1.3 hub. A run against an independent hub
  (bacnet-stack `sc-hub` via Docker) is the remaining B1 step; see
  [BACKLOG.md](BACKLOG.md).
- **No BBMD, foreign-device registration or IPv6.** These are outside the v1
  scope; see [BACKLOG.md](BACKLOG.md).
- **No formal conformance suite.** This suite is the anchor; it proves the
  documented behavior against one independent implementation, not certification.

## Rerun

```bash
make peers       # once: .venv + bacpypes3 0.0.110
make interop     # builds the binary and runs the scenarios above
```

The script uses `127.0.0.1:47810` for the device and `127.0.0.1:47811` for
the proxy. Do not run it concurrently with another interop run or another
full test suite; the fixed ports collide.