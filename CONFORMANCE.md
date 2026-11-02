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
| `bacnet-stack` `sc-hub` | C BACnet stack (hub + BSC clients) | 1.6.1 | `make sc-hub-image` (Docker) |

`scripts/peers-setup.sh` exits 77 when no Python is available, so a bare
machine can run `make test` without the peer. `make interop` and
`make acceptance` treat a missing peer as a failure, not a skip: a green
acceptance run must have actually used the independent stack.

The SC peer is bacnet-stack's own hub and client tools, built from source into
a Docker image (`scripts/sc-hub/Dockerfile`) on libwebsockets. The proxy is a
**node** of that hub, and a bacnet-stack client (`bacwi`, `bacrp`, `bacwp`) is
the node on the other side, so the SC transport is exercised against a
third-party implementation instead of our in-process TLS fake. That image is
one-time cached by Docker; `make interop-sc` exits 77 when Docker, the image or
bacpypes3 is missing.

The peer applications are real `bacpypes3` applications:

- `scripts/interop_device.py` — a device object plus two local analog-value
  objects that report COV on a write (see Finding 2). It answers Who-Is,
  ReadProperty and WriteProperty through the normal bacpypes3 application
  service.
- `scripts/interop_client.py` — a normal bacpypes3 client. It sends
  ReadProperty and WriteProperty, subscribes for COV, decodes the answers
  (including Error PDUs) and exits non-zero when the observed behavior differs
  from the policy.

`scripts/interop-bacnet.sh` starts both around the built
`bin/bacnet-shield` binary, so the proxy is exercised on both legs:

```
[bacpypes3 client] --BACnet/IP--> [bacnet-shield] --BACnet/IP--> [bacpypes3 device]
```

`scripts/interop-sc.sh` is the secure-front-leg counterpart. It generates a
small PKI (SAN `127.0.0.1`, so the Go node's real TLS 1.3 verification is what
gets exercised), starts the bacnet-stack hub in Docker, starts the proxy with
an `sc:` block as a node of that hub, and drives every request with a
bacnet-stack BSC client that is a second node of the same hub:

```
[bacnet-stack client] --BACnet/SC--> [bacnet-stack sc-hub] <--BACnet/SC-- [bacnet-shield]
                                                                                |
                                                                       BACnet/IP v
                                                               [bacpypes3 device]
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
| COV subscription and notification | A third-party client subscribes, changes the monitored value with a write, and receives the device's notification back through the proxy — proving subscriber routing, not broadcast, on the IP leg |
| Segmented response | The client advertises a 50-byte max APDU and reads a 120-byte description, so the device's ComplexACK spans several segments; the reassembled value proves the proxy relayed every segment and carried the client's SegmentACKs back |

The SC interop run repeats the IP-leg scenarios across the secure leg at the
wire level:

| Scenario (over BACnet/SC) | What it proves |
|---|---|
| Connect-Request / Connect-Accept through a real hub | The node handshake is accepted by a third-party hub, including TLS 1.3 and the `hub.bsc.bacnet.org` subprotocol |
| Who-Is reached over SC | An SC client's broadcast NPDU is delivered to the one device as unicast and the I-Am is routed back through the hub to the requesting VMAC |
| ReadProperty over SC | The forward path, invoke-ID translation and the clear-leg read all work when the front leg is SC |
| Write refused by `read_only` | The bacnet-stack client prints `security: write-access-denied`, proving the tagged Error PDU survives the SC leg and is decoded by a third-party stack |
| Device error relayed over SC | A read of an absent object returns the device's own `object: unknown-object` error through the SC leg, so device errors pass opaquely and are not turned into a proxy denial |
| `SIGHUP` reload to a scoped policy | The policy swap happens without dropping the hub connection |
| Write allowed after reload, sibling still denied, read-back | The scoped rule covers exactly its target and the value round-trips |
| Hub restart | The node detects the lost connection, re-attaches to the hub, and serves the next request; the device value is unchanged across the restart |
| COV over SC | A bacnet-stack subscriber receives the subscription's initial notification and a second notification after the value changes, so the device-originated notification is routed by the proxy to the SC subscriber's VMAC over the hub rather than broadcast |

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
state machine are pinned against a real in-process TLS 1.3 hub **and** against
bacnet-stack's own hub in `scripts/interop-sc.sh`; see Finding 3.

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
- bacpypes3's local `Object.write_property` writes through
  `super().__setattr__`, which skips the property monitors that drive COV, so a
  BACnet WriteProperty to a local object changes the value but originates no
  notification. A real device notifies on a change, and the proxy's subscriber
  routing is the behavior under test, so `scripts/interop_device.py` routes the
  ordinary write through `__setattr__` (see `CovAnalogValueObject`). This is a
  fixture adjustment in the peer application; the bytes on the wire stay
  standard and the proxy is unchanged.

No vendor divergence was adapted away in the proxy. Service payloads remain
opaque; the proxy never rewrites a value to satisfy a peer.

### 3. A node must not set its own originating VMAC

The first SC interop run completed the Connect handshake against the real hub
and delivered the client's Who-Is to the proxy, but the proxy's I-Am never came
back and the client listed zero devices. The proxy log showed the hub answering
with a `BVLC-Result` NAK, which we decoded for the first time:

```
hub rejected a message  for_function=0  error_class=1792  error_code=37120
                        details="'Originating Virtual Address' field must be absent"
```

The cause was ours. `Node.SendNPDU` set both the originating and the
destination VMAC on an outbound `Encapsulated-NPDU`. That is a node asserting
its own identity, which the hub is supposed to infer from the WebSocket
connection; bacnet-stack's hub (and the spec, EA-001) reject a frame that
carries it. The fix is to send **only** the destination VMAC and let the hub
stamp the sender on the way to the recipient.

Fixed in `internal/scnet/node.go` and pinned twice: the in-process test hub
(`internal/scnet/node_test.go`) now NAKs a frame with an origin, and
`TestNodeConnectsSendsAndReceives` asserts the origin is **absent**; the Docker
run proves the same rule against the third-party hub. This is the class of bug
that only a real peer finds: our own fake hub had been rewritten to *expect*
the origin, so the Go suite was green on the wrong behavior.

### 4. A BVLC-Result NAK from the hub is worth surfacing

Not a divergence, but a deliberate product change the interop forced: a
`BVLC-Result` NAK from the hub is now logged at `warn` with the function it
refuses, the error class/code and the UTF-8 details string. Before this, a NAK
was a `debug` line, so a hub rejecting every frame looked like a one-way
network fault (requests in, nothing out) rather than a protocol complaint.
There is nothing for the node to retry with — the message was malformed — so
the log line is the whole response.

## Deliberate limits of this layer

- **One peer only.** bacpypes3 is a current, specification-minded stack. A
  legacy controller may disagree with it; the response is to report the
  divergence here, not to normalize it inside the proxy.
- **Segmented responses are interop-covered; segmented requests are not.**
  The Python client advertises a 50-byte max APDU and reads a 120-byte
  description, so the real device answers with a multi-segment ComplexACK and
  the proxy relays every segment and carries the client's SegmentACKs back.
  Device-initiated segmented *requests* (a segmented confirmed COV/event
  notification) are still pinned by in-process tests only; forcing one from the
  peer needs the same payload trick in the other direction.
- **COV interop is single-object and driver-triggered.** The Python client
  exercises `SubscribeCOV` and an unconfirmed notification, and the SC run
  drives `SubscribeCOV` through a bacnet-stack subscriber. Multi-object COV
  (`SubscribeCOVPropertyMultiple` and the two `COVNotificationMultiple`
  services) is implemented and pinned by wire-level Go tests, but neither peer
  implements it (both mark the service TODO), so there is no independent drive
  yet. Confirmed-notification interop and subscription expiry across a long run
  are also in-process only.
- **No BACnet/SC direct (node-to-node) interop.** The proxy attaches to a hub,
  which is the v1 shape. Direct connections are out of scope; see
  [BACKLOG.md](BACKLOG.md).
- **No BBMD, foreign-device registration or IPv6.** These are outside the v1
  scope; see [BACKLOG.md](BACKLOG.md).
- **No formal conformance suite.** This suite is the anchor; it proves the
  documented behavior against one independent implementation, not certification.

## Rerun

```bash
make peers          # once: .venv + bacpypes3 0.0.110
make interop        # builds the binary and runs the BACnet/IP scenarios
make sc-hub-image   # once: bacnet-stack 1.6.1 sc-hub + client tools in Docker
make interop-sc     # builds the binary and runs the BACnet/SC scenarios
make acceptance     # verify + interop
```

The scripts use `127.0.0.1:47810` for the device and `127.0.0.1:47811` for
the proxy; `interop-sc` also binds host port `50050` for the hub. Do not run
them concurrently with another interop run or another full test suite; the
fixed ports collide.