# B3 — BBMD and forwarded-NPDU clients

**Decision: not implemented.** The proxy is not a BBMD and does not accept
BBMD-shaped frames. This note records why, what a future mode would have to
guarantee, and the deployment shapes that avoid the problem entirely. It is a
design decision, not an unfinished feature.

## What a BBMD actually is

BACnet/IP uses UDP broadcasts for discovery and some alarms. A BBMD
(Broadcast Distribution Table manager) lets devices on another IP subnet take
part in those broadcasts:

- A **foreign device** sends `Register-Foreign-Device` (BVLC `0x05`) to the
  BBMD with a lifetime, and the BBMD forwards broadcasts to it.
- A BBMD forwards a broadcast to another BBMD with
  `Distribute-Broadcast-To-Network` (BVLC `0x09`).
- A BBMD delivers a forwarded broadcast to a local station with
  `Forwarded-NPDU` (BVLC `0x04`), whose payload starts with the **original
  sender's 6-octet IP:port** followed by the NPDU.

So a client behind a BBMD does not send an `Original-Unicast` frame to the
proxy. It sends a broadcast to the BBMD, and the proxy receives a
`Forwarded-NPDU` from the BBMD with the client's address in the payload.

## Why the proxy rejects it

The proxy's central control is the client allow-list: "only these source
addresses may reach the device". That is a statement the kernel can enforce,
because the UDP source address is not attacker-chosen.

A `Forwarded-NPDU` breaks that property. The source address the proxy sees is
the **BBMD's**, and the client identity is a field inside the frame. Any host
that can send UDP to the proxy can put any address in that field. Accepting the
frame therefore means:

- trusting the BBMD to tell the truth about the origin, and
- treating the BBMD's IP as the real security boundary, and
- accepting that a compromised or misconfigured BBMD can impersonate every
  client behind it.

The proxy cannot distinguish a truthful BBMD from a host that simply sends
`0x04` with a forged origin. "The BBMD is on the allow-list" is not enough:
the attacker does not need to be the BBMD, only to be able to send it a frame.

There is also a reply-path question. A `Forwarded-NPDU` names the original
sender's `ip:port`; the proxy can answer that address directly only if it is
routable from the proxy. For a foreign device behind NAT, the BBMD is not a
unicast relay, so "supporting the frame" does not automatically produce a
working deployment.

## What a future `trusted_bbmd` mode would need

If a real deployment requires it, the only honest shape is an explicit,
per-device trust decision — never a default:

```yaml
access:
  trusted_bbmd:                     # explicit; empty = reject Forwarded-NPDU
    - "10.8.0.1"                    # the BBMD's source address
  allow: ["10.9.0.0/24"]            # checked against the CLAIMED origin
```

The mode would have to:

1. Accept BVLC `0x04` **only** from an address in `trusted_bbmd`; the BBMD's
   own address must also be in `allow` (or a separate BBMD list), otherwise the
   trust statement is meaningless.
2. Check the ACL, the per-client rate bucket and the device budget against the
   **claimed origin** from the frame, not the UDP source, so one BBMD cannot
   spend another client's tokens.
3. Record in the audit and the log that the client identity is
   **BBMD-attested**, not source-verified, so an incident review can tell the
   difference. The closed reason set should gain a marker such as
   `identity: bbmd`.
4. Reply to the claimed origin as `Original-Unicast` — and fail loudly at
   commissioning if that address is not routable from the proxy.
5. Keep rejecting `Register-Foreign-Device`, `Distribute-Broadcast`,
   `Read-BDT`/`Read-FDT` and every other BBMD-role function. The proxy is not a
   BBMD; it is a client of one at most.
6. Add a test that a forged `0x04` from an untrusted source is silent, and that
   an off-list *claimed* origin is silent even from a trusted BBMD.

That is a security-model change, not a frame parser: it changes the meaning of
the allow-list from "verified source" to "source or trusted attestation". It
should be designed with the deployment's network owner, not enabled because a
client "cannot reach the proxy".

## What to do instead

Most retrofit installations do not need B3:

- **Put the proxy on the clients' BACnet/IP subnet.** The normal shape: one
  local IP per device on port 47808, clients repointed once.
- **Route unicast to the proxy.** BACnet/IP is ordinary UDP. A client on
  another subnet can send a directed `Who-Is` and all requests to the proxy's
  routable address; only broadcast discovery needs a BBMD, and a directed
  `Who-Is` is forwarded by the proxy to its device like any other request.
- **Use BACnet/SC for the client leg.** If the client network is untrusted or
  spans sites, the SC front leg through an existing hub is the intended
  answer; it authenticates nodes and needs no BBMD.
- **If a BBMD is unavoidable**, place the proxy on the BBMD's subnet so the
  proxy still sees the client's real source address, or terminate the BBMD
  function in the building's network infrastructure rather than in the proxy.

## Status

- `Forwarded-NPDU`, `Register-Foreign-Device`, `Read-BDT`, `Read-FDT`,
  `Delete-FDT-Entry`, `Distribute-Broadcast-To-Network` and the IPv6
  equivalents are counted as unsupported and dropped.
- No BBMD role, no BDT/FDT, no foreign-device registration.
- The IPv4 link-layer codec already parses the 6-octet origin of a
  `Forwarded-NPDU` (`BVLC.Origin`) so a future mode would not need a new
  decoder; the work is the trust model, the policy plumbing and the reply
  path.
