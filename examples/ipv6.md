# IPv6 (BACnet/IPv6 on the front leg and/or the device leg)

BACnet/IPv6 is defined in ASHRAE 135 Annex U. It is **not** BACnet/IP with a
longer address: IPv6 frames use link type `0x82`, different function numbers,
3-octet *virtual addresses*, and an address-resolution exchange. bacnet-shield
handles that link layer on either leg, so the security controls and the data
plane are the same as for IPv4.

You do not need IPv6 experience beyond an address literal. A client or device
that already speaks BACnet/IPv6 works unchanged.

## Which shape is yours?

| Situation | `listen_addr` | `device_addr` |
|---|---|---|
| Legacy IPv4 on both sides | IPv4 | IPv4 |
| IPv6 clients, legacy IPv4 controller (common) | IPv6 | IPv4 |
| IPv4 clients, modern IPv6 device | IPv4 | IPv6 |
| IPv6 on both sides | IPv6 | IPv6 |

The two legs are independent. `device_local_addr`, when set, must use the same
family as `device_addr`; validation rejects a mismatch.

## 1. IPv6 clients, IPv4 device

```yaml
devices:
  - name: boiler
    listen_addr: "[::]:47808"          # all IPv6 interfaces
    device_addr: "10.0.0.42:47808"     # legacy IPv4 controller
    access:
      allow: ["2001:db8:10::/48"]
      read_only: true
```

Point the IPv6 clients at the proxy's IPv6 address (or its DNS name with an
AAAA record). The IPv6 allow-list and rate limits use the same rules as IPv4.

## 2. IPv4 clients, IPv6 device

```yaml
devices:
  - name: ahu
    listen_addr: "10.8.0.2:47808"                # IPv4 clients
    device_addr: "[2001:db8:20::42]:47808"       # IPv6 device
    access:
      write_policy:
        default: deny
        rules: [{ oid: "analog-value:5:present-value", action: allow }]
```

The device's virtual address is discovered automatically; nothing else is
configured.

## 3. Both legs IPv6

```yaml
devices:
  - name: chiller
    listen_addr: "[::]:47808"
    device_addr: "[2001:db8:20::43]:47808"
    access:
      allow: ["2001:db8:10::/48"]
      read_only: true
```

## 4. More than one front door

`extra_listen` adds front doors that share the same device leg, policy and
routing tables. A door may be IPv4 or IPv6:

```yaml
devices:
  - name: boiler
    listen_addr: "10.8.0.2:47808"
    extra_listen: ["[::]:47808"]
    device_addr: "10.0.0.42:47808"
```

A retransmission that arrives on the other door is still deduplicated; both
doors are one logical client-facing service.

## Verify before trusting it

```bash
bacnet-shield validate --config /etc/bacnet-shield/gateway.yaml
bacnet-shield selftest --config /etc/bacnet-shield/gateway.yaml
```

`selftest` is family-aware. On an IPv6 device it performs the
VirtualAddressResolution exchange first, then the ReadProperty or Who-Is. A
BACnet Error PDU still counts as reachable (the device answered).

Start the gateway and look for:

```text
device serving  {"device": "boiler", "listen": "[::]:47808", ...}
```

For an IPv6 device leg, the first successful resolution logs:

```text
device virtual address resolved  {"device_vmac": "0d:00:01", "device": "[2001:db8:20::42]:47808"}
```

## How the IPv6 link layer works here

- The proxy answers `VirtualAddressResolution` for an admitted client, so the
  client can learn the proxy's 3-octet virtual address before sending a unicast
  request.
- On the front leg it also answers `AddressResolution` when the target is its
  own virtual address.
- On the device leg the proxy is the requester: it sends
  `VirtualAddressResolution`, retries while unanswered, and also learns the
  device's virtual address from the source of any frame the device sends.
- Until the device's virtual address is known, a request is **dropped**, not
  sent to a guessed address. The client retransmits once resolution completes.
- Broadcast Who-Is from an IPv6 client is still forwarded to that device as
  unicast, and the I-Am is addressed back to the client's virtual address.
- `Forwarded-NPDU`, foreign-device and `Distribute-Broadcast` frames are
  counted unsupported, exactly like their IPv4 counterparts. The proxy is not a
  BBMD/router.

## Troubleshooting

| Symptom | Check |
|---|---|
| Client gets no answer, device sees nothing | Is the client using the proxy's IPv6 literal and the right port? Is the allow-list an IPv6/CIDR entry? |
| Device leg sends nothing | Look for `device virtual address resolved`; a device that does not answer VirtualAddressResolution cannot be sent a unicast frame. Check the device's IPv6 address and that the proxy's source is routable back. |
| Validation says `device_local_addr ... same address family` | `device_local_addr` and `device_addr` must both be IPv4 or both IPv6. |
| `[::]` works locally but not remotely | `[::]` binds all IPv6 interfaces; a firewall or missing route is the usual cause. A concrete address is easier to reason about. |
| An IPv4 client cannot reach an IPv6 listener | Use an IPv6 literal in `listen_addr`; an IPv4 wildcard (`:47808`) is the IPv4 leg. |
| `selftest` fails with no virtual-address answer | The device does not answer Annex U resolution; check the device's IPv6 stack and that UDP 47808 is open both ways. |

## Honest limits

- No independent IPv6 **application** peer is available in this repository yet:
  bacpypes3 ships the Annex U link layer but its `Application` raises
  `NotImplementedError("IPv6")`. The IPv6 paths are pinned by real `[::1]`
  socket tests and a fuzz target, not by a third-party application.
- The proxy does not implement BBMD, foreign-device registration, or
  address-resolution forwarding between links. See
  [../docs/b3-bbmd.md](../docs/b3-bbmd.md) for the BBMD decision.
- The device leg's virtual address is not configurable; it is discovered. A
  device that will not answer resolution is not supported on an IPv6 device
  leg.
