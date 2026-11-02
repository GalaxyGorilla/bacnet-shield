# High availability

**Scope: active/passive, fail-closed, no state replication.** The proxy is a
single UDP forwarder per device. This note describes how to run a warm standby
behind a virtual IP, what survives a failover, and what does not. It is a
deployment pattern, not a cluster protocol.

## What "HA" means here

There is no quorum, no shared state and no automatic leader election inside the
proxy. The supported shape is two identical boxes:

- both run `bacnet-shield` with the same configuration,
- only one is active at a time,
- a virtual IP (VRRP/keepalived) points clients at the active box,
- a health check moves the virtual IP to the standby when the active box fails.

The proxy itself is **fail-closed**: if the box dies and nothing takes over,
clients lose the device. There is no bypass path and no fail-open mode.

## What must be identical on both boxes

- `bacnet-shield` version and the `devices:` configuration (including
  `listen_addr`, `extra_listen`, `device_addr`, policy, and the `sc` block).
- CA/certificate/key files for BACnet/SC, with the same permissions.
- The audit destination policy. Use a central log collector if the audit must
  survive a box loss; a local `audit.file` only covers the node that wrote it.
- The SC identity decision: see [SC identity and failover](#sc-identity-and-failover).

## Bind addresses and the virtual IP

Clients must use the **virtual IP**, never a box's physical address. Bind the
proxy to the wildcard (or the physical interface), not to the VIP itself: the
VIP only exists on the active node, so binding it would make the standby fail
to start.

```yaml
devices:
  - name: boiler
    listen_addr: ":47808"          # accepts the VIP when it moves here
    device_addr: "10.0.0.42:47808"
    access: { read_only: true }
```

Firewall the physical front-leg address so only the VIP is reachable by
clients. Otherwise a client that knows the physical address can bypass the
active/passive decision and talk to the standby.

The device leg is unaffected: the device stays at its configured address, and
the active box's source port is learned by the device as usual.

## Health checks

The metrics listener (when `metrics.addr` is set) serves three paths:

| Path | Meaning |
|---|---|
| `/healthz` | the process is alive and the HTTP handler is serving |
| `/readyz` | the metrics listener is up, which the command only starts after every front/device socket bound |
| `/metrics` | counters, per-device state and the SC link gauge |

These are **not** a device-reachability check. A box can be ready while the
controller is offline. For commissioning or a deeper keepalived check, use
`bacnet-shield selftest --config ...` (it sends a real request to the device
leg) rather than probing the device from the health script.

Example keepalived fragment:

```text
vrrp_script chk_bacnet {
    script "/usr/bin/curl -fsS http://127.0.0.1:9100/readyz"
    interval 2
    fall 3
    rise 2
}

vrrp_instance bacnet_proxy {
    state BACKUP
    interface eth0
    virtual_router_id 51
    priority 100
    advert_int 1
    virtual_ipaddress { 10.8.0.2/24 }
    track_script { chk_bacnet }
}
```

## What is lost on failover

The proxy keeps its routing state in memory. A failover is a cold start for
that state:

- **Pending requests** are lost. A client whose request was in flight when the
  active box died sees a timeout and retransmits; the standby forwards it as a
  new request. A write that the device already applied can therefore be applied
  again if the client retries it. Make setpoint writes idempotent, or confirm
  the value after a failover.
- **The replay cache** is lost, so a retransmission that would have been
  answered from cache reaches the device once more.
- **COV subscriptions** are lost. The device stores the subscriber's old
  transport address (the failed box), so its notifications do not follow the
  VIP. Clients must resubscribe after a failover. This is the most visible
  limitation of an active/passive pair.
- **The learned device source port** is lost; the standby learns it again from
  the next response.
- **Rate-limit buckets** are empty, so a burst may pass immediately after
  failover. The shared device budget is a ceiling, not a history.

State replication (pending table, replay cache, COV subscribers, token buckets)
is deliberately not implemented: it would add a consensus/data-sync protocol to
a security gate that is meant to be a dumb, strict forwarder. If a site needs
sub-second COV continuity, use BACnet/SC with a redundant hub and let the hub
own node availability, not a state-syncing proxy pair.

## SC identity and failover

An SC node has one VMAC/UUID, and a hub will not tolerate two nodes claiming the
same identity. Do **not** run the SC node on both boxes against the same hub at
the same time.

Choose one:

- **Active node only:** start the SC node only on the node that holds the VIP
  (for example, a systemd unit ordered after the VIP). The standby has no SC
  connection until promotion.
- **Distinct identity per node:** give each box its own VMAC/UUID and let the
  clients/hub handle two subscribers. This is not transparent to the SC
  clients; use it only if the hub can route both.
- **Redundant hub:** keep the proxy's single identity and let the hub's own
  redundancy cover the hub, not the proxy box.

The SC hub list (`sc.hubs`) is a failover list for hubs, not for proxy boxes.

## What a failover does not solve

- A compromised active box is still compromised; HA does not restore trust.
- A bad configuration is replicated to both boxes; validate before deploying.
- The device is still a single point of failure.
- The clear device leg is still clear; HA does not add confidentiality.
- A split-brain (both nodes active) can duplicate writes. Keep the VRRP
  priority/firewall discipline strict, and monitor the VIP.

## Operational checklist

1. Same binary, config and SC key material on both boxes.
2. Bind `:47808` (or the physical interface), firewall the physical address,
   advertise only the VIP.
3. Run `validate` and `selftest` on the standby before trusting it.
4. Point the health check at `/readyz` on loopback.
5. Test a failover: pull the active box, confirm the VIP moves, a read works,
   a write is refused/committed as expected, and a COV client resubscribes.
6. Centralize the audit log if it must survive the box.
7. Document the client resubscription step; do not promise transparent COV
   continuity.
