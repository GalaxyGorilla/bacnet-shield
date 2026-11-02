# Access control (who may connect, how hard, and which writes)

Every bacnet-shield deployment has a client leg with peers you may or may not
trust, so each device's `access` block governs all of it: **who** may talk to
the proxy, **how fast**, and **what may be written**. The rules are the same for
an IP client (keyed by `ip:port`) and a BACnet/SC client (keyed by `vmac`),
which is what lets the two front legs share one policy and one set of counters.

In a config file the block sits under one `devices:` entry, so every co-hosted
device gets its own allow-list, rate limit and write policy:

```yaml
devices:
  - name: boiler
    listen_addr: "10.0.0.10:47808"
    device_addr: "10.0.0.42:47808"
    access:
      allow: ["10.8.0.0/24", "192.168.1.7"]   # client allow-list (IP or CIDR)
      sc_allow: ["02:00:00:00:00:0a"]         # SC allow-list (VMAC)
      rate_per_sec: 50                        # per-client request rate (0 = off)
      device_rate_per_sec: 200                # shared rate toward the device (0 = off)
      read_only: true                         # refuse every write
      # ...or, instead of read_only, a scope-limited write policy:
      # write_policy:
      #   default: deny
      #   rules:
      #     - {oid: "analog-value:5:present-value", action: allow}
      #     - {oid: "analog-value:*:present-value", action: deny}
```

`read_only` and `write_policy` are mutually exclusive; both at once is a config
error. `allow`, `sc_allow`, `rate_per_sec` and `device_rate_per_sec` are
independent and optional. Write protection is **opt-in**: with neither
`read_only` nor `write_policy` configured, writes pass through unchanged — the
same "protection is opt-in" shape as the other Shield proxies. Turn it on
deliberately.

## Client allow-list

- `allow` is IP/CIDR: `10.8.0.0/24` admits the whole BMS segment, `192.168.1.7`
  one host. `sc_allow` is a list of 6-octet VMACs (`02:00:00:00:00:0a`).
- An off-list peer is **silently dropped** — no Error, no Reject, nothing. An
  off-list source must not learn that a proxy is there, and answering it would
  only amplify a scan. This is also why an off-list datagram never consumes
  another client's rate token.
- With no list configured, every address is accepted. That is fine when the
  network already bounds who can reach the box; it is not a substitute for one.
- The SC list is a **second** gate behind the hub's own authentication, not a
  replacement for it. The hub decides who may join; `sc_allow` decides which of
  the joined nodes the proxy will serve.

## Per-client rate limit

`rate_per_sec` is a token bucket per client (burst = the rate). It exists to
protect a fragile device from a polling storm and the proxy from a spoofed-source
flood. Over-limit requests are **silently dropped**; the limit is there to absorb
a flood, not to chat with it.

Because the bucket is keyed by the client, one runaway poller is refused its own
requests rather than spending the budget everyone else needs. On the SC leg the
bucket is keyed by VMAC, so two SC nodes never share a limit.

## Shared device budget

`rate_per_sec` bounds one client; `device_rate_per_sec` bounds **all of them
together**, which is what protects a device whose real limit is total traffic
rather than per-poller traffic. It is a single shared token bucket (burst = the
rate):

- the per-client bucket is charged **first**, so a request already refused by a
  client's own limit never spends the shared budget;
- an off-list client never reaches either bucket;
- the IP leg and the SC leg charge the **same** budget, so an SC node cannot
  bypass the ceiling the IP clients live under;
- over-budget requests are **silently dropped** and counted as
  `bacnet_shield_device_rate_limited_total`.

Set it when many otherwise-reasonable pollers (a BMS, a dashboard, an
engineering tool) add up to more than the device can answer:

```yaml
access:
  rate_per_sec: 50          # each client may burst 50/s
  device_rate_per_sec: 200  # ...but the device never sees more than 200/s total
```

## Write protection

Read-only is the coarse switch. The fine-grained form answers *which* writes may
pass:

```yaml
access:
  write_policy:
    default: deny                    # allow-list; use allow for a deny-list
    rules:
      - {oid: "analog-value:5:present-value", action: allow}   # one setpoint
      - {oid: "analog-value:*:present-value", action: deny}    # deny wins
      - {oid: "*:*:object-name",              action: allow}   # name anything
```

Rule vocabulary is `<object-type>:<instance>:<property>`, with `*` allowed in
any part:

- `analog-value:5:present-value` — one property of one object;
- `analog-value:5` — every property of that object;
- `analog-value:*:present-value` — that property of every instance of the type;
- `*` — every write.

An object type or property may be a name (`analog-value`, `present-value`) or
its ASHRAE 135 number. Rules are evaluated as a **set**; their order does not
matter.

The evaluation rules are intentionally identical across the Shield proxies:

| Rule | Meaning |
|---|---|
| **Deny overrides** | One matching deny rejects the whole request. A WritePropertyMultiple can never straddle a forbidden object. |
| **Allow must cover** | An allow authorizes a request only if it matches every object/property the request touches. |
| **Uncovered takes the default** | `default: deny` is an allow-list; `default: allow` is a deny-list. |
| **Fail closed on the undecodable** | A write whose target cannot be decoded is denied, never forwarded "because we could not tell". |
| **Segmented writes are denied** | The policy would see only the first segment, so a client could hide a forbidden target in a later one. |
| **Service-level writes need the default** | CreateObject, DeleteObject, ReinitializeDevice, DeviceCommunicationControl, file writes and list edits have no object target to inspect; only `default: allow` authorizes them. |

Flags equivalent:

```bash
--write-default deny \
--write-allow 'analog-value:5:present-value' \
--write-deny  'analog-value:*:present-value'
```

`--write-allow`/`--write-deny` require an explicit `--write-default`.

## What a denial looks like on the wire

The three cases are deliberately different:

| Denial | Wire result | Why |
|---|---|---|
| Client not on the allow-list | **Silent drop** | An off-list peer must not learn a proxy is there; an error would amplify a flood. |
| Client over the rate limit | **Silent drop** | Same reasoning: the limit absorbs a flood, it does not negotiate with one. |
| Client over the shared device budget | **Silent drop** | Same: the budget protects the device from the sum of the pollers, silently. |
| Write refused by policy | **Error PDU**, class `security` (4), code `write-access-denied` (40) | The peer is legitimate; a timeout would only make it retransmit into the policy forever. |
| Unsupported subscription service | **Error PDU**, class `services` (5), code `service-request-denied` (29) | The device must not install a subscription the proxy cannot track. |
| Confirmed COV notification with no subscriber | **Error PDU**, class `services` (5), code `unknown-subscription` (79) | Answers the device so it stops retransmitting a notification nobody wants. |
| Malformed frame / unsupported BVLC function | **Drop + count** | An unparseable request cannot be authorized. |

The error parameters are **application-tagged ENUMERATEDs**, the form a strict
BACnet stack expects; a raw-octet payload would be dropped by the peer and turn
a clean refusal into a timeout.

Every one of these decisions is *counted* (see the metrics table in the
[README](../README.md#metrics)). For *which* client tried to write *what*, turn
on the [audit trail](operations.md#audit-trail): a refused write is recorded
with its decoded object/property target and a stable reason
(`read_only`, `deny_rule`, `default_deny`, `segmented_write`,
`undecodable_write`, `service_level_denied`).

## Reload without downtime

`SIGHUP` re-reads the config file and swaps **the access policy only** — the part
you change during an incident (cut off a noisy client, lock a write path):

```bash
kill -HUP "$(cat /run/bacnet-shield.pid)"   # or: systemctl reload bacnet-shield-gateway
```

Reloadable: `access.allow`, `access.sc_allow`, `access.rate_per_sec`,
`access.device_rate_per_sec`, `access.read_only`, `access.write_policy`. The
policy is read per datagram, so
the swap takes effect on the next packet with no listener rebind and no dropped
clients.

Everything socket-, file- or crypto-bound (`listen_addr`, `device_addr`,
`device_local_addr`, `device_instance`, timeouts, `max_pending`, `log_level`,
`metrics.addr`, `audit.*` and the whole `sc` block) is reported as a
**restart-only warning** rather than silently ignored. An invalid file, or a
policy that does not compile, keeps the running policy: a reload typo must never
leave the device unprotected, or wide open.

In flags mode there is no file to re-read, so a `SIGHUP` is ignored with a
warning — the flags came from the command line.
