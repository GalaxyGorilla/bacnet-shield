# Operations (day-2: install, commission, monitor, troubleshoot)

The box is deployed and now runs as a service. This is the operations guide:
install the binary and unit, lay out the config, commission against the real
device, watch it, reload the policy in place, and diagnose the things that
actually go wrong.

| I need to… | Go to |
|---|---|
| Understand what the proxy does and does not protect | [`../SECURITY.md`](../SECURITY.md) |
| Pick or change the deployment shape | [`../README.md`](../README.md), [`gateway.md`](gateway.md), [`ipv6.md`](ipv6.md), [`sc.md`](sc.md), [`access-control.md`](access-control.md) |
| See what the independent stacks found | [`../CONFORMANCE.md`](../CONFORMANCE.md) |
| See what the tests actually prove | [`../TESTING.md`](../TESTING.md) |
| Review the architecture and wire-level invariants | [`../AGENTS.md`](../AGENTS.md) |

## Host assumptions

- A small Linux host (an SBC or a small industrial PC) with a static address on
  both the client-facing segment and the device-facing segment. The box needs one
  UDP port for the client leg (default `47808`) and an ephemeral source port
  toward the device unless `device_local_addr` pins one.
- No runtime dependencies: the release binary is static and CGO-free. The SC leg,
  when used, needs outbound TCP to the hub's `wss://` port.
- **No CI by design.** All gates are `make` targets run locally; see
  [TESTING.md](../TESTING.md).

## Install

```bash
make release                                  # stripped static binary
install -m 0755 bin/bacnet-shield /usr/local/bin/bacnet-shield

install -d -m 0755 /etc/bacnet-shield
install -m 0640 configs/gateway.yaml /etc/bacnet-shield/gateway.yaml

install -m 0644 deploy/bacnet-shield-gateway.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now bacnet-shield-gateway
```

The shipped unit is hardened: `Type=notify` with a 30 s watchdog,
`Restart=on-failure`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp`,
and a restricted address-family list (`AF_INET AF_INET6 AF_UNIX` — `AF_UNIX` is
required for `sd_notify`). It runs as the unprivileged `bacnet-shield` user.
Port 47808 is above 1024, so no capability is needed; if you move the client leg
to a privileged port, add `CAP_NET_BIND_SERVICE` as the unit comment describes.

The binary speaks `sd_notify`: it sends `READY=1` only after both sockets bind
and pings `WATCHDOG=1` while running, so a wedged process is restarted by the
host and a bind failure is never advertised as ready.

## Config layout

One file describes one process: process-wide `log_level`, `metrics` and `audit`,
plus a `devices:` list of one or more listener↔device pairs.
`configs/gateway.yaml` is the annotated template; copy it and edit:

- **Restart-only**: adding or removing a device, and `listen_addr`,
  `device_addr`, `device_local_addr`, `device_instance`,
  `request_timeout_secs`, `max_pending`, `log_level`, `metrics.addr`, `audit.*`,
  and the whole `sc` block.
- **Reloadable on `SIGHUP`** (per device, matched by `name`): `access.allow`,
  `access.sc_allow`, `access.rate_per_sec`, `access.device_rate_per_sec`,
  `access.read_only`, `access.write_policy`.

Keep the config readable only by the service user if it names internal addresses
or an `sc` client key. An `sc` client private key (`key_file`) should be `0600`
and owned by the service user.

## Commission against the real device

```bash
# 1. syntax, addresses, allow-lists, policy compile, TLS files
bacnet-shield validate --config /etc/bacnet-shield/gateway.yaml

# 2. a real BACnet request from THIS host to the device leg
bacnet-shield selftest --config /etc/bacnet-shield/gateway.yaml

# 3. start it and confirm readiness
systemctl start bacnet-shield-gateway
systemctl is-active bacnet-shield-gateway
journalctl -u bacnet-shield-gateway -n 20 --no-pager
```

`selftest` reports reachability independently of the running service; a BACnet
Error PDU counts as reachable (the device answered) and is printed with its class
and code. Add `--probe=false` to validate only, and `--json` for tooling.

Then, with the box running, point one real client at it and confirm a read and a
deliberately denied write. A refused write must come back as an Error PDU
immediately — a **timeout** means the denial was not formed correctly and is worth
a bug report; see [CONFORMANCE.md](../CONFORMANCE.md) for how the denial is
pinned on the wire.

## Monitor

`metrics.addr` (default in the example config: `127.0.0.1:9203`) serves
Prometheus at `/metrics`. Bind it to loopback unless the monitoring network is
trusted. Every per-device instrument carries a `device` label (the entry's
`name`), so one scrape covers every co-hosted device; group by `device` to find
the sick one. `bacnet_shield_audit_dropped_total` is process-wide (no device
label). The instruments that matter operationally:

| Signal | Metric | Watch for |
|---|---|---|
| Client traffic | `bacnet_shield_requests_total` | a drop to zero (clients repointed away, or a network change) |
| Forwarding | `bacnet_shield_forwarded_total`, `bacnet_shield_responses_total` | a widening gap between the two (device not answering) |
| Policy | `bacnet_shield_acl_denied_total`, `bacnet_shield_rate_limited_total`, `bacnet_shield_device_rate_limited_total`, `bacnet_shield_writes_denied_total` | a sudden ACL or write-denial spike (misconfigured client, or an incident); a rising device-budget denial (the pollers together exceed what the device should see) |
| Device health | `bacnet_shield_pending`, `bacnet_shield_pending_full_total`, `bacnet_shield_parse_errors_total`, `bacnet_shield_request_timeouts_total`, `bacnet_shield_forward_latency_seconds` | `pending` climbing toward `max_pending`; timeouts climbing; the latency histogram's upper buckets filling (a slow or wedged device) |
| Retransmissions | `bacnet_shield_replayed_total`, `bacnet_shield_retransmits_dropped_total` | a rising dropped count (lossy path or a client retrying during a slow device) |
| COV | `bacnet_shield_cov_subscriptions`, `bacnet_shield_notifications_dropped_total` | notifications with no subscriber (a client that stopped without cancelling) |
| SC link | `bacnet_shield_sc_connected`, `bacnet_shield_sc_reconnects_total` | `sc_connected` at 0 during an outage; reconnects climbing |
| Audit | `bacnet_shield_audit_dropped_total` | any non-zero value means the audit queue overflowed — raise the sink's throughput or investigate a flood |

Logs are console-formatted for journald. `log_level: info` records attach/detach,
denials and reloads; `debug` adds per-datagram routing and parse detail.

The same listener answers `/healthz` (process alive) and `/readyz` (listeners
are bound). `/readyz` is what a supervisor or VRRP health check should use; it
does **not** mean the device is reachable. The proxy is fail-closed and has no
state replication, so HA is an active/passive pair behind a virtual IP — see
[../docs/ha.md](../docs/ha.md) for what survives a failover (pending requests,
the replay cache and COV subscriptions do not).

## Audit trail

Counters tell you *how many* writes were refused; the audit tells you *which*.
Set `audit.file` to append one JSON object per security decision, with the
decoded object/property target of a refused write:

```yaml
audit:
  file: "/var/log/bacnet-shield/audit.jsonl"
  max_mb: 64                                 # rotate, keeping one backup
```

```bash
tail -f /var/log/bacnet-shield/audit.jsonl | jq -c 'select(.event=="write_denied")'
```

Turning it on does not change the data plane: the audit observes decisions the
policy already made. It is bounded two ways — the file rotates at `max_mb`
keeping one backup, and the in-memory queue drops (and counts) records under a
flood rather than blocking the reader. Watch `bacnet_shield_audit_dropped_total`
if you run it during a flood. The file is created `0600`: it names who wrote
what.

## Reload the policy in place

```bash
systemctl reload bacnet-shield-gateway     # ExecReload = kill -HUP
# or: kill -HUP "$(systemctl show -p MainPID --value bacnet-shield-gateway)"
```

Only the access policy is swapped. The listener and the device socket stay up;
clients are not dropped. A restart-only field in the edited file is logged as a
warning, and an invalid file keeps the running policy, so a reload typo can never
leave the device unprotected or wide open.

## Troubleshooting

| Symptom | Likely cause | Check |
|---|---|---|
| Client times out after repointing | Client is off-list, or the port is wrong | `acl_denied_total` climbing? confirm the client is in `allow` and the port matches `listen_addr` |
| Every request times out, `forwarded` rises but `responses` stays flat | Device unreachable or wrong `device_addr` | `bacnet-shield selftest`; `device_addr` is unicast IPv4; a NAT/firewall between box and device |
| Device answers a client that uses a different source port | Device replies from a different port than it was queried on | Expected: the proxy validates the device by **IP** and learns the response port; pin `device_local_addr` only for a firewall rule |
| A write still reaches the device | No `read_only` and no `write_policy` configured | Protection is opt-in; set one of them explicitly |
| A legitimate write is refused | The rule does not cover every target, or a segmented write exceeded the 16 KiB reassembly bound | `writes_denied_total`, `segmented_writes_rejected_total`; check the rule covers the whole WritePropertyMultiple |
| Same invoke ID from two clients gets one answer | (should not happen) | invoke-ID translation is per client; file a bug with the peer keys and invoke ID |
| SC clients never connect | Hub URL, TLS trust, or identity | `sc_connected`; the log shows the dial/handshake failure and the hub URL |
| SC reconnects keep climbing | Unstable hub or network | hub logs; the node backs off 1–30 s and walks the hub list |
| Process restarts in a loop | Bind failure, bad config, or watchdog starvation | `journalctl -u bacnet-shield-gateway`; a bind error is not advertised ready |

## Upgrade

```bash
install -m 0755 bin/bacnet-shield.new /usr/local/bin/bacnet-shield
systemctl restart bacnet-shield-gateway
```

There is no persistent on-disk state (no engine store, no cache), so a restart is
safe and fast: the pending table, replay cache and COV subscriptions are all
in-memory and rebuilt by traffic. Keep the config and any SC key files across the
upgrade.

On `SIGTERM`/`SIGINT` the front leg stops accepting immediately but waits up to
two seconds for requests already at the device to be answered, so a restart does
not turn an in-flight write into a client timeout. The device leg and the SC
transport stay alive for that drain. A datagram that arrives after the signal is
dropped, so a client that keeps polling cannot delay shutdown.

## Security notes

See [SECURITY.md](../SECURITY.md) for the protected assets, trust boundaries and
enforced controls. Two operational points stand out:

- **Bind metrics to loopback** unless the monitoring network is trusted; the port
  is another listener on the box.
- **The device leg is the trusted side, but it is still parsed strictly.** A
  legacy device is exactly the kind of peer that sends a truncated or
  non-conforming frame; every per-datagram handler runs under a panic guard, so
  one hostile packet cannot take the process down. That guard is a safety net,
  never a substitute for fixing the bug.
