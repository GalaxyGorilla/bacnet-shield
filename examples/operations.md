# Operations (day-2: install, commission, monitor, troubleshoot)

The box is deployed and now runs as a service. This is the operations guide:
install the binary and unit, lay out the config, commission against the real
device, watch it, reload the policy in place, and diagnose the things that
actually go wrong.

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

One file describes one proxy instance. `configs/gateway.yaml` is the annotated
template; copy it and edit:

- **Restart-only**: `listen_addr`, `device_addr`, `device_local_addr`,
  `device_instance`, `request_timeout_secs`, `max_pending`, `log_level`,
  `metrics.addr`, and the whole `sc` block.
- **Reloadable on `SIGHUP`**: `access.allow`, `access.sc_allow`,
  `access.rate_per_sec`, `access.read_only`, `access.write_policy`.

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
trusted. The instruments that matter operationally:

| Signal | Metric | Watch for |
|---|---|---|
| Client traffic | `bacnet_shield_requests_total` | a drop to zero (clients repointed away, or a network change) |
| Forwarding | `bacnet_shield_forwarded_total`, `bacnet_shield_responses_total` | a widening gap between the two (device not answering) |
| Policy | `bacnet_shield_acl_denied_total`, `bacnet_shield_rate_limited_total`, `bacnet_shield_writes_denied_total` | a sudden ACL or write-denial spike (misconfigured client, or an incident) |
| Device health | `bacnet_shield_pending`, `bacnet_shield_pending_full_total`, `bacnet_shield_parse_errors_total` | `pending` climbing toward `max_pending`; parse errors (a misbehaving peer) |
| Retransmissions | `bacnet_shield_replayed_total`, `bacnet_shield_retransmits_dropped_total` | a rising dropped count (lossy path or a client retrying during a slow device) |
| COV | `bacnet_shield_cov_subscriptions`, `bacnet_shield_notifications_dropped_total` | notifications with no subscriber (a client that stopped without cancelling) |
| SC link | `bacnet_shield_sc_connected`, `bacnet_shield_sc_reconnects_total` | `sc_connected` at 0 during an outage; reconnects climbing |

Logs are console-formatted for journald. `log_level: info` records attach/detach,
denials and reloads; `debug` adds per-datagram routing and parse detail.

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
| A legitimate write is refused | The rule does not cover every target, or a segmented write | `writes_denied_total`; check the rule covers the whole WritePropertyMultiple |
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
