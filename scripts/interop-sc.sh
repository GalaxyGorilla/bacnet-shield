#!/bin/sh
# interop-sc.sh — drive the built gateway over BACnet/SC against an
# independent hub and an independent client:
#
#   [bacnet-stack bacwi/bacrp] --BACnet/SC--> [bacnet-stack sc-hub] <--BACnet/SC-- [bacnet-shield]
#                                                                                     |
#                                                                            BACnet/IP v
#                                                                    [bacpypes3 device]
#
# The hub and the client are bacnet-stack 1.6.1 (see scripts/sc-hub/Dockerfile),
# so this is the one test where the SC transport talks to a third-party
# implementation instead of our own in-process TLS hub. It proves the connect
# handshake, Encapsulated-NPDU framing (including that a node must NOT assert
# its own originating VMAC), discovery, a read, and the write-denial Error PDU.
#
# Exit 77 when Docker or the bacpypes3 peer is missing (run `make peers`;
# Docker is expected on a machine that runs this target at all).
set -eu
cd "$(dirname "$0")/.."

BIN="bin/bacnet-shield"
PY=".venv/bin/python"
IMAGE="bacnet-shield/sc-hub"
HUB_NAME="bacnet-shield-interop-sc"
HUB_PORT=50050
HUB_URL="wss://127.0.0.1:${HUB_PORT}"

if [ ! -x "$BIN" ]; then
	echo "bin/bacnet-shield missing; run 'make build' first"
	exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
	echo "docker not found; cannot run the SC interop hub (exit 77)"
	exit 77
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
	echo "image $IMAGE missing; run 'make sc-hub-image' (exit 77)"
	exit 77
fi
if [ ! -x "$PY" ] || ! "$PY" -c 'import bacpypes3' 2>/dev/null; then
	echo "bacpypes3 missing; run 'make peers' (exit 77)"
	exit 77
fi

tmp="$(mktemp -d)"
certdir="$tmp/certs"
dev_log="$tmp/device.log"
gw_log="$tmp/gateway.log"
audit="$tmp/audit.jsonl"
cfg="$tmp/gateway.yaml"
pids=""

cleanup() {
	docker rm -f "$HUB_NAME" >/dev/null 2>&1 || true
	for p in $pids; do
		kill "$p" 2>/dev/null || true
	done
	for p in $pids; do
		wait "$p" 2>/dev/null || true
	done
	rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

fail() {
	echo "interop-sc FAILED: $1"
	echo "--- device log"
	cat "$dev_log" 2>/dev/null || true
	echo "--- gateway log"
	cat "$gw_log" 2>/dev/null || true
	echo "--- hub log"
	docker logs "$HUB_NAME" 2>&1 || true
	exit 1
}

wait_for() {
	# wait_for <file> <text> <tenths>
	i=0
	while [ "$i" -lt "$3" ]; do
		if grep -q "$2" "$1" 2>/dev/null; then
			return 0
		fi
		sleep 0.1
		i=$((i + 1))
	done
	return 1
}

wait_for_count() {
	# wait_for_count <file> <text> <min-count> <tenths>
	i=0
	while [ "$i" -lt "$4" ]; do
		n="$(grep -c "$2" "$1" 2>/dev/null || true)"
		if [ "${n:-0}" -ge "$3" ]; then
			return 0
		fi
		sleep 0.1
		i=$((i + 1))
	done
	return 1
}

scrape_metrics() {
	# Python is already a hard dependency of this script, so it doubles as the
	# metrics client instead of adding a curl requirement.
	"$PY" -c 'import sys,urllib.request; sys.stdout.write(urllib.request.urlopen(sys.argv[1], timeout=2).read().decode())' \
		"http://${METRICS_ADDR}/metrics"
}

wait_for_metric() {
	# wait_for_metric <regex> <tenths>
	i=0
	while [ "$i" -lt "$2" ]; do
		if scrape_metrics 2>/dev/null | grep -q "$1"; then
			return 0
		fi
		sleep 0.1
		i=$((i + 1))
	done
	return 1
}

# bsc runs one bacnet-stack client tool inside the hub container. The container
# carries the tools, and the client is another SC node of the same hub.
bsc() {
	_bin="$1"
	shift
	docker exec \
		-e BACNET_SC_PRIMARY_HUB_URI="$HUB_URL" \
		-e BACNET_SC_ISSUER_1_CERTIFICATE_FILE=certs/ca_cert.pem \
		-e BACNET_SC_OPERATIONAL_CERTIFICATE_FILE=certs/client_cert.pem \
		-e BACNET_SC_OPERATIONAL_CERTIFICATE_PRIVATE_KEY_FILE=certs/client_key.pem \
		-e BACNET_SC_SELFSIGNED_ENABLED=1 \
		"$HUB_NAME" timeout 25 "/opt/bacnet/bin/${_bin}" "$@"
}

DEV_ADDR="127.0.0.1:47810"
PROXY_ADDR="127.0.0.1:47811"
METRICS_ADDR="127.0.0.1:47812"

echo "== generating the interop PKI (SAN 127.0.0.1, so the Go node verifies the hub)"
sh scripts/sc-certs.sh "$certdir" >/dev/null

echo "== starting fake BACnet device at $DEV_ADDR"
"$PY" scripts/interop_device.py --address "$DEV_ADDR" --instance 1001 --name Interop >"$dev_log" 2>&1 &
pids="$pids $!"
wait_for "$dev_log" READY 50 || fail "device did not become ready"

echo "== starting bacnet-stack sc-hub on port $HUB_PORT"
docker rm -f "$HUB_NAME" >/dev/null 2>&1 || true
docker run --rm -d --name "$HUB_NAME" \
	-p "${HUB_PORT}:${HUB_PORT}" \
	-v "${certdir}:/opt/bacnet/certs" \
	-e BACNET_SC_ISSUER_1_CERTIFICATE_FILE=certs/ca_cert.pem \
	-e BACNET_SC_OPERATIONAL_CERTIFICATE_FILE=certs/server_cert.pem \
	-e BACNET_SC_OPERATIONAL_CERTIFICATE_PRIVATE_KEY_FILE=certs/server_key.pem \
	-e BACNET_SC_SELFSIGNED_ENABLED=1 \
	-e BACNET_SC_HUB_FUNCTION_BINDING="$HUB_PORT" \
	"$IMAGE" 1 InteropHub >/dev/null || fail "sc-hub container did not start"

write_config() {
	# write_config <read_only|policy>
	if [ "$1" = "read_only" ]; then
		cat >"$cfg" <<EOF
listen_addr: "$PROXY_ADDR"
device_addr: "$DEV_ADDR"
device_instance: 1001
log_level: info
metrics:
  addr: "$METRICS_ADDR"
audit:
  file: "$audit"
access:
  read_only: true
sc:
  vmac: "02:00:00:00:00:01"
  uuid: "00112233-4455-6677-8899-aabbccddeeff"
  hubs:
    - "$HUB_URL"
  ca_file: "$certdir/ca_cert.pem"
  cert_file: "$certdir/client_cert.pem"
  key_file: "$certdir/client_key.pem"
EOF
	else
		cat >"$cfg" <<EOF
listen_addr: "$PROXY_ADDR"
device_addr: "$DEV_ADDR"
device_instance: 1001
log_level: info
metrics:
  addr: "$METRICS_ADDR"
audit:
  file: "$audit"
access:
  write_policy:
    default: deny
    rules:
      - oid: "analog-value:1:present-value"
        action: allow
sc:
  vmac: "02:00:00:00:00:01"
  uuid: "00112233-4455-6677-8899-aabbccddeeff"
  hubs:
    - "$HUB_URL"
  ca_file: "$certdir/ca_cert.pem"
  cert_file: "$certdir/client_cert.pem"
  key_file: "$certdir/client_key.pem"
EOF
	fi
}

write_config read_only
echo "== starting the gateway with a read-only policy and an SC front leg"
"$BIN" gateway --config "$cfg" >"$gw_log" 2>&1 &
pids="$pids $!"
# A successful attach proves both that the hub is up and that the Go node
# verified the hub's certificate and completed the Connect handshake.
wait_for "$gw_log" "attached to hub" 100 || fail "gateway did not attach to the hub"

echo "== metrics show the SC leg up while attached"
wait_for_metric '^bacnet_shield_sc_connected 1$' 30 ||
	fail "sc_connected gauge not 1 after attach (got: $(scrape_metrics 2>/dev/null | grep sc_connected || true))"

echo "== Who-Is over SC reaches device 1001 through the proxy"
whois="$(bsc bacwi --timeout 2000)" || fail "bacwi failed"
echo "$whois" | grep -q "1001" || fail "Who-Is did not discover device 1001 (got: $whois)"

echo "== read analog-value:1 present-value over SC"
read_out="$(bsc bacrp 1001 analog-value 1 present-value)" || fail "bacrp failed"
echo "$read_out" | grep -q "1.000000" || fail "read value wrong (got: $read_out)"

echo "== device errors relay opaquely over SC (unknown object)"
err_out="$(bsc bacrp 1001 analog-value 99 present-value || true)"
echo "$err_out" | grep -q "unknown-object" || fail "device error not relayed (got: $err_out)"

echo "== write refused by the read-only policy"
write_out="$(bsc bacwp 1001 analog-value 1 present-value 0 -1 4 3.5 || true)"
echo "$write_out" | grep -q "write-access-denied" || fail "write denial not seen (got: $write_out)"

echo "== audit trail records the SC denial with its leg, target and reason"
wait_for "$audit" '"event":"write_denied"' 50 || fail "no write_denied audit record over SC"
grep -q '"leg":"sc"' "$audit" || fail "audit did not label the SC leg"
grep -q '"reason":"read_only"' "$audit" || fail "audit reason was not read_only"
grep -q 'analog-value,1:present-value' "$audit" || fail "audit did not record the SC write target"

echo "== SIGHUP: allow analog-value:1:present-value in place"
write_config policy
gw_pid="$(echo "$pids" | awk '{print $NF}')"
kill -HUP "$gw_pid"
wait_for "$gw_log" "access policy reloaded" 50 || fail "policy reload"

echo "== write now allowed for analog-value:1 present-value over SC"
bsc bacwp 1001 analog-value 1 present-value 0 -1 4 3.5 >/dev/null || fail "allowed write"

echo "== write still denied for uncovered analog-value:2 present-value"
write2="$(bsc bacwp 1001 analog-value 2 present-value 0 -1 4 7.5 || true)"
echo "$write2" | grep -q "write-access-denied" || fail "uncovered write not denied (got: $write2)"

echo "== read back the written value over SC"
read_back="$(bsc bacrp 1001 analog-value 1 present-value)" || fail "read-back failed"
echo "$read_back" | grep -q "3.500000" || fail "read-back value wrong (got: $read_back)"

echo "== hub restart: the node re-attaches and keeps serving"
attached_before="$(grep -c 'attached to hub' "$gw_log" || true)"
docker restart "$HUB_NAME" >/dev/null || fail "hub did not restart"
wait_for_count "$gw_log" "attached to hub" "$((attached_before + 1))" 300 ||
	fail "node did not re-attach to the hub after it restarted"

echo "== metrics count the re-attach"
wait_for_metric '^bacnet_shield_sc_reconnects_total [1-9][0-9]*$' 30 ||
	fail "reconnect not reflected on the metrics endpoint (got: $(scrape_metrics 2>/dev/null | grep sc_reconnects || true))"
after="$(bsc bacrp 1001 analog-value 1 present-value)" || fail "read after hub restart failed"
echo "$after" | grep -q "3.500000" || fail "value changed across a hub restart (got: $after)"

echo "== COV: an SC subscriber receives the device's notifications through the proxy"
cov_log="$tmp/cov.log"
# The subscriber is a third bacnet-stack SC node. It prints one line per
# notification; the first is the subscription's initial value, the second is
# the change we trigger below. Receiving the second proves the proxy routed the
# device-originated notification to the SC subscriber (it is not broadcast).
bsc bacscov 1001 analog-value 1 1 unconfirmed 60 >"$cov_log" 2>&1 &
cov_pid=$!
pids="$pids $cov_pid"
wait_for "$cov_log" "Received Notification" 50 || fail "COV subscription over SC (got: $(cat "$cov_log"))"
bsc bacwp 1001 analog-value 1 present-value 0 -1 4 6.5 >/dev/null || fail "COV trigger write"
wait_for_count "$cov_log" "Received Notification" 2 100 ||
	fail "no COV notification for the change over SC (got: $(cat "$cov_log"))"
docker exec "$HUB_NAME" pkill -f bacscov >/dev/null 2>&1 || true

echo "interop-sc ok"
