#!/bin/sh
# interop-bacnet.sh — drive the built gateway with an independent BACnet
# stack (bacpypes3) on both legs:
#
#   [bacpypes3 client] --BACnet/IP--> [bacnet-shield] --BACnet/IP--> [bacpypes3 device]
#
# It proves what the Go tests can only simulate: a third-party client and a
# third-party device agree with the proxy about invoke-ID translation, the
# read path, and the write-denial error. It also exercises SIGHUP policy
# reload with a real client waiting on the other end.
#
# Exit 77 when the bacpypes3 peer is missing (run `make peers`).
set -eu
cd "$(dirname "$0")/.."

BIN="bin/bacnet-shield"
PY=".venv/bin/python"

if [ ! -x "$BIN" ]; then
	echo "bin/bacnet-shield missing; run 'make build' first"
	exit 1
fi
if [ ! -x "$PY" ] || ! "$PY" -c 'import bacpypes3' 2>/dev/null; then
	echo "bacpypes3 missing; run 'make peers' (exit 77)"
	exit 77
fi

tmp="$(mktemp -d)"
dev_log="$tmp/device.log"
gw_log="$tmp/gateway.log"
audit="$tmp/audit.jsonl"
cfg="$tmp/gateway.yaml"
pids=""

cleanup() {
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
	echo "interop FAILED: $1"
	echo "--- device log"
	cat "$dev_log" 2>/dev/null || true
	echo "--- gateway log"
	cat "$gw_log" 2>/dev/null || true
	exit 1
}

wait_for() {
	# wait_for <file> <text> <seconds>
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

DEV_ADDR="127.0.0.1:47810"
PROXY_ADDR="127.0.0.1:47811"

echo "== starting fake BACnet device at $DEV_ADDR"
"$PY" scripts/interop_device.py --address "$DEV_ADDR" --instance 1001 --name Interop >"$dev_log" 2>&1 &
pids="$pids $!"
wait_for "$dev_log" READY 50 || fail "device did not become ready"

write_config() {
	# write_config <read_only|policy>
	if [ "$1" = "read_only" ]; then
		cat >"$cfg" <<EOF
devices:
  - name: interop
    listen_addr: "$PROXY_ADDR"
    device_addr: "$DEV_ADDR"
    device_instance: 1001
    access:
      read_only: true
log_level: info
metrics:
  addr: "127.0.0.1:47812"
audit:
  file: "$audit"
EOF
	else
		cat >"$cfg" <<EOF
devices:
  - name: interop
    listen_addr: "$PROXY_ADDR"
    device_addr: "$DEV_ADDR"
    device_instance: 1001
    access:
      write_policy:
        default: deny
        rules:
          - oid: "analog-value:1:*"
            action: allow
log_level: info
metrics:
  addr: "127.0.0.1:47812"
audit:
  file: "$audit"
EOF
	fi
}

run_client() {
	# run_client <op> [oid] [prop] [expected-value] [write-value]
	BACNET_TARGET="$PROXY_ADDR" BACNET_OP="$1" \
		BACNET_OID="${2:-analog-value,1}" BACNET_PROP="${3:-present-value}" \
		BACNET_EXPECT="${4:-}" BACNET_VALUE="${5:-2.5}" \
		BACNET_TEXT="${BACNET_TEXT:-}" \
		"$PY" scripts/interop_client.py --address 127.0.0.1:0
}

scrape_metrics() {
	curl -fsS "http://127.0.0.1:47812/metrics"
}

write_config read_only
echo "== starting gateway with a read-only policy"
"$BIN" gateway --config "$cfg" >"$gw_log" 2>&1 &
pids="$pids $!"
wait_for "$gw_log" "listening" 50 || fail "gateway did not become ready"

echo "== read through the proxy"
run_client read analog-value,1 present-value 1 || fail "read"

echo "== Who-Is through the proxy"
run_client whois || fail "who-is"

echo "== write refused by the read-only policy"
run_client write-denied analog-value,1 present-value || fail "write-denied"

echo "== audit trail records the refused write, its target and its reason"
wait_for "$audit" '"event":"write_denied"' 50 || fail "no write_denied audit record"
grep -q '"reason":"read_only"' "$audit" || fail "audit reason was not read_only"
grep -q 'analog-value,1:present-value' "$audit" || fail "audit did not record the write target"

echo "== SIGHUP: allow analog-value:1:present-value in place"
write_config policy
gw_pid="$(echo "$pids" | awk '{print $NF}')"
kill -HUP "$gw_pid"
wait_for "$gw_log" "device policy reloaded" 50 || fail "policy reload"

echo "== write now allowed for analog-value,1 present-value"
run_client write analog-value,1 present-value || fail "allowed write"

echo "== write still denied for uncovered analog-value,2 present-value"
run_client write-denied analog-value,2 present-value || fail "uncovered write"

echo "== audit trail records the uncovered write as a default_deny"
wait_for "$audit" '"reason":"default_deny"' 50 || fail "audit did not record default_deny for the uncovered write"

echo "== read back the written value"
run_client read analog-value,1 present-value 2.5 || fail "read-back"

echo "== COV: subscribe, change, and receive the notification through the proxy"
run_client cov analog-value,1 present-value "" 4.25 || fail "cov notification"

echo "== read back the COV-changed value"
run_client read analog-value,1 present-value 4.25 || fail "cov read-back"

echo "== segmented response relayed through the proxy"
run_client read-long analog-value,1 description 120 || fail "segmented read"

echo "== segmented write reassembled and authorized through the proxy"
run_client write-long analog-value,1 description || fail "segmented write"
echo "== read back the segmented-write value"
run_client read-long analog-value,1 description 256 || fail "segmented write read-back"

echo "== the proxy counted the reassembled segmented write"
i=0
while [ "$i" -lt 50 ]; do
	if scrape_metrics 2>/dev/null | grep -q 'bacnet_shield_segmented_writes_total{device="interop"} 1'; then
		break
	fi
	sleep 0.1
	i=$((i + 1))
done
scrape_metrics 2>/dev/null | grep -q 'bacnet_shield_segmented_writes_total{device="interop"} 1' ||
	fail "segmented write was not counted"

echo "interop ok"
