#!/bin/bash
# Stage 2 of the stream harness: `helios stream-daemon` as its own process, with the real ffmpeg
# and srtla_send it starts, through srtla_rec to irl-srt-server, and the test as Helios (the
# daemon's client). Two dummy interfaces are the uplinks (up0 10.10.1.2, up1 10.10.2.2) and the
# receiving side listens on rx0 (10.10.0.1). nginx runs the shipped dist/rtmp/nginx.conf, with
# only its paths changed. The tests (src/modules/stream/e2e.rs) stop Helios mid-stream and check
# the stream carries on, drop and restore an uplink, and take RTMP cameras through nginx and the
# daemon (HEVC, and H.264 passed through), across a daemon restart. Run setup.sh first.
#
# Usage: tests/stream-e2e/helios.sh
set -euo pipefail

E2E=${HELIOS_E2E_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/helios-stream-e2e}
HERE=$(cd "$(dirname "$0")" && pwd)
TOP=$(cd "$HERE/../.." && pwd)
if [ "${HELIOS_E2E_INSIDE:-}" != 1 ]; then
    # Build first, outside the namespace: it has no network.
    (cd "$TOP" && cargo build --locked --features module-stream -q &&
        cargo test --locked --features module-stream --lib --no-run -q)
    exec env HELIOS_E2E_INSIDE=1 unshare --map-root-user --net "$0" "$@"
fi
export PATH=$PATH:/usr/sbin:/sbin
export LD_LIBRARY_PATH=$E2E/sysroot/usr/lib/x86_64-linux-gnu
BIN=$E2E/bin
RUN=$(mktemp -d "${TMPDIR:-/tmp}/helios-e2e.XXXXXX")
PIDS=()
# shellcheck disable=SC2317 # runs from the EXIT trap
cleanup() {
    for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    wait 2>/dev/null || true
    [ -n "${KEEP:-}" ] || rm -rf "$RUN"
}
trap cleanup EXIT

ip link set lo up
for spec in rx0:10.10.0.1 up0:10.10.1.2 up1:10.10.2.2; do
    ip link add "${spec%%:*}" type dummy
    ip addr add "${spec#*:}/24" dev "${spec%%:*}"
    ip link set "${spec%%:*}" up
done
echo "== namespace: rx0 10.10.0.1 (receiver), up0 10.10.1.2 and up1 10.10.2.2 (uplinks)"

mkdir -p "$RUN/sls/logs"
cat >"$RUN/sls/sls.conf" <<CONF
srt {
    worker_threads 1;
    worker_connections 100;
    http_port 8181;
    log_file $RUN/sls/logs/srt_server.log;
    log_level info;
    pidfile $RUN/sls/run/sls.pid;
    server {
        listen_player 4000;
        listen_publisher 4001;
        listen_publisher_srtla 4002;
        latency_min 200;
        latency_max 5000;
        domain_player play;
        domain_publisher publish;
        backlog 100;
        idle_streams_timeout 30;
        app {
            app_player live;
            app_publisher live;
            allow publish all;
            allow play all;
        }
    }
}
CONF
"$BIN/srt_server" -c "$RUN/sls/sls.conf" >"$RUN/sls.log" 2>&1 &
PIDS+=($!)
"$BIN/srtla_rec" --srtla_port 5000 --srt_hostname 127.0.0.1 --srt_port 4002 >"$RUN/srtla_rec.log" 2>&1 &
PIDS+=($!)

# rtmp-ingest: the shipped config, with this run's paths. In the namespace nginx is root and
# would switch workers to nobody, which isn't mapped, so it stays root here.
mkdir -p "$RUN/nginx"
sed -e "s|/usr/lib/nginx/modules/|$E2E/sysroot/usr/lib/nginx/modules/|" \
    -e "s|/run/helios-rtmp/|$RUN/nginx/|" -e "s|/var/lib/helios-rtmp/|$RUN/nginx/|" \
    -e "s|^worker_processes|user root root;\nworker_processes|" \
    "$TOP/dist/rtmp/nginx.conf" >"$RUN/nginx/nginx.conf"
"$BIN/nginx" -t -q -e stderr -p "$RUN/nginx/" -c "$RUN/nginx/nginx.conf"
"$BIN/nginx" -e stderr -p "$RUN/nginx/" -c "$RUN/nginx/nginx.conf" -g 'daemon off;' >"$RUN/nginx.log" 2>&1 &
PIDS+=($!)
sleep 1
echo "== nginx from dist/rtmp/nginx.conf: RTMP :1935, statistics on 127.0.0.1:1937"

echo "== Helios's stream module (src/modules/stream/e2e.rs)"
cd "$TOP"
status=0
HELIOS_E2E_DIR=$E2E HELIOS_E2E_RUN=$RUN HELIOS_E2E_BIN=$TOP/target/debug/helios cargo test --offline --locked --features module-stream \
    --lib -q modules::stream::e2e -- --ignored --nocapture --test-threads=1 \
    >"$RUN/test.log" 2>&1 || status=$?
grep -E "^HELIOS|test result|panicked|left:|right:" "$RUN/test.log" || true
grep -q "test result: ok. 2 passed" "$RUN/test.log" || status=1
if [ "$status" = 0 ]; then
    echo "== passed"
else
    KEEP=1
    echo "== failed; logs in $RUN"
fi
exit "$status"
