#!/bin/bash
# Stage 1 of the stream harness: the external pieces as LLD 4 wires them, with ffmpeg standing
# in for the camera (a DJI Osmo Pocket 3 publishing 1080p30 H.264 + AAC over RTMP) and for the
# job Helios will start. Runs in an unprivileged network namespace, with 127.0.0.2 and 127.0.0.3
# as two uplinks, and checks each assumption the design makes. Prints PASS/FAIL per check and
# exits non-zero if any failed. Run tests/stream-e2e/setup.sh first.
#
#   publisher ffmpeg --RTMP--> nginx (rtmp module) --on_publish--> hook (stand-in for Helios)
#   job ffmpeg <--RTMP-- nginx;  job ffmpeg --SRT--> srtla_send --2 links--> srtla_rec
#   srtla_rec --SRT--> irl-srt-server :4002 (srtla publishers);  player ffmpeg <-- :4000
#
# Usage: tests/stream-e2e/external.sh [--loss PERCENT]
set -euo pipefail

E2E=${HELIOS_E2E_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/helios-stream-e2e}
HERE=$(cd "$(dirname "$0")" && pwd)
if [ "${HELIOS_E2E_INSIDE:-}" != 1 ]; then
    exec env HELIOS_E2E_INSIDE=1 unshare --map-root-user --net "$0" "$@"
fi

export PATH=$PATH:/usr/sbin:/sbin
LOSS=0
[ "${1:-}" = --loss ] && LOSS=${2:?}
BIN=$E2E/bin
export LD_LIBRARY_PATH=$E2E/sysroot/usr/lib/x86_64-linux-gnu
RUN=$(mktemp -d "${TMPDIR:-/tmp}/helios-e2e.XXXXXX")
PIDS=()
# shellcheck disable=SC2317 # runs from the EXIT trap
cleanup() {
    for pid in "${PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    wait 2>/dev/null || true
    [ -n "${KEEP:-}" ] || rm -rf "$RUN"
}
trap cleanup EXIT
FAILED=0
pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; FAILED=1; }
check() { local what=$1; shift; if "$@"; then pass "$what"; else fail "$what"; fi; }
start() { local name=$1; shift; "$@" >"$RUN/$name.log" 2>&1 & PIDS+=($!); }

# The namespace: loopback plus two more addresses as uplinks; optional loss on all of it.
ip link set lo up
ip addr add 127.0.0.2/8 dev lo
ip addr add 127.0.0.3/8 dev lo
if [ "$LOSS" != 0 ]; then tc qdisc add dev lo root netem loss "$LOSS%"; fi
echo "== namespace: lo 127.0.0.1-3, loss ${LOSS}%, run directory $RUN"

# --- Receiving side: irl-srt-server and srtla_rec ---------------------------------------------
mkdir -p "$RUN/sls/logs"
cat >"$RUN/sls/sls.conf" <<CONF
srt {
    worker_threads 1;
    worker_connections 100;
    http_port 8181;
    log_file $RUN/sls/logs/srt_server.log;
    log_level info;
    # A path with a directory: irl-srt-server creates it, and refuses a bare file name.
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
(cd "$RUN/sls" && exec "$BIN/srt_server" -c sls.conf) >"$RUN/sls.log" 2>&1 &
PIDS+=($!)
# srtla_rec must forward to the srtla publisher port (4002), not its default 4001.
start srtla_rec "$BIN/srtla_rec" --srtla_port 5000 --srt_hostname 127.0.0.1 --srt_port 4002

# --- nginx with the RTMP module, and a hook standing in for Helios ----------------------------
TOKEN=$(head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n')
start hook python3 -I "$HERE/hook.py" 8090 "$TOKEN" "$RUN/hook.jsonl"
mkdir -p "$RUN/nginx"
cat >"$RUN/nginx/nginx.conf" <<CONF
load_module $E2E/sysroot/usr/lib/nginx/modules/ngx_rtmp_module.so;
# Here nginx runs as the namespace's root and would switch workers to nobody, which isn't mapped.
# On the boards Helios starts it as helios, so there's no switch and no user directive.
user root root;
worker_processes 1;
error_log stderr warn;
pid $RUN/nginx/nginx.pid;
events { worker_connections 64; }
rtmp {
    # Without this the RTMP module opens nginx's compiled-in /var/log/nginx/access.log,
    # which an unprivileged nginx can't (LLD 4, section 4.2).
    access_log off;
    server {
        listen 1935;
        chunk_size 4096;
        application live {
            live on;
            record off;
            allow publish 127.0.0.0/8;
            deny publish all;
            allow play 127.0.0.1;
            deny play all;
            on_publish http://127.0.0.1:8090/rtmp/publish?token=$TOKEN;
            on_publish_done http://127.0.0.1:8090/rtmp/publish_done?token=$TOKEN;
            notify_method post;
            drop_idle_publisher 10s;
        }
    }
}
CONF
start nginx "$BIN/nginx" -e stderr -p "$RUN/nginx/" -c "$RUN/nginx/nginx.conf" -g 'daemon off;'

# --- srtla_send: two uplinks, control socket ----------------------------------------------------
printf '127.0.0.2\n127.0.0.3\n' >"$RUN/uplinks.ips"
start srtla_send "$BIN/srtla_send" --control-socket "$RUN/srtla.sock" --conn-timeout-ms 5000 \
    6000 127.0.0.1 5000 "$RUN/uplinks.ips"
sleep 2

echo "== the pieces are up"
check "irl-srt-server listens on 4000, 4001, 4002 and its stats on 8181" \
    sh -c "ss -lnu | grep -q ':4000 ' && ss -lnu | grep -q ':4002 ' && ss -lnt | grep -q ':8181 '"
check "srtla_rec listens on UDP 5000" sh -c "ss -lnu | grep -q ':5000 '"
check "nginx listens on TCP 1935" sh -c "ss -lnt | grep -q ':1935 '"
# LLD 4 section 5.1: srtla_send 4.1.0 binds its local port on every interface.
if ss -lnu | grep -qE '(\[::\]|\*|0\.0\.0\.0):6000 '; then
    pass "srtla_send's local port 6000 is bound on all interfaces (as LLD 4 says; needs the firewall rule)"
else
    fail "srtla_send's local port isn't bound on all interfaces: $(ss -lnu | grep ':6000 ' || echo none)"
fi

# --- A camera with the wrong key is refused -----------------------------------------------------
timeout 8 ffmpeg -hide_banner -loglevel error -re -f lavfi -i testsrc2=size=640x360:rate=30 \
    -t 3 -c:v libx264 -preset ultrafast -f flv rtmp://127.0.0.1:1935/live/wrong \
    >"$RUN/wrong.log" 2>&1 && wrong=0 || wrong=$?
check "a publish with an unknown key is refused (hook answered 403)" \
    sh -c "[ $wrong != 0 ] && grep -q '\"name\": \"wrong\"' '$RUN/hook.jsonl'"

# --- The Osmo Pocket 3 stand-in publishes with the built-in key ---------------------------------
start camera ffmpeg -hide_banner -loglevel error -re \
    -f lavfi -i testsrc2=size=1920x1080:rate=30 -f lavfi -i sine=frequency=440:sample_rate=48000 \
    -c:v libx264 -preset ultrafast -tune zerolatency -g 60 -b:v 6M -pix_fmt yuv420p \
    -c:a aac -b:a 128k -f flv rtmp://127.0.0.1:1935/live/ingest
CAMERA=${PIDS[-1]}
sleep 3
check "nginx called on_publish with call, app, name and addr" python3 -I - "$RUN/hook.jsonl" <<'PY'
import json,sys
calls=[json.loads(l) for l in open(sys.argv[1])]
ok=[c for c in calls if c["path"]=="/rtmp/publish" and c["form"].get("call")==["publish"]
    and c["form"].get("app")==["live"] and c["form"].get("name")==["ingest"] and c["form"].get("addr")]
sys.exit(0 if ok else 1)
PY
check "a request without the token is refused" \
    sh -c "! python3 -I -c 'import urllib.request;urllib.request.urlopen(\"http://127.0.0.1:8090/rtmp/publish\", b\"call=publish&name=ingest\")' 2>/dev/null"

# --- The job Helios will start: RTMP back from nginx, HEVC, to srtla_send ------------------------
start job ffmpeg -hide_banner -nostdin -loglevel warning -progress "$RUN/job.progress" \
    -rw_timeout 5000000 -i rtmp://127.0.0.1:1935/live/ingest -map 0:v:0 -map 0:a:0 \
    -c:v libx265 -preset ultrafast -b:v 4M -force_key_frames 'expr:gte(t,n_forced*2)' \
    -x265-params log-level=error -c:a copy -f mpegts -mpegts_flags +resend_headers \
    "srt://127.0.0.1:6000?mode=caller&latency=2000000&streamid=publish/live/ingest"
sleep 8
check "the job's output time advances (-progress)" \
    sh -c "grep -q '^progress=continue' '$RUN/job.progress' && [ \"\$(grep '^out_time_us=' '$RUN/job.progress' | tail -1 | cut -d= -f2)\" -gt 2000000 ]"

# --- srtla_send's statistics over the control socket --------------------------------------------
python3 -I "$HERE/srtla_stats.py" "$RUN/srtla.sock" >"$RUN/stats.json" 2>"$RUN/stats.err" || true
check "srtla_send pushes stats.update with 2 active links" python3 -I - "$RUN/stats.json" <<'PY'
import json,sys
s=json.load(open(sys.argv[1]))
links=s.get("connections") or s.get("links") or []
ips=sorted(str(l.get("ip")) for l in links)
print("      stats:", {k: s.get(k) for k in ("active_links","total_links","total_window","total_in_flight")}, "links:", ips)
sys.exit(0 if s.get("active_links")==2 and ips==["127.0.0.2","127.0.0.3"] else 1)
PY

# --- The receiving side gets HEVC + AAC ---------------------------------------------------------
timeout 20 ffmpeg -hide_banner -loglevel error \
    -i "srt://127.0.0.1:4000?mode=caller&streamid=play/live/ingest&latency=200000" \
    -t 4 -c copy -f mpegts "$RUN/played.ts" >"$RUN/player.log" 2>&1 || true
# ffprobe lists each stream once per program as well: de-duplicate.
codecs=$(ffprobe -v error -show_entries stream=codec_name -of csv=p=0 "$RUN/played.ts" 2>/dev/null | grep -v "^$" | sort -u | tr '\n' ' ')
check "a player on irl-srt-server :4000 gets hevc + aac ($codecs)" sh -c "[ '$codecs' = 'aac hevc ' ]"
# Without an API key, /stats answers for one publisher at a time.
curl -sS "http://127.0.0.1:8181/stats?publisher=publish/live/ingest" >"$RUN/sls-stats.json" 2>&1 || true
check "irl-srt-server's /stats knows the publisher ($(head -c 120 "$RUN/sls-stats.json"))" \
    grep -q '"status": *"ok"' "$RUN/sls-stats.json"

# --- The relay's path: H.264 passed through, no re-encode ---------------------------------------
timeout 12 ffmpeg -hide_banner -nostdin -loglevel error -rw_timeout 5000000 \
    -i rtmp://127.0.0.1:1935/live/ingest -t 4 -map 0:v:0 -map 0:a:0 -c:v copy -c:a copy \
    -f mpegts "$RUN/copy.ts" >"$RUN/copy.log" 2>&1 || true
copy=$(ffprobe -v error -show_entries stream=codec_name -of csv=p=0 "$RUN/copy.ts" 2>/dev/null | grep -v "^$" | sort -u | tr '\n' ' ')
check "H.264 passes through FLV to MPEG-TS untouched ($copy)" sh -c "[ '$copy' = 'aac h264 ' ]"

# --- The camera stops: on_publish_done ----------------------------------------------------------
kill "$CAMERA"
sleep 3
check "nginx called on_publish_done when the camera stopped" \
    grep -q '"call": \["publish_done"\]' "$RUN/hook.jsonl"

# --- The firewall rule for srtla_send's open port -----------------------------------------------
# A second namespace stands for another device on the travel router, joined by a veth pair.
unshare --net sleep 600 &
OTHER=$!
PIDS+=("$OTHER")
sleep 0.5
ip link add veth0 type veth peer name veth1
ip link set veth1 netns "$OTHER"
ip addr add 10.99.0.1/24 dev veth0
ip link set veth0 up
nsenter -t "$OTHER" -n sh -c 'ip link set lo up; ip addr add 10.99.0.2/24 dev veth1; ip link set veth1 up'
send_from_other() {
    nsenter -t "$OTHER" -n python3 -I -c \
        'import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);[s.sendto(b"x"*64,("10.99.0.1",6000)) for _ in range(5)]'
}
nft -f - <<'NFT'
table inet helios {
    counter outside { }
    chain input {
        type filter hook input priority filter; policy accept;
        iifname != "lo" udp dport 6000-6099 counter name outside drop
    }
}
NFT
send_from_other
sleep 0.5
dropped=$(nft list counter inet helios outside | awk '/packets/{print $2}')
check "the nftables rule drops srtla_send's port from another device ($dropped packets)" \
    sh -c "[ '${dropped:-0}' -ge 5 ]"
python3 -I "$HERE/srtla_stats.py" "$RUN/srtla.sock" >"$RUN/stats-after.json" 2>/dev/null || true
check "with the rule in place, both loopback uplinks stay active" python3 -I -c \
    'import json,sys;sys.exit(0 if json.load(open(sys.argv[1])).get("active_links")==2 else 1)' \
    "$RUN/stats-after.json"

echo
if [ "$FAILED" = 0 ]; then echo "== all checks passed"; else echo "== some checks failed; logs in $RUN"; KEEP=1; fi
exit "$FAILED"
