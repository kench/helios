#!/bin/bash
# Builds the stream module's end-to-end harness (LLD 4, section 12) without root: nginx with the
# RTMP module (Debian Trixie's packages, unpacked), irlserver srtla_send, srtla_rec and
# irl-srt-server (built from pinned commits, irl-srt-server against irlserver's SRT fork), all
# into $HELIOS_E2E_DIR (default ~/.cache/helios-stream-e2e). Needs apt-get (download only),
# dpkg-deb, git, cmake, make, g++ and cargo. Run it again to pick up changed pins; finished
# steps are skipped.
#
# Usage: tests/stream-e2e/setup.sh
set -euo pipefail

E2E=${HELIOS_E2E_DIR:-${XDG_CACHE_HOME:-$HOME/.cache}/helios-stream-e2e}
SYS=$E2E/sysroot
SRC=$E2E/src
BIN=$E2E/bin
JOBS=$(nproc)
# The unpacked headers, including Debian's per-architecture ones (opensslconf.h).
INCLUDES="-I$SYS/usr/include -I$SYS/usr/include/x86_64-linux-gnu"

# Debian Trixie packages: the nginx build the boards run, and build-time headers.
PACKAGES=(
    nginx=1.26.3-3+deb13u11
    libnginx-mod-rtmp=1:1.2.2+dfsg-6
    libssl-dev=3.5.7-1~deb13u3
    zlib1g-dev=1:1.3.dfsg+really1.3.1-1+deb13u1
    libspdlog-dev=1:1.15.2+ds-2
    libspdlog1.15=1:1.15.2+ds-2
    libfmt-dev=10.1.1+ds1-4
    libfmt10=10.1.1+ds1-4
)
# Pinned sources: the srtla_send packaged by helios-packages, and the receiving side.
SRTLA_SEND=(https://github.com/irlserver/srtla_send.git 329982543dccda9ca9b99b2b90d1499fd452a7bf)
SRTLA=(https://github.com/irlserver/srtla.git 877dc16e36d3fef421f9cffd345b54a526020732)
SRT_FORK=(https://github.com/irlserver/srt.git f2297192ce9ab572464e84228efbc46f8c1eabf4)
SLS=(https://github.com/irlserver/irl-srt-server.git a86dd8abd3659baea8ca8315bb4842410d4bc292)

mkdir -p "$SYS" "$SRC" "$BIN" "$E2E/debs"

echo "== Debian packages into $SYS"
(
    cd "$E2E/debs"
    for package in "${PACKAGES[@]}"; do
        name=${package%%=*}
        ls "${name}"_*.deb >/dev/null 2>&1 || apt-get download -q=2 "$package"
    done
    for deb in *.deb; do dpkg-deb -x "$deb" "$SYS"; done
)
# The -dev packages' unversioned .so links point at libraries installed on this machine, not
# unpacked here: point them there.
lib=$SYS/usr/lib/x86_64-linux-gnu
for link in "$lib"/*.so; do
    target=$(readlink "$link")
    if [ ! -e "$lib/$target" ] && [ -e "/usr/lib/x86_64-linux-gnu/$target" ]; then
        ln -sfn "/usr/lib/x86_64-linux-gnu/$target" "$link"
    fi
done
ln -sfn "$SYS/usr/sbin/nginx" "$BIN/nginx"

# fetch DIR REPO COMMIT: that commit, with submodules.
fetch() {
    if [ "$(git -C "$1" rev-parse HEAD 2>/dev/null)" != "$3" ]; then
        rm -rf "$1"
        git init -q "$1"
        git -C "$1" fetch -q --depth 1 "$2" "$3"
        git -C "$1" -c advice.detachedHead=false checkout -q FETCH_HEAD
        git -C "$1" submodule -q update --init --depth 1
    fi
    [ "$(git -C "$1" rev-parse HEAD)" = "$3" ] || { echo "$2: not $3" >&2; exit 1; }
}

echo "== srtla_send ${SRTLA_SEND[1]}"
fetch "$SRC/srtla_send" "${SRTLA_SEND[@]}"
if [ ! -x "$BIN/srtla_send" ]; then
    (cd "$SRC/srtla_send" && cargo build -q --locked --release)
    cp "$SRC/srtla_send/target/release/srtla_send" "$BIN/"
fi

echo "== srtla_rec ${SRTLA[1]}"
fetch "$SRC/srtla" "${SRTLA[@]}"
if [ ! -x "$BIN/srtla_rec" ]; then
    cmake -S "$SRC/srtla" -B "$E2E/build/srtla" -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_PREFIX_PATH="$SYS/usr" -Wno-dev >/dev/null
    make -s -C "$E2E/build/srtla" -j "$JOBS" srtla_rec >/dev/null
    cp "$E2E/build/srtla/srtla_rec" "$BIN/"
fi

echo "== irlserver SRT fork ${SRT_FORK[1]}"
fetch "$SRC/srt" "${SRT_FORK[@]}"
if [ ! -e "$E2E/srt/lib/libsrt.a" ] && [ ! -e "$E2E/srt/lib64/libsrt.a" ]; then
    cmake -S "$SRC/srt" -B "$E2E/build/srt" -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="$E2E/srt" -DCMAKE_PREFIX_PATH="$SYS/usr" \
        -DCMAKE_C_FLAGS="$INCLUDES" -DCMAKE_CXX_FLAGS="$INCLUDES" \
        -DENABLE_SHARED=OFF -DENABLE_STATIC=ON -DENABLE_APPS=OFF -Wno-dev >/dev/null
    make -s -C "$E2E/build/srt" -j "$JOBS" install >/dev/null
fi

# Built against the fork above, never this machine's libsrt: the fork's SRTO_SRTLAPATCHES is what
# makes the srtla port handle bonded traffic.
echo "== irl-srt-server ${SLS[1]}"
fetch "$SRC/irl-srt-server" "${SLS[@]}"
if [ ! -x "$BIN/srt_server" ]; then
    cmake -S "$SRC/irl-srt-server" -B "$E2E/build/sls" -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_PREFIX_PATH="$E2E/srt;$SYS/usr" \
        -DCMAKE_CXX_FLAGS="-I$E2E/srt/include $INCLUDES" \
        -DCMAKE_EXE_LINKER_FLAGS="-L$E2E/srt/lib -L$SYS/usr/lib/x86_64-linux-gnu" \
        -DCMAKE_CXX_STANDARD_LIBRARIES="-lcrypto" -Wno-dev >/dev/null
    make -s -C "$E2E/build/sls" -j "$JOBS" >/dev/null
    cp "$(find "$E2E/build/sls" "$SRC/irl-srt-server/bin" -name srt_server -type f 2>/dev/null | head -1)" "$BIN/"
fi

echo "== Ready in $BIN:"
ls "$BIN"
