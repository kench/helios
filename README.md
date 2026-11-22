# helios

Helios on-device agent (Rust): a PKCS#11-held device identity with the bootstrap client, AWS IoT
MQTT, device shadows, commands and device modules (the scanner's display so far). Released as a
Debian package for the arm64 boards.

Design docs (Notion): *Helios - High-Level Design* and the Helios LLDs; current status in *Helios -
Project Status and Handoff*, devices in *Hardware Deployment Information*. Coding standards,
commit message rules and the coverage target are in HLD section 12. `AGENTS.md` summarizes the
layout, checks and rules for coding agents.

## Development

The API contract ([`helios-contract`](https://github.com/kench/helios-contract)) is a git submodule
in `contract/`, pinned to a tagged release. The bootstrap tests read its challenge test vectors and
protocol-test bodies, so clone with `--recurse-submodules`, or run `git submodule update --init`.

The stable toolchain is pinned in `rust-toolchain.toml`. Nightly is used only for rustfmt,
because `rustfmt.toml` uses unstable options.

The SoftHSM2 integration tests (`tests/softhsm.rs`) need the SoftHSM2 PKCS#11 module. They use
`/usr/lib/softhsm/libsofthsm2.so` from Debian's `softhsm2` package, or the path in
`HELIOS_SOFTHSM2_MODULE`. Without the module they're skipped, unless `HELIOS_REQUIRE_SOFTHSM2` is
set, as in CI. Each run uses its own temporary token directory.

`build.rs` embeds the build time, which the identity manager treats as the earliest plausible
clock reading when it checks certificate dates. Set `SOURCE_DATE_EPOCH` for reproducible builds.

Device modules are Cargo features, off by default, so each device's build carries only the
modules it uses: `module-display` (the display module, with its fonts and the `fontdue` and
`jiff` crates), `module-usb` (the usb module, no extra crates), `module-stream` (the stream
module; it needs `module-usb`) and `module-net` (the net module, no extra crates). Builds by
device:

| Device | Build |
| --- | --- |
| Scanner (PROXmobil3) | `cargo zigbuild --release --target armv7-unknown-linux-gnueabihf.2.28 --features module-display,module-usb` |
| Relay (Raspberry Pi 5), transcoder (Orange Pi 5 Plus) | the release workflow's package: `--features module-usb,module-stream,module-net` |

The checks below use `--all-features`; CI also runs Clippy and the tests with
`--no-default-features`.

`dist/systemd/helios.service` has the identity-related unit settings (LLD 1, section 4.5). The
full unit is defined in LLD 6. `dist/helios.toml` is an example config.

```sh
sudo apt install softhsm2
rustup toolchain install nightly --profile minimal --component rustfmt
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov --locked --version 0.9.1

cargo +nightly fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo clippy --locked --all-targets --no-default-features -- -D warnings
cargo test --locked --all-targets --no-default-features
cargo llvm-cov --locked --workspace --all-features --fail-under-lines 90
```

## Running the service

`helios` with no subcommand runs the service, as `helios.service` does. It reads
`/etc/helios/helios.toml` (or `--config <path>`), runs the startup checks, starts the identity
manager, keeps temporary AWS credentials fresh from the AWS IoT credentials provider (LLD 1,
sections 3 to 6), and keeps an MQTT 3.1.1 connection to AWS IoT Core (LLD 2, section 6): client
ID = thing name, the token-backed TLS identity, a clean session, `lifecycle.online` after each
connect and `lifecycle.offline` as the Last Will and on shutdown, and a bounded offline queue for
events. It reports the `helios` shadow (urgent changes at once, the rest at most once per
`mqtt.helios_shadow_interval_s`, 60 s by default), answers commands through the router on
Helios's own `helios/<thing>/cmd|rsp/<module>` topics and as AWS IoT command executions
(`$aws/commands/things/<thing>/executions/<id>/request/json`, answered on `…/response/json`;
`mqtt.commands`, both by default; LLD 2, section 7.3), and checks the clock (LLD 1, section 4.11): the kernel's NTP state, the offset from
server time in replies it gets anyway, and, if the platform writes `/run/helios/boot-clock`
before NTP runs, how far off the clock was at power-on. It reports them in the shadow's `clock`
object and logs offsets over `clock.warn_offset_s` (60 s) as warnings and over 240 s as errors.
It never sets the clock.

Modules (HLD section 6), each turned on in its `[modules.<name>]` section:

- `display` (LLD 9, Cargo feature `module-display`): screens on the scanner's framebuffer, drawn from templates compiled into
  Helios (`status`, `message`, `result`, `blank`, `test`) with Noto Sans (`assets/fonts`, SIL
  Open Font License). The idle `status` screen shows the clock in `time_zone`, the thing name,
  the MQTT connection and the device's address. `display.show` (`template`, `fields`,
  `duration_s`), `display.clear` and `display.status` change it, and the `display` shadow's
  desired state `{"idle": {"template": …, "fields": …}}` sets the idle screen. It writes only the
  rows that change, needs no `unsafe` code, and shows "Helios stopped" on shutdown. It needs the
  `video` group. `bold_font` can name a font file on the device to use for bold text instead, for
  licensed fonts that mustn't be compiled into Helios; the scanner keeps it on the USB drive.
- `stream` (LLD 4, Cargo feature `module-stream`): video streams through ffmpeg to SRT listeners,
  directly or bonded over several uplinks by `srtla_send`. Sources: USB cameras (from the usb
  module), RTMP cameras such as the Osmo Pocket 3 (`rtmp-ingest`: nginx with the RTMP module in
  `helios-rtmp.service`, config `/etc/helios/rtmp/nginx.conf`, keys `ingest`, `ingest-1`...;
  the daemon answers nginx's publish hook and reads its statistics page, so it picks up cameras
  already publishing after a restart), and a generated test pattern. With a Rockchip encoder,
  RTMP input is decoded by MPP and scaled by RGA. A profile's `encoder` is ffmpeg (the default:
  a fixed bitrate) or a GStreamer encoder, belacoder or ceracoder, which sends over SRT itself
  and, with `bitrate_mode = "adaptive"`, adapts the bitrate to the link between
  `min_bitrate_kbps` and the stream's bitrate; a new bitrate reaches it by SIGHUP, without a
  restart. For an RTMP camera the ceiling follows the camera's own video bitrate (nginx's
  `bw_video`, read every 10 s, smoothed, applied on a change of more than 10%), times the
  profile's `source_ceiling_percent` (default 100), so an encoder never spends more than its
  source carries. `stream.start`, `stream.stop` and
  `stream.status`; events `stream.connected`, `stream.live`, `stream.disconnected` and
  `stream.stats`; the `stream` shadow has each stream's and each bonded output's state, with
  per-link statistics. ffmpeg's arguments come only from the local profiles.

  The shadow's desired state (written by the Control API, HLD section 7.3.7) starts and stops
  streams and sets a bitrate override, and can also change a stream's `source`, `profile` (one
  the device defines), `destination` (an `srt://` or `srtla://` URL) and
  `source_ceiling_percent`; `null` goes back to `helios.toml`'s. Each is checked as
  `helios.toml` is, and a refused value is reported in the stream's `rejected` with the reason.
  A destination keeps the configured output's latency and the stream's `streamid` unless the URL
  gives them, and its passphrase is only the URL's; it runs as output `stream:<id>`, and an SRTLA
  one gets its own sender bonding the configured output's uplinks if that's an `srtla` output,
  else `srtla_uplinks`. Each stream reports the `destination` in use and its `overrides`, which
  the daemon saves with the rest of the desired state.

  So the Control API can offer only what's there, the shadow also has `profiles` (each one's
  encoder, bitrates, scale and audio) and `inputs`: the attached USB cameras (selector, port,
  product, whether they record audio, and their capture `formats`: pixel format in ffmpeg's
  names, size and frame rates, read once per camera over V4L2), USB audio devices, the RTMP keys
  (`ingest` and every key a stream takes, with `publish_url` when
  `rtmp_ingest.publish_host` is set) and the test pattern. Each RTMP publisher has its
  `address`, `since`, `video_codec`, `width`, `height` and `video_kbps`. A report that would
  come near AWS IoT's 8 KB leaves the cameras' formats out. Keys that go from the snapshot,
  nested ones too, are set to `null`, so the shadow doesn't keep stale publishers or streams.

  Streams run in the stream daemon, `helios stream-daemon` (`helios-stream.service`, user
  `helios-stream`), so they keep going while Helios restarts or is upgraded; Helios's `stream`
  module is its client over `/run/helios-stream/control.sock` (JSON-RPC lines). The daemon saves
  the desired state in `/var/lib/helios-stream`, and after an upgrade restarts itself only once no
  stream is live.

  `tests/stream-e2e/` runs it end to end without root: `setup.sh` builds nginx's RTMP module,
  `srtla_send`, `srtla_rec` and irl-srt-server (pinned) into `~/.cache/helios-stream-e2e`;
  `external.sh` checks the external pieces together; `helios.sh` runs the daemon as its own
  process with the real ffmpeg and `srtla_send` through `srtla_rec` to irl-srt-server, stops
  Helios mid-stream (the stream carries on, same processes), and drops and restores an uplink;
  with nginx running the shipped `dist/rtmp/nginx.conf`, it takes RTMP cameras through to the
  player (HEVC, and H.264 passed through), refuses an unknown key, and restarts the daemon while
  cameras publish.
- `net` (LLD 3, Cargo feature `module-net`): the network interfaces, in the `net` shadow keyed
  by name: each one's `kind` (`ethernet`, `wifi`, `cellular`, `virtual` or `other`, from sysfs),
  `mac` (and `permanent_mac` when it differs), `driver`, `usb_port`, `oper_state`, `carrier`,
  `admin_up`, `mtu`, `speed_mbps`, `since` (when `oper_state` last changed), `ipv4`
  (`a.b.c.d/n`), `ipv6` (address, prefix, scope and the temporary, deprecated, tentative and
  DAD-failed flags) and `default_routes` (main table: family, gateway and metric, including IPv6
  routes through nexthop objects). Read over rtnetlink, parsed in Helios; a thread listens for
  link, address and route changes, and a change is reported after 1 s of quiet (5 s at most),
  with a `net.changed` event naming the interfaces added and removed and the fields that
  changed. Loopback and `exclude` (default `veth*`) are left out; at most 16 interfaces and 8
  addresses of each family, else `truncated`. Read-only, no extra permissions, no `unsafe`.
  A Wi-Fi interface also has `wifi`: the joined network's `ssid`, the access point's `bssid`,
  `frequency_mhz` and `signal_dbm` (the driver's average), read over nl80211 (generic netlink,
  parsed in Helios), or `null` when it isn't joined. The signal is reported in 5 dB steps that
  move only when the reading has moved a whole step, so it doesn't rewrite the shadow all the
  time; it's read with everything else (link changes, and every minute).
  `helios net list` prints the same snapshot. `tests/net.rs` checks it against a real kernel
  in a user network namespace (`unshare -rn`).

  Wi-Fi networks (LLD 3, section 10): `net.wifi.set` (`ssid`, `passphrase` for WPA-Personal or
  none for an open network, `hidden`), `net.wifi.remove` and `net.wifi.list` commands (the
  Control API's `SetWifiNetwork` and `DeleteWifiNetwork` send the first two), and locally
  `helios wifi add|remove|list` (the passphrase is asked for without echo, or read with
  `--passphrase-file`, never taken as an argument). Helios keeps them in
  `/var/lib/helios/wifi/networks.json` (0600); `helios-wifi.path` then starts
  `helios-wifi.service`, which runs `helios wifi-apply` as root: it writes its own
  `/etc/netplan/60-helios-wifi.yaml` and runs `netplan apply`, or `helios-wifi-NN.nmconnection`
  keyfiles and `nmcli connection reload` where NetworkManager runs, and records the result in
  `/var/lib/helios-wifi/status.json`. The net shadow's `wifi` has the networks (never
  passphrases) and that result. At most 16 networks; no priorities yet (netplan has none).
  Passphrases are never logged or reported, and a command's `Debug` leaves out its arguments.
  The package enables `helios-wifi.path` on a device that has Helios enabled.

  From the Control API the passphrase arrives sealed to the device (LLD 3, section 10.7),
  `{"sealed": {"enc", "ct"}}`, because AWS keeps command executions: HPKE (RFC 9180) with
  DHKEM(P-256, HKDF-SHA256), HKDF-SHA256 and AES-128-GCM, `info` `helios secret v1 <thing>`
  and AAD `wifi.passphrase <ssid>`. Helios makes a `helios-secrets` P-256 key in the token when
  it has none (derive only, never extractable), does the ECDH there and the rest in software,
  and reports the public half in the `helios` shadow's `secrets_key`. A value it can't open fails
  with `SECRET_UNREADABLE`.

The other modules come later.

`dist/helios.toml` is an example config. With the bootstrap service it needs only the module
and CA paths. For development without the service, set `identity.pin = "file:<path>"` and fill
in `device.thing_name`, `identity.token_label`, `identity.key_label` and the four `[aws]`
endpoint settings. Sections this version doesn't use, such as `[modules.usb]`, are logged and
ignored (as `modules.usb`); unknown keys in a known section are errors.

```sh
SOFTHSM2_CONF=/etc/helios/softhsm2.conf helios --config ./helios.toml
HELIOS_LOG=debug helios        # error, warn, info (default), debug or trace
```

Logs go to stderr, without timestamps under journald. Exit codes: 0 after SIGTERM or SIGINT, 78
for a config error or a fatal identity problem such as a wrong PIN (the unit doesn't restart on
78), and 1 for anything else, which systemd restarts.

## Provisioning

`helios provision` sets up and inspects the device's token (LLD 1, section 4.10). Run it as the
`helios` user with the service's `SOFTHSM2_CONF`. The user PIN is prompted for, or read from
`--pin-file` (mode 0400 or 0600), never taken as an argument.

```sh
helios provision show
helios provision challenge-key --out challenge-key.pub.pem   # prints the key's SHA-256 fingerprint
helios provision challenge-key --replace                     # asks before deleting the old key
helios provision verify --thing-name t-01JD5VY2K7M9Q4R6T8V0X2Z4B6   # the startup checks
helios provision verify --bootstrap                          # with the service's PIN and identity
```

`--module` and `--token-label` default to `/usr/lib/softhsm/libsofthsm2.so` and `helios`. Exit
codes: 0 on success, 1 on error, 78 for configuration errors (missing module or token, wrong PIN).

## Releases

The Debian boards (relay and transcoder, arm64) install Helios from the APT repository in
helios-cloud's `AptRepository` stack, and `unattended-upgrades` keeps it current. The scanner
isn't a Debian system and keeps updating from its USB drive.

**Cutting a release:** set `version` in `Cargo.toml` (merged to `main`), then tag that commit
`v<version>` and push the tag. `.github/workflows/release.yml` checks the tag matches the version
and is on `main`, builds for `aarch64-unknown-linux-gnu` against glibc 2.31 with `cargo zigbuild`,
packages it with `cargo deb` (`[package.metadata.deb]`, maintainer scripts in `dist/debian/`), and
publishes: `.github/scripts/build-apt-repo.sh` adds the package to the pool, regenerates the index
with `apt-ftparchive` and signs `Release`/`InRelease`; the workflow uploads packages first and
`InRelease` last, then invalidates `/dists/*` on CloudFront. A version can't be republished with
different contents.

The package installs `/usr/bin/helios`, `helios.service` (not enabled: a board needs its config and
token first), an example config in `/usr/share/doc/helios/examples/`, and
`/etc/apt/apt.conf.d/52helios-unattended-upgrades`, which lets `unattended-upgrades` install Helios
releases. Its `postinst` creates the `helios` system user and restarts Helios on upgrades if it's
running. It depends on `softhsm2` and recommends `unattended-upgrades`.

The workflow needs the repository secret `APT_SIGNING_KEY` (an armored GPG private key without a
passphrase) and the variables `APT_BUCKET`, `APT_DISTRIBUTION_ID` and `APT_PUBLISHER_ROLE_ARN`
(helios-cloud's stack outputs `AptBucketName`, `AptDistributionId` and `AptPublisherRoleArn`).

**Setting up a board** (`<repo>` is the `AptRepositoryUrl` output):

```sh
sudo apt install curl gpg unattended-upgrades
curl -fsSL <repo>/keys/helios-archive-keyring.asc \
  | sudo gpg --dearmor -o /usr/share/keyrings/helios-archive-keyring.gpg
echo "deb [arch=arm64 signed-by=/usr/share/keyrings/helios-archive-keyring.gpg] <repo> stable main" \
  | sudo tee /etc/apt/sources.list.d/helios.list
sudo apt update && sudo apt install helios
```

## CI

`.github/workflows/ci.yml` runs on pull requests and pushes to `main`:

- **Conventional Commits** (pull requests only): the PR title and every non-merge commit
  subject must follow `<type>(<scope>)!: <summary>`. The check is
  `.github/scripts/check-conventional-commit.sh`.
- **Format:** `cargo +nightly fmt --check`.
- **Clippy:** `-D warnings`, with the lints from `Cargo.toml`, with all features and with none.
- **Test and coverage:** installs SoftHSM2, then runs `cargo test` with all features and with none,
  and `cargo llvm-cov` (all features) with at least 90% line coverage.
  The lcov and HTML reports are uploaded as the `coverage` artifact. Any file excluded from
  coverage must be listed in the workflow with `--ignore-filename-regex`.
