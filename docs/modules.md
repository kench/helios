# Helios modules

Each module is a Cargo feature, off by default, and is turned on in its `[modules.<name>]`
section of `helios.toml` (see [`dist/helios.toml`](../dist/helios.toml) for every setting). A
module runs under the supervisor, which restarts it with backoff. Its state is in the `helios`
shadow's `modules`.

| Module | Feature | Design | Where |
| --- | --- | --- | --- |
| [display](#display) | `module-display` | LLD 9 | scanner |
| [usb](#usb) | `module-usb` | LLD 5 | all |
| [stream](#stream) | `module-stream` (needs `module-usb`) | LLD 4 | boards |
| [net](#net) | `module-net` | LLD 3 | boards |
| [gps](#gps) | `module-gps` | LLD 10 | boards |

## display

Screens on the scanner's framebuffer, drawn from templates compiled into Helios: `status`,
`message`, `result`, `blank` and `test`.

- **Idle screen:** `status` shows the clock (in `time_zone`), the thing name, the MQTT
  connection and the device's address. The `display` shadow's desired state
  `{"idle": {"template": …, "fields": …}}` sets a different one.
- **Commands:** `display.show` (`template`, `fields`, `duration_s`), `display.clear` and
  `display.status`.
- **Fonts:** Noto Sans (`assets/fonts`, SIL Open Font License). `bold_font` can name a font file
  on the device for bold text, for licensed fonts that mustn't be compiled in.
- **Behaviour:** it redraws only the rows that change, and shows "Helios stopped" on shutdown.
- **Needs:** the `video` group, and the kernel's console detached from the framebuffer.

## usb

USB devices arriving and leaving, from the kernel's uevents and sysfs.

- **Events:** `usb.attached`, `usb.changed` and `usb.detached` on `helios/<thing>/evt/usb`.
  Devices already present at start appear only in the shadow.
- **Shadow and command:** the `usb` shadow, and `usb.status`.
- **Settings:** `settle_ms` (quiet time before a device is announced), `hubs`, `ignore`, and
  `max_events_per_port` (for flapping ports).

## stream

Video streams through an encoder to SRT listeners, either directly or bonded over several
uplinks by `srtla_send`.

**Sources**
- **USB cameras,** from the usb module.
- **RTMP cameras** such as the Osmo Pocket 3, through nginx's RTMP module in
  `helios-rtmp.service` (keys `ingest`, `ingest-1`, …). The daemon answers nginx's publish hook
  and reads its statistics page, so after a restart it picks up cameras already publishing.
- **A generated test pattern.**

**Encoders** (a profile's `encoder`)
- **`ffmpeg`** (the default): a fixed bitrate. With a Rockchip encoder, MPP decodes RTMP input
  and RGA scales it.
- **`belacoder` or `ceracoder`** (GStreamer): these send over SRT themselves. With
  `bitrate_mode = "adaptive"`, the bitrate follows the link between `min_bitrate_kbps` and the
  stream's bitrate. A new bitrate arrives by SIGHUP, without a restart.
- **The ceiling for RTMP cameras:** the camera's own video bitrate times
  `source_ceiling_percent` (100% by default), so the encoder never sends more than the source
  carries.

**The daemon**
- Streams run in `helios stream-daemon` (`helios-stream.service`, user `helios-stream`), so they
  keep going while Helios restarts or upgrades.
- Helios's `stream` module is a client over `/run/helios-stream/control.sock` (JSON-RPC lines).
- The daemon saves the desired state in `/var/lib/helios-stream`. After an upgrade, it restarts
  itself only once no stream is live.

**Commands and events**
- Commands: `stream.start`, `stream.stop` and `stream.status`.
- Events: `stream.connected`, `stream.live`, `stream.disconnected` and `stream.stats`.
- ffmpeg's arguments come only from the local profiles.

**The `stream` shadow** reports each stream and each bonded output, with per-link statistics. It
also lists what the Control API can offer:
- `profiles`;
- `inputs`: the USB cameras (with their capture formats), USB audio devices, the RTMP keys (with
  each publisher's codec, size and bitrate) and the test pattern.

Keys that disappear are set to `null`. If a report would come near AWS IoT's 8 KB limit, the
cameras' formats are left out.

**Desired state** (written by the Control API) can:
- start and stop streams, and override the bitrate;
- change a stream's `source`, `profile`, `destination` (`srt://` or `srtla://`) and
  `source_ceiling_percent`. Setting `null` goes back to `helios.toml`'s value.

Each value is checked the same way `helios.toml` is. A refused value shows in the stream's
`rejected`, with the reason. A destination keeps the output's latency and the stream's
`streamid` unless the URL gives them. It runs as output `stream:<id>`, and an `srtla://`
destination gets its own sender over the output's uplinks (or `srtla_uplinks`).

**Bonding and standby.** By default, every uplink with a source route bonds. With
`srtla_standby = true` (LLD 3, 3.5.1), only one of the uplinks that share a public address
bonds, chosen by kind (Ethernet, then cellular, then Wi-Fi), then metric, then name. The others
wait in the output's `standby`. Either way, a working link stays bonded until its replacement
has registered.

Standby is off because a link joining from standby waits out srtla_send's 5 s startup grace,
which is longer than SRT's peer timeout. Losing the bonded uplink outright then drops the stream
for a few seconds. With every uplink bonded, nothing drops when a cable is pulled, at the same
bitrate (measured on the Orange Pi, 2026-11-24).

**End-to-end tests:** `tests/stream-e2e/` runs without root.
1. `setup.sh` builds pinned nginx-rtmp, `srtla_send`, `srtla_rec` and irl-srt-server.
2. `external.sh` checks those pieces together.
3. `helios.sh` runs the daemon with the real ffmpeg through `srtla_rec`. It stops Helios
   mid-stream, drops and restores an uplink, takes RTMP cameras through to the player, and
   restarts the daemon while cameras are publishing.

## net

The network interfaces, read-only over rtnetlink. Needs no extra permissions and no `unsafe`.

**The `net` shadow**, keyed by interface name, has for each one:

| What | Fields |
| --- | --- |
| Identity | `kind` (`ethernet`, `wifi`, `cellular`, `virtual`, `other`), `mac`, `permanent_mac`, `driver`, `usb_port` |
| Link | `oper_state`, `carrier`, `admin_up`, `mtu`, `speed_mbps`, `since` |
| Addresses | `ipv4` (`a.b.c.d/n`), `ipv6` (address, prefix, scope, flags), `default_routes` |
| Routing | `source_route`: `{table, rule}` when `helios-routes` gives the interface its own table; `rule` is true once each address has its `from` rule |
| Public address | `public_ipv4`: `{address, checked_at}`, from the bootstrap API's egress echo, for each interface with `rule: true` (`public_address_check`) |
| Wi-Fi | `wifi`: `ssid`, `bssid`, `frequency_mhz`, `signal_dbm` (in 5 dB steps), from nl80211 |

- **Public address checks:** at start, when the uplink's address or route changes, and about
  every 15 minutes. After a failure, the last address stays, with `error` and `failed_at`.
  Public addresses go only to the shadow, never to the log.
- **Changes:** reported after 1 s of quiet (5 s at most), with a `net.changed` event.
- **Limits:** loopback and `exclude` (default `veth*`) are left out. At most 16 interfaces and 8
  addresses per family are reported; beyond that the report is `truncated`.
- **Locally:** `helios net list` prints the same snapshot. `tests/net.rs` checks it in a user
  network namespace.

### Wi-Fi networks (LLD 3, 10)

- **Commands:** `net.wifi.set` (`ssid`, `passphrase` or none for an open network, `hidden`),
  `net.wifi.remove` and `net.wifi.list`. The Control API's `SetWifiNetwork` and
  `DeleteWifiNetwork` send the first two.
- **Locally:** `helios wifi add|remove|list`. The passphrase is prompted for or read with
  `--passphrase-file`.
- **Storage:** `/var/lib/helios/wifi/networks.json` (0600), at most 16 networks.
- **Applying:** `helios-wifi.path` starts `helios-wifi.service` (root), which writes netplan or
  NetworkManager keyfiles and records the result. The net shadow's `wifi` shows the networks
  (never passphrases) and that result.
- **Sealed passphrases:** from the Control API, the passphrase arrives sealed to the device,
  because AWS keeps command executions. The sealing is HPKE (RFC 9180): DHKEM(P-256,
  HKDF-SHA256), AES-128-GCM, with `info` set to `helios secret v1 <thing>` and the AAD to
  `wifi.passphrase <ssid>`. The ECDH runs in the token with a non-extractable `helios-secrets`
  key, whose public half is in the `helios` shadow's `secrets_key`. A value Helios can't open
  fails with `SECRET_UNREADABLE`.

Passphrases are never logged or reported.

## gps

The position, from gpsd.

- **The `gps` shadow** has the full fix. It's updated at once when the fix is gained or lost,
  every 25 m (at most every 10 s) while moving, and once an hour while still.
- **`device`:** names a receiver for gpsd to open through its control socket, at start and
  whenever gpsd loses it. Use it for USB serial bridges that gpsd's hotplug rules don't know.
- **Needs:** gpsd running. The package's `gpsd.socket` drop-in opens its control socket to Helios.
