# helios

The Helios on-device agent, in Rust. It keeps the device key in a PKCS#11 token (SoftHSM2), gets
its PIN and identity from the bootstrap service, stays connected to AWS IoT Core over MQTT,
reports state through device shadows, answers commands, and runs device modules: display, usb,
stream, net and gps. The Debian boards install it as an APT package. The scanner runs it from a
USB drive.

- **Modules:** [`docs/modules.md`](docs/modules.md) describes what each one reports, its commands
  and its settings.
- **Example config:** [`dist/helios.toml`](dist/helios.toml), with every setting commented.
- **Coding agents:** [`AGENTS.md`](AGENTS.md) has the layout, the checks and the rules.

## Build and test

```sh
git clone --recurse-submodules git@github.com:kench/helios.git   # contract/ is a submodule
sudo apt install softhsm2
rustup toolchain install nightly --profile minimal --component rustfmt   # rustfmt only
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov --locked --version 0.9.1

cargo +nightly fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo clippy --locked --all-targets --no-default-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo test --locked --all-targets --no-default-features
cargo llvm-cov --locked --workspace --all-features --fail-under-lines 90
```

CI ([`ci.yml`](.github/workflows/ci.yml)) runs the same checks, and they're required on `main`.
Pull requests are also checked for Conventional Commits.

- **Toolchain:** stable, pinned in `rust-toolchain.toml`. Nightly is used only for rustfmt.
- **SoftHSM2 tests:** `tests/softhsm.rs` uses `/usr/lib/softhsm/libsofthsm2.so`, or the path in
  `HELIOS_SOFTHSM2_MODULE`. Without the module it's skipped, unless `HELIOS_REQUIRE_SOFTHSM2` is
  set (as in CI).
- **Build time:** `build.rs` embeds it, and certificate checks use it as the earliest plausible
  clock reading. Set `SOURCE_DATE_EPOCH` for reproducible builds.
- **Coverage:** lcov and HTML reports are uploaded as the `coverage` artifact. A file left out of
  coverage must be listed in `ci.yml` with `--ignore-filename-regex`.

### Builds by device

Each module is a Cargo feature and is off by default.

| Device | Build |
| --- | --- |
| Scanner (PROXmobil3, armv7) | `cargo zigbuild --release --target armv7-unknown-linux-gnueabihf.2.28 --features module-display,module-usb` |
| Boards (Raspberry Pi 5, Orange Pi 5 Plus) | the release workflow's package: `module-usb,module-stream,module-net,module-gps,module-web` |
| Provisioning computer | `cargo build --release` |

## Running

`helios` with no subcommand runs the service, as `helios.service` does.

```sh
SOFTHSM2_CONF=/etc/helios/softhsm2.conf helios --config ./helios.toml   # default /etc/helios/helios.toml
HELIOS_LOG=debug helios                   # error, warn, info (default), debug, trace
```

The service:
- **Identity and credentials** (LLD 1): starts the identity manager and keeps temporary AWS
  credentials fresh from the AWS IoT credentials provider.
- **MQTT** (LLD 2): connects to AWS IoT Core over MQTT 3.1.1, with the thing name as the client
  ID. It publishes `lifecycle.online` on connect and `lifecycle.offline` as the Last Will, and
  keeps a bounded queue of events while offline. When the connection's local address goes away
  (for example, a cable pulled), it reconnects within about 2 s.
- **The `helios` shadow:** urgent changes go at once, the rest at most every
  `mqtt.helios_shadow_interval_s` (60 s).
- **Commands:** answered on `helios/<thing>/cmd|rsp/<module>` and as AWS IoT command executions
  (`mqtt.commands`, both by default).
- **Clock** (LLD 1, 4.11): checks the kernel's NTP state and the offset from server time, and
  warns above `clock.warn_offset_s`. It never sets the clock. `clock.report = "full"` adds the
  details to the shadow.

### Config

With the bootstrap service, the config needs only the module and CA paths. For development
without it, set `identity.pin = "file:<path>"` and fill in `device.thing_name`,
`identity.token_label`, `identity.key_label` and the four `[aws]` endpoints. A module section
this build doesn't include is logged and ignored. An unknown key in a known section is an error.

### Logs and exit codes

Logs go to stderr, without timestamps under journald.

| Code | Meaning | systemd |
| --- | --- | --- |
| 0 | stopped by SIGTERM or SIGINT | — |
| 78 | config error, or a fatal identity problem such as a wrong PIN | not restarted |
| 1 | anything else | restarted |

## Provisioning

`helios provision` sets up and checks the device's token (LLD 1, 4.10). Run it as the `helios`
user with the service's `SOFTHSM2_CONF`. The PIN is prompted for or read from `--pin-file` (mode
0400 or 0600), never taken as an argument.

```sh
helios provision show
helios provision challenge-key --out challenge-key.pub.pem   # prints its SHA-256 fingerprint
helios provision challenge-key --replace                     # asks before deleting the old key
helios provision verify --thing-name t-01JD5VY2K7M9Q4R6T8V0X2Z4B6
helios provision verify --bootstrap                          # with the service's PIN and identity
```

`--module` and `--token-label` default to `/usr/lib/softhsm/libsofthsm2.so` and `helios`. Exit
codes: 0 for success, 1 for an error, 78 for a configuration error.

## Releases

1. Set `version` in `Cargo.toml` in a PR and merge it.
2. Tag the merge commit `v<version>` and push the tag. Only admins can create `v*` tags.

[`release.yml`](.github/workflows/release.yml) then:
- checks that the tag matches the version and is on `main`;
- builds the arm64 package (`cargo zigbuild` against glibc 2.31, then `cargo deb`);
- publishes it to the APT repository from helios-cloud's `AptRepository` stack.

A version can't be republished with different contents, so if a release fails, release the next
version instead of moving the tag. `unattended-upgrades` installs new releases on the boards.

- **Repository settings it needs:** the secret `APT_SIGNING_KEY` (an armored GPG key without a
  passphrase), and the variables `APT_BUCKET`, `APT_DISTRIBUTION_ID` and `APT_PUBLISHER_ROLE_ARN`
  (helios-cloud's stack outputs).
- **What the package installs:** `/usr/bin/helios`, the systemd units (Helios isn't enabled
  until the board has its config and token), an example config, and an `unattended-upgrades`
  rule for Helios. It creates the `helios` user and restarts Helios on upgrade.

To add a board to the repository (`<repo>` is the `AptRepositoryUrl` output):

```sh
sudo apt install curl gpg unattended-upgrades
curl -fsSL <repo>/keys/helios-archive-keyring.asc \
  | sudo gpg --dearmor -o /usr/share/keyrings/helios-archive-keyring.gpg
echo "deb [arch=arm64 signed-by=/usr/share/keyrings/helios-archive-keyring.gpg] <repo> stable main" \
  | sudo tee /etc/apt/sources.list.d/helios.list
sudo apt update && sudo apt install helios
```
