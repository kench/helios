# helios

Helios on-device agent (Rust): AWS IoT MQTT, device shadows and the bootstrap client.

Design docs (Notion): *Helios - High-Level Design* and the Helios LLDs. Coding standards,
commit message rules and the coverage target are in HLD section 12.

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
`mqtt.helios_shadow_interval_s`, 60 s by default), answers commands through the router (`helios.ping`
for now), and checks the clock (LLD 1, section 4.11): the kernel's NTP state, the offset from
server time in replies it gets anyway, and, if the platform writes `/run/helios/boot-clock`
before NTP runs, how far off the clock was at power-on. It reports them in the shadow's `clock`
object and logs offsets over `clock.warn_offset_s` (60 s) as warnings and over 240 s as errors.
It never sets the clock. The other modules come later (LLD 2).

`dist/helios.toml` is an example config. With the bootstrap service it needs only the module
and CA paths. For development without the service, set `identity.pin = "file:<path>"` and fill
in `device.thing_name`, `identity.token_label`, `identity.key_label` and the four `[aws]`
endpoint settings. Sections this version doesn't use, such as `[modules.usb]`, are logged and
ignored; unknown keys in a known section are errors.

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

## CI

`.github/workflows/ci.yml` runs on pull requests and pushes to `main`:

- **Conventional Commits** (pull requests only): the PR title and every non-merge commit
  subject must follow `<type>(<scope>)!: <summary>`. The check is
  `.github/scripts/check-conventional-commit.sh`.
- **Format:** `cargo +nightly fmt --check`.
- **Clippy:** `-D warnings`, with the lints from `Cargo.toml`.
- **Test and coverage:** installs SoftHSM2, then runs `cargo test` and `cargo llvm-cov` with at least
  90% line coverage.
  The lcov and HTML reports are uploaded as the `coverage` artifact. Any file excluded from
  coverage must be listed in the workflow with `--ignore-filename-regex`.
