# AGENTS.md

Helios is the on-device agent: a Rust service that holds the device key in a PKCS#11 token
(SoftHSM2), gets its PIN and identity from the bootstrap service, connects to AWS IoT Core over
MQTT, reports device state through shadows, answers commands, and runs device modules. The
design lives in Notion under "Embedded Hardware Development Notes": start with "Helios - Project
Status and Handoff", then the High-Level Design and the LLDs it links (LLD 1 identity, LLD 2
messaging, LLD 9 display). `README.md` covers building, running, provisioning and releases.

## Layout

```
src/identity/      PKCS#11 token, rustls signer, PINs, bootstrap client, identity manager (LLD 1)
src/credentials/   AWS credentials through the AWS IoT credentials provider
src/mqtt/          connection manager, envelopes, shadow manager, the helios shadow (LLD 2)
src/router/        command router; CommandTransport (custom cmd/rsp topics now)
src/clock/         clock checks (LLD 1, 4.11); kernel.rs holds the only allowed unsafe code
src/modules/       device modules, each behind a Cargo feature (display: LLD 9)
src/provision/     `helios provision` (challenge key, show, verify)
src/service.rs     wires everything together for `helios` with no subcommand
contract/          git submodule: helios-contract (Bootstrap API model and test vectors)
assets/fonts/      Noto Sans subsets for the display (OFL)
dist/              example config, systemd unit, Debian maintainer scripts
.github/           CI, the release workflow and build-apt-repo.sh
```

## Check your work

The toolchain is pinned in `rust-toolchain.toml`; rustfmt runs on nightly.

```sh
cargo +nightly fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo clippy --locked --all-targets --no-default-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo test --locked --all-targets --no-default-features
cargo llvm-cov --locked --workspace --all-features --fail-under-lines 90
```

CI runs all of these on every PR and they're required on `main`. The SoftHSM2 integration tests
need Debian's `softhsm2`.

## Builds by device

| Device | Command |
| --- | --- |
| Scanner (PROXmobil3, armv7, glibc 2.28) | `cargo zigbuild --release --target armv7-unknown-linux-gnueabihf.2.28 --features module-display` (zig 0.14.1) |
| Debian boards (arm64) | built and published by `.github/workflows/release.yml` on a `v*` tag: `aarch64-unknown-linux-gnu.2.31`, `cargo deb --no-strip` |
| Provisioning computer (x86-64) | `cargo build --release` (used by the provisioning scripts) |

The scanner runs Helios from its USB drive (`~/workspace/helios/scanner-usb`, not in this
repository): install a new build both on the drive (`helios/bin/helios`) and, for a live test,
in `/run/helios/bin` on the scanner.

## Releases

Set `version` in `Cargo.toml` in a PR; once merged, the owner tags the merge commit
`v<version>` and pushes it (a ruleset allows only admins to create `v*` tags). The workflow
checks the tag, builds the arm64 package and publishes it to the Helios APT repository. A tag's
workflow runs as it was at the tagged commit: if a release fails, fix it and release the next
version rather than moving the tag.

## Rules

- Conventional Commits for commits and PR titles (checked in CI); squash merges.
- `unsafe_code = "deny"`. The only exception is the read-only `adjtimex` call in
  `src/clock/kernel.rs`; any other `unsafe` needs the owner's OK. Prefer safe crates (`rustix`).
- `unwrap_used` is denied. Document errors and panics on public items; keep 90% line coverage.
- Never log or print PINs, and never put them in process arguments.
- Modules are Cargo features, off by default; a module's config section is ignored in builds
  without it. The scanner build needs `--features module-display`.
- Licensed fonts (Roobert TW Bold) are loaded at run time from the device and are never committed
  or compiled in. Nothing from INIT's vendor software goes into this repository.
- Don't push tags or change repository settings without the owner's OK.
