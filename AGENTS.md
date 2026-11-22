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
src/clock/         clock checks (LLD 1, 4.11); kernel.rs holds an allowed unsafe call (adjtimex)
src/modules/       device modules behind Cargo features (display: LLD 9, usb: LLD 5, stream: LLD 4), the Module trait and
                   the supervisor that restarts them (LLD 5, section 14)
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
need Debian's `softhsm2`. The stream module's end-to-end harness is `tests/stream-e2e/` (see
the README); it isn't in CI yet.

## Builds by device

| Device | Command |
| --- | --- |
| Scanner (PROXmobil3, armv7, glibc 2.28) | `cargo zigbuild --release --target armv7-unknown-linux-gnueabihf.2.28 --features module-display,module-usb` (zig 0.14.1) |
| Debian boards (arm64) | built and published by `.github/workflows/release.yml` on a `v*` tag: `aarch64-unknown-linux-gnu.2.31 --features module-usb,module-stream,module-net`, `cargo deb --no-strip` |
| Provisioning computer (x86-64) | `cargo build --release` (used by the provisioning scripts) |

The scanner runs Helios from its USB drive (`~/workspace/helios/scanner-usb`, not in this
repository): install a new build both on the drive (`helios/bin/helios`) and, for a live test,
in `/run/helios/bin` on the scanner.

## Releases

Set `version` in `Cargo.toml` in a PR; once merged, the merge commit is tagged `v<version>` and
pushed (a ruleset allows only admins to create `v*` tags): by the owner, or by an agent the owner
has OK'd for that release, which first checks that the commit is the release PR's merge on
`origin/main`, that its version matches, that CI passed on it and that the tag doesn't exist, then
pushes only that tag and watches the workflow. The workflow
checks the tag, builds the arm64 package and publishes it to the Helios APT repository. A tag's
workflow runs as it was at the tagged commit: if a release fails, fix it and release the next
version rather than moving the tag.

## Rules

- Conventional Commits for commits and PR titles (checked in CI); squash merges.
- `unsafe_code = "deny"`. The approved exceptions: the read-only `adjtimex` call in
  `src/clock/kernel.rs`, and registering owned descriptors with tokio
  (`AsyncFd::register_with_interest`) in `src/modules/usb/uevent.rs` and `mounts.rs`, since tokio
  deprecated its safe-looking constructors as unsound, and the three read-only V4L2 enumerate
  ioctls (`VIDIOC_ENUM_FMT`, `_FRAMESIZES`, `_FRAMEINTERVALS`) in
  `src/modules/stream/v4l2.rs`, since rustix has no safe wrappers (owner, 2026-11-22). Any other
  `unsafe` needs the owner's OK.
  Prefer safe crates (`rustix`).
- `unwrap_used` is denied. Document errors and panics on public items; keep 90% line coverage.
- Never log or print PINs, and never put them in process arguments.
- Modules are Cargo features, off by default; a module's config section is ignored in builds
  without it. The scanner build needs `--features module-display,module-usb`, the boards'
  package `--features module-usb,module-stream,module-net` (`FEATURES` in `release.yml`).
- Streams run in `helios stream-daemon` (`helios-stream.service`); Helios's `stream` module is
  only its client (`src/modules/stream/client.rs`, protocol in `control.rs`). Engine changes go
  in the daemon side; anything that must survive a Helios restart belongs there.
- Stream module changes run through `tests/stream-e2e/` before their PR (`setup.sh`, then
  `external.sh` and `helios.sh`; no root needed), with the result in the PR.
- A module implements `Module` (`src/modules/mod.rs`) and runs under the supervisor, which gives
  each run a fresh `ModuleContext` and restarts it with backoff; module state is in the `helios`
  shadow's `modules`.
- Licensed fonts (Roobert TW Bold) are loaded at run time from the device and are never committed
  or compiled in. Nothing from INIT's vendor software goes into this repository.
- Don't push tags or change repository settings without the owner's OK; an OK for a release
  covers that one tag (see Releases).
