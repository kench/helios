# AGENTS.md

Helios is the on-device agent (Rust). [`README.md`](README.md) covers building, running and
releases, and [`docs/modules.md`](docs/modules.md) covers the modules.

The design is in Notion, under "Embedded Hardware Development Notes". Start with "Helios -
Project Status and Handoff", then read the High-Level Design and the LLD for your area:
- LLD 1: identity;
- LLD 2: messaging;
- LLD 3: net;
- LLD 4: stream;
- LLD 5: usb;
- LLD 9: display;
- LLD 10: gps.

## Layout

```
src/identity/     PKCS#11 token, rustls signer, PINs, bootstrap client, identity manager
src/credentials/  AWS credentials (AWS IoT credentials provider)
src/mqtt/         connection manager, envelopes, shadows
src/router/       commands; CommandTransport (custom topics, AWS IoT commands)
src/clock/        clock checks
src/modules/      display, usb, stream, net, gps; the Module trait and the supervisor
src/provision/    `helios provision`
src/service.rs    wires it all together
contract/         submodule: helios-contract (API model, test vectors)
dist/             example config, systemd units, Debian scripts, nginx/nftables/iproute2 files
tests/            integration tests; stream-e2e/ is the stream harness
```

## Before you push

Run the checks in the README's "Build and test" section locally, and get them passing first.
Keep PRs few, and batch related changes into one. Avoid fix-up pushes, since every push reruns
CI.

Stream module changes also need `tests/stream-e2e/` (`setup.sh`, then `external.sh` and
`helios.sh`; no root needed), with the result in the PR.

## Rules

- **Commits:** Conventional Commits for commits and PR titles, and squash merges.
- **`unsafe`:** denied. The approved exceptions are:
  - `adjtimex` (read-only) in `src/clock/kernel.rs`;
  - `AsyncFd::register_with_interest` in `src/modules/usb/uevent.rs` and `mounts.rs`;
  - the V4L2 enumerate ioctls in `src/modules/stream/v4l2.rs`.

  Anything else needs the owner's OK. Prefer safe crates such as `rustix`.
- **Code:** `unwrap_used` is denied. Document errors and panics on public items, and keep line
  coverage at 90% or more.
- **Secrets:** never log or print PINs or passphrases, and never pass them as process arguments.
- **Modules:** each is a Cargo feature, off by default. The release package's `FEATURES` are in
  `release.yml`. A module implements `Module` (`src/modules/mod.rs`).
- **Streams:** they run in the stream daemon. Helios's `stream` module is only a client
  (`client.rs`, protocol in `control.rs`), so anything that must survive a Helios restart goes
  in the daemon.
- **Never commit:** licensed fonts (Roobert TW Bold, loaded from the device at run time) or
  anything from INIT's vendor software.
- **Ask the owner first:** before pushing tags or changing repository settings. An OK for a
  release covers that one tag. Tag the release PR's merge commit on `origin/main` only after
  checking:
  - its version matches the tag;
  - CI passed on it;
  - the tag doesn't exist yet.

  Then push only that tag and watch the workflow. Never move a tag.
- **Scanner builds:** they go on its USB drive (`helios/bin/helios`). For a live test, also copy
  them to `/run/helios/bin` on the scanner.
