# helios

Helios on-device agent (Rust): AWS IoT MQTT, device shadows and the bootstrap client.

Design docs (Notion): *Helios - High-Level Design* and the Helios LLDs. Coding standards,
commit message rules and the coverage target are in HLD section 12.

## Development

The stable toolchain is pinned in `rust-toolchain.toml`. Nightly is used only for rustfmt,
because `rustfmt.toml` uses unstable options.

```sh
rustup toolchain install nightly --profile minimal --component rustfmt
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov --locked --version 0.9.1

cargo +nightly fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo llvm-cov --locked --workspace --all-features --fail-under-lines 90
```

## CI

`.github/workflows/ci.yml` runs on pull requests and pushes to `main`:

- **Conventional Commits** (pull requests only): the PR title and every non-merge commit
  subject must follow `<type>(<scope>)!: <summary>`. The check is
  `.github/scripts/check-conventional-commit.sh`.
- **Format:** `cargo +nightly fmt --check`.
- **Clippy:** `-D warnings`, with the lints from `Cargo.toml`.
- **Test and coverage:** `cargo test`, then `cargo llvm-cov` with at least 90% line coverage.
  The lcov and HTML reports are uploaded as the `coverage` artifact. Any file excluded from
  coverage must be listed in the workflow with `--ignore-filename-regex`.
