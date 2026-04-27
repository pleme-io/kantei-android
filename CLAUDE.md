# kantei-android

> **★★★ CSE / Knowable Construction.** This repo operates under **Constructive Substrate Engineering** — canonical specification at [`pleme-io/theory/CONSTRUCTIVE-SUBSTRATE-ENGINEERING.md`](https://github.com/pleme-io/theory/blob/main/CONSTRUCTIVE-SUBSTRATE-ENGINEERING.md). The Compounding Directive (operational rules: solve once, load-bearing fixes only, idiom-first, models stay current, direction beats velocity) is in the org-level pleme-io/CLAUDE.md ★★★ section. Read both before non-trivial changes.


ADB transport and GrapheneOS compliance profiles for kantei. Implements
`DeviceTransport` via `adb_client`. Built-in CIS/NIST/STIG profiles.

## Core Components

- **AdbTransport** -- implements `kantei::DeviceTransport` over ADB server
- **grapheneos_profile()** -- built-in GrapheneOS hardened device profile (6 checks)
- **GRAPHENEOS_HARDENED_PROFILE** -- raw YAML constant for the built-in profile

## Build & Test

```bash
cargo check     # compile check
cargo test      # run tests (no ADB connection needed)
cargo clippy    # lint
```

## Testing

12 tests using `kantei::MockTransport` -- no real ADB connection required.
Tests cover: trait bounds, profile parsing, all-pass evaluation, individual
check failures (AVB, encryption, patches), report determinism, compliance
status, and critical failure counts.

## Conventions

- Edition 2024, Rust 1.91.0+, MIT license
- clippy pedantic, release profile (codegen-units=1, lto=true)
- All pleme-io Rust library conventions apply
