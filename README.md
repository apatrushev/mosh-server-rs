# mosh-rs

Minimal compatible [mosh](https://mosh.org/) server implementation in Rust.

Written entirely by Claude (Anthropic) — no manual coding involved. The original C++ mosh codebase (14k+ LoC) was reimplemented as a ~1500 line Rust server, fully compatible with the standard mosh client.

## Features

- Full wire compatibility with the original mosh client
- AES-128-OCB3 encryption
- SSP (State Synchronization Protocol) transport
- PTY management with MOTD support
- Single static binary with minimal runtime dependencies (libpthread, libutil)

## Building

```bash
cargo build --release
```

### Cross-compilation for Linux (from macOS)

```bash
cargo install cargo-zigbuild
rustup target add x86_64-unknown-linux-gnu
cargo zigbuild --release --target x86_64-unknown-linux-gnu
```

## Usage

Copy the binary to a remote server and connect using the standard mosh client:

```bash
mosh --server=/path/to/mosh-rs your-server.example.com
```

## Metrics

| | Original (C++) | mosh-rs |
|---|---|---|
| Code | 14k+ LoC | ~1500 LoC |
| Binary size | ~370 KB (+ many shared libs) | ~1.2 MB (static) |
| Dependencies | libprotobuf, libncurses, libssl, zlib, ... | libpthread, libutil |

## Disclaimer

This server was written by an AI without manual code review or security audit. Use at your own risk.

## License

GPL-3.0-or-later — same as the original [mosh](https://github.com/mobile-shell/mosh).
