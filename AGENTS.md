# AGENTS.md

## Build & Test

```bash
cargo build
cargo test
```

Any stable Rust toolchain works. CI runs on `windows-latest`, `ubuntu-latest`, and `macos-latest`. The app targets Windows for named pipes, Hyper-V sockets, and WSL endpoints; STDIO, TCP, UNIX, EXEC, and serial port endpoints work on all platforms.

Run a single test:
```bash
cargo test test_name
```

No linter or formatter config is enforced. `rustfmt` and `clippy` are available via the Nix dev shell but not mandated by CI.

## Project Layout

```
src/
  main.rs              # CLI entry point (clap), parse → strategy + factory → relay
  lib.rs               # public library root
  address.rs           # AddressElement parser (TAG:addr,opt=val)
  relay.rs             # bidirectional copy via tokio::io::copy_bidirectional
  endpoint/
    mod.rs             # Connector/Listener traits, Strategy enum, parse dispatch
    stdio.rs           # STDIO
    tcp.rs             # TCP, TCP-LISTEN
    exec.rs            # EXEC (child process stdin/stdout)
    unix.rs            # UNIX, UNIX-LISTEN
    serial.rs          # SP (serial port, via tokio-serial)
    npipe.rs           # NPIPE, NPIPE-LISTEN  [cfg(windows)]
    hvsock.rs          # HVSOCK, HVSOCK-LISTEN [cfg(windows)]
    wsl.rs             # WSL (sugar over EXEC) [cfg(windows)]
tests/
  integration_tests.rs # TCP relay integration tests
```

The `flake.nix` / `rust-toolchain.toml` / `.envrc` provide a Nix dev shell.

## Architecture

The app takes two positional arguments: `address1` (strategy — drives execution, supports listen and connect) and `address2` (factory — always connect-only, instantiated per incoming connection). This asymmetry matters when adding endpoint types.

### Core traits

- **`Connector`** — `async fn connect(&self) -> Result<BoxedStream>` — used for both strategy connect-mode and factory
- **`Listener`** — `async fn accept(&mut self) -> Result<BoxedStream>` — used for strategy listen-mode
- **`AsyncReadWrite`** — combines `AsyncRead + AsyncWrite + Unpin + Send` into a single trait object

`Strategy` is an enum: `Connect(Box<dyn Connector>)` or `Listen(Box<dyn Listener>)`.

### Adding a new endpoint

1. Create `src/endpoint/new_type.rs` with:
   - A config struct with parsed fields
   - A `try_parse_*` function taking `&AddressElement` → `Option<ConfigStruct>`
   - A connector struct implementing `Connector` (and optionally a listener struct implementing `Listener`)
2. Add `pub mod new_type;` to `src/endpoint/mod.rs`
3. Wire `try_parse_*` calls into `parse_strategy()` and/or `parse_factory()` — first match wins
4. Gate Windows-only endpoints with `#[cfg(windows)]`

### Address string format

```
TAG:address,option1=value1,option2=value2
```

Parsed by `AddressElement::try_parse`. Supports quoted values in the address portion.

## Dependencies

- **clap 4** — CLI argument parsing with derive macros
- **tokio** (full features) — async runtime, TCP, Unix sockets, process, named pipes
- **tokio-serial** — serial port support (cross-platform)
- **async-trait** — async methods in traits
- **anyhow** — error handling
- **socket2 + uuid** (Windows only) — raw Hyper-V socket support
