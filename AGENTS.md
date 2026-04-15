# AGENTS.md

## Build & Test

This is a Cargo workspace. Build and test the entire workspace:

```bash
cargo build --workspace
cargo test --workspace
```

Build or test a single crate:
```bash
cargo build -p winsocat
cargo test -p smb2-pipe
```

Run a single test:
```bash
cargo test test_name
```

Any stable Rust toolchain works. CI runs on `windows-latest`, `ubuntu-latest`, and `macos-latest`. The app targets Windows for named pipes, Hyper-V sockets, and WSL endpoints; STDIO, TCP, UNIX, EXEC, and serial port endpoints work on all platforms.

## Formatting & Linting

Both are enforced by CI and must pass before tests run.

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings -W clippy::all -W clippy::correctness -W clippy::complexity -W clippy::style -W clippy::suspicious -W clippy::perf
```

Run `cargo fmt` before committing. Run clippy frequently during development to catch issues early.

## Project Layout

```
Cargo.toml                   # workspace root
crates/
  winsocat/                  # CLI binary + library crate
    Cargo.toml
    src/
      main.rs                # CLI entry point (clap), parse → strategy + factory → relay
      lib.rs                 # public library root
      address.rs             # AddressElement parser (TAG:addr,opt=val)
      relay.rs               # bidirectional copy via tokio::io::copy_bidirectional
      endpoint/
        mod.rs               # Connector/Listener traits, Strategy enum, parse dispatch
        stdio.rs             # STDIO
        tcp.rs               # TCP, TCP-LISTEN
        exec.rs              # EXEC (child process stdin/stdout)
        unix.rs              # UNIX, UNIX-LISTEN
        serial.rs            # SP (serial port, via tokio-serial)
        npipe.rs             # NPIPE, NPIPE-LISTEN  [cfg(windows)]
        hvsock.rs            # HVSOCK, HVSOCK-LISTEN [cfg(windows)]
        wsl.rs               # WSL (sugar over EXEC) [cfg(windows)]
        smb_pipe.rs          # SMB-PIPE (remote pipe via smb2-pipe crate)
    tests/
      integration_tests.rs   # TCP, EXEC, UNIX, STDIO, multi-conn integration tests
    helpers/
      echo_helper.rs         # Minimal stdin→stdout copier for EXEC tests
  smb2-pipe/                 # Minimal SMB2 client for remote named pipe access
    Cargo.toml
    src/
      lib.rs                 # library root
      auth.rs                # Auth enum (Ntlm, Anonymous)
      ntlm.rs                # NTLM token generation via ntlmclient
      transport.rs           # async send/recv with NetBIOS framing
      session.rs             # connection orchestration (negotiate → create)
      client.rs              # SmbPipeClient (AsyncRead+AsyncWrite via DuplexStream)
      protocol/
        mod.rs               # framing, status codes, encode/decode helpers
        header.rs            # 64-byte SMB2 header
        negotiate.rs         # Negotiate request/response
        session_setup.rs     # Session Setup request/response
        tree_connect.rs      # Tree Connect request/response
        create.rs            # Create request/response, FileId
        read.rs              # Read request/response
        write.rs             # Write request/response
        close.rs             # Close request/response
        tree_disconnect.rs   # Tree Disconnect request/response
        logoff.rs            # Logoff request/response
    tests/
      integration_tests.rs   # Mock SMB2 server + client echo tests
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

1. Create `crates/winsocat/src/endpoint/new_type.rs` with:
   - A config struct with parsed fields
   - A `try_parse_*` function taking `&AddressElement` → `Option<ConfigStruct>`
   - A connector struct implementing `Connector` (and optionally a listener struct implementing `Listener`)
2. Add `pub mod new_type;` to `crates/winsocat/src/endpoint/mod.rs`
3. Wire `try_parse_*` calls into `parse_strategy()` and/or `parse_factory()` — first match wins
4. Gate Windows-only endpoints with `#[cfg(windows)]`

### Address string format

```
TAG:address,option1=value1,option2=value2
```

Parsed by `AddressElement::try_parse`. Supports quoted values in the address portion.

## Dependencies

### winsocat
- **clap 4** — CLI argument parsing with derive macros
- **tokio** (full features) — async runtime, TCP, Unix sockets, process, named pipes
- **tokio-serial** — serial port support (cross-platform)
- **async-trait** — async methods in traits
- **anyhow** — error handling
- **smb2-pipe** — SMB2 named pipe client (workspace crate)
- **socket2 + uuid** (Windows only) — raw Hyper-V socket support

### smb2-pipe
- **tokio** (net, io-util, sync, rt) — async TCP, I/O, channels, and runtime
- **anyhow** — error handling
- **ntlmclient** — NTLM token generation
