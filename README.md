# winsocat [![Testing][ci-badge]][ci]

[ci]: https://github.com/hardselius/winsocat/actions/workflows/unit-test.yml
[ci-badge]: https://github.com/hardselius/winsocat/actions/workflows/unit-test.yml/badge.svg

A socat-like relay for bridging I/O streams across protocols and
platforms. Connect standard I/O, TCP sockets, Unix sockets, named
pipes, serial ports, Hyper-V sockets, and remote SMB2 pipes — in any
combination.

> Rust rewrite of [firejox/WinSocat](https://github.com/firejox/WinSocat),
> originally written in C#/.NET.

## Installation

[Install Rust](https://rustup.rs/) and build from source:

```
cargo install --path crates/winsocat
```

## Usage

```
winsocat [OPTIONS] <ADDRESS1> <ADDRESS2>
```

`ADDRESS1` drives execution — it can either connect to a remote
endpoint or listen for incoming connections. `ADDRESS2` is the other
side of the relay, created fresh for each incoming connection when
listening.

Addresses use the format `TAG:address,option=value,...`. Tags are
case-insensitive.

| Tag | Mode | Platform | Description |
|---|---|---|---|
| `STDIO` | connect | all | Standard input/output |
| `TCP` | connect | all | TCP client |
| `TCP-LISTEN` | listen | all | TCP server |
| `EXEC` | connect | all | Child process stdin/stdout |
| `UNIX` | connect | unix | Unix domain socket client |
| `UNIX-LISTEN` | listen | unix | Unix domain socket server |
| `NPIPE` | connect | windows | Windows named pipe client |
| `NPIPE-LISTEN` | listen | windows | Windows named pipe server |
| `HVSOCK` | connect | windows | Hyper-V socket client |
| `HVSOCK-LISTEN` | listen | windows | Hyper-V socket server |
| `WSL` | connect | windows | WSL process (sugar over EXEC) |
| `SP` | connect | all | Serial port |
| `SMB-PIPE` | connect | all | Remote named pipe over SMB2 |

Listen-mode tags (`TCP-LISTEN`, `UNIX-LISTEN`, `NPIPE-LISTEN`,
`HVSOCK-LISTEN`) are only valid for `ADDRESS1`.

### Options

| Flag | Description |
|---|---|
| `-v`, `--verbose` | Print SMB2 protocol diagnostics to stderr |

## Quick Start

These examples work on any platform. You need two terminal windows.

**Chat between two terminals:**

```
# Terminal 1 — listen
winsocat TCP-LISTEN:127.0.0.1:8000 STDIO

# Terminal 2 — connect
winsocat STDIO TCP:127.0.0.1:8000
```

Anything typed in either terminal appears in the other.

**Pipe a command's output over TCP:**

```
# Terminal 1 — serve a directory listing
winsocat TCP-LISTEN:127.0.0.1:9000 EXEC:ls

# Terminal 2 — connect and read
winsocat STDIO TCP:127.0.0.1:9000
```

**TCP port forwarding:**

```
winsocat TCP-LISTEN:127.0.0.1:8080 TCP:example.com:80
```

Connecting to `localhost:8080` now reaches `example.com:80`.

## Address Types

### STDIO

Reads from stdin, writes to stdout. Useful for interactive sessions
and piping data through winsocat.

```
winsocat STDIO TCP:127.0.0.1:80
```

### TCP / TCP-LISTEN

Standard TCP connections. `TCP` connects to a remote host, `TCP-LISTEN`
accepts incoming connections and spawns a relay for each one.

```
# Connect stdin/stdout to a TCP server
winsocat STDIO TCP:127.0.0.1:80

# Forward one TCP port to another
winsocat TCP-LISTEN:127.0.0.1:8080 TCP:example.com:80
```

### EXEC

Spawns a child process and relays its stdin/stdout. The command is
passed as-is to the system shell.

```
# Serve a directory listing
winsocat TCP-LISTEN:127.0.0.1:9000 EXEC:ls
```

On Windows:

```
winsocat EXEC:C:\Windows\System32\cmd.exe TCP:127.0.0.1:8000
```

### UNIX / UNIX-LISTEN

Unix domain sockets. Available on macOS and Linux.

```
# Bridge a Unix socket and a TCP port
winsocat UNIX-LISTEN:/tmp/test.sock TCP:127.0.0.1:8000
```

```
# Connect to an existing Unix socket
winsocat STDIO UNIX:/tmp/test.sock
```

### Named Pipes — NPIPE / NPIPE-LISTEN (Windows)

Windows named pipes, both local and remote.

```
# Listen on a local named pipe
winsocat NPIPE-LISTEN:myPipe TCP:127.0.0.1:80

# Connect to a remote named pipe
winsocat NPIPE:RemoteServer:RemotePipe STDIO

# Bridge a named pipe and a Unix socket
winsocat NPIPE-LISTEN:fooPipe UNIX:foo.sock
```

### Hyper-V Sockets — HVSOCK / HVSOCK-LISTEN (Windows)

Communicate with Hyper-V virtual machines using VM ID and service ID.
Useful for bridging between a Windows host and WSL2 or other Hyper-V
guests.

```
winsocat STDIO HVSOCK:0cb41c0b-fd26-4a41-8370-dccb048e216e:00000ac9-facb-11e6-bd58-64006a7986d3
```

VSOCK ports on Linux map to service IDs on Windows following the
pattern `[port in hex]-facb-11e6-bd58-64006a7986d3`. Winsocat
provides a shorthand for this:

```
winsocat STDIO HVSOCK:0cb41c0b-fd26-4a41-8370-dccb048e216e:vsock-2761
```

Here `vsock-2761` expands to `00000ac9-facb-11e6-bd58-64006a7986d3`
(2761 = 0xAC9). See [Hyper-V integration services][hyperv-docs] for
details.

[hyperv-docs]: https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/make-integration-service

### WSL (Windows)

Syntax sugar for running a command inside a WSL distribution. This:

```
winsocat STDIO WSL:cat,distribution=Ubuntu,user=root
```

is equivalent to:

```
winsocat STDIO EXEC:"C:\Windows\System32\wsl.exe -d Ubuntu -u root cat"
```

Both `distribution` and `user` are optional — omit them to use the
default WSL distribution and user.

**Bridging WSL and Windows named pipes:**

```
# Windows side: named pipe → WSL Unix socket
winsocat NPIPE-LISTEN:fooPipe WSL:"socat STDIO unix-connect:foo.sock"

# WSL side: Unix socket → Windows named pipe
socat unix-listen:foo.sock,fork EXEC:"/path/to/winsocat STDIO NPIPE:fooPipe"
```

### Serial Port — SP

Relay data to and from a serial port. The `baudrate`, `parity`,
`databits`, and `stopbits` options are all optional.

```
winsocat SP:COM1,baudrate=115200 STDIO
```

**Paired virtual ports with [com0com](https://sourceforge.net/projects/com0com/):**

Create a virtual pair `COM5 <=> COM6`, then connect each end:

```
# Terminal 1
winsocat SP:COM5 STDIO

# Terminal 2
winsocat SP:COM6 STDIO
```

The two terminals can now communicate through the virtual serial link.

### SMB-PIPE

Connect to a remote Windows named pipe over SMB2. This works from any
platform — no Windows client required. Authentication uses NTLM.

```
winsocat TCP-LISTEN:8080 SMB-PIPE:fileserver:mypipe,user=admin,password=secret,domain=CORP
```

This forwards TCP connections on port 8080 to the named pipe `mypipe`
on `fileserver`.

| Option | Default | Description |
|---|---|---|
| `user` | *(anonymous)* | NTLM username |
| `password` | *(empty)* | Password (supports `$ENV_VAR` references) |
| `domain` | `.` | NTLM domain |
| `port` | `445` | SMB2 TCP port |

**Using an environment variable for the password:**

```
export SMB_PASSWORD=secret
winsocat STDIO SMB-PIPE:server:pipe,user=admin,password=$SMB_PASSWORD
```

**Troubleshooting:** Pass `-v` to see the full SMB2 handshake and
per-message diagnostics on stderr.

**Limitations:** SMB2 message signing is not implemented. Connections
to servers that require signing (`RequireSecuritySignature = True`)
will be rejected during session setup.

## License

[MIT](LICENSE)
