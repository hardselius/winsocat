# winsocat [![Testing][ci-badge]][ci] [![Release][release-badge]][release]

[ci]: https://github.com/hardselius/winsocat/actions/workflows/unit-test.yml
[ci-badge]: https://github.com/hardselius/winsocat/actions/workflows/unit-test.yml/badge.svg
[release]: https://github.com/hardselius/winsocat/releases
[release-badge]: https://img.shields.io/github/v/release/hardselius/winsocat?include_prereleases

> **Note:** This is an experimental, AI-assisted rewrite of [firejox/WinSocat](https://github.com/firejox/WinSocat) in Rust. The original project is a .NET/C# application. This rewrite aims for CLI compatibility with the original while targeting cross-platform support. It is not production-ready.

WinSocat is a socat-like program specific on Windows platform. It can bridge Windows named pipe and other general I/O, e.g., STDIO, TCP, the STDIO of Process.

## Installation

### From source
[Install Rust](https://rustup.rs/) and build from source:

```
cargo install --path .
```

## Quick Start

These examples work on any platform (macOS, Linux, Windows). You just need two terminal windows.

### Chat between two terminals

Start a listener in one terminal, connect from the other, and type messages back and forth:

```
# Terminal 1: listen for incoming connections
winsocat TCP-LISTEN:127.0.0.1:8000 STDIO

# Terminal 2: connect to the listener
winsocat STDIO TCP:127.0.0.1:8000
```

Anything you type in either terminal appears in the other.

### Connect to an existing server

If something is already listening (e.g. netcat), connect to it:

```
# Terminal 1: start a listener with netcat
nc -l 8000

# Terminal 2: connect with winsocat
winsocat STDIO TCP:127.0.0.1:8000
```

> **Note:** If nothing is listening, you'll get `Connection refused`. Start the listener first.

### Pipe a command's output over TCP

Use `EXEC` to run a command and relay its stdin/stdout over the network:

```
# Terminal 1: serve a directory listing to anyone who connects
winsocat TCP-LISTEN:127.0.0.1:9000 EXEC:ls

# Terminal 2: connect and see the output
winsocat STDIO TCP:127.0.0.1:9000
```

On Windows, use `EXEC:dir` instead of `EXEC:ls`.

### TCP port forwarding

Forward a local port to a remote service:

```
winsocat TCP-LISTEN:127.0.0.1:8080 TCP:example.com:80
```

Now connecting to `localhost:8080` reaches `example.com:80`.

### Unix socket to TCP relay (macOS/Linux)

Bridge a Unix domain socket and a TCP port:

```
# Terminal 1: listen on a TCP port
nc -l 8000

# Terminal 2: relay from a Unix socket to TCP
winsocat UNIX-LISTEN:/tmp/test.sock TCP:127.0.0.1:8000

# Terminal 3: connect to the Unix socket
socat - UNIX-CONNECT:/tmp/test.sock
```

Text typed in Terminal 3 appears in Terminal 1, and vice versa.

## Command Form

The WinSocat is accept two address pattern

```
winsocat.exe [address1] [address2]
```

The `address1` can accept `STDIO`, `TCP-LISTEN`, `TCP`, `NPIPE`, `NPIPE-LISTEN`, `EXEC`, `WSL`, `UNIX`, `UNIX-LISTEN`, `HVSOCK`, `HVSOCK-LISTEN`, `SP`, `SMB-PIPE` socket types.

The `address2` can accept `STDIO`, `TCP`, `NPIPE`, `EXEC`, `WSL`, `UNIX`, `HVSOCK`, `SP`, `SMB-PIPE` socket types.

## Examples

* It can bridge standard input/output and tcp connection to address **127.0.0.1** on port **80**.
```
winsocat STDIO TCP:127.0.0.1:80
```

* It can forward from Windows named pipe to remote tcp socket.
```
winsocat NPIPE-LISTEN:myPipe TCP:127.0.0.1:80
```

* It can use Windows named pipe for network connection
```
winsocat NPIPE:RemoteServer:RemotePipe STDIO
```

* It can create reverse shell.
```
winsocat EXEC:C:\Windows\system32\cmd.exe TCP:127.0.0.1:8000
```

* It can bridge Windows named pipe and [unix socket on Windows](https://devblogs.microsoft.com/commandline/af_unix-comes-to-windows/)
```
winsocat NPIPE-LISTEN:fooPipe UNIX:foo.sock
```

### Interact with WSL(Windows Subsystem for Linux)

WinSocat provide the syntax sugar for WSL program. Hence, this example
```
winsocat STDIO WSL:cat,distribution=Ubuntu,user=root
```
would be equivalent to
```
winsocat STDIO EXEC:"C:\Windows\System32\wsl.exe -d Ubuntu -u root cat"
```
if `wsl.exe` is located on `C:\Windows\System32`.

The `distribution` and `user` are optional parameters. If these parameters are not specified, it will run with the default options.
You can combine the `socat` of WSL distribution for the communication between WSL and Windows Host.

* Windows named pipe forwarding to WSL Unix Socket
```
winsocat NPIPE-LISTEN:fooPipe WSL:"socat STDIO unix-connect:foo.sock"
```

* WSL Unix Socket forwarding to Windows named pipe
```
socat unix-listen:foo.sock,fork EXEC:"/path/to/winsocat.exe STDIO NPIPE:fooPipe"
```

### HyperV Socket Support

WinSocat is also allow to interact with hyper-v socket. It requires the vmId and serviceId to connect. For example, you can use this

```
winsocat stdio hvsock:0cb41c0b-fd26-4a41-8370-dccb048e216e:00000ac9-facb-11e6-bd58-64006a7986d3
```

to connect the VSOCK socket opened by WSL2 program. This program is running under the HyperV-VM with vmId `0cb41c0b-fd26-4a41-8370-dccb048e216e`. 
And it opens the VSOCK port 2761(the hex format is 0x00000ac9). According to [hyper-v on windows](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/make-integration-service),
the VSOCK port on Linux will be equivalent to the serviceId `[port in hex]-facb-11e6-bd58-64006a7986d3` on windows. Hence, WinSocat provide the short representation for VSOCK.

```
winsocat stdio hvsock:0cb41c0b-fd26-4a41-8370-dccb048e216e:vsock-2761
```

This `vsock-2761` will be viewed as the serviceId `00000ac9-facb-11e6-bd58-64006a7986d3`.

### SMB-PIPE Support

WinSocat can connect to remote Windows named pipes via SMB2, without needing a Windows client. This works on all platforms.

```
winsocat TCP-LISTEN:8080 SMB-PIPE:fileserver:mypipe,user=admin,password=secret,domain=CORP
```

This forwards TCP connections on port 8080 to the named pipe `mypipe` on `fileserver` using NTLM authentication.

Options:
- `user` — NTLM username (omit for anonymous access)
- `password` — password (supports `$ENV_VAR` references for security)
- `domain` — NTLM domain (default: `.`)
- `port` — TCP port for SMB2 (default: 445)

Example with environment variable for the password:
```
winsocat STDIO SMB-PIPE:server:pipe,user=admin,password=$SMB_PASSWORD
```

### Serial Port Support

WinSocat can relay the data of serial port. For example,

```
winsocat sp:COM1,baudrate=12500,parity=1,databits=16,stopbits=0 stdio
```

The `baudrate`, `parity`, `databits` and `stopbits` is optional parameter. Another example is to integrate
with [com0com](https://sourceforge.net/projects/com0com/).

1. Assume you have already created paired com port `COM5 <=> COM6` via [com0com](https://sourceforge.net/projects/com0com/).
2. Execute the command at terminal
```
winsocat sp:COM5 stdio
```
3. Execute the command at another terminal
```
winsocat sp:COM6 stdio
```

Now these two terminals can interact with each other.
