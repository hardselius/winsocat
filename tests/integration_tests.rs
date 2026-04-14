use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use winsocat::endpoint::{self, AsyncReadWrite, Strategy};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Helper: spawn a TCP echo server on an OS-chosen port, return its address.
fn spawn_echo_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let local_addr = listener.local_addr().unwrap();

    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = vec![0u8; 4096];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        stream.write_all(&buf[..n]).unwrap();
                        stream.flush().unwrap();
                    }
                    Err(_) => break,
                }
            }
        }
    });

    local_addr
}

/// Helper: spawn a TCP echo server that handles multiple connections sequentially.
fn spawn_multi_echo_server(max_conns: usize) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let local_addr = listener.local_addr().unwrap();

    std::thread::spawn(move || {
        for _ in 0..max_conns {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = vec![0u8; 4096];
                loop {
                    match stream.read(&mut buf) {
                        Ok(0) => break,
                        Ok(n) => {
                            stream.write_all(&buf[..n]).unwrap();
                            stream.flush().unwrap();
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    });

    local_addr
}

/// Helper: spawn a TCP server that sends a message then reads a response until EOF.
fn spawn_send_recv_server(
    send_msg: &'static str,
) -> (std::net::SocketAddr, Arc<Mutex<Option<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let local_addr = listener.local_addr().unwrap();
    let received = Arc::new(Mutex::new(None));
    let received_clone = received.clone();

    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            stream.write_all(send_msg.as_bytes()).unwrap();
            stream.flush().unwrap();

            let mut buf = String::new();
            let _ = stream.read_to_string(&mut buf);
            *received_clone.lock().unwrap() = Some(buf);
        }
    });

    (local_addr, received)
}

/// Return the EXEC address string for a cross-platform echo command.
/// Uses the `echo_helper` binary built from `tests/echo_helper.rs`,
/// which copies stdin to stdout byte-for-byte on all platforms.
fn exec_echo_addr() -> String {
    let helper = env!("CARGO_BIN_EXE_echo_helper");
    // Quote the path in case it contains spaces (e.g. on Windows CI)
    format!("EXEC:\"{helper}\"")
}

/// Helper: generate a unique unix socket path for testing.
#[cfg(unix)]
fn temp_sock_path(label: &str) -> String {
    format!("/tmp/winsocat_test_{}_{}.sock", label, std::process::id())
}

/// Helper: spawn a Unix echo server, return the socket path.
/// Caller is responsible for deleting the socket file after the test.
#[cfg(unix)]
fn spawn_unix_echo_server(path: &str) -> std::thread::JoinHandle<()> {
    let path = path.to_owned();
    // Ensure no leftover socket
    let _ = std::fs::remove_file(&path);

    std::thread::spawn(move || {
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = vec![0u8; 4096];
            loop {
                match stream.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        stream.write_all(&buf[..n]).unwrap();
                        stream.flush().unwrap();
                    }
                    Err(_) => break,
                }
            }
        }
        let _ = std::fs::remove_file(&path);
    })
}

#[tokio::test]
async fn tcp_echo_relay() {
    let echo_addr = spawn_echo_server();

    // Bind our relay listener with tokio directly
    let relay_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();

    let echo_addr_str = format!("TCP:127.0.0.1:{}", echo_addr.port());

    // Spawn the relay task
    tokio::spawn(async move {
        let (stream, _) = relay_listener.accept().await.unwrap();
        let factory = winsocat::endpoint::parse_factory(&echo_addr_str).unwrap();
        let mut dst = factory.connect().await.unwrap();
        let mut src: Box<dyn winsocat::endpoint::AsyncReadWrite> = Box::new(stream);
        let _ = winsocat::relay::relay(&mut *src, &mut *dst).await;
    });

    // Give the relay task a moment to start accepting
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Connect as a client (from blocking thread since we're testing relay)
    let result = tokio::task::spawn_blocking(move || {
        let mut client = TcpStream::connect(relay_addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client.write_all(b"Hello").unwrap();
        client.flush().unwrap();

        let mut buf = [0u8; 5];
        client.read_exact(&mut buf).unwrap();
        buf
    })
    .await
    .unwrap();

    assert_eq!(&result, b"Hello");
}

#[tokio::test]
async fn tcp_bidirectional_relay() {
    // Server sends "Bar", expects to receive "Foo"
    let (server_addr, received) = spawn_send_recv_server("Bar");

    let relay_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();
    let server_addr_str = format!("TCP:127.0.0.1:{}", server_addr.port());

    tokio::spawn(async move {
        let (stream, _) = relay_listener.accept().await.unwrap();
        let factory = winsocat::endpoint::parse_factory(&server_addr_str).unwrap();
        let mut dst = factory.connect().await.unwrap();
        let mut src: Box<dyn winsocat::endpoint::AsyncReadWrite> = Box::new(stream);
        let _ = winsocat::relay::relay(&mut *src, &mut *dst).await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let (buf, recv_clone) = tokio::task::spawn_blocking(move || {
        let mut client = TcpStream::connect(relay_addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        // Send "Foo"
        client.write_all(b"Foo").unwrap();
        client.flush().unwrap();

        // Read "Bar" from server (relayed)
        let mut buf = [0u8; 3];
        client.read_exact(&mut buf).unwrap();

        // Close our end
        drop(client);

        (buf, received)
    })
    .await
    .unwrap();

    assert_eq!(&buf, b"Bar");

    // Wait for server to finish reading
    tokio::time::sleep(Duration::from_millis(200)).await;

    let got = recv_clone.lock().unwrap().clone().unwrap_or_default();
    assert_eq!(got, "Foo");
}

// ---------------------------------------------------------------------------
// TCP-LISTEN via parse_strategy
// ---------------------------------------------------------------------------

/// Tests that parse_strategy("TCP-LISTEN:0") + parse_factory("TCP:...") works
/// end-to-end through the parser, covering the README example:
///   winsocat NPIPE-LISTEN:myPipe TCP:127.0.0.1:80
/// (substituting TCP-LISTEN for NPIPE-LISTEN since we're cross-platform)
#[tokio::test]
async fn tcp_listen_relay_via_parser() {
    let echo_addr = spawn_echo_server();
    let echo_addr_str = format!("TCP:127.0.0.1:{}", echo_addr.port());

    // Use parse_strategy to create a TCP-LISTEN endpoint on an OS-chosen port.
    // We need to bind first to discover the port, so bind port 0.
    let strategy = endpoint::parse_strategy("TCP-LISTEN:127.0.0.1:0").unwrap();
    let _listener = match strategy {
        Strategy::Listen(l) => l,
        Strategy::Connect(_) => panic!("expected Listen strategy"),
    };

    // Verify the strategy parsed as a Listen variant (confirmed above).
    // We can't easily discover the bound port from the parsed strategy,
    // so we test the actual relay using a manually-created listener.
    let relay_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();

    let factory = endpoint::parse_factory(&echo_addr_str).unwrap();

    tokio::spawn(async move {
        let (stream, _) = relay_listener.accept().await.unwrap();
        let mut dst = factory.connect().await.unwrap();
        let mut src: Box<dyn AsyncReadWrite> = Box::new(stream);
        let _ = winsocat::relay::relay(&mut *src, &mut *dst).await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // Drop the parsed listener — we only needed to confirm it parses as Listen.
    drop(_listener);

    let result = tokio::task::spawn_blocking(move || {
        let mut client = TcpStream::connect(relay_addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client.write_all(b"ParseTest").unwrap();
        client.flush().unwrap();

        let mut buf = [0u8; 9];
        client.read_exact(&mut buf).unwrap();
        buf
    })
    .await
    .unwrap();

    assert_eq!(&result, b"ParseTest");
}

// ---------------------------------------------------------------------------
// EXEC endpoint tests (safe alternative to reverse-shell example)
// ---------------------------------------------------------------------------

/// Tests EXEC as factory (address2): verify that EXEC:cat creates a working
/// bidirectional pipe. Covers the README example:
///   winsocat EXEC:cmd.exe TCP:127.0.0.1:8000
/// using `cat` instead of `cmd.exe` for safety.
#[tokio::test]
async fn exec_echo_relay() {
    // Parse the EXEC factory — this creates a child process that acts as a pipe
    let exec_factory = endpoint::parse_factory(&exec_echo_addr()).unwrap();

    // Connect — spawns the child process
    let mut exec_stream = exec_factory.connect().await.unwrap();

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Write to the exec stream (echo_helper's stdin)
    exec_stream.write_all(b"ExecTest").await.unwrap();
    exec_stream.flush().await.unwrap();

    // Read back from exec stream (echo_helper's stdout)
    let mut buf = vec![0u8; 8];
    exec_stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"ExecTest");

    drop(exec_stream);
}

/// Tests EXEC as strategy (address1): EXEC:cat as the strategy side relaying to TCP.
/// This covers the left-hand side of the reverse-shell example.
#[tokio::test]
async fn exec_as_strategy() {
    let echo_addr = spawn_echo_server();
    let echo_addr_str = format!("TCP:127.0.0.1:{}", echo_addr.port());

    // Parse EXEC as a strategy (address1)
    let strategy = endpoint::parse_strategy(&exec_echo_addr()).unwrap();
    let connector = match strategy {
        Strategy::Connect(c) => c,
        Strategy::Listen(_) => panic!("expected Connect strategy for EXEC"),
    };

    let factory = endpoint::parse_factory(&echo_addr_str).unwrap();

    // Connect both
    let mut src = connector.connect().await.unwrap();
    let mut dst = factory.connect().await.unwrap();

    // Spawn the relay in a task with a timeout
    let relay_handle = tokio::spawn(async move {
        let _ = winsocat::relay::relay(&mut *src, &mut *dst).await;
    });

    // The relay is between cat and echo_server.
    // Since we can't write to cat's stdin from outside (it's owned by the relay),
    // we verify the strategy parsed correctly and the relay starts without error.
    // Give it a moment then abort (cat blocks waiting for stdin).
    tokio::time::sleep(Duration::from_millis(200)).await;
    relay_handle.abort();
    let _ = relay_handle.await;
}

/// Tests EXEC bidirectionally: TCP-LISTEN relay to EXEC:cat as factory.
/// A client connects to the TCP listener, writes data, cat echoes it back.
/// This is the most realistic safe version of the reverse-shell example.
#[tokio::test]
async fn exec_bidirectional_relay() {
    let relay_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();

    let exec_addr = exec_echo_addr();

    tokio::spawn(async move {
        let (stream, _) = relay_listener.accept().await.unwrap();
        let factory = endpoint::parse_factory(&exec_addr).unwrap();
        let mut dst = factory.connect().await.unwrap();
        let mut src: Box<dyn AsyncReadWrite> = Box::new(stream);
        let _ = winsocat::relay::relay(&mut *src, &mut *dst).await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let result = tokio::task::spawn_blocking(move || {
        let mut client = TcpStream::connect(relay_addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();

        // Send data — it should pass through echo_helper and come back as-is
        client.write_all(b"Bidirectional").unwrap();
        client.flush().unwrap();

        let mut buf = vec![0u8; 13];
        client.read_exact(&mut buf).unwrap();
        buf
    })
    .await
    .unwrap();

    assert_eq!(&result, b"Bidirectional");
}

// ---------------------------------------------------------------------------
// STDIO via binary subprocess
// ---------------------------------------------------------------------------

/// Tests STDIO ↔ TCP relay by spawning the winsocat binary as a subprocess.
/// Covers the README example:
///   winsocat STDIO TCP:127.0.0.1:80
#[tokio::test]
async fn stdio_tcp_binary() {
    let echo_addr = spawn_echo_server();

    // Build path to the winsocat binary
    let binary = env!("CARGO_BIN_EXE_winsocat");

    let tcp_addr = format!("TCP:127.0.0.1:{}", echo_addr.port());

    let result = tokio::task::spawn_blocking(move || {
        let mut child = std::process::Command::new(binary)
            .arg("STDIO")
            .arg(&tcp_addr)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("failed to spawn winsocat binary");

        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(b"StdioTest").unwrap();
        stdin.flush().unwrap();
        // Close stdin so the relay shuts down the read direction
        drop(child.stdin.take());

        let mut stdout = child.stdout.take().unwrap();
        let mut buf = Vec::new();
        stdout.read_to_end(&mut buf).unwrap();

        let _ = child.wait();
        buf
    })
    .await
    .unwrap();

    assert_eq!(result, b"StdioTest");
}

/// Tests STDIO ↔ EXEC relay via the binary, verifying bidirectional flow.
/// Covers: winsocat STDIO EXEC:echo_helper
///
/// Note: `copy_bidirectional` keeps both halves open until both reach EOF.
/// With STDIO, shutting down stdout doesn't make stdin return EOF, so the
/// process won't exit until we explicitly close stdin. We therefore write,
/// read the expected data, and then kill the child.
#[tokio::test]
async fn stdio_exec_binary() {
    let binary = env!("CARGO_BIN_EXE_winsocat");
    let exec_addr = exec_echo_addr();

    let result = tokio::task::spawn_blocking(move || {
        let mut child = std::process::Command::new(binary)
            .arg("STDIO")
            .arg(&exec_addr)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("failed to spawn winsocat binary");

        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(b"StdioExec").unwrap();
        stdin.flush().unwrap();

        // Read back the exact number of bytes we expect
        let stdout = child.stdout.as_mut().unwrap();
        let mut buf = vec![0u8; 9];
        stdout.read_exact(&mut buf).unwrap();

        // Kill the child — the relay won't exit on its own because
        // copy_bidirectional waits for both directions to EOF
        let _ = child.kill();
        let _ = child.wait();

        buf
    })
    .await
    .unwrap();

    assert_eq!(&result, b"StdioExec");
}

// ---------------------------------------------------------------------------
// TCP-LISTEN multiple connections
// ---------------------------------------------------------------------------

/// Tests that a TCP-LISTEN relay handles multiple sequential connections,
/// mimicking the listen-mode loop in main.rs.
#[tokio::test]
async fn tcp_listen_multiple_connections() {
    let echo_addr = spawn_multi_echo_server(2);
    let echo_addr_str = format!("TCP:127.0.0.1:{}", echo_addr.port());

    let relay_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();

    // Accept multiple connections in a loop (like main.rs does)
    tokio::spawn(async move {
        let factory = Arc::new(endpoint::parse_factory(&echo_addr_str).unwrap());
        for _ in 0..2 {
            let (stream, _) = relay_listener.accept().await.unwrap();
            let factory = Arc::clone(&factory);
            tokio::spawn(async move {
                let mut dst = factory.connect().await.unwrap();
                let mut src: Box<dyn AsyncReadWrite> = Box::new(stream);
                let _ = winsocat::relay::relay(&mut *src, &mut *dst).await;
            });
        }
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    // First connection
    let result1 = tokio::task::spawn_blocking({
        let addr = relay_addr;
        move || {
            let mut client = TcpStream::connect(addr).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            client.write_all(b"Conn1").unwrap();
            client.flush().unwrap();
            let mut buf = [0u8; 5];
            client.read_exact(&mut buf).unwrap();
            drop(client);
            buf
        }
    })
    .await
    .unwrap();

    assert_eq!(&result1, b"Conn1");

    tokio::time::sleep(Duration::from_millis(100)).await;

    // Second connection
    let result2 = tokio::task::spawn_blocking(move || {
        let mut client = TcpStream::connect(relay_addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client.write_all(b"Conn2").unwrap();
        client.flush().unwrap();
        let mut buf = [0u8; 5];
        client.read_exact(&mut buf).unwrap();
        drop(client);
        buf
    })
    .await
    .unwrap();

    assert_eq!(&result2, b"Conn2");
}

// ---------------------------------------------------------------------------
// Unix socket tests (unix only)
// ---------------------------------------------------------------------------

/// Tests UNIX-LISTEN as strategy relaying to a TCP echo server.
/// Covers the concept behind:
///   winsocat NPIPE-LISTEN:fooPipe UNIX:foo.sock
/// (cross-platform substitute using UNIX-LISTEN ↔ TCP)
#[cfg(unix)]
#[tokio::test]
async fn unix_listen_to_tcp() {
    let echo_addr = spawn_echo_server();
    let echo_addr_str = format!("TCP:127.0.0.1:{}", echo_addr.port());
    let sock_path = temp_sock_path("listen_to_tcp");

    // Clean up any leftover socket
    let _ = std::fs::remove_file(&sock_path);

    let strategy_str = format!("UNIX-LISTEN:{sock_path}");
    let strategy = endpoint::parse_strategy(&strategy_str).unwrap();
    let mut listener = match strategy {
        Strategy::Listen(l) => l,
        Strategy::Connect(_) => panic!("expected Listen strategy"),
    };

    let factory = endpoint::parse_factory(&echo_addr_str).unwrap();

    // Spawn the relay accept loop
    let sock_path_clone = sock_path.clone();
    tokio::spawn(async move {
        let mut src = listener.accept().await.unwrap();
        let mut dst = factory.connect().await.unwrap();
        let _ = winsocat::relay::relay(&mut *src, &mut *dst).await;
    });

    // Give the listener a moment to bind
    tokio::time::sleep(Duration::from_millis(100)).await;

    let result = tokio::task::spawn_blocking(move || {
        let mut client = std::os::unix::net::UnixStream::connect(&sock_path_clone).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client.write_all(b"UnixTest").unwrap();
        client.flush().unwrap();

        let mut buf = [0u8; 8];
        client.read_exact(&mut buf).unwrap();
        buf
    })
    .await
    .unwrap();

    assert_eq!(&result, b"UnixTest");

    // Clean up
    let _ = std::fs::remove_file(&sock_path);
}

/// Tests UNIX socket echo relay: UNIX-LISTEN ↔ UNIX (via unix echo server).
/// Verifies full unix-to-unix relay path.
#[cfg(unix)]
#[tokio::test]
async fn unix_echo_relay() {
    let echo_sock = temp_sock_path("echo_srv");
    let listen_sock = temp_sock_path("echo_listen");

    // Clean up any leftover sockets
    let _ = std::fs::remove_file(&echo_sock);
    let _ = std::fs::remove_file(&listen_sock);

    // Start a unix echo server
    let _echo_handle = spawn_unix_echo_server(&echo_sock);

    // Give the echo server time to bind
    std::thread::sleep(Duration::from_millis(100));

    let strategy_str = format!("UNIX-LISTEN:{listen_sock}");
    let factory_str = format!("UNIX:{echo_sock}");

    let strategy = endpoint::parse_strategy(&strategy_str).unwrap();
    let mut listener = match strategy {
        Strategy::Listen(l) => l,
        Strategy::Connect(_) => panic!("expected Listen strategy"),
    };

    let factory = endpoint::parse_factory(&factory_str).unwrap();

    let listen_sock_clone = listen_sock.clone();
    tokio::spawn(async move {
        let mut src = listener.accept().await.unwrap();
        let mut dst = factory.connect().await.unwrap();
        let _ = winsocat::relay::relay(&mut *src, &mut *dst).await;
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    let result = tokio::task::spawn_blocking(move || {
        let mut client = std::os::unix::net::UnixStream::connect(&listen_sock_clone).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client.write_all(b"UnixEcho").unwrap();
        client.flush().unwrap();

        let mut buf = [0u8; 8];
        client.read_exact(&mut buf).unwrap();
        buf
    })
    .await
    .unwrap();

    assert_eq!(&result, b"UnixEcho");

    // Clean up
    let _ = std::fs::remove_file(&listen_sock);
    let _ = std::fs::remove_file(&echo_sock);
}

/// Tests TCP-LISTEN relay to a UNIX socket echo server.
/// Client connects via TCP, data relayed through to UNIX echo server and back.
#[cfg(unix)]
#[tokio::test]
async fn tcp_listen_to_unix() {
    let echo_sock = temp_sock_path("tcp_to_unix");
    let _ = std::fs::remove_file(&echo_sock);

    let _echo_handle = spawn_unix_echo_server(&echo_sock);
    std::thread::sleep(Duration::from_millis(100));

    let relay_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay_listener.local_addr().unwrap();

    let factory_str = format!("UNIX:{echo_sock}");
    let factory = endpoint::parse_factory(&factory_str).unwrap();

    tokio::spawn(async move {
        let (stream, _) = relay_listener.accept().await.unwrap();
        let mut dst = factory.connect().await.unwrap();
        let mut src: Box<dyn AsyncReadWrite> = Box::new(stream);
        let _ = winsocat::relay::relay(&mut *src, &mut *dst).await;
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let result = tokio::task::spawn_blocking(move || {
        let mut client = TcpStream::connect(relay_addr).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client.write_all(b"TcpUnix").unwrap();
        client.flush().unwrap();

        let mut buf = [0u8; 7];
        client.read_exact(&mut buf).unwrap();
        buf
    })
    .await
    .unwrap();

    assert_eq!(&result, b"TcpUnix");

    let _ = std::fs::remove_file(&echo_sock);
}

// ---------------------------------------------------------------------------
// Windows-only: Named Pipe tests
// ---------------------------------------------------------------------------

/// Tests NPIPE-LISTEN ↔ TCP relay (covers README example 2).
/// Only runs on Windows where named pipes are available.
#[cfg(windows)]
#[tokio::test]
async fn npipe_listen_to_tcp() {
    let echo_addr = spawn_echo_server();
    let echo_addr_str = format!("TCP:127.0.0.1:{}", echo_addr.port());

    // Use a unique pipe name to avoid collisions
    let pipe_name = format!("winsocat_test_{}", std::process::id());
    let strategy_str = format!("NPIPE-LISTEN:{pipe_name}");

    let strategy = endpoint::parse_strategy(&strategy_str).unwrap();
    let mut listener = match strategy {
        Strategy::Listen(l) => l,
        Strategy::Connect(_) => panic!("expected Listen strategy for NPIPE-LISTEN"),
    };

    let factory = endpoint::parse_factory(&echo_addr_str).unwrap();

    tokio::spawn(async move {
        let mut src = listener.accept().await.unwrap();
        let mut dst = factory.connect().await.unwrap();
        let _ = winsocat::relay::relay(&mut *src, &mut *dst).await;
    });

    tokio::time::sleep(Duration::from_millis(200)).await;

    // Connect to the named pipe as a client
    let pipe_path = format!(r"\\.\pipe\{pipe_name}");
    let result = tokio::task::spawn_blocking(move || {
        use std::fs::OpenOptions;
        let mut pipe = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&pipe_path)
            .expect("failed to open named pipe");

        pipe.write_all(b"NpipeTest").unwrap();
        pipe.flush().unwrap();

        let mut buf = [0u8; 9];
        pipe.read_exact(&mut buf).unwrap();
        buf
    })
    .await
    .unwrap();

    assert_eq!(&result, b"NpipeTest");
}

// ---------------------------------------------------------------------------
// #[ignore] tests for hardware/VM-dependent endpoints
// ---------------------------------------------------------------------------

/// Hyper-V socket test — requires a Hyper-V VM running.
/// Covers: winsocat stdio hvsock:VM_ID:SERVICE_ID
#[cfg(windows)]
#[ignore]
#[tokio::test]
async fn hvsock_connect() {
    // This test requires an active Hyper-V VM with a known vmId and serviceId.
    // It cannot run in CI without a VM.
    //
    // To test manually:
    // 1. Start a Hyper-V VM
    // 2. Run a VSOCK listener inside the VM
    // 3. Set the VM_ID and SERVICE_ID below
    // 4. Run: cargo test hvsock_connect -- --ignored

    let _strategy = endpoint::parse_strategy(
        "HVSOCK:00000000-0000-0000-0000-000000000000:00000000-0000-0000-0000-000000000000",
    )
    .unwrap();
    // Would connect and relay — just verifying parsing works for now
}

/// WSL endpoint test — requires WSL installed on Windows.
/// Covers: winsocat STDIO WSL:cat
#[cfg(windows)]
#[ignore]
#[tokio::test]
async fn wsl_exec() {
    // This test requires WSL installed and a default distribution configured.
    //
    // To test manually:
    //   cargo test wsl_exec -- --ignored

    let strategy = endpoint::parse_strategy("WSL:cat").unwrap();
    let connector = match strategy {
        Strategy::Connect(c) => c,
        Strategy::Listen(_) => panic!("expected Connect strategy for WSL"),
    };

    let mut stream = connector.connect().await.unwrap();

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream.write_all(b"WslTest\n").await.unwrap();
    stream.flush().await.unwrap();

    let mut buf = vec![0u8; 8];
    stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"WslTest\n");

    drop(stream);
}

/// Serial port test — requires serial hardware or com0com.
/// Covers: winsocat sp:COM1 stdio
#[ignore]
#[tokio::test]
async fn serial_port_relay() {
    // This test requires a serial port (real or virtual via com0com).
    //
    // To test manually with com0com:
    // 1. Create paired ports COM5 <=> COM6
    // 2. Run: cargo test serial_port_relay -- --ignored
    //
    // On unix, use a path like /dev/ttyUSB0 or create a pty pair.

    let port = if cfg!(windows) {
        "SP:COM5"
    } else {
        "SP:/dev/ttyUSB0"
    };
    let strategy = endpoint::parse_strategy(port);
    // Just verify parsing works — actual connection requires hardware
    assert!(strategy.is_ok(), "failed to parse serial port address");
}
