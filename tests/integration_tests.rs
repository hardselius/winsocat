use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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

#[tokio::test]
async fn tcp_echo_relay() {
    let echo_addr = spawn_echo_server();

    // Bind our relay listener with tokio directly
    let relay_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap();
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

    let relay_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap();
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
