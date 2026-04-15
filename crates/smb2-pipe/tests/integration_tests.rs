//! Integration tests for the SMB2 pipe client using a mock SMB2 server.
//!
//! The mock server implements just enough of the SMB2 protocol to
//! exercise the full connection lifecycle: negotiate → session setup
//! (NTLM) → tree connect → create → read/write → close → logoff.
//!
//! The mock server handles concurrent READ and WRITE requests by
//! splitting the TCP connection and using a response channel. This
//! mirrors how the client sends READ and WRITE requests concurrently.

use std::collections::VecDeque;
use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Mutex;

use smb2_pipe::auth::Auth;
use smb2_pipe::client::SmbPipeClient;
use smb2_pipe::protocol::create::FileId;
use smb2_pipe::protocol::{
    self, Smb2Command, Smb2Flags, Smb2Header, STATUS_MORE_PROCESSING_REQUIRED, STATUS_SUCCESS,
};

// ── Mock SMB2 Server ────────────────────────────────────────────────────

/// A pending READ that hasn't been answered yet.
struct PendingRead {
    req_header: Smb2Header,
}

/// Shared state for the mock pipe.
struct MockPipeState {
    data: VecDeque<u8>,
    pending_read: Option<PendingRead>,
}

/// A minimal mock SMB2 server that echoes pipe writes back on reads.
///
/// Uses split TCP to handle concurrent in-flight requests from the
/// client. When a READ arrives with no data available, it's held
/// pending until a WRITE provides data.
struct MockSmb2Server {
    listener: TcpListener,
}

impl MockSmb2Server {
    async fn bind() -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        Ok(Self { listener })
    }

    fn port(&self) -> u16 {
        self.listener.local_addr().unwrap().port()
    }

    /// Accept one connection and handle SMB2 protocol messages.
    async fn serve_one(self) -> Result<()> {
        let (stream, _) = self.listener.accept().await?;

        let session_id: u64 = 0x0000_0001_0000_0041;
        let tree_id: u32 = 1;
        let file_id = FileId {
            persistent: 0xAAAA_BBBB_CCCC_DDDD,
            volatile: 0x1111_2222_3333_4444,
        };

        let pipe_state = Arc::new(Mutex::new(MockPipeState {
            data: VecDeque::new(),
            pending_read: None,
        }));

        // Split TCP for concurrent request/response handling
        let (mut tcp_read, tcp_write) = stream.into_split();
        let tcp_write = Arc::new(Mutex::new(tcp_write));

        // Channel for signaling shutdown
        let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel::<()>(1);

        // Request processing loop
        loop {
            // Read the next request
            let mut nb_hdr = [0u8; 4];
            let read_result = tokio::select! {
                r = tcp_read.read_exact(&mut nb_hdr) => r,
                _ = shutdown_rx.recv() => break,
            };
            if read_result.is_err() {
                break;
            }
            let payload_len = protocol::decode_nb_header(&nb_hdr);
            let mut payload = vec![0u8; payload_len];
            if tcp_read.read_exact(&mut payload).await.is_err() {
                break;
            }

            let msg = protocol::decode_message(&payload)?;
            let req_hdr = msg.header;

            match req_hdr.command {
                Smb2Command::Negotiate => {
                    let body = encode_negotiate_response();
                    let hdr = response_header(&req_hdr, STATUS_SUCCESS, 0, 0);
                    send_response_on(&tcp_write, &hdr, &body).await?;
                }
                Smb2Command::SessionSetup => {
                    if req_hdr.session_id == 0 {
                        let challenge = build_ntlm_challenge();
                        let body = encode_session_setup_response(&challenge);
                        let hdr = response_header(
                            &req_hdr,
                            STATUS_MORE_PROCESSING_REQUIRED,
                            session_id,
                            0,
                        );
                        send_response_on(&tcp_write, &hdr, &body).await?;
                    } else {
                        let body = encode_session_setup_response(&[]);
                        let hdr = response_header(&req_hdr, STATUS_SUCCESS, session_id, 0);
                        send_response_on(&tcp_write, &hdr, &body).await?;
                    }
                }
                Smb2Command::TreeConnect => {
                    let body = encode_tree_connect_response();
                    let hdr = response_header(&req_hdr, STATUS_SUCCESS, session_id, tree_id);
                    send_response_on(&tcp_write, &hdr, &body).await?;
                }
                Smb2Command::Create => {
                    let body = encode_create_response(&file_id);
                    let hdr = response_header(&req_hdr, STATUS_SUCCESS, session_id, tree_id);
                    send_response_on(&tcp_write, &hdr, &body).await?;
                }
                Smb2Command::Read => {
                    let mut state = pipe_state.lock().await;
                    if state.data.is_empty() {
                        // Hold this READ pending until data arrives
                        state.pending_read = Some(PendingRead {
                            req_header: req_hdr,
                        });
                    } else {
                        // Data available — respond immediately
                        let available: Vec<u8> = state.data.drain(..).collect();
                        let body = encode_read_response(&available);
                        let hdr = response_header(&req_hdr, STATUS_SUCCESS, session_id, tree_id);
                        send_response_on(&tcp_write, &hdr, &body).await?;
                    }
                }
                Smb2Command::Write => {
                    let written_data = extract_write_data(&msg.body);
                    let count = written_data.len() as u32;

                    let mut state = pipe_state.lock().await;
                    state.data.extend(&written_data);

                    // Respond to the WRITE
                    let body = encode_write_response(count);
                    let hdr = response_header(&req_hdr, STATUS_SUCCESS, session_id, tree_id);
                    send_response_on(&tcp_write, &hdr, &body).await?;

                    // If there's a pending READ, fulfill it now
                    if let Some(pending) = state.pending_read.take() {
                        let available: Vec<u8> = state.data.drain(..).collect();
                        let body = encode_read_response(&available);
                        let hdr = response_header(
                            &pending.req_header,
                            STATUS_SUCCESS,
                            session_id,
                            tree_id,
                        );
                        // Drop state lock before sending
                        drop(state);
                        send_response_on(&tcp_write, &hdr, &body).await?;
                    }
                }
                Smb2Command::Close => {
                    let body = encode_close_response();
                    let hdr = response_header(&req_hdr, STATUS_SUCCESS, session_id, tree_id);
                    send_response_on(&tcp_write, &hdr, &body).await?;
                }
                Smb2Command::TreeDisconnect => {
                    let body = encode_simple_response(4);
                    let hdr = response_header(&req_hdr, STATUS_SUCCESS, session_id, tree_id);
                    send_response_on(&tcp_write, &hdr, &body).await?;
                }
                Smb2Command::Logoff => {
                    let body = encode_simple_response(4);
                    let hdr = response_header(&req_hdr, STATUS_SUCCESS, session_id, 0);
                    send_response_on(&tcp_write, &hdr, &body).await?;
                    let _ = shutdown_tx.send(()).await;
                    break;
                }
            }
        }

        Ok(())
    }
}

// ── Response helpers ────────────────────────────────────────────────────

fn response_header(req: &Smb2Header, status: u32, session_id: u64, tree_id: u32) -> Smb2Header {
    let mut hdr = Smb2Header::new_request(req.command, req.message_id);
    hdr.flags = Smb2Flags::SERVER_TO_REDIR;
    hdr.status = status;
    hdr.session_id = session_id;
    hdr.tree_id = tree_id;
    hdr.credit_request_response = 1;
    hdr
}

async fn send_response_on(
    tcp_write: &Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    hdr: &Smb2Header,
    body: &[u8],
) -> Result<()> {
    let mut buf = Vec::with_capacity(4 + 64 + body.len());
    protocol::encode_message(hdr, body, &mut buf);
    let mut w = tcp_write.lock().await;
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

/// Build a minimal NTLM Type 2 (Challenge) message.
///
/// The `ntlmclient` crate expects at least 56 bytes for a valid
/// challenge. This produces a valid message with an empty target
/// name and a minimal target info containing just MsvAvEOL.
fn build_ntlm_challenge() -> Vec<u8> {
    let mut msg = Vec::new();

    // NTLMSSP\0 signature (8 bytes)
    msg.extend_from_slice(b"NTLMSSP\0");
    // Message type = 2 (4 bytes)
    msg.extend_from_slice(&2u32.to_le_bytes());
    // Target name: length=0, max_length=0, offset=56 (8 bytes)
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&56u32.to_le_bytes());
    // Negotiate flags (4 bytes) — UNICODE | NTLM | TARGET_INFO
    let flags: u32 = 0x00808201;
    msg.extend_from_slice(&flags.to_le_bytes());
    // Server challenge (8 bytes)
    msg.extend_from_slice(&[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
    // Reserved / context (8 bytes)
    msg.extend_from_slice(&[0u8; 8]);
    // Target info: length=4, max_length=4, offset=56 (8 bytes)
    msg.extend_from_slice(&4u16.to_le_bytes());
    msg.extend_from_slice(&4u16.to_le_bytes());
    msg.extend_from_slice(&56u32.to_le_bytes());
    // OS version (8 bytes)
    msg.extend_from_slice(&[10, 0, 0, 0, 0, 0, 0, 0]);
    // Target info data: MsvAvEOL (type=0x0000, length=0x0000)
    msg.extend_from_slice(&0u16.to_le_bytes());
    msg.extend_from_slice(&0u16.to_le_bytes());

    msg
}

fn encode_negotiate_response() -> Vec<u8> {
    let mut body = Vec::new();

    // StructureSize (2) = 65
    body.extend_from_slice(&65u16.to_le_bytes());
    // SecurityMode (2) = 1
    body.extend_from_slice(&1u16.to_le_bytes());
    // DialectRevision (2) = 0x0210 (SMB 2.1)
    body.extend_from_slice(&0x0210u16.to_le_bytes());
    // NegotiateContextCount (2) = 0
    body.extend_from_slice(&0u16.to_le_bytes());
    // ServerGuid (16)
    body.extend_from_slice(&[0u8; 16]);
    // Capabilities (4) = 0
    body.extend_from_slice(&0u32.to_le_bytes());
    // MaxTransactSize (4)
    body.extend_from_slice(&65536u32.to_le_bytes());
    // MaxReadSize (4)
    body.extend_from_slice(&65536u32.to_le_bytes());
    // MaxWriteSize (4)
    body.extend_from_slice(&65536u32.to_le_bytes());
    // SystemTime (8)
    body.extend_from_slice(&0u64.to_le_bytes());
    // ServerStartTime (8)
    body.extend_from_slice(&0u64.to_le_bytes());
    // SecurityBufferOffset (2) = 128
    body.extend_from_slice(&128u16.to_le_bytes());
    // SecurityBufferLength (2) = 0
    body.extend_from_slice(&0u16.to_le_bytes());
    // NegotiateContextOffset (4) = 0
    body.extend_from_slice(&0u32.to_le_bytes());

    body
}

fn encode_session_setup_response(security_buffer: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();

    // StructureSize (2) = 9
    body.extend_from_slice(&9u16.to_le_bytes());
    // SessionFlags (2) = 0
    body.extend_from_slice(&0u16.to_le_bytes());
    // SecurityBufferOffset (2) = 72
    let offset: u16 = 64 + 8;
    body.extend_from_slice(&offset.to_le_bytes());
    // SecurityBufferLength (2)
    body.extend_from_slice(&(security_buffer.len() as u16).to_le_bytes());
    // SecurityBuffer (variable)
    body.extend_from_slice(security_buffer);

    body
}

fn encode_tree_connect_response() -> Vec<u8> {
    let mut body = Vec::new();

    // StructureSize (2) = 16
    body.extend_from_slice(&16u16.to_le_bytes());
    // ShareType (1) = 0x02 (named pipe)
    body.push(0x02);
    // Reserved (1)
    body.push(0);
    // ShareFlags (4) = 0
    body.extend_from_slice(&0u32.to_le_bytes());
    // ShareCapabilities (4) = 0
    body.extend_from_slice(&0u32.to_le_bytes());
    // MaximalAccess (4)
    body.extend_from_slice(&0x001F_01FFu32.to_le_bytes());

    body
}

fn encode_create_response(file_id: &FileId) -> Vec<u8> {
    let mut body = Vec::new();

    // StructureSize (2) = 89
    body.extend_from_slice(&89u16.to_le_bytes());
    // OplockLevel (1) = 0
    body.push(0);
    // Flags (1) = 0
    body.push(0);
    // CreateAction (4) = 1 (opened)
    body.extend_from_slice(&1u32.to_le_bytes());
    // CreationTime through EndOfFile: 6 × 8 = 48 bytes of zeros
    body.extend_from_slice(&[0u8; 48]);
    // FileAttributes (4) = 0
    body.extend_from_slice(&0u32.to_le_bytes());
    // Reserved2 (4)
    body.extend_from_slice(&0u32.to_le_bytes());
    // FileId (16)
    file_id.encode(&mut body);
    // CreateContextsOffset (4) = 0
    body.extend_from_slice(&0u32.to_le_bytes());
    // CreateContextsLength (4) = 0
    body.extend_from_slice(&0u32.to_le_bytes());

    body
}

fn encode_read_response(data: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();

    // StructureSize (2) = 17
    body.extend_from_slice(&17u16.to_le_bytes());
    // DataOffset (1) = 80 (header=64 + body fixed=16)
    body.push(80);
    // Reserved (1)
    body.push(0);
    // DataLength (4)
    body.extend_from_slice(&(data.len() as u32).to_le_bytes());
    // DataRemaining (4) = 0
    body.extend_from_slice(&0u32.to_le_bytes());
    // Reserved2 (4)
    body.extend_from_slice(&0u32.to_le_bytes());
    // Data (variable)
    body.extend_from_slice(data);

    body
}

fn extract_write_data(body: &[u8]) -> Vec<u8> {
    if body.len() < 48 {
        return Vec::new();
    }
    let data_length = u32::from_le_bytes(body[4..8].try_into().unwrap()) as usize;
    let data_start = 48;
    let data_end = data_start + data_length;
    if data_end <= body.len() {
        body[data_start..data_end].to_vec()
    } else {
        body[data_start..].to_vec()
    }
}

fn encode_write_response(count: u32) -> Vec<u8> {
    let mut body = Vec::new();

    // StructureSize (2) = 17
    body.extend_from_slice(&17u16.to_le_bytes());
    // Reserved (2)
    body.extend_from_slice(&0u16.to_le_bytes());
    // Count (4)
    body.extend_from_slice(&count.to_le_bytes());
    // Remaining (4) = 0
    body.extend_from_slice(&0u32.to_le_bytes());
    // WriteChannelInfoOffset (2) = 0
    body.extend_from_slice(&0u16.to_le_bytes());
    // WriteChannelInfoLength (2) = 0
    body.extend_from_slice(&0u16.to_le_bytes());

    body
}

fn encode_close_response() -> Vec<u8> {
    let mut body = Vec::new();

    // StructureSize (2) = 60
    body.extend_from_slice(&60u16.to_le_bytes());
    // Flags (2) = 0
    body.extend_from_slice(&0u16.to_le_bytes());
    // Reserved (4)
    body.extend_from_slice(&0u32.to_le_bytes());
    // CreationTime through EndOfFile: 5 × 8 = 40 bytes of zeros
    body.extend_from_slice(&[0u8; 40]);
    // FileAttributes (4)
    body.extend_from_slice(&0u32.to_le_bytes());

    body
}

fn encode_simple_response(structure_size: u16) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&structure_size.to_le_bytes());
    body.extend_from_slice(&0u16.to_le_bytes());
    body
}

// ── Tests ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn smb_pipe_client_write_then_read() {
    let server = MockSmb2Server::bind().await.unwrap();
    let port = server.port();

    let server_handle = tokio::spawn(async move {
        if let Err(e) = server.serve_one().await {
            eprintln!("mock server error: {e}");
        }
    });

    let auth = Auth::ntlm("testuser", "testpass", "TESTDOMAIN");
    let client = SmbPipeClient::connect("127.0.0.1", port, "testpipe", &auth)
        .await
        .unwrap();

    let mut stream = client.stream;

    // Write data
    let test_data = b"hello from smb pipe test";
    stream.write_all(test_data).await.unwrap();

    // Give the background tasks time to process
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Read it back (the mock server echoes writes)
    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], test_data);

    // Close the stream (triggers teardown)
    drop(stream);

    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_handle).await;
}

#[tokio::test]
async fn smb_pipe_client_anonymous_auth() {
    let server = MockSmb2Server::bind().await.unwrap();
    let port = server.port();

    let server_handle = tokio::spawn(async move {
        if let Err(e) = server.serve_one().await {
            eprintln!("mock server error: {e}");
        }
    });

    let auth = Auth::Anonymous;
    let client = SmbPipeClient::connect("127.0.0.1", port, "testpipe", &auth)
        .await
        .unwrap();

    let mut stream = client.stream;

    stream.write_all(b"anon test").await.unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"anon test");

    drop(stream);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_handle).await;
}

#[tokio::test]
async fn smb_pipe_client_multiple_writes() {
    let server = MockSmb2Server::bind().await.unwrap();
    let port = server.port();

    let server_handle = tokio::spawn(async move {
        if let Err(e) = server.serve_one().await {
            eprintln!("mock server error: {e}");
        }
    });

    let auth = Auth::ntlm("user", "pass", ".");
    let client = SmbPipeClient::connect("127.0.0.1", port, "testpipe", &auth)
        .await
        .unwrap();

    let mut stream = client.stream;

    // Multiple writes before reading
    stream.write_all(b"first").await.unwrap();
    stream.write_all(b"second").await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // Read all data back
    let mut buf = vec![0u8; 1024];
    let n = stream.read(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"firstsecond");

    drop(stream);
    let _ = tokio::time::timeout(std::time::Duration::from_secs(2), server_handle).await;
}
