//! High-level async pipe client implementing `AsyncRead + AsyncWrite`.
//!
//! `SmbPipeClient` wraps an SMB2 [`Session`] and exposes the remote named
//! pipe as a standard Tokio async stream.
//!
//! The design splits the TCP connection into read/write halves and uses
//! a response dispatcher to match SMB2 responses to their requests by
//! message ID. This allows READ and WRITE operations to be in-flight
//! concurrently, which is essential for named pipes where READ may block
//! on the server until data is available.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::{oneshot, Mutex};
use tokio::task::JoinHandle;

use crate::auth::Auth;
use crate::protocol::create::FileId;
use crate::protocol::{
    self, Smb2Command, Smb2Header, Smb2Response, STATUS_BUFFER_OVERFLOW, STATUS_SUCCESS,
};
use crate::session::Session;

/// Default read buffer size.
const DEFAULT_READ_SIZE: u32 = 65536;

/// A connected SMB2 named pipe that implements `AsyncRead + AsyncWrite`
/// via the returned `DuplexStream`.
///
/// The `stream` field is the end you read/write. Background tasks handle
/// translating those reads/writes into SMB2 protocol messages.
pub struct SmbPipeClient {
    /// The caller's end of the duplex stream.
    pub stream: DuplexStream,
    /// Handle to the background reader task.
    _reader_task: JoinHandle<()>,
    /// Handle to the background writer task.
    _writer_task: JoinHandle<()>,
    /// Handle to the response dispatcher task.
    _dispatcher_task: JoinHandle<()>,
    /// Handle to the teardown task.
    _teardown_task: JoinHandle<()>,
}

/// Shared state for sending SMB2 requests on the TCP write half.
struct Sender {
    tcp_write: OwnedWriteHalf,
}

/// Pending response table: message_id → oneshot sender.
type PendingMap = HashMap<u64, oneshot::Sender<io::Result<Smb2Response>>>;

impl SmbPipeClient {
    /// Connect to a remote named pipe via SMB2 and return an async stream.
    ///
    /// `server` is the hostname or IP of the SMB server.
    /// `port` is the TCP port (usually 445).
    /// `pipe_name` is the pipe name without a leading backslash.
    /// `auth` specifies the authentication method.
    pub async fn connect(server: &str, port: u16, pipe_name: &str, auth: &Auth) -> Result<Self> {
        let session = Session::connect(server, port, pipe_name, auth).await?;

        let max_read = session.max_read_size.min(DEFAULT_READ_SIZE);
        let max_write = session.max_write_size.min(DEFAULT_READ_SIZE);
        let session_id = session.session_id;
        let tree_id = session.tree_id;
        let file_id = session.file_id;
        let start_message_id = session.message_id;

        // Split TCP into read/write halves
        let (tcp_read, tcp_write) = session.stream.into_split();

        // Monotonically increasing message ID
        let message_id = Arc::new(AtomicU64::new(start_message_id));

        // Shared sender (TCP write half)
        let sender = Arc::new(Mutex::new(Sender { tcp_write }));

        // Pending response table
        let pending: Arc<Mutex<PendingMap>> = Arc::new(Mutex::new(HashMap::new()));

        // Duplex channel: caller ↔ background reader/writer tasks
        let (caller_stream, bg_stream) = tokio::io::duplex(DEFAULT_READ_SIZE as usize);
        let (mut bg_read, mut bg_write) = tokio::io::split(bg_stream);

        // Channel to signal teardown
        let (teardown_tx, teardown_rx) = oneshot::channel::<()>();

        // Dispatcher task: reads from TCP, routes responses by message ID
        let disp_pending = Arc::clone(&pending);
        let dispatcher_task = tokio::spawn(async move {
            dispatch_responses(tcp_read, disp_pending).await;
        });

        // Reader task: issues SMB2 READs, feeds data to the duplex stream
        let read_sender = Arc::clone(&sender);
        let read_pending = Arc::clone(&pending);
        let read_mid = Arc::clone(&message_id);
        let read_file_id = file_id;
        let reader_task = tokio::spawn(async move {
            loop {
                let result = send_smb2_read(
                    &read_sender,
                    &read_pending,
                    &read_mid,
                    session_id,
                    tree_id,
                    &read_file_id,
                    max_read,
                )
                .await;

                match result {
                    Ok(data) if data.is_empty() => break, // EOF
                    Ok(data) => {
                        if bg_write.write_all(&data).await.is_err() {
                            break; // Caller dropped
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // Writer task: reads from caller, issues SMB2 WRITEs
        let write_sender = Arc::clone(&sender);
        let write_pending = Arc::clone(&pending);
        let write_mid = Arc::clone(&message_id);
        let write_file_id = file_id;
        let writer_task = tokio::spawn(async move {
            let mut buf = vec![0u8; max_write as usize];
            loop {
                let n = match bg_read.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                let result = send_smb2_write(
                    &write_sender,
                    &write_pending,
                    &write_mid,
                    session_id,
                    tree_id,
                    &write_file_id,
                    &buf[..n],
                )
                .await;
                if result.is_err() {
                    break;
                }
            }
            // Signal that writing is done, trigger teardown
            let _ = teardown_tx.send(());
        });

        // Teardown task: waits for writer to finish, then cleans up
        let teardown_sender = Arc::clone(&sender);
        let teardown_mid = Arc::clone(&message_id);
        let teardown_file_id = file_id;
        let teardown_task = tokio::spawn(async move {
            // Wait for the writer task to signal completion
            let _ = teardown_rx.await;
            // Give a small delay for pending reads to complete
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            // Perform graceful close
            let _ = send_smb2_close_session(
                &teardown_sender,
                &teardown_mid,
                session_id,
                tree_id,
                &teardown_file_id,
            )
            .await;
        });

        Ok(Self {
            stream: caller_stream,
            _reader_task: reader_task,
            _writer_task: writer_task,
            _dispatcher_task: dispatcher_task,
            _teardown_task: teardown_task,
        })
    }
}

// ── Response dispatcher ─────────────────────────────────────────────────

async fn dispatch_responses(mut tcp_read: OwnedReadHalf, pending: Arc<Mutex<PendingMap>>) {
    loop {
        // Read NetBIOS header
        let mut nb_hdr = [0u8; 4];
        if tcp_read.read_exact(&mut nb_hdr).await.is_err() {
            break; // Connection closed
        }
        let payload_len = protocol::decode_nb_header(&nb_hdr);
        if payload_len < protocol::SMB2_HEADER_SIZE {
            break;
        }

        let mut payload = vec![0u8; payload_len];
        if tcp_read.read_exact(&mut payload).await.is_err() {
            break;
        }

        let resp = match protocol::decode_message(&payload) {
            Ok(r) => r,
            Err(_) => break,
        };

        let mid = resp.header.message_id;

        // Route to the waiting task
        let sender = {
            let mut map = pending.lock().await;
            map.remove(&mid)
        };

        if let Some(tx) = sender {
            let _ = tx.send(Ok(resp));
        }
    }

    // Connection closed — fail all pending requests
    let mut map = pending.lock().await;
    for (_, tx) in map.drain() {
        let _ = tx.send(Err(io::Error::new(
            io::ErrorKind::ConnectionAborted,
            "SMB2 connection closed",
        )));
    }
}

// ── Request senders ─────────────────────────────────────────────────────

/// Send an SMB2 request and register a pending response slot.
///
/// Returns a oneshot receiver that will receive the response.
async fn send_request(
    sender: &Arc<Mutex<Sender>>,
    pending: &Arc<Mutex<PendingMap>>,
    message_id: &Arc<AtomicU64>,
    hdr: &mut Smb2Header,
    body: &[u8],
) -> io::Result<oneshot::Receiver<io::Result<Smb2Response>>> {
    let mid = message_id.fetch_add(1, Ordering::SeqCst);
    hdr.message_id = mid;

    let (tx, rx) = oneshot::channel();

    // Register the pending response before sending
    {
        let mut map = pending.lock().await;
        map.insert(mid, tx);
    }

    // Send the request
    {
        let mut s = sender.lock().await;
        let mut buf = Vec::with_capacity(4 + protocol::SMB2_HEADER_SIZE + body.len());
        protocol::encode_message(hdr, body, &mut buf);
        if let Err(e) = s.tcp_write.write_all(&buf).await {
            // Remove from pending on send failure
            let mut map = pending.lock().await;
            map.remove(&mid);
            return Err(e);
        }
        let _ = s.tcp_write.flush().await;
    }

    Ok(rx)
}

async fn send_smb2_read(
    sender: &Arc<Mutex<Sender>>,
    pending: &Arc<Mutex<PendingMap>>,
    message_id: &Arc<AtomicU64>,
    session_id: u64,
    tree_id: u32,
    file_id: &FileId,
    max_read_size: u32,
) -> io::Result<Vec<u8>> {
    let mut hdr = Smb2Header::new_request(Smb2Command::Read, 0);
    hdr.session_id = session_id;
    hdr.tree_id = tree_id;

    let body = protocol::read::encode_read_request(file_id, max_read_size, 0);

    let rx = send_request(sender, pending, message_id, &mut hdr, &body).await?;

    let resp = rx
        .await
        .map_err(|_| io::Error::other("response channel closed"))??;

    if resp.header.status != STATUS_SUCCESS && resp.header.status != STATUS_BUFFER_OVERFLOW {
        if resp.header.status == protocol::STATUS_PIPE_DISCONNECTED
            || resp.header.status == protocol::STATUS_PIPE_CLOSING
            || resp.header.status == protocol::STATUS_PIPE_BROKEN
            || resp.header.status == protocol::STATUS_END_OF_FILE
        {
            return Ok(Vec::new());
        }
        return Err(io::Error::other(format!(
            "SMB2 READ failed: NT status 0x{:08X}",
            resp.header.status
        )));
    }

    let read_resp = protocol::read::decode_read_response(&resp.body)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    Ok(read_resp.data)
}

async fn send_smb2_write(
    sender: &Arc<Mutex<Sender>>,
    pending: &Arc<Mutex<PendingMap>>,
    message_id: &Arc<AtomicU64>,
    session_id: u64,
    tree_id: u32,
    file_id: &FileId,
    data: &[u8],
) -> io::Result<usize> {
    let mut hdr = Smb2Header::new_request(Smb2Command::Write, 0);
    hdr.session_id = session_id;
    hdr.tree_id = tree_id;

    let body = protocol::write::encode_write_request(file_id, data, 0);

    let rx = send_request(sender, pending, message_id, &mut hdr, &body).await?;

    let resp = rx
        .await
        .map_err(|_| io::Error::other("response channel closed"))??;

    if resp.header.status != STATUS_SUCCESS {
        return Err(io::Error::other(format!(
            "SMB2 WRITE failed: NT status 0x{:08X}",
            resp.header.status
        )));
    }

    let write_resp = protocol::write::decode_write_response(&resp.body)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    Ok(write_resp.count as usize)
}

/// Send close, tree disconnect, and logoff (best-effort).
async fn send_smb2_close_session(
    sender: &Arc<Mutex<Sender>>,
    message_id: &Arc<AtomicU64>,
    session_id: u64,
    tree_id: u32,
    file_id: &FileId,
) -> io::Result<()> {
    // We send these without waiting for responses (best-effort teardown).
    // This avoids deadlocks if the dispatcher has already stopped.

    let mut s = sender.lock().await;

    // Close
    let mid = message_id.fetch_add(1, Ordering::SeqCst);
    let mut hdr = Smb2Header::new_request(Smb2Command::Close, mid);
    hdr.session_id = session_id;
    hdr.tree_id = tree_id;
    let body = protocol::close::encode_close_request(file_id);
    let mut buf = Vec::new();
    protocol::encode_message(&hdr, &body, &mut buf);
    let _ = s.tcp_write.write_all(&buf).await;

    // Tree disconnect
    let mid = message_id.fetch_add(1, Ordering::SeqCst);
    let mut hdr = Smb2Header::new_request(Smb2Command::TreeDisconnect, mid);
    hdr.session_id = session_id;
    hdr.tree_id = tree_id;
    let body = protocol::tree_disconnect::encode_tree_disconnect_request();
    buf.clear();
    protocol::encode_message(&hdr, &body, &mut buf);
    let _ = s.tcp_write.write_all(&buf).await;

    // Logoff
    let mid = message_id.fetch_add(1, Ordering::SeqCst);
    let mut hdr = Smb2Header::new_request(Smb2Command::Logoff, mid);
    hdr.session_id = session_id;
    let body = protocol::logoff::encode_logoff_request();
    buf.clear();
    protocol::encode_message(&hdr, &body, &mut buf);
    let _ = s.tcp_write.write_all(&buf).await;

    let _ = s.tcp_write.flush().await;

    Ok(())
}
