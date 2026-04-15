//! High-level async pipe client implementing `AsyncRead + AsyncWrite`.
//!
//! `SmbPipeClient` wraps an SMB2 [`Session`] and exposes the remote named
//! pipe as a standard Tokio async stream. A single background task
//! serializes all SMB2 READ and WRITE operations on the TCP connection.

use std::io;

use anyhow::Result;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::auth::Auth;
use crate::protocol::create::FileId;
use crate::protocol::{self, Smb2Command, Smb2Header, STATUS_BUFFER_OVERFLOW, STATUS_SUCCESS};
use crate::session::Session;
use crate::transport;

/// Default read buffer size.
const DEFAULT_READ_SIZE: u32 = 65536;

/// Internal command sent to the background SMB2 worker task.
enum SmbOp {
    Read {
        reply: tokio::sync::oneshot::Sender<io::Result<Vec<u8>>>,
    },
    Write {
        data: Vec<u8>,
        reply: tokio::sync::oneshot::Sender<io::Result<usize>>,
    },
}

/// A connected SMB2 named pipe that implements `AsyncRead + AsyncWrite`
/// via the returned `DuplexStream`.
///
/// The `stream` field is the end you read/write. Background tasks handle
/// translating those reads/writes into SMB2 protocol messages.
pub struct SmbPipeClient {
    /// The caller's end of the duplex stream — implements `AsyncRead + AsyncWrite`.
    pub stream: DuplexStream,
    /// Handle to the background reader task.
    _reader_task: JoinHandle<()>,
    /// Handle to the background writer task.
    _writer_task: JoinHandle<()>,
    /// Handle to the SMB2 worker task.
    _worker_task: JoinHandle<()>,
}

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
        let message_id = session.message_id;
        let tcp_stream = session.stream;

        // Channel for sending operations to the worker
        let (op_tx, mut op_rx) = mpsc::channel::<SmbOp>(16);

        // Duplex channel: caller ↔ background reader/writer tasks
        let (caller_stream, bg_stream) = tokio::io::duplex(DEFAULT_READ_SIZE as usize);
        let (mut bg_read, mut bg_write) = tokio::io::split(bg_stream);

        // Worker task: owns the TCP stream, serializes all SMB2 ops
        let worker_task = tokio::spawn(async move {
            let mut stream = tcp_stream;
            let mut mid = message_id;

            while let Some(op) = op_rx.recv().await {
                match op {
                    SmbOp::Read { reply } => {
                        let result =
                            smb2_read(&mut stream, mid, session_id, tree_id, &file_id, max_read)
                                .await;
                        mid += 1;
                        let _ = reply.send(result);
                    }
                    SmbOp::Write { data, reply } => {
                        let result =
                            smb2_write(&mut stream, mid, session_id, tree_id, &file_id, &data)
                                .await;
                        mid += 1;
                        let _ = reply.send(result);
                    }
                }
            }

            // Channel closed — perform teardown
            let _ = smb2_close_session(&mut stream, &mut mid, session_id, tree_id, &file_id).await;
        });

        // Reader task: issues SMB2 READs, feeds data to caller
        let read_tx = op_tx.clone();
        let reader_task = tokio::spawn(async move {
            loop {
                let (tx, rx) = tokio::sync::oneshot::channel();
                if read_tx.send(SmbOp::Read { reply: tx }).await.is_err() {
                    break;
                }
                match rx.await {
                    Ok(Ok(data)) if data.is_empty() => break, // EOF
                    Ok(Ok(data)) => {
                        if bg_write.write_all(&data).await.is_err() {
                            break; // caller dropped
                        }
                    }
                    _ => break,
                }
            }
        });

        // Writer task: reads from caller, issues SMB2 WRITEs
        let writer_task = tokio::spawn(async move {
            let mut buf = vec![0u8; max_write as usize];
            loop {
                let n = match bg_read.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                let (tx, rx) = tokio::sync::oneshot::channel();
                if op_tx
                    .send(SmbOp::Write {
                        data: buf[..n].to_vec(),
                        reply: tx,
                    })
                    .await
                    .is_err()
                {
                    break;
                }
                match rx.await {
                    Ok(Ok(_)) => {}
                    _ => break,
                }
            }
        });

        Ok(Self {
            stream: caller_stream,
            _reader_task: reader_task,
            _writer_task: writer_task,
            _worker_task: worker_task,
        })
    }
}

// ── SMB2 operations ─────────────────────────────────────────────────────

async fn smb2_read(
    stream: &mut tokio::net::TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: &FileId,
    max_read_size: u32,
) -> io::Result<Vec<u8>> {
    let mut hdr = Smb2Header::new_request(Smb2Command::Read, message_id);
    hdr.session_id = session_id;
    hdr.tree_id = tree_id;

    let body = protocol::read::encode_read_request(file_id, max_read_size, 0);

    transport::send_message(stream, &hdr, &body)
        .await
        .map_err(io::Error::other)?;

    let resp = transport::recv_message(stream)
        .await
        .map_err(io::Error::other)?;

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

async fn smb2_write(
    stream: &mut tokio::net::TcpStream,
    message_id: u64,
    session_id: u64,
    tree_id: u32,
    file_id: &FileId,
    data: &[u8],
) -> io::Result<usize> {
    let mut hdr = Smb2Header::new_request(Smb2Command::Write, message_id);
    hdr.session_id = session_id;
    hdr.tree_id = tree_id;

    let body = protocol::write::encode_write_request(file_id, data, 0);

    transport::send_message(stream, &hdr, &body)
        .await
        .map_err(io::Error::other)?;

    let resp = transport::recv_message(stream)
        .await
        .map_err(io::Error::other)?;

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

async fn smb2_close_session(
    stream: &mut tokio::net::TcpStream,
    message_id: &mut u64,
    session_id: u64,
    tree_id: u32,
    file_id: &FileId,
) -> io::Result<()> {
    // Close pipe handle
    let mut hdr = Smb2Header::new_request(Smb2Command::Close, *message_id);
    hdr.session_id = session_id;
    hdr.tree_id = tree_id;
    *message_id += 1;
    let body = protocol::close::encode_close_request(file_id);
    let _ = transport::send_message(stream, &hdr, &body).await;
    let _ = transport::recv_message(stream).await;

    // Tree disconnect
    let mut hdr = Smb2Header::new_request(Smb2Command::TreeDisconnect, *message_id);
    hdr.session_id = session_id;
    hdr.tree_id = tree_id;
    *message_id += 1;
    let body = protocol::tree_disconnect::encode_tree_disconnect_request();
    let _ = transport::send_message(stream, &hdr, &body).await;
    let _ = transport::recv_message(stream).await;

    // Logoff
    let mut hdr = Smb2Header::new_request(Smb2Command::Logoff, *message_id);
    hdr.session_id = session_id;
    *message_id += 1;
    let body = protocol::logoff::encode_logoff_request();
    let _ = transport::send_message(stream, &hdr, &body).await;
    let _ = transport::recv_message(stream).await;

    Ok(())
}
