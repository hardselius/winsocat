//! SMB2 transport: send and receive framed messages over TCP.
//!
//! Each SMB2 message on the wire is prefixed by a 4-byte NetBIOS session
//! header that contains the payload length. This module handles framing.

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::protocol::{self, Smb2Header, Smb2Response, SMB2_HEADER_SIZE};

/// Send an SMB2 message (header + body) over the TCP stream.
///
/// Writes the 4-byte NetBIOS frame header followed by the SMB2 header
/// and body.
pub async fn send_message(stream: &mut TcpStream, header: &Smb2Header, body: &[u8]) -> Result<()> {
    let mut buf = Vec::with_capacity(4 + SMB2_HEADER_SIZE + body.len());
    protocol::encode_message(header, body, &mut buf);
    stream
        .write_all(&buf)
        .await
        .context("failed to send SMB2 message")?;
    stream.flush().await.context("failed to flush stream")?;
    Ok(())
}

/// Receive a complete SMB2 message from the TCP stream.
///
/// Reads the 4-byte NetBIOS frame header, then reads the full payload,
/// and parses it into an `Smb2Response`.
pub async fn recv_message(stream: &mut TcpStream) -> Result<Smb2Response> {
    // Read the 4-byte NetBIOS header
    let mut nb_header = [0u8; 4];
    stream
        .read_exact(&mut nb_header)
        .await
        .context("failed to read NetBIOS header")?;
    let payload_len = protocol::decode_nb_header(&nb_header);

    if payload_len < SMB2_HEADER_SIZE {
        anyhow::bail!(
            "SMB2 payload too short: {} bytes (need at least {})",
            payload_len,
            SMB2_HEADER_SIZE
        );
    }

    // Read the full SMB2 payload
    let mut payload = vec![0u8; payload_len];
    stream
        .read_exact(&mut payload)
        .await
        .context("failed to read SMB2 payload")?;

    // Parse into header + body
    protocol::decode_message(&payload).context("failed to decode SMB2 message")
}
