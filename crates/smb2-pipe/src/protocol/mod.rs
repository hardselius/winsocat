//! SMB2 wire protocol types and serialization.
//!
//! This module implements binary encoding/decoding for the subset of SMB2
//! messages needed to open, read, and write a remote named pipe:
//!
//! - NetBIOS session transport frame (4 bytes)
//! - SMB2 header (64 bytes)
//! - Negotiate, Session Setup, Tree Connect, Create, Read, Write, Close,
//!   Tree Disconnect, and Logoff request/response pairs

mod header;

pub mod close;
pub mod create;
pub mod logoff;
pub mod negotiate;
pub mod read;
pub mod session_setup;
pub mod tree_connect;
pub mod tree_disconnect;
pub mod write;

pub use header::{Smb2Command, Smb2Flags, Smb2Header};

use std::io::{self, Cursor, Read};

// ── SMB2 magic ──────────────────────────────────────────────────────────

/// SMB2 protocol magic: `\xFESMB`
pub const SMB2_MAGIC: [u8; 4] = [0xFE, b'S', b'M', b'B'];

/// SMB2 header is always 64 bytes on the wire.
pub const SMB2_HEADER_SIZE: usize = 64;

// ── NT Status codes we care about ───────────────────────────────────────

/// Operation completed successfully.
pub const STATUS_SUCCESS: u32 = 0x0000_0000;

/// More processing is required (used during NTLM session setup).
pub const STATUS_MORE_PROCESSING_REQUIRED: u32 = 0xC000_0016;

/// The pipe has been ended by the server.
pub const STATUS_PIPE_DISCONNECTED: u32 = 0xC000_00B0;

/// The pipe is being closed.
pub const STATUS_PIPE_CLOSING: u32 = 0xC000_00B1;

/// End of file (no more data to read).
pub const STATUS_END_OF_FILE: u32 = 0xC000_0011;

/// Buffer overflow — partial data returned.
pub const STATUS_BUFFER_OVERFLOW: u32 = 0x8000_0005;

/// The pipe is broken (remote end closed).
pub const STATUS_PIPE_BROKEN: u32 = 0xC000_014B;

/// The operation is pending — the server will respond asynchronously.
pub const STATUS_PENDING: u32 = 0x0000_0103;

/// No data available on the pipe right now (try again).
pub const STATUS_PIPE_EMPTY: u32 = 0xC000_00D9;

// ── NetBIOS session transport framing ───────────────────────────────────

/// Encode a NetBIOS session message header (RFC 1002 §4.3.1).
///
/// The frame is 4 bytes: one zero byte followed by 3 bytes of big-endian
/// payload length. The maximum payload is 2^24 − 1 = 16 MiB.
pub fn encode_nb_header(payload_len: usize) -> [u8; 4] {
    let len = payload_len as u32;
    [0x00, (len >> 16) as u8, (len >> 8) as u8, len as u8]
}

/// Decode a 4-byte NetBIOS session header, returning the payload length.
pub fn decode_nb_header(buf: &[u8; 4]) -> usize {
    ((buf[1] as usize) << 16) | ((buf[2] as usize) << 8) | (buf[3] as usize)
}

// ── Encoding helpers ────────────────────────────────────────────────────

/// Write a complete SMB2 message (NetBIOS frame + header + body) into `out`.
pub fn encode_message(header: &Smb2Header, body: &[u8], out: &mut Vec<u8>) {
    let smb2_len = SMB2_HEADER_SIZE + body.len();
    out.extend_from_slice(&encode_nb_header(smb2_len));
    header.encode(out);
    out.extend_from_slice(body);
}

// ── Decoding helpers ────────────────────────────────────────────────────

/// A parsed SMB2 response: header plus the body bytes after the header.
#[derive(Debug)]
pub struct Smb2Response {
    pub header: Smb2Header,
    pub body: Vec<u8>,
}

/// Parse a raw SMB2 message (without the NetBIOS frame) into header + body.
pub fn decode_message(data: &[u8]) -> io::Result<Smb2Response> {
    if data.len() < SMB2_HEADER_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "SMB2 message too short: {} bytes, need at least {}",
                data.len(),
                SMB2_HEADER_SIZE
            ),
        ));
    }
    let header = Smb2Header::decode(&data[..SMB2_HEADER_SIZE])?;
    let body = data[SMB2_HEADER_SIZE..].to_vec();
    Ok(Smb2Response { header, body })
}

// ── Cursor-based read helpers ───────────────────────────────────────────

pub(crate) fn read_u16_le(cursor: &mut Cursor<&[u8]>) -> io::Result<u16> {
    let mut buf = [0u8; 2];
    cursor.read_exact(&mut buf)?;
    Ok(u16::from_le_bytes(buf))
}

pub(crate) fn read_u32_le(cursor: &mut Cursor<&[u8]>) -> io::Result<u32> {
    let mut buf = [0u8; 4];
    cursor.read_exact(&mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

pub(crate) fn read_u64_le(cursor: &mut Cursor<&[u8]>) -> io::Result<u64> {
    let mut buf = [0u8; 8];
    cursor.read_exact(&mut buf)?;
    Ok(u64::from_le_bytes(buf))
}

pub(crate) fn read_bytes(cursor: &mut Cursor<&[u8]>, len: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    cursor.read_exact(&mut buf)?;
    Ok(buf)
}

pub(crate) fn skip(cursor: &mut Cursor<&[u8]>, n: usize) -> io::Result<()> {
    let pos = cursor.position();
    cursor.set_position(pos + n as u64);
    Ok(())
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netbios_header_roundtrip() {
        let sizes = [0, 1, 255, 256, 65535, 65536, 0xFF_FFFF];
        for &size in &sizes {
            let encoded = encode_nb_header(size);
            assert_eq!(encoded[0], 0x00, "first byte must be zero");
            let decoded = decode_nb_header(&encoded);
            assert_eq!(decoded, size, "roundtrip failed for size {size}");
        }
    }

    #[test]
    fn netbios_header_known_values() {
        // 100 bytes = 0x000064
        assert_eq!(encode_nb_header(100), [0x00, 0x00, 0x00, 0x64]);
        // 1000 bytes = 0x0003E8
        assert_eq!(encode_nb_header(1000), [0x00, 0x00, 0x03, 0xE8]);
    }
}
