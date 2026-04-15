//! SMB2 WRITE request/response.

use std::io::{self, Cursor};

use super::create::FileId;
use super::{read_u16_le, read_u32_le};

// ── Request ─────────────────────────────────────────────────────────────

/// Encode an SMB2 WRITE request body.
///
/// `data` is the bytes to write to the pipe.
/// `offset` is the byte offset (usually 0 for pipes).
pub fn encode_write_request(file_id: &FileId, data: &[u8], offset: u64) -> Vec<u8> {
    let mut body = Vec::new();

    // StructureSize (2) — always 49
    body.extend_from_slice(&49u16.to_le_bytes());
    // DataOffset (2) — offset from start of SMB2 header to write data
    // Header(64) + body fixed part(48) = 112
    let data_offset: u16 = 64 + 48;
    body.extend_from_slice(&data_offset.to_le_bytes());
    // Length (4) — number of bytes to write
    body.extend_from_slice(&(data.len() as u32).to_le_bytes());
    // Offset (8)
    body.extend_from_slice(&offset.to_le_bytes());
    // FileId (16)
    file_id.encode(&mut body);
    // Channel (4) — 0
    body.extend_from_slice(&0u32.to_le_bytes());
    // RemainingBytes (4) — 0
    body.extend_from_slice(&0u32.to_le_bytes());
    // WriteChannelInfoOffset (2) — 0
    body.extend_from_slice(&0u16.to_le_bytes());
    // WriteChannelInfoLength (2) — 0
    body.extend_from_slice(&0u16.to_le_bytes());
    // Flags (4) — 0
    body.extend_from_slice(&0u32.to_le_bytes());
    // Buffer (variable) — the actual data
    body.extend_from_slice(data);

    body
}

// ── Response ────────────────────────────────────────────────────────────

/// Parsed SMB2 WRITE response.
#[derive(Debug)]
pub struct WriteResponse {
    /// Number of bytes written.
    pub count: u32,
    /// Remaining bytes (server hint).
    pub remaining: u32,
}

/// Decode an SMB2 WRITE response body.
pub fn decode_write_response(body: &[u8]) -> io::Result<WriteResponse> {
    let mut cursor = Cursor::new(body);

    let _structure_size = read_u16_le(&mut cursor)?; // 17
    let _reserved = read_u16_le(&mut cursor)?;
    let count = read_u32_le(&mut cursor)?;
    let remaining = read_u32_le(&mut cursor)?;

    Ok(WriteResponse { count, remaining })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_request_encoding() {
        let fid = FileId {
            persistent: 1,
            volatile: 2,
        };
        let data = b"hello pipe";
        let body = encode_write_request(&fid, data, 0);
        // StructureSize = 49
        assert_eq!(u16::from_le_bytes([body[0], body[1]]), 49);
        // DataOffset = 112
        assert_eq!(u16::from_le_bytes([body[2], body[3]]), 112);
        // Length = 10
        assert_eq!(u32::from_le_bytes(body[4..8].try_into().unwrap()), 10);
        // Total: 48 fixed + 10 data = 58
        assert_eq!(body.len(), 58);
        // Data at end
        assert_eq!(&body[48..], data.as_slice());
    }
}
