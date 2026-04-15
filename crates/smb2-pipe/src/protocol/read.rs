//! SMB2 READ request/response.

use std::io::{self, Cursor};

use super::create::FileId;
use super::{read_u16_le, read_u32_le, skip};

// ── Request ─────────────────────────────────────────────────────────────

/// Encode an SMB2 READ request body.
///
/// `length` is the maximum number of bytes to read.
/// `offset` is the byte offset in the file/pipe (usually 0 for pipes).
pub fn encode_read_request(file_id: &FileId, length: u32, offset: u64) -> Vec<u8> {
    let mut body = Vec::new();

    // StructureSize (2) — always 49
    body.extend_from_slice(&49u16.to_le_bytes());
    // Padding (1) — 0x50 (required minimum read buffer offset)
    body.push(0x50);
    // Flags (1) — 0
    body.push(0);
    // Length (4) — max bytes to read
    body.extend_from_slice(&length.to_le_bytes());
    // Offset (8)
    body.extend_from_slice(&offset.to_le_bytes());
    // FileId (16)
    file_id.encode(&mut body);
    // MinimumCount (4) — 0 (return whatever is available)
    body.extend_from_slice(&0u32.to_le_bytes());
    // Channel (4) — 0
    body.extend_from_slice(&0u32.to_le_bytes());
    // RemainingBytes (4) — 0
    body.extend_from_slice(&0u32.to_le_bytes());
    // ReadChannelInfoOffset (2) — 0
    body.extend_from_slice(&0u16.to_le_bytes());
    // ReadChannelInfoLength (2) — 0
    body.extend_from_slice(&0u16.to_le_bytes());
    // Buffer (1) — must be at least 1 byte
    body.push(0);

    body
}

// ── Response ────────────────────────────────────────────────────────────

/// Parsed SMB2 READ response.
#[derive(Debug)]
pub struct ReadResponse {
    /// The data that was read.
    pub data: Vec<u8>,
    /// Number of bytes remaining (server hint).
    pub data_remaining: u32,
}

/// Decode an SMB2 READ response body.
pub fn decode_read_response(body: &[u8]) -> io::Result<ReadResponse> {
    let mut cursor = Cursor::new(body);

    let _structure_size = read_u16_le(&mut cursor)?; // 17
    let data_offset = {
        let mut buf = [0u8; 1];
        std::io::Read::read_exact(&mut cursor, &mut buf)?;
        buf[0]
    };
    skip(&mut cursor, 1)?; // Reserved
    let data_length = read_u32_le(&mut cursor)?;
    let data_remaining = read_u32_le(&mut cursor)?;

    // DataOffset is from start of SMB2 header
    let buf_start = data_offset as usize - 64;
    let buf_end = buf_start + data_length as usize;
    let data = if buf_end <= body.len() {
        body[buf_start..buf_end].to_vec()
    } else {
        Vec::new()
    };

    Ok(ReadResponse {
        data,
        data_remaining,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_request_encoding() {
        let fid = FileId {
            persistent: 1,
            volatile: 2,
        };
        let body = encode_read_request(&fid, 65536, 0);
        // StructureSize = 49
        assert_eq!(u16::from_le_bytes([body[0], body[1]]), 49);
        // Length = 65536
        assert_eq!(u32::from_le_bytes(body[4..8].try_into().unwrap()), 65536);
        // Total size: 49 bytes
        assert_eq!(body.len(), 49);
    }
}
