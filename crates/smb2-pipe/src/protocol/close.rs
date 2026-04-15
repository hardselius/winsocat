//! SMB2 CLOSE request/response.

use std::io::{self, Cursor};

use super::create::FileId;
use super::read_u16_le;

// ── Request ─────────────────────────────────────────────────────────────

/// Encode an SMB2 CLOSE request body.
pub fn encode_close_request(file_id: &FileId) -> Vec<u8> {
    let mut body = Vec::new();

    // StructureSize (2) — always 24
    body.extend_from_slice(&24u16.to_le_bytes());
    // Flags (2) — 0 (don't request post-close attributes)
    body.extend_from_slice(&0u16.to_le_bytes());
    // Reserved (4)
    body.extend_from_slice(&0u32.to_le_bytes());
    // FileId (16)
    file_id.encode(&mut body);

    body
}

// ── Response ────────────────────────────────────────────────────────────

/// Parsed SMB2 CLOSE response.
#[derive(Debug)]
pub struct CloseResponse {
    /// Flags from the response.
    pub flags: u16,
}

/// Decode an SMB2 CLOSE response body.
pub fn decode_close_response(body: &[u8]) -> io::Result<CloseResponse> {
    let mut cursor = Cursor::new(body);

    let _structure_size = read_u16_le(&mut cursor)?; // 60
    let flags = read_u16_le(&mut cursor)?;

    Ok(CloseResponse { flags })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn close_request_encoding() {
        let fid = FileId {
            persistent: 0xAAAA,
            volatile: 0xBBBB,
        };
        let body = encode_close_request(&fid);
        // StructureSize = 24
        assert_eq!(u16::from_le_bytes([body[0], body[1]]), 24);
        // Total = 24 bytes
        assert_eq!(body.len(), 24);
        // FileId persistent at offset 8
        assert_eq!(u64::from_le_bytes(body[8..16].try_into().unwrap()), 0xAAAA);
        // FileId volatile at offset 16
        assert_eq!(u64::from_le_bytes(body[16..24].try_into().unwrap()), 0xBBBB);
    }
}
