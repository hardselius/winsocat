//! SMB2 TREE_DISCONNECT request/response.

use std::io::{self, Cursor};

use super::read_u16_le;

// ── Request ─────────────────────────────────────────────────────────────

/// Encode an SMB2 TREE_DISCONNECT request body.
pub fn encode_tree_disconnect_request() -> Vec<u8> {
    let mut body = Vec::new();

    // StructureSize (2) — always 4
    body.extend_from_slice(&4u16.to_le_bytes());
    // Reserved (2)
    body.extend_from_slice(&0u16.to_le_bytes());

    body
}

// ── Response ────────────────────────────────────────────────────────────

/// Parsed SMB2 TREE_DISCONNECT response.
#[derive(Debug)]
pub struct TreeDisconnectResponse {
    /// Structure size (always 4).
    pub structure_size: u16,
}

/// Decode an SMB2 TREE_DISCONNECT response body.
pub fn decode_tree_disconnect_response(body: &[u8]) -> io::Result<TreeDisconnectResponse> {
    let mut cursor = Cursor::new(body);
    let structure_size = read_u16_le(&mut cursor)?;
    Ok(TreeDisconnectResponse { structure_size })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_disconnect_request_encoding() {
        let body = encode_tree_disconnect_request();
        assert_eq!(body.len(), 4);
        assert_eq!(u16::from_le_bytes([body[0], body[1]]), 4);
    }

    #[test]
    fn tree_disconnect_response_roundtrip() {
        let body = encode_tree_disconnect_request();
        let resp = decode_tree_disconnect_response(&body).unwrap();
        assert_eq!(resp.structure_size, 4);
    }
}
