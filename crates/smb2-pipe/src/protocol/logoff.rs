//! SMB2 LOGOFF request/response.

use std::io::{self, Cursor};

use super::read_u16_le;

// ── Request ─────────────────────────────────────────────────────────────

/// Encode an SMB2 LOGOFF request body.
pub fn encode_logoff_request() -> Vec<u8> {
    let mut body = Vec::new();

    // StructureSize (2) — always 4
    body.extend_from_slice(&4u16.to_le_bytes());
    // Reserved (2)
    body.extend_from_slice(&0u16.to_le_bytes());

    body
}

// ── Response ────────────────────────────────────────────────────────────

/// Parsed SMB2 LOGOFF response.
#[derive(Debug)]
pub struct LogoffResponse {
    /// Structure size (always 4).
    pub structure_size: u16,
}

/// Decode an SMB2 LOGOFF response body.
pub fn decode_logoff_response(body: &[u8]) -> io::Result<LogoffResponse> {
    let mut cursor = Cursor::new(body);
    let structure_size = read_u16_le(&mut cursor)?;
    Ok(LogoffResponse { structure_size })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logoff_request_encoding() {
        let body = encode_logoff_request();
        assert_eq!(body.len(), 4);
        assert_eq!(u16::from_le_bytes([body[0], body[1]]), 4);
    }

    #[test]
    fn logoff_response_roundtrip() {
        let body = encode_logoff_request();
        let resp = decode_logoff_response(&body).unwrap();
        assert_eq!(resp.structure_size, 4);
    }
}
