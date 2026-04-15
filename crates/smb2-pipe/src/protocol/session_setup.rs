//! SMB2 SESSION_SETUP request/response.
//!
//! Carries NTLM (or SPNEGO-wrapped NTLM) authentication tokens.

use std::io::{self, Cursor};

use super::read_u16_le;

// ── Request ─────────────────────────────────────────────────────────────

/// Encode an SMB2 SESSION_SETUP request body.
///
/// `security_buffer` is the NTLM/SPNEGO token to send.
/// `previous_session_id` is 0 for a new session.
pub fn encode_session_setup_request(security_buffer: &[u8], previous_session_id: u64) -> Vec<u8> {
    let mut body = Vec::new();

    // StructureSize (2) — always 25
    body.extend_from_slice(&25u16.to_le_bytes());
    // Flags (1) — 0 = no binding
    body.push(0);
    // SecurityMode (1) — signing enabled
    body.push(0x01);
    // Capabilities (4) — none
    body.extend_from_slice(&0u32.to_le_bytes());
    // Channel (4) — 0
    body.extend_from_slice(&0u32.to_le_bytes());
    // SecurityBufferOffset (2) — offset from start of SMB2 header
    // Header = 64 bytes, body fixed part = 24 bytes (the structure is 25
    // but the last byte of the fixed part overlaps with the buffer).
    // Actual offset = 64 + 24 = 88
    let offset: u16 = 64 + 24;
    body.extend_from_slice(&offset.to_le_bytes());
    // SecurityBufferLength (2)
    body.extend_from_slice(&(security_buffer.len() as u16).to_le_bytes());
    // PreviousSessionId (8)
    body.extend_from_slice(&previous_session_id.to_le_bytes());
    // SecurityBuffer (variable)
    body.extend_from_slice(security_buffer);

    body
}

// ── Response ────────────────────────────────────────────────────────────

/// Parsed SMB2 SESSION_SETUP response.
#[derive(Debug)]
pub struct SessionSetupResponse {
    /// Session flags.
    pub session_flags: u16,
    /// Security buffer (server's NTLM challenge or final token).
    pub security_buffer: Vec<u8>,
}

/// Decode an SMB2 SESSION_SETUP response body.
pub fn decode_session_setup_response(body: &[u8]) -> io::Result<SessionSetupResponse> {
    let mut cursor = Cursor::new(body);

    let _structure_size = read_u16_le(&mut cursor)?; // 9
    let session_flags = read_u16_le(&mut cursor)?;
    let security_buffer_offset = read_u16_le(&mut cursor)?;
    let security_buffer_length = read_u16_le(&mut cursor)?;

    let buf_start = security_buffer_offset as usize - 64;
    let buf_end = buf_start + security_buffer_length as usize;
    let security_buffer = if buf_end <= body.len() {
        body[buf_start..buf_end].to_vec()
    } else {
        Vec::new()
    };

    Ok(SessionSetupResponse {
        session_flags,
        security_buffer,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_setup_request_encoding() {
        let token = b"NTLMSSP_TOKEN";
        let body = encode_session_setup_request(token, 0);
        // Fixed part: 24 bytes + token length
        assert_eq!(body.len(), 24 + token.len());
        // StructureSize = 25
        assert_eq!(u16::from_le_bytes([body[0], body[1]]), 25);
        // SecurityBufferOffset = 88
        assert_eq!(u16::from_le_bytes([body[12], body[13]]), 88);
        // SecurityBufferLength
        assert_eq!(u16::from_le_bytes([body[14], body[15]]), token.len() as u16);
        // Token appears at end
        assert_eq!(&body[24..], token);
    }
}
