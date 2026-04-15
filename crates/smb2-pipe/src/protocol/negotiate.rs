//! SMB2 NEGOTIATE request/response.
//!
//! We negotiate SMB 2.1 (dialect 0x0210) with no special capabilities.

use std::io::{self, Cursor};

use super::{read_bytes, read_u16_le, read_u32_le, read_u64_le};

/// SMB2 dialect 2.1
pub const DIALECT_SMB_2_1: u16 = 0x0210;

/// SMB2 dialect 3.0
pub const DIALECT_SMB_3_0: u16 = 0x0300;

// ── Request ─────────────────────────────────────────────────────────────

/// Encode an SMB2 NEGOTIATE request body.
///
/// We offer SMB 2.1 as the only dialect, which keeps things simple and
/// avoids the need for encryption/signing negotiation.
pub fn encode_negotiate_request(dialects: &[u16]) -> Vec<u8> {
    let mut body = Vec::new();

    // StructureSize (2) — always 36
    body.extend_from_slice(&36u16.to_le_bytes());
    // DialectCount (2)
    body.extend_from_slice(&(dialects.len() as u16).to_le_bytes());
    // SecurityMode (2) — signing enabled but not required
    body.extend_from_slice(&0x0001u16.to_le_bytes());
    // Reserved (2)
    body.extend_from_slice(&0u16.to_le_bytes());
    // Capabilities (4) — none
    body.extend_from_slice(&0u32.to_le_bytes());
    // ClientGuid (16) — all zeros (anonymous)
    body.extend_from_slice(&[0u8; 16]);
    // ClientStartTime (8) — zero (not used for dialect ≤ 0x0311)
    body.extend_from_slice(&0u64.to_le_bytes());
    // Dialects (2 bytes each)
    for &dialect in dialects {
        body.extend_from_slice(&dialect.to_le_bytes());
    }

    body
}

// ── Response ────────────────────────────────────────────────────────────

/// Parsed SMB2 NEGOTIATE response (fields we care about).
#[derive(Debug)]
pub struct NegotiateResponse {
    /// Negotiated dialect (e.g. 0x0210 for SMB 2.1).
    pub dialect_revision: u16,
    /// Server security mode flags.
    pub security_mode: u16,
    /// Server GUID.
    pub server_guid: [u8; 16],
    /// Server capabilities flags.
    pub capabilities: u32,
    /// Max transact size.
    pub max_transact_size: u32,
    /// Max read size.
    pub max_read_size: u32,
    /// Max write size.
    pub max_write_size: u32,
    /// Security buffer (SPNEGO/NTLMSSP init token).
    pub security_buffer: Vec<u8>,
}

/// Decode an SMB2 NEGOTIATE response body.
pub fn decode_negotiate_response(body: &[u8]) -> io::Result<NegotiateResponse> {
    let mut cursor = Cursor::new(body);

    let _structure_size = read_u16_le(&mut cursor)?; // 65
    let security_mode = read_u16_le(&mut cursor)?;
    let dialect_revision = read_u16_le(&mut cursor)?;
    let _negotiate_context_count = read_u16_le(&mut cursor)?; // reserved for 2.1

    let mut server_guid = [0u8; 16];
    cursor.set_position(cursor.position()); // noop, just for clarity
    let guid_bytes = read_bytes(&mut cursor, 16)?;
    server_guid.copy_from_slice(&guid_bytes);

    let capabilities = read_u32_le(&mut cursor)?;
    let max_transact_size = read_u32_le(&mut cursor)?;
    let max_read_size = read_u32_le(&mut cursor)?;
    let max_write_size = read_u32_le(&mut cursor)?;
    let _system_time = read_u64_le(&mut cursor)?;
    let _server_start_time = read_u64_le(&mut cursor)?;

    let security_buffer_offset = read_u16_le(&mut cursor)?;
    let security_buffer_length = read_u16_le(&mut cursor)?;

    let _negotiate_context_offset = read_u32_le(&mut cursor)?;

    // SecurityBuffer starts at offset relative to the beginning of the
    // SMB2 header. We receive only the body here, so we adjust:
    // offset_in_body = security_buffer_offset - 64 (header size)
    let buf_start = security_buffer_offset as usize - 64;
    let buf_end = buf_start + security_buffer_length as usize;
    let security_buffer = if buf_end <= body.len() {
        body[buf_start..buf_end].to_vec()
    } else {
        Vec::new()
    };

    Ok(NegotiateResponse {
        dialect_revision,
        security_mode,
        server_guid,
        capabilities,
        max_transact_size,
        max_read_size,
        max_write_size,
        security_buffer,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiate_request_encoding() {
        let body = encode_negotiate_request(&[DIALECT_SMB_2_1]);
        // StructureSize(2) + DialectCount(2) + SecurityMode(2) + Reserved(2)
        // + Capabilities(4) + ClientGuid(16) + ClientStartTime(8) + Dialect(2) = 38
        assert_eq!(body.len(), 38);
        // StructureSize = 36
        assert_eq!(u16::from_le_bytes([body[0], body[1]]), 36);
        // DialectCount = 1
        assert_eq!(u16::from_le_bytes([body[2], body[3]]), 1);
        // Dialect at the end
        assert_eq!(u16::from_le_bytes([body[36], body[37]]), DIALECT_SMB_2_1);
    }

    #[test]
    fn negotiate_request_multiple_dialects() {
        let body = encode_negotiate_request(&[DIALECT_SMB_2_1, DIALECT_SMB_3_0]);
        // 36 (fixed) + 4 (2 dialects × 2 bytes) = 40
        assert_eq!(body.len(), 40);
        assert_eq!(u16::from_le_bytes([body[2], body[3]]), 2);
    }
}
