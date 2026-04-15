//! SMB2 TREE_CONNECT request/response.
//!
//! Used to connect to a share (we always connect to `\\server\IPC$`).

use std::io::{self, Cursor};

use super::{read_u16_le, read_u32_le, skip};

// ── Request ─────────────────────────────────────────────────────────────

/// Encode an SMB2 TREE_CONNECT request body.
///
/// `path` is the UNC share path, e.g. `\\server\IPC$`, encoded as UTF-16LE.
pub fn encode_tree_connect_request(path: &str) -> Vec<u8> {
    let path_utf16: Vec<u8> = path.encode_utf16().flat_map(|c| c.to_le_bytes()).collect();

    let mut body = Vec::new();

    // StructureSize (2) — always 9
    body.extend_from_slice(&9u16.to_le_bytes());
    // Reserved / Flags (2) — 0
    body.extend_from_slice(&0u16.to_le_bytes());
    // PathOffset (2) — offset from start of SMB2 header
    // Header(64) + body fixed part(8) = 72
    let offset: u16 = 64 + 8;
    body.extend_from_slice(&offset.to_le_bytes());
    // PathLength (2) — in bytes, UTF-16LE
    body.extend_from_slice(&(path_utf16.len() as u16).to_le_bytes());
    // Path (variable)
    body.extend_from_slice(&path_utf16);

    body
}

// ── Response ────────────────────────────────────────────────────────────

/// Parsed SMB2 TREE_CONNECT response.
#[derive(Debug)]
pub struct TreeConnectResponse {
    /// Share type (0x01 = disk, 0x02 = named pipe, 0x03 = print).
    pub share_type: u8,
    /// Share flags.
    pub share_flags: u32,
    /// Share capabilities.
    pub share_capabilities: u32,
    /// Maximal access rights.
    pub maximal_access: u32,
}

/// Decode an SMB2 TREE_CONNECT response body.
pub fn decode_tree_connect_response(body: &[u8]) -> io::Result<TreeConnectResponse> {
    let mut cursor = Cursor::new(body);

    let _structure_size = read_u16_le(&mut cursor)?; // 16
    let share_type = {
        let mut buf = [0u8; 1];
        std::io::Read::read_exact(&mut cursor, &mut buf)?;
        buf[0]
    };
    skip(&mut cursor, 1)?; // Reserved
    let share_flags = read_u32_le(&mut cursor)?;
    let share_capabilities = read_u32_le(&mut cursor)?;
    let maximal_access = read_u32_le(&mut cursor)?;

    Ok(TreeConnectResponse {
        share_type,
        share_flags,
        share_capabilities,
        maximal_access,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tree_connect_request_encoding() {
        let body = encode_tree_connect_request(r"\\server\IPC$");
        // StructureSize = 9
        assert_eq!(u16::from_le_bytes([body[0], body[1]]), 9);
        // PathOffset = 72
        assert_eq!(u16::from_le_bytes([body[4], body[5]]), 72);
        // Path is UTF-16LE — "\\server\IPC$" is 13 chars = 26 bytes
        let path_len = u16::from_le_bytes([body[6], body[7]]);
        assert_eq!(path_len, 26);
    }
}
