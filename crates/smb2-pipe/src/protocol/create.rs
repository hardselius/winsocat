//! SMB2 CREATE request/response.
//!
//! Used to open a named pipe on the remote server. We open with
//! read/write access and specify pipe-appropriate disposition/options.

use std::io::{self, Cursor};

use super::{read_u16_le, read_u32_le, read_u64_le, skip};

// ── Access mask flags ───────────────────────────────────────────────────

/// Generic read access.
pub const FILE_READ_DATA: u32 = 0x0000_0001;
/// Generic write access.
pub const FILE_WRITE_DATA: u32 = 0x0000_0002;
/// Append data.
pub const FILE_APPEND_DATA: u32 = 0x0000_0004;
/// Read attributes.
pub const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
/// Read/write/execute for the pipe.
pub const GENERIC_ALL: u32 = 0x1000_0000;

// ── Share access ────────────────────────────────────────────────────────

/// Allow others to read.
pub const FILE_SHARE_READ: u32 = 0x0000_0001;
/// Allow others to write.
pub const FILE_SHARE_WRITE: u32 = 0x0000_0002;

// ── Create disposition ──────────────────────────────────────────────────

/// Open existing file/pipe.
pub const FILE_OPEN: u32 = 0x0000_0001;

// ── Create options ──────────────────────────────────────────────────────

/// Non-directory file.
pub const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;

// ── Impersonation levels ────────────────────────────────────────────────

/// Impersonation level: Impersonation.
pub const SECURITY_IMPERSONATION: u32 = 0x0000_0002;

// ── File ID ─────────────────────────────────────────────────────────────

/// An SMB2 file handle (16 bytes: persistent + volatile).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileId {
    pub persistent: u64,
    pub volatile: u64,
}

impl FileId {
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.persistent.to_le_bytes());
        out.extend_from_slice(&self.volatile.to_le_bytes());
    }
}

// ── Request ─────────────────────────────────────────────────────────────

/// Encode an SMB2 CREATE request body to open a named pipe.
///
/// `pipe_name` is the pipe name without the leading backslash,
/// e.g. `my_pipe` for `\\server\IPC$\my_pipe`.
pub fn encode_create_request(pipe_name: &str) -> Vec<u8> {
    let name_utf16: Vec<u8> = pipe_name
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    let mut body = Vec::new();

    // StructureSize (2) — always 57
    body.extend_from_slice(&57u16.to_le_bytes());
    // SecurityFlags (1) — 0
    body.push(0);
    // RequestedOplockLevel (1) — none
    body.push(0);
    // ImpersonationLevel (4)
    body.extend_from_slice(&SECURITY_IMPERSONATION.to_le_bytes());
    // SmbCreateFlags (8) — 0
    body.extend_from_slice(&0u64.to_le_bytes());
    // Reserved (8)
    body.extend_from_slice(&0u64.to_le_bytes());
    // DesiredAccess (4)
    let access = FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_READ_ATTRIBUTES;
    body.extend_from_slice(&access.to_le_bytes());
    // FileAttributes (4) — 0 (not applicable for pipes)
    body.extend_from_slice(&0u32.to_le_bytes());
    // ShareAccess (4)
    body.extend_from_slice(&(FILE_SHARE_READ | FILE_SHARE_WRITE).to_le_bytes());
    // CreateDisposition (4)
    body.extend_from_slice(&FILE_OPEN.to_le_bytes());
    // CreateOptions (4)
    body.extend_from_slice(&FILE_NON_DIRECTORY_FILE.to_le_bytes());
    // NameOffset (2) — offset from start of SMB2 header
    // Header(64) + body fixed part(56) = 120
    let name_offset: u16 = 64 + 56;
    body.extend_from_slice(&name_offset.to_le_bytes());
    // NameLength (2) — in bytes, UTF-16LE
    body.extend_from_slice(&(name_utf16.len() as u16).to_le_bytes());
    // CreateContextsOffset (4) — 0 (no create contexts)
    body.extend_from_slice(&0u32.to_le_bytes());
    // CreateContextsLength (4) — 0
    body.extend_from_slice(&0u32.to_le_bytes());
    // Name (variable)
    body.extend_from_slice(&name_utf16);

    body
}

// ── Response ────────────────────────────────────────────────────────────

/// Parsed SMB2 CREATE response (fields we care about).
#[derive(Debug)]
pub struct CreateResponse {
    /// Oplock level granted.
    pub oplock_level: u8,
    /// Create action taken.
    pub create_action: u32,
    /// File ID (handle to the opened pipe).
    pub file_id: FileId,
}

/// Decode an SMB2 CREATE response body.
pub fn decode_create_response(body: &[u8]) -> io::Result<CreateResponse> {
    let mut cursor = Cursor::new(body);

    let _structure_size = read_u16_le(&mut cursor)?; // 89
    let oplock_level = {
        let mut buf = [0u8; 1];
        std::io::Read::read_exact(&mut cursor, &mut buf)?;
        buf[0]
    };
    skip(&mut cursor, 1)?; // Flags
    let create_action = read_u32_le(&mut cursor)?;
    let _creation_time = read_u64_le(&mut cursor)?;
    let _last_access_time = read_u64_le(&mut cursor)?;
    let _last_write_time = read_u64_le(&mut cursor)?;
    let _change_time = read_u64_le(&mut cursor)?;
    let _allocation_size = read_u64_le(&mut cursor)?;
    let _end_of_file = read_u64_le(&mut cursor)?;
    let _file_attributes = read_u32_le(&mut cursor)?;
    skip(&mut cursor, 4)?; // Reserved2

    let persistent = read_u64_le(&mut cursor)?;
    let volatile = read_u64_le(&mut cursor)?;
    let file_id = FileId {
        persistent,
        volatile,
    };

    // We skip CreateContextsOffset/Length — not needed.

    Ok(CreateResponse {
        oplock_level,
        create_action,
        file_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_request_encoding() {
        let body = encode_create_request("testpipe");
        // StructureSize = 57
        assert_eq!(u16::from_le_bytes([body[0], body[1]]), 57);
        // NameOffset = 120 (at body offset 44)
        assert_eq!(u16::from_le_bytes([body[44], body[45]]), 120);
        // NameLength = 16 (8 chars × 2 bytes UTF-16LE, at body offset 46)
        assert_eq!(u16::from_le_bytes([body[46], body[47]]), 16);
        // Total: 56 fixed + 16 name = 72
        assert_eq!(body.len(), 72);
    }

    #[test]
    fn file_id_encode() {
        let fid = FileId {
            persistent: 0x1122_3344_5566_7788,
            volatile: 0xAABB_CCDD_EEFF_0011,
        };
        let mut buf = Vec::new();
        fid.encode(&mut buf);
        assert_eq!(buf.len(), 16);
        assert_eq!(
            u64::from_le_bytes(buf[0..8].try_into().unwrap()),
            fid.persistent
        );
        assert_eq!(
            u64::from_le_bytes(buf[8..16].try_into().unwrap()),
            fid.volatile
        );
    }
}
