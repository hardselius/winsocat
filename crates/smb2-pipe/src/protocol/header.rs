//! SMB2 packet header (64 bytes).

use std::io::{self, Cursor, Read};

use super::{read_u16_le, read_u32_le, read_u64_le, SMB2_MAGIC};

/// SMB2 command codes used by this crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum Smb2Command {
    Negotiate = 0x0000,
    SessionSetup = 0x0001,
    Logoff = 0x0002,
    TreeConnect = 0x0003,
    TreeDisconnect = 0x0004,
    Create = 0x0005,
    Close = 0x0006,
    Read = 0x0008,
    Write = 0x0009,
}

impl Smb2Command {
    pub fn from_u16(v: u16) -> io::Result<Self> {
        match v {
            0x0000 => Ok(Self::Negotiate),
            0x0001 => Ok(Self::SessionSetup),
            0x0002 => Ok(Self::Logoff),
            0x0003 => Ok(Self::TreeConnect),
            0x0004 => Ok(Self::TreeDisconnect),
            0x0005 => Ok(Self::Create),
            0x0006 => Ok(Self::Close),
            0x0008 => Ok(Self::Read),
            0x0009 => Ok(Self::Write),
            other => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown SMB2 command: 0x{other:04X}"),
            )),
        }
    }
}

/// SMB2 header flags.
pub struct Smb2Flags;

impl Smb2Flags {
    /// This message is a response (set by the server).
    pub const SERVER_TO_REDIR: u32 = 0x0000_0001;
}

/// The 64-byte SMB2 packet header.
///
/// Fields we don't actively use are preserved as raw bytes so that
/// round-tripping works for debugging.
#[derive(Debug, Clone)]
pub struct Smb2Header {
    /// Structure size — always 64.
    pub structure_size: u16,
    /// Credit charge (usually 1 for our messages).
    pub credit_charge: u16,
    /// NT status code (responses) or channel sequence (requests).
    pub status: u32,
    /// Command code.
    pub command: Smb2Command,
    /// Credits requested/granted.
    pub credit_request_response: u16,
    /// Flags (see [`Smb2Flags`]).
    pub flags: u32,
    /// Chain offset (0 for non-compounded).
    pub next_command: u32,
    /// Message ID — monotonically increasing per connection.
    pub message_id: u64,
    /// Reserved / async ID.
    pub async_id: u64,
    /// Session ID.
    pub session_id: u64,
    /// Signature (16 bytes, all zeros when unsigned).
    pub signature: [u8; 16],
    /// Tree ID (stored in the async_id field's upper 32 bits for sync).
    pub tree_id: u32,
}

impl Smb2Header {
    /// Create a new request header with sensible defaults.
    pub fn new_request(command: Smb2Command, message_id: u64) -> Self {
        Self {
            structure_size: 64,
            credit_charge: 1,
            status: 0,
            command,
            // Request multiple credits so concurrent READ+WRITE can
            // both be in-flight. Servers may grant fewer, but asking
            // for a reasonable number avoids credit starvation.
            credit_request_response: 16,
            flags: 0,
            next_command: 0,
            message_id,
            async_id: 0,
            session_id: 0,
            tree_id: 0,
            signature: [0u8; 16],
        }
    }

    /// Encode this header into `out` (appends exactly 64 bytes).
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&SMB2_MAGIC);
        out.extend_from_slice(&self.structure_size.to_le_bytes());
        out.extend_from_slice(&self.credit_charge.to_le_bytes());
        out.extend_from_slice(&self.status.to_le_bytes());
        out.extend_from_slice(&(self.command as u16).to_le_bytes());
        out.extend_from_slice(&self.credit_request_response.to_le_bytes());
        out.extend_from_slice(&self.flags.to_le_bytes());
        out.extend_from_slice(&self.next_command.to_le_bytes());
        out.extend_from_slice(&self.message_id.to_le_bytes());
        // For synchronous requests: ProcessId (4 bytes) + TreeId (4 bytes)
        // replaces the 8-byte AsyncId field.
        out.extend_from_slice(&0u32.to_le_bytes()); // ProcessId (reserved)
        out.extend_from_slice(&self.tree_id.to_le_bytes());
        out.extend_from_slice(&self.session_id.to_le_bytes());
        out.extend_from_slice(&self.signature);
    }

    /// Decode a 64-byte header from `data`.
    pub fn decode(data: &[u8]) -> io::Result<Self> {
        if data.len() < 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "header too short",
            ));
        }

        let mut cursor = Cursor::new(data);

        // Magic
        let mut magic = [0u8; 4];
        cursor.read_exact(&mut magic)?;
        if magic != SMB2_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bad SMB2 magic: {magic:02X?}"),
            ));
        }

        let structure_size = read_u16_le(&mut cursor)?;
        let credit_charge = read_u16_le(&mut cursor)?;
        let status = read_u32_le(&mut cursor)?;
        let command_raw = read_u16_le(&mut cursor)?;
        let command = Smb2Command::from_u16(command_raw)?;
        let credit_request_response = read_u16_le(&mut cursor)?;
        let flags = read_u32_le(&mut cursor)?;
        let next_command = read_u32_le(&mut cursor)?;
        let message_id = read_u64_le(&mut cursor)?;

        // Sync: ProcessId(4) + TreeId(4), or Async: AsyncId(8)
        let _process_id = read_u32_le(&mut cursor)?;
        let tree_id = read_u32_le(&mut cursor)?;
        let async_id = 0; // we only use sync

        let session_id = read_u64_le(&mut cursor)?;

        let mut signature = [0u8; 16];
        cursor.read_exact(&mut signature)?;

        Ok(Self {
            structure_size,
            credit_charge,
            status,
            command,
            credit_request_response,
            flags,
            next_command,
            message_id,
            async_id,
            session_id,
            tree_id,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let mut hdr = Smb2Header::new_request(Smb2Command::Negotiate, 0);
        hdr.session_id = 0xDEAD_BEEF;
        hdr.tree_id = 42;

        let mut buf = Vec::new();
        hdr.encode(&mut buf);
        assert_eq!(buf.len(), 64);

        let decoded = Smb2Header::decode(&buf).unwrap();
        assert_eq!(decoded.command, Smb2Command::Negotiate);
        assert_eq!(decoded.session_id, 0xDEAD_BEEF);
        assert_eq!(decoded.tree_id, 42);
        assert_eq!(decoded.message_id, 0);
        assert_eq!(decoded.structure_size, 64);
    }

    #[test]
    fn header_bad_magic() {
        let buf = [0u8; 64];
        let err = Smb2Header::decode(&buf).unwrap_err();
        assert!(err.to_string().contains("bad SMB2 magic"));
    }

    #[test]
    fn command_from_u16_known() {
        assert_eq!(
            Smb2Command::from_u16(0x0000).unwrap(),
            Smb2Command::Negotiate
        );
        assert_eq!(Smb2Command::from_u16(0x0009).unwrap(), Smb2Command::Write);
    }

    #[test]
    fn command_from_u16_unknown() {
        assert!(Smb2Command::from_u16(0xFFFF).is_err());
    }
}
