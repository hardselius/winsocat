//! SMB2 session establishment: negotiate, authenticate, and connect to IPC$.
//!
//! This module orchestrates the SMB2 connection setup sequence:
//!
//! 1. TCP connect to port 445
//! 2. SMB2 NEGOTIATE
//! 3. SMB2 SESSION_SETUP (NTLM Type 1 → server challenge → NTLM Type 3)
//! 4. SMB2 TREE_CONNECT to `\\server\IPC$`
//! 5. SMB2 CREATE to open the named pipe

use anyhow::{bail, Context, Result};
use tokio::net::TcpStream;

use crate::auth::Auth;
use crate::ntlm;
use crate::protocol::create::FileId;
use crate::protocol::{
    self, Smb2Command, Smb2Header, STATUS_MORE_PROCESSING_REQUIRED, STATUS_SUCCESS,
};
use crate::transport;
use crate::{status_name, verbose};

/// State for an established SMB2 session.
#[derive(Debug)]
pub struct Session {
    /// The TCP stream to the SMB2 server.
    pub stream: TcpStream,
    /// Session ID assigned by the server.
    pub session_id: u64,
    /// Tree ID for the IPC$ share.
    pub tree_id: u32,
    /// File ID (handle) for the opened pipe.
    pub file_id: FileId,
    /// Monotonically increasing message ID.
    pub message_id: u64,
    /// Server's max read size.
    pub max_read_size: u32,
    /// Server's max write size.
    pub max_write_size: u32,
}

impl Session {
    /// Establish an SMB2 session and open a named pipe.
    ///
    /// `server` is the hostname or IP address of the SMB server.
    /// `port` is the TCP port (usually 445).
    /// `pipe_name` is the pipe name without leading backslash, e.g. `"my_pipe"`.
    /// `auth` specifies the authentication method.
    pub async fn connect(server: &str, port: u16, pipe_name: &str, auth: &Auth) -> Result<Self> {
        // 1. TCP connect
        let addr = format!("{server}:{port}");
        let mut stream = TcpStream::connect(&addr)
            .await
            .with_context(|| format!("failed to connect to {addr}"))?;

        let mut message_id: u64 = 0;

        // 2. SMB2 NEGOTIATE
        let (max_read_size, max_write_size) = smb2_negotiate(&mut stream, &mut message_id).await?;

        // 3. SMB2 SESSION_SETUP (NTLM two-leg)
        let session_id = smb2_session_setup(&mut stream, &mut message_id, auth).await?;

        // 4. SMB2 TREE_CONNECT to \\server\IPC$
        let ipc_path = format!(r"\\{server}\IPC$");
        let tree_id =
            smb2_tree_connect(&mut stream, &mut message_id, session_id, &ipc_path).await?;

        // 5. SMB2 CREATE to open the pipe
        let file_id =
            smb2_create(&mut stream, &mut message_id, session_id, tree_id, pipe_name).await?;

        Ok(Session {
            stream,
            session_id,
            tree_id,
            file_id,
            message_id,
            max_read_size,
            max_write_size,
        })
    }

    /// Gracefully close the pipe, disconnect tree, and log off.
    pub async fn close(&mut self) -> Result<()> {
        // Close the pipe handle
        smb2_close(
            &mut self.stream,
            &mut self.message_id,
            self.session_id,
            self.tree_id,
            &self.file_id,
        )
        .await
        .ok(); // Best-effort

        // Tree disconnect
        smb2_tree_disconnect(
            &mut self.stream,
            &mut self.message_id,
            self.session_id,
            self.tree_id,
        )
        .await
        .ok();

        // Logoff
        smb2_logoff(&mut self.stream, &mut self.message_id, self.session_id)
            .await
            .ok();

        Ok(())
    }
}

// ── Step helpers ────────────────────────────────────────────────────────

async fn smb2_negotiate(stream: &mut TcpStream, message_id: &mut u64) -> Result<(u32, u32)> {
    let hdr = Smb2Header::new_request(Smb2Command::Negotiate, *message_id);
    *message_id += 1;

    let body =
        protocol::negotiate::encode_negotiate_request(&[protocol::negotiate::DIALECT_SMB_2_1]);

    transport::send_message(stream, &hdr, &body).await?;
    let resp = transport::recv_message(stream).await?;

    if verbose() {
        eprintln!(
            "[smb2] NEGOTIATE response: status={} credits={}",
            status_name(resp.header.status),
            resp.header.credit_request_response,
        );
    }

    if resp.header.status != STATUS_SUCCESS {
        bail!("NEGOTIATE failed: NT status 0x{:08X}", resp.header.status);
    }

    let neg = protocol::negotiate::decode_negotiate_response(&resp.body)
        .context("failed to parse NEGOTIATE response")?;

    if verbose() {
        eprintln!(
            "[smb2] NEGOTIATE: dialect=0x{:04X} security_mode=0x{:04X} \
             max_read={} max_write={} max_transact={} caps=0x{:08X}",
            neg.dialect_revision,
            neg.security_mode,
            neg.max_read_size,
            neg.max_write_size,
            neg.max_transact_size,
            neg.capabilities,
        );
    }

    if neg.dialect_revision != protocol::negotiate::DIALECT_SMB_2_1 {
        bail!(
            "server negotiated unexpected dialect: 0x{:04X}",
            neg.dialect_revision
        );
    }

    Ok((neg.max_read_size, neg.max_write_size))
}

async fn smb2_session_setup(
    stream: &mut TcpStream,
    message_id: &mut u64,
    auth: &Auth,
) -> Result<u64> {
    let workstation = "WINSOCAT";

    // --- Leg 1: Send NTLM Negotiate (Type 1) ---
    let negotiate_token = match auth {
        Auth::Ntlm { .. } => ntlm::negotiate_token(workstation)?,
        Auth::Anonymous => ntlm::anonymous_negotiate_token()?,
    };

    if verbose() {
        eprintln!(
            "[smb2] SESSION_SETUP leg 1: sending {} byte NTLM negotiate token",
            negotiate_token.len()
        );
    }

    let hdr = Smb2Header::new_request(Smb2Command::SessionSetup, *message_id);
    *message_id += 1;

    let body = protocol::session_setup::encode_session_setup_request(&negotiate_token, 0);

    transport::send_message(stream, &hdr, &body).await?;
    let resp = transport::recv_message(stream).await?;

    if verbose() {
        eprintln!(
            "[smb2] SESSION_SETUP leg 1 response: status={} session_id=0x{:016X}",
            status_name(resp.header.status),
            resp.header.session_id,
        );
    }

    if resp.header.status != STATUS_MORE_PROCESSING_REQUIRED {
        bail!(
            "SESSION_SETUP leg 1 failed: expected STATUS_MORE_PROCESSING_REQUIRED, \
             got NT status 0x{:08X}",
            resp.header.status
        );
    }

    let session_id = resp.header.session_id;

    let setup_resp = protocol::session_setup::decode_session_setup_response(&resp.body)
        .context("failed to parse SESSION_SETUP response (leg 1)")?;

    // --- Leg 2: Send NTLM Authenticate (Type 3) ---
    let auth_token = match auth {
        Auth::Ntlm {
            username,
            password,
            domain,
        } => ntlm::authenticate_token(
            &setup_resp.security_buffer,
            username,
            password,
            domain,
            workstation,
        )?,
        Auth::Anonymous => ntlm::anonymous_authenticate_token(&setup_resp.security_buffer)?,
    };

    if verbose() {
        eprintln!(
            "[smb2] SESSION_SETUP leg 2: sending {} byte NTLM auth token",
            auth_token.len()
        );
    }

    let mut hdr = Smb2Header::new_request(Smb2Command::SessionSetup, *message_id);
    hdr.session_id = session_id;
    *message_id += 1;

    let body = protocol::session_setup::encode_session_setup_request(&auth_token, 0);

    transport::send_message(stream, &hdr, &body).await?;
    let resp = transport::recv_message(stream).await?;

    if verbose() {
        eprintln!(
            "[smb2] SESSION_SETUP leg 2 response: status={}",
            status_name(resp.header.status),
        );
    }

    if resp.header.status != STATUS_SUCCESS {
        bail!(
            "SESSION_SETUP leg 2 failed: NT status 0x{:08X}",
            resp.header.status
        );
    }

    Ok(session_id)
}

async fn smb2_tree_connect(
    stream: &mut TcpStream,
    message_id: &mut u64,
    session_id: u64,
    path: &str,
) -> Result<u32> {
    if verbose() {
        eprintln!("[smb2] TREE_CONNECT: path={path}");
    }

    let mut hdr = Smb2Header::new_request(Smb2Command::TreeConnect, *message_id);
    hdr.session_id = session_id;
    *message_id += 1;

    let body = protocol::tree_connect::encode_tree_connect_request(path);

    transport::send_message(stream, &hdr, &body).await?;
    let resp = transport::recv_message(stream).await?;

    if verbose() {
        eprintln!(
            "[smb2] TREE_CONNECT response: status={} tree_id={}",
            status_name(resp.header.status),
            resp.header.tree_id,
        );
    }

    if resp.header.status != STATUS_SUCCESS {
        bail!(
            "TREE_CONNECT failed: NT status 0x{:08X}",
            resp.header.status
        );
    }

    let tree = protocol::tree_connect::decode_tree_connect_response(&resp.body)
        .context("failed to parse TREE_CONNECT response")?;

    if verbose() {
        eprintln!("[smb2] TREE_CONNECT: share_type=0x{:02X}", tree.share_type);
    }

    // share_type 0x02 = named pipe
    if tree.share_type != 0x02 {
        bail!(
            "expected named pipe share (type 0x02), got type 0x{:02X}",
            tree.share_type
        );
    }

    Ok(resp.header.tree_id)
}

async fn smb2_create(
    stream: &mut TcpStream,
    message_id: &mut u64,
    session_id: u64,
    tree_id: u32,
    pipe_name: &str,
) -> Result<FileId> {
    if verbose() {
        eprintln!("[smb2] CREATE: pipe_name={pipe_name}");
    }

    let mut hdr = Smb2Header::new_request(Smb2Command::Create, *message_id);
    hdr.session_id = session_id;
    hdr.tree_id = tree_id;
    *message_id += 1;

    let body = protocol::create::encode_create_request(pipe_name);

    transport::send_message(stream, &hdr, &body).await?;
    let resp = transport::recv_message(stream).await?;

    if verbose() {
        eprintln!(
            "[smb2] CREATE response: status={}",
            status_name(resp.header.status),
        );
    }

    if resp.header.status != STATUS_SUCCESS {
        bail!("CREATE failed: NT status 0x{:08X}", resp.header.status);
    }

    let create = protocol::create::decode_create_response(&resp.body)
        .context("failed to parse CREATE response")?;

    if verbose() {
        eprintln!(
            "[smb2] CREATE: file_id=({:016X},{:016X}) action={}",
            create.file_id.persistent, create.file_id.volatile, create.create_action,
        );
    }

    Ok(create.file_id)
}

async fn smb2_close(
    stream: &mut TcpStream,
    message_id: &mut u64,
    session_id: u64,
    tree_id: u32,
    file_id: &FileId,
) -> Result<()> {
    let mut hdr = Smb2Header::new_request(Smb2Command::Close, *message_id);
    hdr.session_id = session_id;
    hdr.tree_id = tree_id;
    *message_id += 1;

    let body = protocol::close::encode_close_request(file_id);

    transport::send_message(stream, &hdr, &body).await?;
    let resp = transport::recv_message(stream).await?;

    if resp.header.status != STATUS_SUCCESS {
        bail!("CLOSE failed: NT status 0x{:08X}", resp.header.status);
    }

    Ok(())
}

async fn smb2_tree_disconnect(
    stream: &mut TcpStream,
    message_id: &mut u64,
    session_id: u64,
    tree_id: u32,
) -> Result<()> {
    let mut hdr = Smb2Header::new_request(Smb2Command::TreeDisconnect, *message_id);
    hdr.session_id = session_id;
    hdr.tree_id = tree_id;
    *message_id += 1;

    let body = protocol::tree_disconnect::encode_tree_disconnect_request();

    transport::send_message(stream, &hdr, &body).await?;
    let resp = transport::recv_message(stream).await?;

    if resp.header.status != STATUS_SUCCESS {
        bail!(
            "TREE_DISCONNECT failed: NT status 0x{:08X}",
            resp.header.status
        );
    }

    Ok(())
}

async fn smb2_logoff(stream: &mut TcpStream, message_id: &mut u64, session_id: u64) -> Result<()> {
    let mut hdr = Smb2Header::new_request(Smb2Command::Logoff, *message_id);
    hdr.session_id = session_id;
    *message_id += 1;

    let body = protocol::logoff::encode_logoff_request();

    transport::send_message(stream, &hdr, &body).await?;
    let resp = transport::recv_message(stream).await?;

    if resp.header.status != STATUS_SUCCESS {
        bail!("LOGOFF failed: NT status 0x{:08X}", resp.header.status);
    }

    Ok(())
}
