//! Minimal SMB2 client for reading and writing remote Windows named pipes.
//!
//! This crate implements just enough of the SMB2 protocol to connect to a
//! remote named pipe, authenticate with NTLM, and expose the pipe as an
//! `AsyncRead + AsyncWrite` stream. It is not a general-purpose SMB client.
//!
//! Call [`set_verbose(true)`] before connecting to enable diagnostic output
//! on stderr.

use std::sync::atomic::{AtomicBool, Ordering};

pub mod auth;
pub mod client;
pub mod ntlm;
pub mod protocol;
pub mod session;
pub mod transport;

/// Global verbose flag.
static VERBOSE: AtomicBool = AtomicBool::new(false);

/// Enable or disable verbose diagnostic logging on stderr.
pub fn set_verbose(enabled: bool) {
    VERBOSE.store(enabled, Ordering::Relaxed);
}

/// Returns `true` if verbose diagnostic logging is enabled.
pub fn verbose() -> bool {
    VERBOSE.load(Ordering::Relaxed)
}

/// Format an NT status code as a human-readable name (or hex).
pub fn status_name(status: u32) -> String {
    match status {
        protocol::STATUS_SUCCESS => "STATUS_SUCCESS".to_string(),
        protocol::STATUS_PENDING => "STATUS_PENDING".to_string(),
        protocol::STATUS_MORE_PROCESSING_REQUIRED => "STATUS_MORE_PROCESSING_REQUIRED".to_string(),
        protocol::STATUS_BUFFER_OVERFLOW => "STATUS_BUFFER_OVERFLOW".to_string(),
        protocol::STATUS_PIPE_DISCONNECTED => "STATUS_PIPE_DISCONNECTED".to_string(),
        protocol::STATUS_PIPE_CLOSING => "STATUS_PIPE_CLOSING".to_string(),
        protocol::STATUS_PIPE_BROKEN => "STATUS_PIPE_BROKEN".to_string(),
        protocol::STATUS_PIPE_EMPTY => "STATUS_PIPE_EMPTY".to_string(),
        protocol::STATUS_END_OF_FILE => "STATUS_END_OF_FILE".to_string(),
        _ => format!("0x{status:08X}"),
    }
}
