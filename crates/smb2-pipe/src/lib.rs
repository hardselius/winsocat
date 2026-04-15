//! Minimal SMB2 client for reading and writing remote Windows named pipes.
//!
//! This crate implements just enough of the SMB2 protocol to connect to a
//! remote named pipe, authenticate with NTLM, and expose the pipe as an
//! `AsyncRead + AsyncWrite` stream. It is not a general-purpose SMB client.
