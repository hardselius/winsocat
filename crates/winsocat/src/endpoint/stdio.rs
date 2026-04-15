use anyhow::Result;
use tokio::io::{self, AsyncRead, AsyncWrite};

use super::{BoxedStream, Connector};
use crate::address::AddressElement;

/// Wrapper that joins tokio stdin + stdout into a single AsyncRead+AsyncWrite.
struct StdioPair {
    stdin: io::Stdin,
    stdout: io::Stdout,
}

impl AsyncRead for StdioPair {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.stdin).poll_read(cx, buf)
    }
}

impl AsyncWrite for StdioPair {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.stdout).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.stdout).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.stdout).poll_shutdown(cx)
    }
}

pub struct StdioConnector;

#[async_trait::async_trait]
impl Connector for StdioConnector {
    async fn connect(&self) -> Result<BoxedStream> {
        Ok(Box::new(StdioPair {
            stdin: io::stdin(),
            stdout: io::stdout(),
        }))
    }
}

pub fn try_parse_strategy(elem: &AddressElement) -> Option<StdioConnector> {
    if elem.tag.eq_ignore_ascii_case("STDIO") {
        Some(StdioConnector)
    } else {
        None
    }
}

pub fn try_parse_factory(elem: &AddressElement) -> Option<StdioConnector> {
    try_parse_strategy(elem)
}
