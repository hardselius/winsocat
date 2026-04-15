use anyhow::Result;
use tokio::io::{self, AsyncRead, AsyncWrite};
use tokio::net::windows::named_pipe::{ClientOptions, ServerOptions};

use super::{BoxedStream, Connector, Listener};
use crate::address::AddressElement;

#[derive(Debug, Clone)]
pub struct NamedPipeStreamConfig {
    pub server_name: String,
    pub pipe_name: String,
}

#[derive(Debug, Clone)]
pub struct NamedPipeListenConfig {
    pub pipe_name: String,
}

impl NamedPipeStreamConfig {
    /// Full pipe path: `\\server\pipe\name`
    pub fn pipe_path(&self) -> String {
        format!("\\\\{}\\pipe\\{}", self.server_name, self.pipe_name)
    }
}

impl NamedPipeListenConfig {
    pub fn pipe_path(&self) -> String {
        format!("\\\\.\\pipe\\{}", self.pipe_name)
    }
}

pub fn try_parse_npipe_stream(elem: &AddressElement) -> Option<NamedPipeStreamConfig> {
    if !elem.tag.eq_ignore_ascii_case("NPIPE") {
        return None;
    }

    let sep_index = elem.address.rfind(':');
    let (server_name, pipe_name) = match sep_index {
        None | Some(0) => (".", elem.address.trim_start_matches(':')),
        Some(i) => (&elem.address[..i], &elem.address[i + 1..]),
    };

    Some(NamedPipeStreamConfig {
        server_name: server_name.to_string(),
        pipe_name: pipe_name.to_string(),
    })
}

pub fn try_parse_npipe_listen(elem: &AddressElement) -> Option<NamedPipeListenConfig> {
    if !elem.tag.eq_ignore_ascii_case("NPIPE-LISTEN") {
        return None;
    }
    Some(NamedPipeListenConfig {
        pipe_name: elem.address.clone(),
    })
}

/// Wrapper that unifies NamedPipeClient into AsyncRead+AsyncWrite.
struct NamedPipeStream(tokio::net::windows::named_pipe::NamedPipeClient);

impl AsyncRead for NamedPipeStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for NamedPipeStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// Wrapper for NamedPipeServer
struct NamedPipeServerStream(tokio::net::windows::named_pipe::NamedPipeServer);

impl AsyncRead for NamedPipeServerStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for NamedPipeServerStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

pub struct NamedPipeConnector(NamedPipeStreamConfig);

#[async_trait::async_trait]
impl Connector for NamedPipeConnector {
    async fn connect(&self) -> Result<BoxedStream> {
        let path = self.0.pipe_path();
        let client = ClientOptions::new().open(&path)?;
        Ok(Box::new(NamedPipeStream(client)))
    }
}

pub struct NamedPipeListenerEndpoint {
    config: NamedPipeListenConfig,
}

#[async_trait::async_trait]
impl Listener for NamedPipeListenerEndpoint {
    async fn accept(&mut self) -> Result<BoxedStream> {
        let path = self.config.pipe_path();
        let server = ServerOptions::new()
            .first_pipe_instance(false)
            .create(&path)?;
        server.connect().await?;
        Ok(Box::new(NamedPipeServerStream(server)))
    }
}

pub fn try_parse_connect_strategy(elem: &AddressElement) -> Option<NamedPipeConnector> {
    try_parse_npipe_stream(elem).map(NamedPipeConnector)
}

pub fn try_parse_listen_strategy(elem: &AddressElement) -> Option<NamedPipeListenerEndpoint> {
    try_parse_npipe_listen(elem).map(|config| NamedPipeListenerEndpoint { config })
}

pub fn try_parse_factory(elem: &AddressElement) -> Option<NamedPipeConnector> {
    try_parse_npipe_stream(elem).map(NamedPipeConnector)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_npipe_stream() {
        let cases = [
            ("NPIPE:fooServer:barPipe", "fooServer", "barPipe"),
            ("NPIPE::fooPipe", ".", "fooPipe"),
            ("NPIPE:fooPipe", ".", "fooPipe"),
        ];
        for (input, expected_server, expected_pipe) in cases {
            let elem = AddressElement::try_parse(input).unwrap();
            let config = try_parse_npipe_stream(&elem).unwrap();
            assert_eq!(config.server_name, expected_server, "server for {input}");
            assert_eq!(config.pipe_name, expected_pipe, "pipe for {input}");
        }
    }

    #[test]
    fn case_insensitive_npipe() {
        for input in ["NPIPE:fooServer:barPipe", "npipe:fooServer:barPipe"] {
            let elem = AddressElement::try_parse(input).unwrap();
            assert!(try_parse_npipe_stream(&elem).is_some());
        }
    }

    #[test]
    fn parse_npipe_listen() {
        let elem = AddressElement::try_parse("NPIPE-LISTEN:fooPipe").unwrap();
        let config = try_parse_npipe_listen(&elem).unwrap();
        assert_eq!(config.pipe_name, "fooPipe");
    }

    #[test]
    fn reject_non_npipe() {
        for input in [
            "STDIO",
            "TCP:127.0.0.1:80",
            "TCP-LISTEN:127.0.0.1:80",
            "NPIPE-LISTEN:fooPipe",
            "EXEC:'C:\\Foo.exe bar'",
        ] {
            let elem = AddressElement::try_parse(input).unwrap();
            assert!(
                try_parse_npipe_stream(&elem).is_none(),
                "should not parse as NPIPE: {input}"
            );
        }
    }
}
