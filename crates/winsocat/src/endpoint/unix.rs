use std::path::PathBuf;

use anyhow::Result;
use tokio::net::{UnixListener as TokioUnixListener, UnixStream};

use super::{BoxedStream, Connector, Listener};
use crate::address::AddressElement;

#[derive(Debug, Clone)]
pub struct UnixStreamConfig {
    pub path: PathBuf,
}

#[derive(Debug, Clone)]
pub struct UnixListenConfig {
    pub path: PathBuf,
}

pub fn try_parse_unix_stream(elem: &AddressElement) -> Option<UnixStreamConfig> {
    if !elem.tag.eq_ignore_ascii_case("UNIX") {
        return None;
    }
    Some(UnixStreamConfig {
        path: PathBuf::from(&elem.address),
    })
}

pub fn try_parse_unix_listen(elem: &AddressElement) -> Option<UnixListenConfig> {
    if !elem.tag.eq_ignore_ascii_case("UNIX-LISTEN") {
        return None;
    }
    Some(UnixListenConfig {
        path: PathBuf::from(&elem.address),
    })
}

pub struct UnixConnector(UnixStreamConfig);

#[async_trait::async_trait]
impl Connector for UnixConnector {
    async fn connect(&self) -> Result<BoxedStream> {
        let stream = UnixStream::connect(&self.0.path).await?;
        Ok(Box::new(stream))
    }
}

pub struct UnixListenerEndpoint {
    config: UnixListenConfig,
    listener: Option<TokioUnixListener>,
}

#[async_trait::async_trait]
impl Listener for UnixListenerEndpoint {
    async fn accept(&mut self) -> Result<BoxedStream> {
        if self.listener.is_none() {
            self.listener = Some(TokioUnixListener::bind(&self.config.path)?);
        }
        let (stream, _) = self.listener.as_ref().unwrap().accept().await?;
        Ok(Box::new(stream))
    }
}

impl Drop for UnixListenerEndpoint {
    fn drop(&mut self) {
        // Clean up the socket file on drop (matches C# behavior)
        let _ = std::fs::remove_file(&self.config.path);
    }
}

pub fn try_parse_connect_strategy(elem: &AddressElement) -> Option<UnixConnector> {
    try_parse_unix_stream(elem).map(UnixConnector)
}

pub fn try_parse_listen_strategy(elem: &AddressElement) -> Option<UnixListenerEndpoint> {
    try_parse_unix_listen(elem).map(|config| UnixListenerEndpoint {
        config,
        listener: None,
    })
}

pub fn try_parse_factory(elem: &AddressElement) -> Option<UnixConnector> {
    try_parse_unix_stream(elem).map(UnixConnector)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_unix_stream() {
        let elem = AddressElement::try_parse("UNIX:foo.sock").unwrap();
        let config = try_parse_unix_stream(&elem).unwrap();
        assert_eq!(config.path, PathBuf::from("foo.sock"));
    }

    #[test]
    fn parse_unix_listen() {
        let elem = AddressElement::try_parse("UNIX-LISTEN:/tmp/test.sock").unwrap();
        let config = try_parse_unix_listen(&elem).unwrap();
        assert_eq!(config.path, PathBuf::from("/tmp/test.sock"));
    }

    #[test]
    fn reject_non_unix() {
        let elem = AddressElement::try_parse("TCP:127.0.0.1:80").unwrap();
        assert!(try_parse_unix_stream(&elem).is_none());
        assert!(try_parse_unix_listen(&elem).is_none());
    }
}
