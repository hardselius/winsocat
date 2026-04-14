pub mod stdio;
pub mod tcp;
pub mod exec;
pub mod unix;
pub mod serial;

#[cfg(windows)]
pub mod npipe;
#[cfg(windows)]
pub mod hvsock;
#[cfg(windows)]
pub mod wsl;

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};

/// Combined async read+write trait for use as a trait object.
pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

/// A connected I/O stream that can be relayed.
pub type BoxedStream = Box<dyn AsyncReadWrite>;

/// An endpoint that can connect (produce a single stream).
#[async_trait::async_trait]
pub trait Connector: Send + Sync {
    async fn connect(&self) -> Result<BoxedStream>;
}

/// An endpoint that can listen and accept connections.
#[async_trait::async_trait]
pub trait Listener: Send {
    async fn accept(&mut self) -> Result<BoxedStream>;
}

/// Strategy for address1: either connect once or listen+accept in a loop.
pub enum Strategy {
    Connect(Box<dyn Connector>),
    Listen(Box<dyn Listener>),
}

/// Factory for address2: always connect.
pub struct Factory(Box<dyn Connector>);

impl Factory {
    pub fn new(connector: Box<dyn Connector>) -> Self {
        Self(connector)
    }

    pub async fn connect(&self) -> Result<BoxedStream> {
        self.0.connect().await
    }
}

/// Parse address1 into a Strategy. First match wins.
pub fn parse_strategy(input: &str) -> Result<Strategy> {
    let elem = crate::address::AddressElement::try_parse(input)
        .ok_or_else(|| anyhow::anyhow!("failed to parse address: {input}"))?;

    if let Some(s) = stdio::try_parse_strategy(&elem) {
        return Ok(Strategy::Connect(Box::new(s)));
    }
    if let Some(s) = tcp::try_parse_connect_strategy(&elem) {
        return Ok(Strategy::Connect(Box::new(s)));
    }
    if let Some(s) = tcp::try_parse_listen_strategy(&elem) {
        return Ok(Strategy::Listen(Box::new(s)));
    }
    if let Some(s) = exec::try_parse_strategy(&elem) {
        return Ok(Strategy::Connect(Box::new(s)));
    }
    #[cfg(windows)]
    {
        if let Some(s) = npipe::try_parse_connect_strategy(&elem) {
            return Ok(Strategy::Connect(Box::new(s)));
        }
        if let Some(s) = npipe::try_parse_listen_strategy(&elem) {
            return Ok(Strategy::Listen(Box::new(s)));
        }
        if let Some(s) = wsl::try_parse_strategy(&elem) {
            return Ok(Strategy::Connect(Box::new(s)));
        }
    }
    if let Some(s) = unix::try_parse_connect_strategy(&elem) {
        return Ok(Strategy::Connect(Box::new(s)));
    }
    if let Some(s) = unix::try_parse_listen_strategy(&elem) {
        return Ok(Strategy::Listen(Box::new(s)));
    }
    #[cfg(windows)]
    {
        if let Some(s) = hvsock::try_parse_connect_strategy(&elem) {
            return Ok(Strategy::Connect(Box::new(s)));
        }
        if let Some(s) = hvsock::try_parse_listen_strategy(&elem) {
            return Ok(Strategy::Listen(Box::new(s)));
        }
    }
    if let Some(s) = serial::try_parse_strategy(&elem) {
        return Ok(Strategy::Connect(Box::new(s)));
    }

    anyhow::bail!("\"{input}\" is not available on [address1]")
}

/// Parse address2 into a Factory. First match wins.
pub fn parse_factory(input: &str) -> Result<Factory> {
    let elem = crate::address::AddressElement::try_parse(input)
        .ok_or_else(|| anyhow::anyhow!("failed to parse address: {input}"))?;

    if let Some(f) = stdio::try_parse_factory(&elem) {
        return Ok(Factory::new(Box::new(f)));
    }
    if let Some(f) = tcp::try_parse_factory(&elem) {
        return Ok(Factory::new(Box::new(f)));
    }
    if let Some(f) = exec::try_parse_factory(&elem) {
        return Ok(Factory::new(Box::new(f)));
    }
    #[cfg(windows)]
    {
        if let Some(f) = npipe::try_parse_factory(&elem) {
            return Ok(Factory::new(Box::new(f)));
        }
        if let Some(f) = wsl::try_parse_factory(&elem) {
            return Ok(Factory::new(Box::new(f)));
        }
    }
    if let Some(f) = unix::try_parse_factory(&elem) {
        return Ok(Factory::new(Box::new(f)));
    }
    #[cfg(windows)]
    {
        if let Some(f) = hvsock::try_parse_factory(&elem) {
            return Ok(Factory::new(Box::new(f)));
        }
    }
    if let Some(f) = serial::try_parse_factory(&elem) {
        return Ok(Factory::new(Box::new(f)));
    }

    anyhow::bail!("\"{input}\" is not available on [address2]")
}
