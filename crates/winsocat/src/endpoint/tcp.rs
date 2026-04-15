use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use anyhow::Result;
use tokio::net::{TcpListener as TokioTcpListener, TcpStream};

use super::{BoxedStream, Connector, Listener};
use crate::address::AddressElement;

// --- Config types ---

#[derive(Debug, Clone)]
pub struct TcpStreamConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct TcpListenConfig {
    pub addr: IpAddr,
    pub port: u16,
}

// --- Parsing ---

pub fn try_parse_tcp_stream(elem: &AddressElement) -> Option<TcpStreamConfig> {
    if !elem.tag.eq_ignore_ascii_case("TCP") {
        return None;
    }

    let sep_index = elem.address.rfind(':');
    let (host, port_str) = match sep_index {
        None | Some(0) => ("0.0.0.0", elem.address.trim_start_matches(':')),
        Some(i) => (&elem.address[..i], &elem.address[i + 1..]),
    };

    let port: u16 = port_str.parse().ok()?;
    Some(TcpStreamConfig {
        host: host.to_string(),
        port,
    })
}

pub fn try_parse_tcp_listen(elem: &AddressElement) -> Option<TcpListenConfig> {
    if !elem.tag.eq_ignore_ascii_case("TCP-LISTEN") {
        return None;
    }

    let sep_index = elem.address.rfind(':');
    let (addr_str, port_str) = match sep_index {
        None | Some(0) => ("0.0.0.0", elem.address.trim_start_matches(':')),
        Some(i) => (&elem.address[..i], &elem.address[i + 1..]),
    };

    let addr: IpAddr = addr_str
        .parse()
        .unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
    let port: u16 = port_str.parse().ok()?;
    Some(TcpListenConfig { addr, port })
}

// --- Connector ---

pub struct TcpConnector(TcpStreamConfig);

#[async_trait::async_trait]
impl Connector for TcpConnector {
    async fn connect(&self) -> Result<BoxedStream> {
        let stream = TcpStream::connect((&*self.0.host, self.0.port)).await?;
        Ok(Box::new(stream))
    }
}

// --- Listener ---

pub struct TcpListenerEndpoint {
    config: TcpListenConfig,
    listener: Option<TokioTcpListener>,
}

#[async_trait::async_trait]
impl Listener for TcpListenerEndpoint {
    async fn accept(&mut self) -> Result<BoxedStream> {
        if self.listener.is_none() {
            let addr = SocketAddr::new(self.config.addr, self.config.port);
            self.listener = Some(TokioTcpListener::bind(addr).await?);
        }
        let (stream, _) = self.listener.as_ref().unwrap().accept().await?;
        Ok(Box::new(stream))
    }
}

// --- Parse entry points ---

pub fn try_parse_connect_strategy(elem: &AddressElement) -> Option<TcpConnector> {
    try_parse_tcp_stream(elem).map(TcpConnector)
}

pub fn try_parse_listen_strategy(elem: &AddressElement) -> Option<TcpListenerEndpoint> {
    try_parse_tcp_listen(elem).map(|config| TcpListenerEndpoint {
        config,
        listener: None,
    })
}

pub fn try_parse_factory(elem: &AddressElement) -> Option<TcpConnector> {
    try_parse_tcp_stream(elem).map(TcpConnector)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_tcp_stream_inputs() {
        for input in ["TCP:127.0.0.1:80", "TCP::80", "TCP:80"] {
            let elem = AddressElement::try_parse(input).unwrap();
            assert!(
                try_parse_tcp_stream(&elem).is_some(),
                "should parse: {input}"
            );
        }
    }

    #[test]
    fn case_insensitive_tcp() {
        for input in ["TCP:127.0.0.1:80", "Tcp:127.0.0.1:80"] {
            let elem = AddressElement::try_parse(input).unwrap();
            assert!(try_parse_tcp_stream(&elem).is_some());
        }
    }

    #[test]
    fn invalid_tcp_stream_inputs() {
        for input in [
            "STDIO",
            "TCP-LISTEN:127.0.0.1:80",
            "NPIPE:fooServer:barPipe",
            "NPIPE-LISTEN:fooPipe",
            "EXEC:'C:\\Foo.exe bar'",
        ] {
            let elem = AddressElement::try_parse(input).unwrap();
            assert!(
                try_parse_tcp_stream(&elem).is_none(),
                "should not parse as TCP: {input}"
            );
        }
    }

    #[test]
    fn tcp_stream_host_parsing() {
        let cases = [
            ("TCP:127.0.0.1:80", "127.0.0.1"),
            ("TCP::80", "0.0.0.0"),
            ("TCP:80", "0.0.0.0"),
        ];
        for (input, expected) in cases {
            let elem = AddressElement::try_parse(input).unwrap();
            let config = try_parse_tcp_stream(&elem).unwrap();
            assert_eq!(config.host, expected, "host mismatch for {input}");
        }
    }

    #[test]
    fn tcp_stream_port_parsing() {
        let cases = [("TCP:127.0.0.1:80", 80), ("TCP::80", 80), ("TCP:80", 80)];
        for (input, expected) in cases {
            let elem = AddressElement::try_parse(input).unwrap();
            let config = try_parse_tcp_stream(&elem).unwrap();
            assert_eq!(config.port, expected, "port mismatch for {input}");
        }
    }

    #[test]
    fn valid_tcp_listen_inputs() {
        let elem = AddressElement::try_parse("TCP-LISTEN:127.0.0.1:80").unwrap();
        let config = try_parse_tcp_listen(&elem).unwrap();
        assert_eq!(config.addr, "127.0.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(config.port, 80);
    }

    #[test]
    fn tcp_listen_default_addr() {
        let elem = AddressElement::try_parse("TCP-LISTEN:80").unwrap();
        let config = try_parse_tcp_listen(&elem).unwrap();
        assert_eq!(config.addr, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
        assert_eq!(config.port, 80);
    }
}
