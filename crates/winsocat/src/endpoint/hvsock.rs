use anyhow::Result;
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::net::TcpStream;

use super::{BoxedStream, Connector, Listener};
use crate::address::AddressElement;

// Hyper-V socket constants
const AF_HYPERV: i32 = 34;
const HV_PROTOCOL_RAW: i32 = 1;
const SOCKADDR_HV_SIZE: usize = 36;

// Well-known VM GUIDs
const GUID_ZERO: uuid::Uuid = uuid::Uuid::nil();
const GUID_WILDCARD: uuid::Uuid = uuid::Uuid::nil();

fn guid_broadcast() -> uuid::Uuid {
    uuid::Uuid::parse_str("FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF").unwrap()
}
fn guid_children() -> uuid::Uuid {
    uuid::Uuid::parse_str("90db8b89-0d35-4f79-8ce9-49ea0ac8b7cd").unwrap()
}
fn guid_loopback() -> uuid::Uuid {
    uuid::Uuid::parse_str("e0e16197-dd56-4a10-9195-5ee7a155a838").unwrap()
}
fn guid_parent() -> uuid::Uuid {
    uuid::Uuid::parse_str("a42e7cda-d03f-480c-9cc2-a4de20abb878").unwrap()
}

fn parse_vm_guid(addr: &str) -> Option<uuid::Uuid> {
    if addr.eq_ignore_ascii_case("ZERO") {
        return Some(GUID_ZERO);
    }
    if addr.eq_ignore_ascii_case("WILDCARD") {
        return Some(GUID_WILDCARD);
    }
    if addr.eq_ignore_ascii_case("BROADCAST") {
        return Some(guid_broadcast());
    }
    if addr.eq_ignore_ascii_case("CHILDREN") {
        return Some(guid_children());
    }
    if addr.eq_ignore_ascii_case("LOOPBACK") {
        return Some(guid_loopback());
    }
    if addr.eq_ignore_ascii_case("PARENT") {
        return Some(guid_parent());
    }
    uuid::Uuid::parse_str(addr).ok()
}

fn parse_service_id(addr: &str) -> Option<uuid::Uuid> {
    if let Some(port_str) = addr
        .strip_prefix("VSOCK-")
        .or_else(|| addr.strip_prefix("vsock-"))
    {
        let port: u32 = port_str.parse().ok()?;
        // serviceId format for VSOCK: {port}-facb-11e6-bd58-64006a7986d3
        let guid_str = format!("{:08x}-facb-11e6-bd58-64006a7986d3", port);
        return uuid::Uuid::parse_str(&guid_str).ok();
    }
    uuid::Uuid::parse_str(addr).ok()
}

/// Serialize a Hyper-V socket address into a raw sockaddr buffer.
fn serialize_hvsock_addr(vm_id: &uuid::Uuid, service_id: &uuid::Uuid) -> Vec<u8> {
    let mut buf = vec![0u8; SOCKADDR_HV_SIZE];
    // Family at offset 0 (u16 LE)
    let family = AF_HYPERV as u16;
    buf[0..2].copy_from_slice(&family.to_ne_bytes());
    // Reserved at offset 2 (u16)
    buf[2..4].copy_from_slice(&0u16.to_ne_bytes());
    // VM ID at offset 4 (16 bytes, mixed-endian UUID)
    buf[4..20].copy_from_slice(vm_id.as_bytes());
    // Service ID at offset 20 (16 bytes, mixed-endian UUID)
    buf[20..36].copy_from_slice(service_id.as_bytes());
    buf
}

#[derive(Debug, Clone)]
pub struct HyperVStreamConfig {
    pub vm_id: uuid::Uuid,
    pub service_id: uuid::Uuid,
}

#[derive(Debug, Clone)]
pub struct HyperVListenConfig {
    pub vm_id: uuid::Uuid,
    pub service_id: uuid::Uuid,
}

fn parse_hvsock_ids(elem: &AddressElement) -> Option<(uuid::Uuid, uuid::Uuid)> {
    let sep_idx = elem.address.rfind(':')?;
    if sep_idx == 0 {
        return None;
    }

    let vm_id = parse_vm_guid(&elem.address[..sep_idx])?;
    let service_id = parse_service_id(&elem.address[sep_idx + 1..])?;
    Some((vm_id, service_id))
}

pub fn try_parse_hvsock_stream(elem: &AddressElement) -> Option<HyperVStreamConfig> {
    if !elem.tag.eq_ignore_ascii_case("HVSOCK") {
        return None;
    }
    let (vm_id, service_id) = parse_hvsock_ids(elem)?;
    Some(HyperVStreamConfig { vm_id, service_id })
}

pub fn try_parse_hvsock_listen(elem: &AddressElement) -> Option<HyperVListenConfig> {
    if !elem.tag.eq_ignore_ascii_case("HVSOCK-LISTEN") {
        return None;
    }
    let (vm_id, service_id) = parse_hvsock_ids(elem)?;
    Some(HyperVListenConfig { vm_id, service_id })
}

fn connect_hvsock(vm_id: &uuid::Uuid, service_id: &uuid::Uuid) -> Result<Socket> {
    let socket = Socket::new(
        Domain::from(AF_HYPERV),
        Type::STREAM,
        Some(Protocol::from(HV_PROTOCOL_RAW)),
    )?;

    let addr_buf = serialize_hvsock_addr(vm_id, service_id);
    let addr = unsafe { SockAddr::new(*(addr_buf.as_ptr() as *const _), SOCKADDR_HV_SIZE as _) };
    socket.connect(&addr)?;
    Ok(socket)
}

fn bind_hvsock(vm_id: &uuid::Uuid, service_id: &uuid::Uuid) -> Result<Socket> {
    let socket = Socket::new(
        Domain::from(AF_HYPERV),
        Type::STREAM,
        Some(Protocol::from(HV_PROTOCOL_RAW)),
    )?;

    let addr_buf = serialize_hvsock_addr(vm_id, service_id);
    let addr = unsafe { SockAddr::new(*(addr_buf.as_ptr() as *const _), SOCKADDR_HV_SIZE as _) };
    socket.bind(&addr)?;
    socket.listen(128)?;
    Ok(socket)
}

pub struct HyperVConnector(HyperVStreamConfig);

#[async_trait::async_trait]
impl Connector for HyperVConnector {
    async fn connect(&self) -> Result<BoxedStream> {
        let vm_id = self.0.vm_id;
        let service_id = self.0.service_id;

        // Connect synchronously in a blocking task (Hyper-V sockets
        // are not easily usable with tokio's async reactor)
        let std_stream = tokio::task::spawn_blocking(move || -> Result<std::net::TcpStream> {
            let socket = connect_hvsock(&vm_id, &service_id)?;
            socket.set_nonblocking(true)?;
            Ok(socket.into())
        })
        .await??;

        let stream = TcpStream::from_std(std_stream)?;
        Ok(Box::new(stream))
    }
}

pub struct HyperVListenerEndpoint {
    config: HyperVListenConfig,
    socket: Option<Socket>,
}

#[async_trait::async_trait]
impl Listener for HyperVListenerEndpoint {
    async fn accept(&mut self) -> Result<BoxedStream> {
        if self.socket.is_none() {
            let socket = bind_hvsock(&self.config.vm_id, &self.config.service_id)?;
            self.socket = Some(socket);
        }

        let socket_ref = self.socket.as_ref().unwrap();
        // Clone the raw fd for the blocking task
        let socket_clone = socket_ref.try_clone()?;

        let std_stream = tokio::task::spawn_blocking(move || -> Result<std::net::TcpStream> {
            let (accepted, _) = socket_clone.accept()?;
            accepted.set_nonblocking(true)?;
            Ok(accepted.into())
        })
        .await??;

        let stream = TcpStream::from_std(std_stream)?;
        Ok(Box::new(stream))
    }
}

pub fn try_parse_connect_strategy(elem: &AddressElement) -> Option<HyperVConnector> {
    try_parse_hvsock_stream(elem).map(HyperVConnector)
}

pub fn try_parse_listen_strategy(elem: &AddressElement) -> Option<HyperVListenerEndpoint> {
    try_parse_hvsock_listen(elem).map(|config| HyperVListenerEndpoint {
        config,
        socket: None,
    })
}

pub fn try_parse_factory(elem: &AddressElement) -> Option<HyperVConnector> {
    try_parse_hvsock_stream(elem).map(HyperVConnector)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hvsock_stream() {
        let input =
            "HVSOCK:0cb41c0b-fd26-4a41-8370-dccb048e216e:00000ac9-facb-11e6-bd58-64006a7986d3";
        let elem = AddressElement::try_parse(input).unwrap();
        let config = try_parse_hvsock_stream(&elem).unwrap();
        assert_eq!(
            config.vm_id,
            uuid::Uuid::parse_str("0cb41c0b-fd26-4a41-8370-dccb048e216e").unwrap()
        );
        assert_eq!(
            config.service_id,
            uuid::Uuid::parse_str("00000ac9-facb-11e6-bd58-64006a7986d3").unwrap()
        );
    }

    #[test]
    fn parse_hvsock_vsock_shorthand() {
        let input = "HVSOCK:0cb41c0b-fd26-4a41-8370-dccb048e216e:vsock-2761";
        let elem = AddressElement::try_parse(input).unwrap();
        let config = try_parse_hvsock_stream(&elem).unwrap();
        assert_eq!(
            config.service_id,
            uuid::Uuid::parse_str("00000ac9-facb-11e6-bd58-64006a7986d3").unwrap()
        );
    }

    #[test]
    fn parse_hvsock_listen() {
        let input = "HVSOCK-LISTEN:WILDCARD:00000ac9-facb-11e6-bd58-64006a7986d3";
        let elem = AddressElement::try_parse(input).unwrap();
        let config = try_parse_hvsock_listen(&elem).unwrap();
        assert_eq!(config.vm_id, uuid::Uuid::nil());
    }

    #[test]
    fn parse_vm_guid_aliases() {
        assert_eq!(parse_vm_guid("ZERO"), Some(uuid::Uuid::nil()));
        assert_eq!(parse_vm_guid("WILDCARD"), Some(uuid::Uuid::nil()));
        assert!(parse_vm_guid("BROADCAST").is_some());
        assert!(parse_vm_guid("CHILDREN").is_some());
        assert!(parse_vm_guid("LOOPBACK").is_some());
        assert!(parse_vm_guid("PARENT").is_some());
    }

    #[test]
    fn reject_non_hvsock() {
        let elem = AddressElement::try_parse("TCP:127.0.0.1:80").unwrap();
        assert!(try_parse_hvsock_stream(&elem).is_none());
        assert!(try_parse_hvsock_listen(&elem).is_none());
    }

    #[test]
    fn reject_missing_service_id() {
        let elem = AddressElement::try_parse("HVSOCK:some-guid").unwrap();
        assert!(try_parse_hvsock_stream(&elem).is_none());
    }
}
