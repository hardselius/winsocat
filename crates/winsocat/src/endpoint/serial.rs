use anyhow::Result;
use tokio_serial::SerialPortBuilderExt;

use super::{BoxedStream, Connector};
use crate::address::AddressElement;

#[derive(Debug, Clone)]
pub struct SerialConfig {
    pub port_name: String,
    pub baud_rate: u32,
    // tokio-serial uses different types for parity/data_bits/stop_bits
    pub parity: tokio_serial::Parity,
    pub data_bits: tokio_serial::DataBits,
    pub stop_bits: tokio_serial::StopBits,
}

pub fn try_parse_serial(elem: &AddressElement) -> Option<SerialConfig> {
    if !elem.tag.eq_ignore_ascii_case("SP") {
        return None;
    }

    let port_name = elem.address.clone();

    let baud_rate = match elem.options.get("baudrate") {
        Some(v) => v.parse().ok()?,
        None => 9600,
    };

    let parity = match elem.options.get("parity") {
        Some(v) => match v.as_str() {
            "0" => tokio_serial::Parity::None,
            "1" => tokio_serial::Parity::Odd,
            "2" => tokio_serial::Parity::Even,
            _ => return None,
        },
        None => tokio_serial::Parity::None,
    };

    let data_bits = match elem.options.get("databits") {
        Some(v) => match v.as_str() {
            "5" => tokio_serial::DataBits::Five,
            "6" => tokio_serial::DataBits::Six,
            "7" => tokio_serial::DataBits::Seven,
            "8" => tokio_serial::DataBits::Eight,
            _ => return None,
        },
        None => tokio_serial::DataBits::Eight,
    };

    // C# StopBits enum: None=0, One=1, Two=2, OnePointFive=3.
    // The underlying serialport crate only supports One and Two;
    // stopbits=3 (OnePointFive) is not available and will be rejected.
    let stop_bits = match elem.options.get("stopbits") {
        Some(v) => match v.as_str() {
            "0" => tokio_serial::StopBits::One, // C# StopBits.None maps to 0
            "1" => tokio_serial::StopBits::One,
            "2" => tokio_serial::StopBits::Two,
            _ => return None,
        },
        None => tokio_serial::StopBits::One,
    };

    Some(SerialConfig {
        port_name,
        baud_rate,
        parity,
        data_bits,
        stop_bits,
    })
}

pub struct SerialConnector(SerialConfig);

#[async_trait::async_trait]
impl Connector for SerialConnector {
    async fn connect(&self) -> Result<BoxedStream> {
        let port = tokio_serial::new(&self.0.port_name, self.0.baud_rate)
            .parity(self.0.parity)
            .data_bits(self.0.data_bits)
            .stop_bits(self.0.stop_bits)
            .open_native_async()?;
        Ok(Box::new(port))
    }
}

pub fn try_parse_strategy(elem: &AddressElement) -> Option<SerialConnector> {
    try_parse_serial(elem).map(SerialConnector)
}

pub fn try_parse_factory(elem: &AddressElement) -> Option<SerialConnector> {
    try_parse_serial(elem).map(SerialConnector)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_serial_defaults() {
        let elem = AddressElement::try_parse("SP:COM1").unwrap();
        let config = try_parse_serial(&elem).unwrap();
        assert_eq!(config.port_name, "COM1");
        assert_eq!(config.baud_rate, 9600);
    }

    #[test]
    fn parse_serial_with_options() {
        let elem =
            AddressElement::try_parse("SP:COM1,baudrate=12500,parity=1,databits=8,stopbits=2")
                .unwrap();
        let config = try_parse_serial(&elem).unwrap();
        assert_eq!(config.port_name, "COM1");
        assert_eq!(config.baud_rate, 12500);
    }

    #[test]
    fn reject_non_serial() {
        let elem = AddressElement::try_parse("TCP:127.0.0.1:80").unwrap();
        assert!(try_parse_serial(&elem).is_none());
    }
}
