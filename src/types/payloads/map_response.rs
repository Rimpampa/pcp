/*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    |                 Mapping Nonce (96 bits)                       |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |   Protocol    |          Reserved (24 bits)                   |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |        Internal Port          |    Assigned External Port     |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    |            Assigned External IP Address (128 bits)            |
    |                                                               |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

use crate::types::{Ipv6Address, Parsable, ParsingError, ProtocolNumber, Slorp};
use std::convert::{TryFrom, TryInto};
use std::net::{IpAddr, Ipv6Addr};

pub type MapResponseType<'a> = Slorp<MapResponsePayload, MapResponsePayloadSlice<'a>>;

#[derive(Debug)]
pub struct MapResponsePayload {
    pub nonce: [u8; 12],
    pub protocol: ProtocolNumber,
    pub internal_port: u16,
    pub external_port: u16,
    pub external_address: IpAddr,
}

impl MapResponsePayload {
    /// Size of the PCP map response payload (in bytes)
    const SIZE: usize = 36;
}

pub struct MapResponsePayloadSlice<'a> {
    slice: &'a [u8],
}

impl MapResponsePayloadSlice<'_> {
    /// Returns the nonce
    pub fn nonce(&self) -> &[u8] {
        &self.slice[..12]
    }
    /// Returns the protocol number
    pub fn protocol(&self) -> ProtocolNumber {
        self.slice[12].try_into().unwrap()
    }
    /// Returns the internal port number
    pub fn internal_port(&self) -> u16 {
        u16::from_be_bytes(self.slice[16..18].try_into().unwrap())
    }
    /// Returns the assigned external port number
    pub fn external_port(&self) -> u16 {
        u16::from_be_bytes(self.slice[18..20].try_into().unwrap())
    }
    /// Returns the assigned external IP address. If it's an IPv4 mapping it will return the IPv6
    /// mapped IPv4 address (::ffff:a.b.c.d)
    pub fn external_address(&self) -> Ipv6Addr {
        <[u8; 16]>::try_from(&self.slice[20..36]).unwrap().into()
    }
}

impl Parsable for MapResponsePayloadSlice<'_> {
    type Parsed = MapResponsePayload;

    fn parse(&self) -> Self::Parsed {
        MapResponsePayload {
            nonce: self.nonce().try_into().unwrap(),
            protocol: self.protocol(),
            internal_port: self.internal_port(),
            external_port: self.external_port(),
            external_address: self.external_address().true_form(),
        }
    }
    /// Returns the inner slice
    fn slice(&self) -> &[u8] {
        self.slice
    }
}

impl<'a> TryFrom<&'a [u8]> for MapResponsePayloadSlice<'a> {
    type Error = ParsingError;

    fn try_from(slice: &'a [u8]) -> Result<MapResponsePayloadSlice<'a>, Self::Error> {
        if slice.len() < MapResponsePayload::SIZE {
            // Err("The size of the slice is too small")
            ParsingError::InvalidSliceLength(MapResponsePayload::SIZE).into()
        } else if ProtocolNumber::try_from(slice[12]).is_err() {
            ParsingError::NotAProtocolNumber(slice[12]).into()
        } else {
            Ok(MapResponsePayloadSlice {
                slice: &slice[..MapResponsePayload::SIZE],
            })
        }
    }
}
