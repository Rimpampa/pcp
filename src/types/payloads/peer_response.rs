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
    |       Remote Peer Port        |     Reserved (16 bits)        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    |               Remote Peer IP Address (128 bits)               |
    |                                                               |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

use crate::types::{Parsable, ParsingError, ProtocolNumber, Slorp};
use std::convert::{TryFrom, TryInto};
use std::net::Ipv6Addr;

pub type PeerResponseType<'a> = Slorp<PeerResponsePayload, PeerResponsePayloadSlice<'a>>;

#[derive(Debug)]
pub struct PeerResponsePayload {
    pub nonce: [u8; 12],
    pub protocol: ProtocolNumber,
    pub internal_port: u16,
    pub external_port: u16,
    pub external_address: Ipv6Addr,
    pub remote_port: u16,
    pub remote_address: Ipv6Addr,
}

impl PeerResponsePayload {
    /// Size of the PCP map response payload (in bytes)
    const SIZE: usize = 56;
}

pub struct PeerResponsePayloadSlice<'a> {
    slice: &'a [u8],
}

impl PeerResponsePayloadSlice<'_> {
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
    /// Returns the remote peer's port number
    pub fn remote_port(&self) -> u16 {
        u16::from_be_bytes(self.slice[36..38].try_into().unwrap())
    }
    // Returns the remote peer's IP address. If it's an IPv4 mapping it will return the IPv6
    /// mapped IPv4
    pub fn remote_address(&self) -> Ipv6Addr {
        <[u8; 16]>::try_from(&self.slice[40..56]).unwrap().into()
    }
}

impl Parsable for PeerResponsePayloadSlice<'_> {
    type Parsed = PeerResponsePayload;

    fn parse(&self) -> Self::Parsed {
        PeerResponsePayload {
            nonce: self.nonce().try_into().unwrap(),
            protocol: self.protocol(),
            internal_port: self.internal_port(),
            external_port: self.external_port(),
            external_address: self.external_address(),
            remote_port: self.remote_port(),
            remote_address: self.remote_address(),
        }
    }
    /// Returns the inner slice
    fn slice(&self) -> &[u8] {
        self.slice
    }
}

impl<'a> TryFrom<&'a [u8]> for PeerResponsePayloadSlice<'a> {
    type Error = ParsingError;

    fn try_from(slice: &'a [u8]) -> Result<PeerResponsePayloadSlice<'a>, Self::Error> {
        if slice.len() < PeerResponsePayload::SIZE {
            ParsingError::InvalidSliceLength(PeerResponsePayload::SIZE).into()
        } else if ProtocolNumber::try_from(slice[12]).is_err() {
            ParsingError::NotAProtocolNumber(slice[12]).into()
        } else {
            Ok(PeerResponsePayloadSlice {
                slice: &slice[..PeerResponsePayload::SIZE],
            })
        }
    }
}
