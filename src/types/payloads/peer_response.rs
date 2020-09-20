//! # Format
//!
//! The RFC defines the following format for the peer respnse payload:
/*!

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
//! **Lifetime** (in common header):
//!     On a success response, this indicates
//!     the lifetime for this mapping, in seconds.  On an error response,
//!     this indicates how long clients should assume they'll get the same
//!     error response from the PCP server if they repeat the same
//!     request.
//!
//! **Mapping Nonce**: Copied from the request.
//!
//! **Protocol**: Copied from the request.
//!
//! **Reserved**:
//!     24 reserved bits, MUST be set to 0 on transmission, MUST be ignored on reception.
//!
//! **Internal Port**: Copied from request.
//!
//! **Assigned External Port**:
//!     On a success response, this is the assigned
//!     external port for the mapping.  On an error response, the
//!     suggested external port is copied from the request.
//!
//! **Assigned External IP Address**:
//!     On a success response, this is the
//!     assigned external IPv4 or IPv6 address for the mapping.  On an
//!     error response, the suggested external IP address is copied from
//!     the request.
//!
//! **Remote Peer Port**: Copied from request.
//!
//! **Reserved**:
//! 16 reserved bits, MUST be set to 0 on transmission, MUST be ignored on reception.
//!
//! **Remote Peer IP Address**: Copied from the request.

use crate::types::{Ipv6Address, Parsable, ParsingError, ProtocolNumber};
use std::convert::{TryFrom, TryInto};
use std::net::{IpAddr, Ipv6Addr};

/// A correctly formed `PeerResponsePayload` containing a nonce (copied from the request),
/// the `ProtocolNumber` of the request, the internal port from which the PCP
/// client will receive incoming packets (copied from the request), the external port and
/// address selected by the PCP server, the remote host port number and address specified
/// in the request
#[derive(PartialEq, Debug)]
pub struct PeerResponsePayload {
    pub nonce: [u8; 12],
    pub protocol: ProtocolNumber,
    pub internal_port: u16,
    pub external_port: u16,
    pub external_address: IpAddr,
    pub remote_port: u16,
    pub remote_address: IpAddr,
}

impl PeerResponsePayload {
    /// Size of the PCP map response payload (in bytes)
    pub const SIZE: usize = 56;
}

/// A zero-copy type containing a valid PCP peer response payload.
/// It can be obtained via the `try_from` method (from the `std::TryFrom`
/// trait) from a slice containing a valid sequence of bytes.
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
    pub fn external_address(&self) -> IpAddr {
        Ipv6Addr::from(<[u8; 16]>::try_from(&self.slice[20..36]).unwrap()).unmap()
    }

    /// Returns the remote peer's port number
    pub fn remote_port(&self) -> u16 {
        u16::from_be_bytes(self.slice[36..38].try_into().unwrap())
    }

    /// Returns the remote peer's IP address. If it's an IPv4 mapping it will return the IPv6
    /// mapped IPv4
    pub fn remote_address(&self) -> IpAddr {
        Ipv6Addr::from(<[u8; 16]>::try_from(&self.slice[40..56]).unwrap()).unmap()
    }

    /// Returns the inner slice
    pub fn slice(&self) -> &[u8] {
        self.slice
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
}

impl<'a> TryFrom<&'a [u8]> for PeerResponsePayloadSlice<'a> {
    type Error = ParsingError;

    fn try_from(slice: &'a [u8]) -> Result<PeerResponsePayloadSlice<'a>, Self::Error> {
        if slice.len() < PeerResponsePayload::SIZE {
            Err(ParsingError::InvalidSliceLength(PeerResponsePayload::SIZE))
        } else if ProtocolNumber::try_from(slice[12]).is_err() {
            Err(ParsingError::NotAProtocolNumber(slice[12]))
        } else {
            Ok(PeerResponsePayloadSlice {
                slice: &slice[..PeerResponsePayload::SIZE],
            })
        }
    }
}
