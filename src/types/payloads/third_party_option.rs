//! # Format
//!
//! The RFC defines the following format for the third party option payload:
/*!

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Option Code=1 |  Reserved     |   Option Length=16            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    |                Internal IP Address (128 bits)                 |
    |                                                               |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
//! **Internal IP Address**: Internal IP address for this mapping.

use crate::types::{Ipv6Address, Parsable, ParsingError};
use std::convert::TryFrom;
use std::net::{IpAddr, Ipv6Addr};

/// A correctly formed `ThirdPartyOptionPayload` containing the address of the other host
#[derive(PartialEq, Debug)]
pub struct ThirdPartyOptionPayload {
    pub address: IpAddr,
}

impl ThirdPartyOptionPayload {
    /// Size of the third party option payload (in bytes)
    pub const SIZE: usize = 16;

    /// Creates a new third party option header
    pub const fn new(address: IpAddr) -> Self {
        ThirdPartyOptionPayload { address }
    }

    /// Creates a correctly formatted byte array representing the payload
    pub fn bytes(&self) -> [u8; Self::SIZE] {
        match self.address {
            IpAddr::V4(ip) => ip.to_ipv6_mapped(),
            IpAddr::V6(ip) => ip,
        }
        .octets()
    }
}

/// A zero-copy type containing a valid PCP third party option payload.
/// It can be obtained via the `try_from` method (from the `std::TryFrom`
/// trait) from a slice containing a valid sequence of bytes.
pub struct ThirdPartyOptionPayloadSlice<'a> {
    slice: &'a [u8],
}

impl ThirdPartyOptionPayloadSlice<'_> {
    /// Returns the address
    pub fn address(&self) -> IpAddr {
        Ipv6Addr::from(<[u8; 16]>::try_from(&self.slice[..]).unwrap()).unmap()
    }

    /// Returns the inner slice
    pub const fn slice(&self) -> &[u8] {
        self.slice
    }
}

impl Parsable for ThirdPartyOptionPayloadSlice<'_> {
    type Parsed = ThirdPartyOptionPayload;

    fn parse(&self) -> Self::Parsed {
        ThirdPartyOptionPayload {
            address: self.address(),
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for ThirdPartyOptionPayloadSlice<'a> {
    type Error = ParsingError;

    fn try_from(slice: &'a [u8]) -> Result<ThirdPartyOptionPayloadSlice<'a>, Self::Error> {
        // The size of the slice must be at least 4
        if slice.len() < ThirdPartyOptionPayload::SIZE {
            Err(ParsingError::InvalidSliceLength(
                ThirdPartyOptionPayload::SIZE,
            ))
        }
        // It's a valid header
        else {
            Ok(ThirdPartyOptionPayloadSlice {
                slice: &slice[..ThirdPartyOptionPayload::SIZE],
            })
        }
    }
}
