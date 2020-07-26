/*
     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Option Code=3 |  Reserved     |   Option Length=20            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |    Reserved   | Prefix Length |      Remote Peer Port         |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    |               Remote Peer IP address (128 bits)               |
    |                                                               |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
use crate::types::{Parsable, ParsingError};
use std::convert::{TryFrom, TryInto};
use std::net::{IpAddr, Ipv6Addr};

#[derive(PartialEq, Debug)]
pub struct FilterOptionPayload {
    pub prefix: u8,
    pub remote_port: u16,
    pub remote_address: IpAddr,
}

impl FilterOptionPayload {
    /// Size of the PCP option header (in bytes)
    pub const SIZE: usize = 20;

    /// Creates a new option header
    pub const fn new(prefix: u8, remote_port: u16, remote_address: IpAddr) -> Self {
        FilterOptionPayload {
            prefix,
            remote_port,
            remote_address,
        }
    }

	#[rustfmt::skip]
    pub fn bytes(&self) -> [u8; Self::SIZE] {
		let rem_ip = match self.remote_address.into() {
			IpAddr::V4(ip) => ip.to_ipv6_mapped(),
			IpAddr::V6(ip) => ip,
		}.octets();
		let rem_port = self.remote_port.to_be_bytes();
		[
			0, self.prefix, rem_port[0], rem_port[1],
			rem_ip[0], rem_ip[1], rem_ip[2], rem_ip[3],
			rem_ip[4], rem_ip[5], rem_ip[6], rem_ip[7],
			rem_ip[8], rem_ip[9], rem_ip[10], rem_ip[11],
			rem_ip[12], rem_ip[13], rem_ip[14], rem_ip[15],
		]
	}
}

pub struct FilterOptionPayloadSlice<'a> {
    slice: &'a [u8],
}

impl FilterOptionPayloadSlice<'_> {
    /// Returns the number of bits that get checked by the filter
    pub fn prefix(&self) -> u8 {
        self.slice[1]
    }
    /// Returns the port that gets filtered
    pub fn remote_port(&self) -> u16 {
        u16::from_be_bytes(self.slice[2..4].try_into().unwrap())
    }
    /// Returns the address
    pub fn remote_address(&self) -> Ipv6Addr {
        match <[u8; 16]>::try_from(&self.slice[4..20]) {
            Ok(arr) => arr.into(),
            _ => unreachable!(),
        }
    }
    /// Returns the inner slice
    pub fn slice(&self) -> &[u8] {
        self.slice
    }
}

impl Parsable for FilterOptionPayloadSlice<'_> {
    type Parsed = FilterOptionPayload;

    fn parse(&self) -> Self::Parsed {
        FilterOptionPayload {
            prefix: self.prefix(),
            remote_port: self.remote_port(),
            remote_address: self.remote_address().into(),
        }
    }
}

impl<'a> TryFrom<&'a [u8]> for FilterOptionPayloadSlice<'a> {
    type Error = ParsingError;

    fn try_from(slice: &'a [u8]) -> Result<FilterOptionPayloadSlice<'a>, Self::Error> {
        // The size of the slice must be at least 4
        if slice.len() < FilterOptionPayload::SIZE {
            Err(ParsingError::InvalidSliceLength(FilterOptionPayload::SIZE))
        }
        // If the prefix is smaller than 96, check that the address is not an IPv4 IPv6 mapped
        // as those addresses start at the 96th bit
        else if slice[1] < 96
            && (slice[4..14].iter().all(|&v| v == 0) && slice[14] == 0xff && slice[15] == 0xff)
        {
            Err(ParsingError::InvalidPrefix(slice[1]))
        }
        // It's a valid header
        else {
            Ok(FilterOptionPayloadSlice {
                slice: &slice[..FilterOptionPayload::SIZE],
            })
        }
    }
}
