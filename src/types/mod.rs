//! This module defines all the structs representing PCP response and request
//! packets and the fields contained in them.
//!
//! # Parsing
//!
//! Every type that may be retrieved from the network (all the response types)
//! have a *-Sliced* counterpart that serves as a zero-copy type that just
//! checks if the provided slice is valid and provides methods to access the
//! fields.
//!
//! All those types implement the `Parsable` trait so that they can be copied
//! into a struct where the fields can be accessed directly.
//!
//! # Sending
//!
//! Every data type that is owned has a `bytes` method that returns a correctly
//! formatted byte array representing that data, that can be directly be sent
//! to the PCP server. For the slice types, only the ones that are composed of a
//! single slice have the `slice` methods that returns the inner slice, which
//! can be directly used to send the data, the others have to be parsed first or
//! the fields have to be accessed one at the time.
//!
//! # Recieving
//!
//! When a slice of data is received for the network it can then be made into a
//! -Slice data type via the `try_from` method, as each of them implements the
//! `TryFrom` trait (from std), that checks if the data is valid for that type
//! and returns a `Result` that can lead to a `ParsingError` if the data is not
//! valid

// TODO: make the slice types composed of more slices single sliced, and add unchecked variants of try_from

// TODO: (maybe) use unsafe code to remove unnecessary checks

pub mod headers;
mod op_code;
mod option;
mod option_code;
mod parsing_error;
pub mod payloads;
mod protocols;
mod request;
mod response;
mod result_code;

pub use op_code::OpCode;
pub use option::{PacketOption, PacketOptionSlice};
pub use option_code::OptionCode;
pub use parsing_error::ParsingError;
pub use protocols::ProtocolNumber;
pub use request::RequestPacket;
pub use response::{ResponsePacket, ResponsePacketSlice};
pub use result_code::ResultCode;

use headers::*;
use payloads::*;
use std::convert::TryFrom;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// This trait is used to parse non-copy version of PCP data formats into owned types
pub trait Parsable {
    type Parsed;
    /// Parses the fields of the data
    fn parse(&self) -> Self::Parsed;
}

impl<P, S> Parsable for Vec<S>
where
    S: Parsable<Parsed = P>,
{
    type Parsed = Vec<P>;

    fn parse(&self) -> Self::Parsed {
        self.iter().map(S::parse).collect()
    }
}

/// Simple trait to add methods to the Ipv6Addr type
pub trait Ipv6Address {
    /// Tells if an IPv6 address is an IPv4-mapped IPv6 address
    fn is_mapped(&self) -> bool;
    /// Returns the IPv4 address contained in an IPv4-mapped IPv6 address,
    /// or the IPv6 address if it's not mapped
    fn unmap(self) -> IpAddr;
}

impl Ipv6Address for Ipv6Addr {
    fn is_mapped(&self) -> bool {
        match self.octets() {
            // IPv4-mapped IPv6 addresses are of the form ::ffff:a.b.c.d
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, _, _, _, _] => true,
            _ => false,
        }
    }

    fn unmap(self) -> IpAddr {
        match self.octets() {
            // IPv4-mapped IPv6 addresses have to form ::ffff:a.b.c.d
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, a, b, c, d] => {
                IpAddr::V4(Ipv4Addr::new(a, b, c, d))
            }
            _ => IpAddr::V6(self),
        }
    }
}
