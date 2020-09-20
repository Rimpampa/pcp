//! # Format
//!
//! The RFC defines the following format for the request header:
/*!

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Version = 2  |R|   Opcode    |         Reserved              |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                 Requested Lifetime (32 bits)                  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    |            PCP Client's IP Address (128 bits)                 |
    |                                                               |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    :                                                               :
    :             (optional) Opcode-specific information            :
    :                                                               :
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    :                                                               :
    :             (optional) PCP Options                            :
    :                                                               :
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
//! **Version**: Only version 2 is supported
//!
//! **R**: Indicates Request (0) or Response (1).
//!
//! **Opcode**: A 7-bit value specifying the operation to be performed.
//!
//! **Reserved**:
//!     16 reserved bits. MUST be zero on transmission and MUST be ignored on reception.
//!
//! **Requested Lifetime**:
//!     An unsigned 32-bit integer, in seconds, ranging
//!     from 0 to 2^32-1 seconds. This is used by the MAP and PEER
//!     Opcodes defined in this document for their requested lifetime.
//!
//! **PCP Client's IP Address**:
//!     The source IPv4 or IPv6 address in the IP
//!     header used by the PCP client when sending this PCP request.  An
//!     IPv4 address is represented using an IPv4-mapped IPv6 address.
//!
//! **Opcode-specific information**:
//!     Payload data for this Opcode. The length of this data
//!     is determined by the Opcode definition.
//!
//! **PCP Options**:
//!     Zero, one, or more options that are legal for both a
//!     PCP request and for this Opcode.
use crate::types::OpCode;
use std::net::IpAddr;

/// A correctly formed PCP `RequestHeader` containing a version number, an `OpCode`,
/// a lifetime duration (in seconds) and the address of the client
pub struct RequestHeader {
    pub version: u8,
    pub opcode: OpCode,
    pub lifetime: u32,
    pub address: IpAddr,
}

impl RequestHeader {
    /// Size in bytes of every PCP request header
    pub const SIZE: usize = 24;

    /// Constructs a new `RequestHeader`
    pub fn new(version: u8, opcode: OpCode, lifetime: u32, address: IpAddr) -> Self {
        Self {
            version,
            opcode,
            lifetime,
            address,
        }
    }

    /// Creates a correctly formatted byte array representing the header
    #[rustfmt::skip]
    pub fn bytes(&self) -> [u8; Self::SIZE] {
        let lifetime = self.lifetime.to_be_bytes();
        // As specified in the RFC for IPv4 addresses, their IPv4-mapped IPv6 value must be used
        let address = match self.address {
            IpAddr::V4(ipv4) => ipv4.to_ipv6_mapped(),
            IpAddr::V6(ipv6) => ipv6,
        }
        .octets();
		[
			self.version,
			self.opcode as u8, // MSB is zero = it's a request
			0, 0,
			lifetime[0], lifetime[1], lifetime[2], lifetime[3],
			address[0], address[1], address[2], address[3],
			address[4], address[5], address[6], address[7],
			address[8], address[9], address[10], address[11],
			address[12], address[13], address[14], address[15],
		]
    }
}
