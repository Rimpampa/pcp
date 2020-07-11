/*
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
use crate::types::OpCode;
use std::net::IpAddr;

pub struct RequestHeader {
    version: u8,
    opcode: OpCode, // MSb is always 1
    lifetime: u32,
    address: IpAddr,
}

impl RequestHeader {
    pub const SIZE: usize = 24;

    pub fn new(version: u8, opcode: OpCode, lifetime: u32, address: IpAddr) -> Self {
        Self {
            version,
            opcode,
            lifetime,
            address,
        }
    }
	#[rustfmt::skip]
    pub fn bytes(&self) -> [u8; Self::SIZE] {
		let lifetime = self.lifetime.to_be_bytes();
		// As specified in the RFC for IPv4 addresses, their IPv6 mapped value must be used
		let address = match self.address {
			IpAddr::V4(ipv4) => ipv4.to_ipv6_mapped(),
			IpAddr::V6(ipv6) => ipv6,
		}.octets();
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
