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
    |        Internal Port          |    Suggested External Port    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    |           Suggested External IP Address (128 bits)            |
    |                                                               |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

use crate::types::ProtocolNumber;
use std::net::IpAddr;

#[derive(PartialEq, Debug)]
pub struct MapRequestPayload {
    pub nonce: [u8; 12],
    pub protocol: ProtocolNumber,
    pub internal_port: u16,
    pub external_port: u16,
    pub external_address: IpAddr,
}

impl MapRequestPayload {
    /// Size of the PCP map request payload (in bytes)
    pub const SIZE: usize = 36;

    /// Creates a new map request payload. If the external port is not known use 0, same goes for
    /// the external address, if it's not known use the UNSPECIFIED address of the relative version
    pub fn new(
        nonce: [u8; 12],
        protocol: Option<ProtocolNumber>,
        internal_port: u16,
        external_port: u16,
        external_address: IpAddr,
    ) -> Self {
        MapRequestPayload {
            nonce,
            // Hoptop is number zero which also means "all" or "any"
            protocol: protocol.unwrap_or(ProtocolNumber::Hopopt),
            internal_port,
            external_port,
            external_address,
        }
    }

	#[rustfmt::skip]
    pub fn bytes(&self) -> [u8; Self::SIZE] {
		let int_port = self.internal_port.to_be_bytes();
		let ext_port = self.external_port.to_be_bytes();
		let ext_ip = match self.external_address {
			IpAddr::V4(ip) => ip.to_ipv6_mapped(),
			IpAddr::V6(ip) => ip,
		}.octets();
		[
			self.nonce[0], self.nonce[1], self.nonce[2], self.nonce[3],
			self.nonce[4], self.nonce[5], self.nonce[6], self.nonce[7],
			self.nonce[8], self.nonce[9], self.nonce[10], self.nonce[11],
			self.protocol as u8,
			0, 0, 0,
			int_port[0], int_port[1],
			ext_port[0], ext_port[1],
			ext_ip[0], ext_ip[1], ext_ip[2], ext_ip[3],
			ext_ip[4], ext_ip[5], ext_ip[6], ext_ip[7],
			ext_ip[8], ext_ip[9], ext_ip[10], ext_ip[11],
			ext_ip[12], ext_ip[13], ext_ip[14], ext_ip[15],
		]
	}
}
