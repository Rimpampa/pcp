//! # Format
//!
//! The RFC defines the following format for the map request payload:
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
    |        Internal Port          |    Suggested External Port    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    |           Suggested External IP Address (128 bits)            |
    |                                                               |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/
//! **Requested lifetime** (in common header):
//!     Requested lifetime of this mapping, in seconds. The value 0 indicates "delete".
//!
//! **Mapping Nonce**: Random value chosen by the PCP client.
//!
//! **Protocol**:
//!     Upper-layer protocol associated with this Opcode. Values
//!     are taken from the IANA protocol registry. The value 0 has a special
//!     meaning for 'all protocols'.
//!
//! **Reserved**: 24 reserved bits, MUST be sent as 0 and MUST be ignored when received.
//!
//! **Internal Port**:
//!     Internal port for the mapping. The value 0 indicates
//!     'all ports', and is legal when the lifetime is zero (a delete
//!     request), if the protocol does not use 16-bit port numbers, or the
//!     client is requesting 'all ports'.  If the protocol is zero
//!     (meaning 'all protocols'), then internal port MUST be zero on
//!     transmission and MUST be ignored on reception.
//!
//! **Suggested External Port**:
//!     Suggested external port for the mapping. This is useful for
//!     refreshing a mapping, especially after the PCP
//!     server loses state.  If the PCP client does not know the external
//!     port, or does not have a preference, it MUST use 0.
//!
//! **Suggested External IP Address**:
//!     Suggested external IPv4 or IPv6 address. This is useful
//!     for refreshing a mapping, especially after the PCP server loses state.

use crate::types::ProtocolNumber;
use std::net::IpAddr;

/// A correctly formed PCP `MapRequestPayload` containing a nonce, the `ProtocolNumber` relative
/// to the protcol that will be used by this mapping, the internal port from which the PCP client
/// will receive incoming packets, a *suggested* external port and address, that the PCP server will
/// try to use for receiving packets from the remote hosts
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

    /// Creates a correctly formatted byte array representing the payload
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
