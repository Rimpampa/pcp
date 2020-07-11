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
use crate as pcp;
use std::net::IpAddr;

#[repr(C)]
struct RequestHeader {
    version: u8,
    opcode: u8,    // MSb is always 1
    reserved: u16, // MUST be 0
    lifetime: u32,
}

pub struct Request<'a> {
    header: RequestHeader,
    payload: &'a [u8],
    options: &'a [pcp::Option<'a>],
}

impl Request<'_> {}

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
pub struct Map {
    nonce: [u8; 12],
    protocol: u8,
    reserved: [u8; 3], // MUST be 0
    int_port: u16,
    ext_port: u16, // (suggested)
    ext_addr: IpAddr, // (suggested)
}

impl Map {
    pub fn map(
        internal_port: u16,
        protocol: pcp::ProtocolNumber,
        external_addr: Option<IpAddr>,
        external_port: Option<u16>,
    ) -> Map {
        Map {
            nonce: [0; 12],
            protocol,
            reserved: [0; 3],
            int_port: internal_port,
            ext_port: external_port.unwrap_or(0),
            ext_addr: external_addr.unwrap_or(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)),
        }
    }
}