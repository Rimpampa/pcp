use std::net::Ipv6Addr;

use super::*;
use util::{Deserialize, Serialize, ConstantSize};

pub type Nonce = [u8; 12];

/// PCP map response payload
///
/// # Format
///
/// ```plain
/// 0               1               2               3
/// 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 8
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |                 Mapping Nonce (96 bits)                       |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Protocol    |          Reserved (24 bits)                   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |        Internal Port          |    Assigned External Port     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |            Assigned External IP Address (128 bits)            |
/// |                                                               |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(PartialEq, Debug)]
pub struct MapResponsePayload {
    /// Random data, copied from the corresponding request
    pub nonce: Nonce,
    /// The requested protocol number
    pub protocol: ProtocolNumber,
    /// The requested Port to which the packets will get mapped
    pub internal_port: u16,
    /// The assigned external port
    pub external_port: u16,
    /// The assigned external address
    pub external_addr: Ipv6Addr,
}

impl MapResponsePayload {
    pub const SIZE: usize = 36;
}

impl Serialize for MapResponsePayload {
    fn se(&self, s: &mut [u8]) {
        let s: &mut [_; Self::SIZE] = util::sized_mut(s).unwrap();
        self.nonce.se(&mut s[..12]);
        s[13] = self.protocol as u8;
        self.internal_port.se(&mut s[16..18]);
        self.external_port.se(&mut s[18..20]);
        self.external_addr.se(&mut s[20..36]);
    }
}

impl TryFrom<&[u8]> for MapResponsePayload {
    type Error = Error;

    fn try_from(s: &[u8]) -> Result<Self, Self::Error> {
        let s: &[_; Self::SIZE] = util::sized_ref(s)?;
        Ok(Self {
            nonce: s[..12].de(),
            protocol: s[13].try_into()?,
            internal_port: s[16..18].de(),
            external_port: s[18..20].de(),
            external_addr: s[20..36].de(),
        })
    }
}

/// PCP map request payload
///
/// # Format
///
/// ```plain
/// 0               1               2               3
/// 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 8
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |                 Mapping Nonce (96 bits)                       |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Protocol    |          Reserved (24 bits)                   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |        Internal Port          |    Suggested External Port    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |           Suggested External IP Address (128 bits)            |
/// |                                                               |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(PartialEq, Debug)]
pub struct MapRequestPayload {
    /// Randomly generated data.
    pub nonce: Nonce,
    /// Protocol number for the mapping, see [ProtocolNumber] for possible options.
    pub protocol: ProtocolNumber,
    /// The port to which packets will be mapped to.
    pub internal_port: u16,
    /// The port from which outside packets will get mapped. If 0 the server
    /// will choose one automatically.
    pub external_port: u16,
    /// The address from which outside packets will get mapped.
    pub external_addr: Ipv6Addr,
}

impl MapRequestPayload {
    pub const SIZE: usize = 36;
}

impl Serialize for MapRequestPayload {
    fn se(&self, s: &mut [u8]) {
        let s: &mut [_; Self::SIZE] = util::sized_mut(s).unwrap();
        self.nonce.se(&mut s[0..12]);
        s[12] = self.protocol as u8;
        self.external_port.se(&mut s[16..18]);
        self.internal_port.se(&mut s[18..20]);
        self.external_addr.se(&mut s[20..36]);
    }
}

impl TryFrom<&[u8]> for MapRequestPayload {
    type Error = Error;

    fn try_from(s: &[u8]) -> Result<Self, Self::Error> {
        let s: &[_; Self::SIZE] = util::sized_ref(s)?;
        Ok(Self {
            nonce: s[0..12].de(),
            protocol: s[12].try_into()?,
            external_port: s[16..18].de(),
            internal_port: s[18..20].de(),
            external_addr: s[20..36].de(),
        })
    }
}

/// PCP peer response payload
///
/// # Format
///
/// ```plain
/// 0               1               2               3
/// 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 8
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |                 Mapping Nonce (96 bits)                       |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Protocol    |          Reserved (24 bits)                   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |        Internal Port          |    Assigned External Port     |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |            Assigned External IP Address (128 bits)            |
/// |                                                               |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |       Remote Peer Port        |     Reserved (16 bits)        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |               Remote Peer IP Address (128 bits)               |
/// |                                                               |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(PartialEq, Debug)]
pub struct PeerResponsePayload {
    pub nonce: Nonce,
    pub protocol: ProtocolNumber,
    pub internal_port: u16,
    pub external_port: u16,
    pub external_addr: Ipv6Addr,
    pub remote_port: u16,
    pub remote_addr: Ipv6Addr,
}

impl PeerResponsePayload {
    pub const SIZE: usize = 56;
}

impl Serialize for PeerResponsePayload {
    fn se(&self, s: &mut [u8]) {
        let s: &mut [_; Self::SIZE] = util::sized_mut(s).unwrap();
        s[12] = self.protocol as u8;
        self.nonce.se(&mut s[0..12]);
        self.internal_port.se(&mut s[16..18]);
        self.external_port.se(&mut s[18..20]);
        self.external_addr.se(&mut s[20..36]);
        self.remote_port.se(&mut s[36..38]);
        self.remote_addr.se(&mut s[40..56]);
    }
}

impl TryFrom<&[u8]> for PeerResponsePayload {
    type Error = Error;

    fn try_from(s: &[u8]) -> Result<Self, Self::Error> {
        let s: &[_; Self::SIZE] = util::sized_ref(s)?;
        Ok(Self {
            nonce: s[0..12].de(),
            protocol: s[12].try_into()?,
            internal_port: s[16..18].de(),
            external_port: s[18..20].de(),
            external_addr: s[20..36].de(),
            remote_port: s[36..38].de(),
            remote_addr: s[40..56].de(),
        })
    }
}

/// PCP peer request payload
///
/// # Format
///
/// ```plain
/// 0               1               2               3
/// 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 8
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |                 Mapping Nonce (96 bits)                       |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |   Protocol    |          Reserved (24 bits)                   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |        Internal Port          |    Suggested External Port    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |           Suggested External IP Address (128 bits)            |
/// |                                                               |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |       Remote Peer Port        |     Reserved (16 bits)        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |               Remote Peer IP Address (128 bits)               |
/// |                                                               |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(PartialEq, Debug)]
pub struct PeerRequestPayload {
    pub nonce: Nonce,
    pub protocol: ProtocolNumber,
    pub internal_port: u16,
    pub external_port: u16,
    pub external_addr: Ipv6Addr,
    pub remote_port: u16,
    pub remote_addr: Ipv6Addr,
}

impl PeerRequestPayload {
    pub const SIZE: usize = 56;
}

impl Serialize for PeerRequestPayload {
    fn se(&self, s: &mut [u8]) {
        let s: &mut [_; Self::SIZE] = util::sized_mut(s).unwrap();
        self.nonce.se(&mut s[0..12]);
        s[12] = self.protocol as u8;
        self.internal_port.se(&mut s[16..18]);
        self.external_port.se(&mut s[18..20]);
        self.external_addr.se(&mut s[20..36]);
        self.remote_port.se(&mut s[36..38]);
        self.remote_addr.se(&mut s[40..56]);
    }
}

impl TryFrom<&[u8]> for PeerRequestPayload {
    type Error = Error;

    fn try_from(s: &[u8]) -> Result<Self, Self::Error> {
        let s: &[_; Self::SIZE] = util::sized_ref(s)?;
        Ok(Self {
            nonce: s[0..12].de(),
            protocol: s[12].try_into()?,
            internal_port: s[16..18].de(),
            external_port: s[18..20].de(),
            external_addr: s[20..36].de(),
            remote_port: s[36..38].de(),
            remote_addr: s[40..56].de(),
        })
    }
}
