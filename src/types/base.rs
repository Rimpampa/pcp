//! This module contains all the headers described in the RFC

use super::*;
use std::convert::{TryFrom, TryInto};
use std::net::Ipv6Addr;

// ====================================== UTILITY FUNCTIONS =======================================

fn try_get<const S: usize>(s: &[u8]) -> Option<&[u8; S]> {
    Some(s.get(..S)?.try_into().unwrap())
}

fn try_get_mut<const S: usize>(s: &mut [u8]) -> Option<&mut [u8; S]> {
    Some(s.get_mut(..S)?.try_into().unwrap())
}

trait Util {
    fn get(s: &[u8]) -> Self;
    fn set(&self, s: &mut [u8]);
}

fn get<G: Util>(s: &[u8]) -> G {
    G::get(s)
}

impl<const S: usize> Util for [u8; S] {
    fn get(s: &[u8]) -> Self {
        s.try_into().unwrap()
    }

    fn set(&self, s: &mut [u8]) {
        s.copy_from_slice(self)
    }
}

impl Util for u16 {
    fn get(s: &[u8]) -> Self {
        Self::from_be_bytes(get(s))
    }

    fn set(&self, s: &mut [u8]) {
        self.to_be_bytes().set(s)
    }
}

impl Util for u32 {
    fn get(s: &[u8]) -> Self {
        Self::from_be_bytes(get(s))
    }

    fn set(&self, s: &mut [u8]) {
        self.to_be_bytes().set(s)
    }
}

impl Util for std::net::Ipv6Addr {
    fn get(s: &[u8]) -> Self {
        <[u8; 16]>::get(s).into()
    }

    fn set(&self, s: &mut [u8]) {
        self.octets().set(s)
    }
}

// =========================================== HEADERS ============================================

/*
    PCP REQUEST HEADER

     0               1               2               3
     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 8
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

/// A correctly formed PCP request header.
#[derive(PartialEq, Debug)]
pub struct RequestHeader {
    /// Version of the PCP protocol being used, only 2 is supported.
    pub version: u8,
    /// The code identifying the operation to request, see [OpCode].
    pub opcode: OpCode,
    /// The amount of time to request to the server for which the request should remain valid.
    pub lifetime: u32,
    /// Address of the client sending this request.
    pub address: Ipv6Addr,
}

impl RequestHeader {
    /// Size of the PCP request header (in bytes)
    pub const SIZE: usize = 24;

    /// Constructs a new [RequestHeader]
    pub fn new(version: u8, opcode: OpCode, lifetime: u32, address: Ipv6Addr) -> Self {
        Self {
            version,
            opcode,
            lifetime,
            address,
        }
    }

    /// Constructs a new PCP map request header
    pub fn map(version: u8, lifetime: u32, address: Ipv6Addr) -> Self {
        Self {
            version: 2,
            address,
            lifetime,
            opcode: OpCode::Map,
        }
    }

    /// Constructs a new PCP peer request header
    pub fn peer(version: u8, lifetime: u32, address: Ipv6Addr) -> Self {
        Self {
            version: 2,
            address,
            lifetime,
            opcode: OpCode::Peer,
        }
    }

    /// Constructs a new PCP announce request header
    pub fn announce(version: u8, address: Ipv6Addr) -> Self {
        Self {
            version: 2,
            address,
            lifetime: 0,
            opcode: OpCode::Peer,
        }
    }

    pub fn size(&self) -> usize {
        Self::SIZE
    }

    pub fn copy_to(&self, s: &mut [u8]) {
        let s = try_get_mut::<{ Self::SIZE }>(s).unwrap();
        s[0] = self.version;
        s[1] = self.opcode as u8;
        self.lifetime.set(&mut s[4..8]);
        self.address.set(&mut s[8..24]);
    }
}

impl TryFrom<&[u8]> for RequestHeader {
    type Error = ParsingError;

    fn try_from(s: &[u8]) -> Result<Self, Self::Error> {
        let s = try_get::<{ Self::SIZE }>(s)
            .ok_or_else(|| ParsingError::InvalidSliceLength(s.len()))?;
        if s[0] != 2 {
            return Err(ParsingError::VersionNotSupported(s[0]));
        }
        if s[1] & 0b10000000 != 0 {
            return Err(ParsingError::NotARequest);
        }
        Ok(Self {
            version: s[0],
            opcode: s[1].try_into()?,
            lifetime: get(&s[4..8]),
            address: get(&s[8..24]),
        })
    }
}

/*
    PCP RESPONSE HEADER

     0               1               2               3
     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 8
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Version = 2  |R|   Opcode    |   Reserved    |  Result Code  |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Lifetime (32 bits)                       |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                     Epoch Time (32 bits)                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    |                      Reserved (96 bits)                       |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    :                                                               :
    :             (optional) Opcode-specific response data          :
    :                                                               :
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    :             (optional) Options                                :
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/// A correctly formed PCP response header.
#[derive(PartialEq, Debug)]
pub struct ResponseHeader {
    /// Version of the PCP protocol being used, only 2 is supported.
    pub version: u8,
    /// The code identifying the requested operation, see [OpCode].
    pub opcode: OpCode,
    /// The result of the operation, see [ResultCode].
    pub result: ResultCode,
    /// The lifetime assigned to the request, that is how long it will remain valid.
    /// It may not be the same amount requested.
    pub lifetime: u32,
    /// Server's epoch, for client-server synchronization.
    pub epoch: u32,
}

impl ResponseHeader {
    /// Size of the PCP response header (in bytes)
    pub const SIZE: usize = 24;

    pub fn size(&self) -> usize {
        Self::SIZE
    }

    pub fn copy_to(&self, s: &mut [u8]) {
        let s = try_get_mut::<{ Self::SIZE }>(s).unwrap();
        s[0] = self.version;
        s[1] = self.opcode as u8;
        s[3] = self.result as u8;
        self.lifetime.set(&mut s[4..8]);
        self.epoch.set(&mut s[8..12]);
    }
}

impl TryFrom<&[u8]> for ResponseHeader {
    type Error = ParsingError;

    fn try_from(s: &[u8]) -> Result<Self, Self::Error> {
        let s = try_get::<{ Self::SIZE }>(s)
            .ok_or_else(|| ParsingError::InvalidSliceLength(s.len()))?;
        if s[0] != 2 {
            return Err(ParsingError::VersionNotSupported(s[0]));
        }
        if s[1] & 0b10000000 > 0 {
            return Err(ParsingError::NotAResponse);
        }
        Ok(Self {
            version: s[0],
            opcode: s[1].try_into()?,
            result: s[3].try_into()?,
            lifetime: get(&s[4..8]),
            epoch: get(&s[8..12]),
        })
    }
}

/*
    PCP OPTION HEADER

     0               1               2               3
     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 8
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |  Option Code  |  Reserved     |       Option Length           |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    :                     (optional) Payload                        :
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/// A correctly formed PCP option header.
#[derive(PartialEq, Debug)]
pub struct OptionHeader {
    /// The code that identifies the option type, see [OptionCode].
    pub code: OptionCode,
    /// The length of the option data, in bytes. It depends on the [OptionCode].
    pub length: u16,
}

impl OptionHeader {
    /// Size of the PCP option header (in bytes)
    pub const SIZE: usize = 4;

    /// Constructs a new filter option header
    pub const fn filter() -> Self {
        let code = OptionCode::Filter;
        let length = FilterOptionPayload::SIZE as u16;
        Self { code, length }
    }

    /// Constructs a new third party option header
    pub const fn third_party() -> Self {
        let code = OptionCode::ThirdParty;
        let length = ThirdPartyOptionPayload::SIZE as u16;
        Self { code, length }
    }

    /// Constructs a new prefer failure option header
    pub const fn prefer_failure() -> Self {
        let code = OptionCode::PreferFailure;
        Self { code, length: 0 }
    }

    pub fn size(&self) -> usize {
        Self::SIZE
    }

    pub fn copy_to(&self, s: &mut [u8]) {
        let s = try_get_mut::<{ Self::SIZE }>(s).unwrap();
        s[0] = self.code as u8;
        self.length.set(&mut s[2..4]);
    }
}

impl TryFrom<&[u8]> for OptionHeader {
    type Error = ParsingError;

    fn try_from(s: &[u8]) -> Result<Self, Self::Error> {
        let s = try_get::<{ Self::SIZE }>(s)
            .ok_or_else(|| ParsingError::InvalidSliceLength(s.len()))?;
        let code = s[0].try_into()?;
        let length = get(&s[2..4]);
        let check = match code {
            OptionCode::Filter => FilterOptionPayload::SIZE,
            OptionCode::ThirdParty => ThirdPartyOptionPayload::SIZE,
            OptionCode::PreferFailure => 0,
        };
        if length != check as u16 {
            return Err(ParsingError::InvalidOptionLength(code, length as usize));
        }
        Ok(Self { code, length })
    }
}

// =========================================== PAYLOADS ===========================================

/*
    PCP MAP RESPONSE PAYLOAD

     0               1               2               3
     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 8
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
*/

#[derive(PartialEq, Debug)]
pub struct MapResponsePayload {
    /// Random data, copied from the corresponding request
    pub nonce: [u8; 12],
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
    /// Size of the PCP map reponse payload (in bytes)
    pub const SIZE: usize = 36;

    pub fn size(&self) -> usize {
        Self::SIZE
    }

    pub fn copy_to(&self, s: &mut [u8]) {
        let s = try_get_mut::<{ Self::SIZE }>(s).unwrap();
        self.nonce.set(&mut s[..12]);
        s[13] = self.protocol as u8;
        self.internal_port.set(&mut s[16..18]);
        self.external_port.set(&mut s[18..20]);
        self.external_addr.set(&mut s[20..36]);
    }
}

impl TryFrom<&[u8]> for MapResponsePayload {
    type Error = ParsingError;

    fn try_from(s: &[u8]) -> Result<Self, Self::Error> {
        let s = try_get::<{ Self::SIZE }>(s)
            .ok_or_else(|| ParsingError::InvalidSliceLength(s.len()))?;
        Ok(Self {
            nonce: get(&s[..12]),
            protocol: s[13].try_into()?,
            internal_port: get(&s[16..18]),
            external_port: get(&s[18..20]),
            external_addr: get(&s[20..36]),
        })
    }
}

/*
    PCP MAP REQUEST PAYLOAD

     0               1               2               3
     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 8
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

/// A correctly formed PCP map request payload.
#[derive(PartialEq, Debug)]
pub struct MapRequestPayload {
    /// Randomly generated data.
    pub nonce: [u8; 12],
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
    /// Size of the PCP map request payload (in bytes)
    pub const SIZE: usize = 36;

    /// Creates a new map request payload. If the external port is not known use 0, same goes for
    /// the external address, if it's not known use the UNSPECIFIED address of the relative version
    pub fn new(
        nonce: [u8; 12],
        protocol: Option<ProtocolNumber>,
        internal_port: u16,
        external_port: u16,
        external_addr: Ipv6Addr,
    ) -> Self {
        MapRequestPayload {
            nonce,
            // Hoptop is number zero which also means "all" or "any"
            protocol: protocol.unwrap_or(ProtocolNumber::Hopopt),
            internal_port,
            external_port,
            external_addr,
        }
    }

    pub fn size(&self) -> usize {
        Self::SIZE
    }

    pub fn copy_to(&self, s: &mut [u8]) {
        let s = try_get_mut::<{ Self::SIZE }>(s).unwrap();
        self.nonce.set(&mut s[0..12]);
        s[12] = self.protocol as u8;
        self.external_port.set(&mut s[16..18]);
        self.internal_port.set(&mut s[18..20]);
        self.external_addr.set(&mut s[20..36]);
    }
}

impl TryFrom<&[u8]> for MapRequestPayload {
    type Error = ParsingError;

    fn try_from(s: &[u8]) -> Result<Self, Self::Error> {
        let s = try_get::<{ Self::SIZE }>(s)
            .ok_or_else(|| ParsingError::InvalidSliceLength(s.len()))?;
        Ok(Self {
            nonce: get(&s[0..12]),
            protocol: s[12].try_into()?,
            external_port: get(&s[16..18]),
            internal_port: get(&s[18..20]),
            external_addr: get(&s[20..36]),
        })
    }
}

/*
    PCP PEER RESPONSE PAYLOAD

     0               1               2               3
     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 8
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

/// A correctly formed PCP peer request payload.
#[derive(PartialEq, Debug)]
pub struct PeerResponsePayload {
    pub nonce: [u8; 12],
    pub protocol: ProtocolNumber,
    pub internal_port: u16,
    pub external_port: u16,
    pub external_addr: Ipv6Addr,
    pub remote_port: u16,
    pub remote_addr: Ipv6Addr,
}

impl PeerResponsePayload {
    /// Size of the PCP map response payload (in bytes)
    pub const SIZE: usize = 56;

    fn size(&self) -> usize {
        Self::SIZE
    }

    fn copy_to(&self, s: &mut [u8]) {
        let s = try_get_mut::<{ Self::SIZE }>(s).unwrap();
        s[12] = self.protocol as u8;
        self.nonce.set(&mut s[0..12]);
        self.internal_port.set(&mut s[16..18]);
        self.external_port.set(&mut s[18..20]);
        self.external_addr.set(&mut s[20..36]);
        self.remote_port.set(&mut s[36..38]);
        self.remote_addr.set(&mut s[40..56]);
    }
}

impl TryFrom<&[u8]> for PeerResponsePayload {
    type Error = ParsingError;

    fn try_from(s: &[u8]) -> Result<Self, Self::Error> {
        let s = try_get::<{ Self::SIZE }>(s)
            .ok_or_else(|| ParsingError::InvalidSliceLength(s.len()))?;
        Ok(Self {
            nonce: get(&s[0..12]),
            protocol: s[12].try_into()?,
            internal_port: get(&s[16..18]),
            external_port: get(&s[18..20]),
            external_addr: get(&s[20..36]),
            remote_port: get(&s[36..38]),
            remote_addr: get(&s[40..56]),
        })
    }
}

/*
    PCP PEER REQUEST PAYLOAD

     0               1               2               3
     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 8
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
    |       Remote Peer Port        |     Reserved (16 bits)        |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    |               Remote Peer IP Address (128 bits)               |
    |                                                               |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

/// A correctly formed peer request payload`
#[derive(PartialEq, Debug)]
pub struct PeerRequestPayload {
    pub nonce: [u8; 12],
    pub protocol: ProtocolNumber,
    pub internal_port: u16,
    pub external_port: u16,
    pub external_addr: Ipv6Addr,
    pub remote_port: u16,
    pub remote_addr: Ipv6Addr,
}

impl PeerRequestPayload {
    /// Size of the PCP peer request payload (in bytes)
    pub const SIZE: usize = 56;

    /// Creates a new peer request payload. If the _external_port_ is not known use 0, same goes for
    /// the _external_address_, if it's not known use the `UNSPECIFIED` address of the relative version.
    pub fn new(
        nonce: [u8; 12],
        protocol: Option<ProtocolNumber>,
        internal_port: u16,
        external_port: u16,
        external_addr: Ipv6Addr,
        remote_port: u16,
        remote_addr: Ipv6Addr,
    ) -> Self {
        PeerRequestPayload {
            nonce,
            // Hoptop is number zero which also means "all" or "any"
            protocol: protocol.unwrap_or(ProtocolNumber::Hopopt),
            internal_port,
            external_port,
            external_addr,
            remote_port,
            remote_addr,
        }
    }

    pub fn size(&self) -> usize {
        Self::SIZE
    }

    pub fn copy_to(&self, s: &mut [u8]) {
        let s = try_get_mut::<{ Self::SIZE }>(s).unwrap();
        self.nonce.set(&mut s[0..12]);
        s[12] = self.protocol as u8;
        self.internal_port.set(&mut s[16..18]);
        self.external_port.set(&mut s[18..20]);
        self.external_addr.set(&mut s[20..36]);
        self.remote_port.set(&mut s[36..38]);
        self.remote_addr.set(&mut s[40..56]);
    }
}

impl TryFrom<&[u8]> for PeerRequestPayload {
    type Error = ParsingError;

    fn try_from(s: &[u8]) -> Result<Self, Self::Error> {
        let s = try_get::<{ Self::SIZE }>(s)
            .ok_or_else(|| ParsingError::InvalidSliceLength(s.len()))?;
        Ok(Self {
            nonce: get(&s[0..12]),
            protocol: s[12].try_into()?,
            internal_port: get(&s[16..18]),
            external_port: get(&s[18..20]),
            external_addr: get(&s[20..36]),
            remote_port: get(&s[36..38]),
            remote_addr: get(&s[40..56]),
        })
    }
}

/*
    PCP FILTER OPTION PAYLOAD

     0               1               2               3
     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 8
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

/// A correctly formed PCP filter option payload
#[derive(PartialEq, Debug)]
pub struct FilterOptionPayload {
    /// The number of bits in the address to consider when filtering
    pub prefix: u8,
    /// The port that the remote peer has to use
    pub remote_port: u16,
    /// The address that the remote peer has to use
    pub remote_addr: Ipv6Addr,
}

impl FilterOptionPayload {
    pub const CODE: OptionCode = OptionCode::Filter;

    pub const SIZE: usize = 20;

    pub fn size(&self) -> usize {
        Self::SIZE
    }

    pub fn copy_to(&self, s: &mut [u8]) {
        let s = try_get_mut::<{ Self::SIZE }>(s).unwrap();
        s[1] = self.prefix;
        self.remote_port.set(&mut s[2..4]);
        self.remote_addr.set(&mut s[4..20]);
    }
}

impl TryFrom<&[u8]> for FilterOptionPayload {
    type Error = ParsingError;

    fn try_from(s: &[u8]) -> Result<Self, Self::Error> {
        let s = try_get::<{ Self::SIZE }>(s)
            .ok_or_else(|| ParsingError::InvalidSliceLength(s.len()))?;
        if let [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, _, _, _, _] = s[4..20] {
            if s[1] < 96 {
                return Err(ParsingError::InvalidPrefix(s[1]));
            }
        }
        Ok(Self {
            prefix: s[1],
            remote_port: get(&s[2..4]),
            remote_addr: get(&s[4..20]),
        })
    }
}

/*
    PCP THIRD PARTY OPTION PAYLOAD

     0               1               2               3
     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 8
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Option Code=1 |  Reserved     |   Option Length=16            |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                                                               |
    |                Internal IP Address (128 bits)                 |
    |                                                               |
    |                                                               |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/// A correctly formed third party option payload.
#[derive(PartialEq, Debug)]
pub struct ThirdPartyOptionPayload {
    pub address: Ipv6Addr,
}

impl ThirdPartyOptionPayload {
    pub const CODE: OptionCode = OptionCode::ThirdParty;

    /// Size of the third party option payload (in bytes)
    pub const SIZE: usize = 16;

    /// Creates a new third party option header
    pub const fn new(address: Ipv6Addr) -> Self {
        ThirdPartyOptionPayload { address }
    }

    pub fn size(&self) -> usize {
        Self::SIZE
    }

    pub fn copy_to(&self, s: &mut [u8]) {
        let s = try_get_mut::<{ Self::SIZE }>(s).unwrap();
        self.address.set(&mut s[..]);
    }
}

impl TryFrom<&[u8]> for ThirdPartyOptionPayload {
    type Error = ParsingError;

    fn try_from(s: &[u8]) -> Result<Self, Self::Error> {
        let s = try_get::<{ Self::SIZE }>(s)
            .ok_or_else(|| ParsingError::InvalidSliceLength(s.len()))?;
        Ok(Self { address: get(s) })
    }
}

/*
    PCP THIRD PARTY OPTION PAYLOAD

     0               1               2               3
     0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 8
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    | Option Code=2 |  Reserved     |   Option Length=0             |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

// TODOs
#[derive(Debug)]
pub struct PreferFailureOptionPayload {}

impl PreferFailureOptionPayload {
    const CODE: OptionCode = OptionCode::PreferFailure;

    const SIZE: usize = 0;

    pub fn size(&self) -> usize {
        0
    }

    pub fn copy_to(&self, _: &[u8]) {}
}

impl TryFrom<&[u8]> for PreferFailureOptionPayload {
    type Error = ParsingError;

    fn try_from(s: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self {})
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        use OpCode::*;
        use ResultCode::*;

        // Headers - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

        let h = ResponseHeader {
            epoch: 1,
            lifetime: 1,
            opcode: Announce,
            result: AddressMismatch,
            version: 2,
        };
        let b = &mut [0; ResponseHeader::SIZE];
        h.copy_to(b);
        assert_eq!(Ok(h), b.as_ref().try_into());

        let h = RequestHeader::new(2, Announce, 10, "::1".parse().unwrap());
        let b = &mut [0; RequestHeader::SIZE];
        h.copy_to(b);
        assert_eq!(Ok(h), b.as_ref().try_into());

        let b = &mut [0; OptionHeader::SIZE];
        let h = OptionHeader::prefer_failure();
        h.copy_to(b);
        assert_eq!(Ok(h), b.as_ref().try_into());

        let h = OptionHeader::third_party();
        h.copy_to(b);
        assert_eq!(Ok(h), b.as_ref().try_into());

        let h = OptionHeader::filter();
        h.copy_to(b);
        assert_eq!(Ok(h), b.as_ref().try_into());

        // Payloads - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
    }
}
