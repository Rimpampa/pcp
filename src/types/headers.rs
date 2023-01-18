use std::net::Ipv6Addr;

use super::*;
use util::{Deserialize, Serialize};

/// PCP request header
///
/// # Format
///
/// ```plain
/// 0               1               2               3
/// 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 8
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Version = 2  |R|   Opcode    |         Reserved              |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                 Requested Lifetime (32 bits)                  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |            PCP Client's IP Address (128 bits)                 |
/// |                                                               |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// :                                                               :
/// :             (optional) Opcode-specific information            :
/// :                                                               :
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// :                                                               :
/// :             (optional) PCP Options                            :
/// :                                                               :
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
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
    /// Size of the PCP [RequestHeader] (in bytes)
    pub const SIZE: usize = 24;

    /// Constructs a new PCP *map* [RequestHeader]
    pub fn map(version: u8, lifetime: u32, address: Ipv6Addr) -> Self {
        Self {
            version,
            address,
            lifetime,
            opcode: OpCode::Map,
        }
    }

    /// Constructs a new PCP *peer* [RequestHeader]
    pub fn peer(version: u8, lifetime: u32, address: Ipv6Addr) -> Self {
        Self {
            version,
            address,
            lifetime,
            opcode: OpCode::Peer,
        }
    }

    /// Constructs a new PCP *announce* [RequestHeader]
    pub fn announce(version: u8, address: Ipv6Addr) -> Self {
        Self {
            version,
            address,
            lifetime: 0,
            opcode: OpCode::Peer,
        }
    }

    pub fn size(&self) -> usize {
        Self::SIZE
    }

    pub fn serialize(&self, s: &mut [u8]) {
        let s: &mut [_; Self::SIZE] = util::sized_mut(s).unwrap();
        s[0] = self.version;
        s[1] = self.opcode as u8;
        self.lifetime.se(&mut s[4..8]);
        self.address.se(&mut s[8..24]);
    }
}

impl TryFrom<&[u8]> for RequestHeader {
    type Error = Error;

    fn try_from(s: &[u8]) -> Result<Self, Self::Error> {
        let s: &[_; Self::SIZE] = util::sized_ref(s)?;
        if s[0] != 2 {
            return Err(Error::VersionNotSupported(s[0]));
        }
        if s[1] & 0b10000000 != 0 {
            return Err(Error::NotARequest);
        }
        Ok(Self {
            version: s[0],
            opcode: s[1].try_into()?,
            lifetime: s[4..8].de(),
            address: s[8..24].de(),
        })
    }
}

/// PCP response header
///
/// # Format
///
/// ```plain
/// 0               1               2               3
/// 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 8
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Version = 2  |R|   Opcode    |   Reserved    |  Result Code  |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                      Lifetime (32 bits)                       |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                     Epoch Time (32 bits)                      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |                      Reserved (96 bits)                       |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// :                                                               :
/// :             (optional) Opcode-specific response data          :
/// :                                                               :
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// :             (optional) Options                                :
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
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

    pub fn serialize(&self, s: &mut [u8]) {
        let s: &mut [_; Self::SIZE] = util::sized_mut(s).unwrap();
        s[0] = self.version;
        s[1] = self.opcode as u8;
        s[3] = self.result as u8;
        self.lifetime.se(&mut s[4..8]);
        self.epoch.se(&mut s[8..12]);
    }
}

impl TryFrom<&[u8]> for ResponseHeader {
    type Error = Error;

    fn try_from(s: &[u8]) -> Result<Self, Self::Error> {
        let s: &[_; Self::SIZE] = util::sized_ref(s)?;
        if s[0] != 2 {
            return Err(Error::VersionNotSupported(s[0]));
        }
        if s[1] & 0b10000000 > 0 {
            return Err(Error::NotAResponse);
        }
        Ok(Self {
            version: s[0],
            opcode: s[1].try_into()?,
            result: s[3].try_into()?,
            lifetime: s[4..8].de(),
            epoch: s[8..12].de(),
        })
    }
}