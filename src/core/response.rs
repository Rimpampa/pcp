use std::net::Ipv6Addr;

use super::{payload::Payload, util, Epoch, Error, OpCode, ProtocolNumber, ResultCode};
use util::{Deserializer, Serializer};

pub type Nonce = [u8; 12];

/// PCP map response payload
///
/// # Format
///
/// ```plain
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
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
pub struct Map {
    /// Random data, copied from the corresponding request
    pub nonce: Nonce,
    /// Protocol number, copied from the corresponding request
    pub protocol: ProtocolNumber,
    /// Internal port number, copied from the corresponding request
    pub internal_port: u16,
    /// The assigned external port
    ///
    /// Note that on an error response this field is copied from the request.
    pub assigned_external_port: u16,
    /// The assigned external IP address
    ///
    /// An IPv6 address is represented directly, and an IPv4 address is represented
    /// using the IPv4-mapped address syntax, check [`Ipv4Addr::to_ipv6_mapped`].
    ///
    /// Note that on an error response this field is copied from the request.
    pub assigned_external_addr: Ipv6Addr,
}

impl Map {
    pub const SIZE: usize = 36;
}

impl util::Serialize for &Map {
    fn serialize<const S: usize>(self, buffer: Serializer<S>) -> util::Result<Serializer<S>> {
        buffer
            .serialize(self.nonce)?
            .serialize(self.protocol as u8)?
            .serialize([0u8; 3])?
            .serialize(self.internal_port)?
            .serialize(self.assigned_external_port)?
            .serialize(self.assigned_external_addr)
    }
}

impl util::Deserialize for Map {
    fn deserialize(data: &mut Deserializer) -> util::Result<Self> {
        Ok(Self {
            nonce: data.deserialize()?,
            protocol: data.deserialize()?,
            internal_port: data.skip(3)?.deserialize()?,
            assigned_external_port: data.deserialize()?,
            assigned_external_addr: data.deserialize()?,
        })
    }
}

/// PCP peer response payload
///
/// # Format
///
/// ```plain
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
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
pub struct Peer {
    /// Random data, copied from the corresponding request
    pub nonce: Nonce,
    /// Protocol number, copied from the corresponding request
    pub protocol: ProtocolNumber,
    /// Port number, copied from the corresponding request
    pub internal_port: u16,
    /// The assigned external port
    ///
    /// Note that on an error response this field is copied from the request.
    pub assigned_external_port: u16,
    /// The assigned external IP address
    ///
    /// An IPv6 address is represented directly, and an IPv4 address is represented
    /// using the IPv4-mapped address syntax, check [`Ipv4Addr::to_ipv6_mapped`].
    ///
    /// Note that on an error response this field is copied from the request.
    pub assigned_external_addr: Ipv6Addr,
    /// Remote peer port number, copied from the corresponding request
    pub remote_peer_port: u16,
    /// Remote peer IP address, copied from the corresponding request
    pub remote_peer_addr: Ipv6Addr,
}

impl Peer {
    pub const SIZE: usize = 56;
}

impl util::Serialize for &Peer {
    fn serialize<const S: usize>(self, buffer: Serializer<S>) -> util::Result<Serializer<S>> {
        buffer
            .serialize(self.nonce)?
            .serialize(self.protocol as u8)?
            .serialize([0u8; 3])?
            .serialize(self.internal_port)?
            .serialize(self.assigned_external_port)?
            .serialize(self.assigned_external_addr)?
            .serialize(self.remote_peer_port)?
            .serialize([0u8; 2])?
            .serialize(self.remote_peer_addr)
    }
}

impl util::Deserialize for Peer {
    fn deserialize(data: &mut Deserializer) -> util::Result<Self> {
        Ok(Self {
            nonce: data.deserialize()?,
            protocol: data.deserialize()?,
            internal_port: data.skip(3)?.deserialize()?,
            assigned_external_port: data.deserialize()?,
            assigned_external_addr: data.deserialize()?,
            remote_peer_port: data.deserialize()?,
            remote_peer_addr: data.skip(2)?.deserialize()?,
        })
    }
}

const fn max_options_size(payload_size: usize) -> usize {
    super::MAX_PACKET_SIZE - Response::HEADER_SIZE - payload_size
}

pub type MapPayload = Payload<Map, { max_options_size(Map::SIZE) }>;

pub type PeerPayload = Payload<Peer, { max_options_size(Peer::SIZE) }>;

pub type AnnouncePayload = Payload<(), { max_options_size(0) }>;

/// PCP request payload
///
/// This enum has a discriminant for each [`OpCode`]
/// which contains the payload and the options requested.
///
/// The tag of this enum could be compared to the `Opcode`
/// field of the request header (check [`RequestPacket`])
#[derive(PartialEq, Debug)]
pub enum ResponsePayload {
    /// Payload data for a **map** request
    Map(MapPayload),
    /// Payload data for a **peer** request
    Peer(PeerPayload),
    /// Payload data for a **announce** request
    Announce(AnnouncePayload),
}

impl ResponsePayload {
    /// Returns the [`OpCode`] of this request
    pub const fn opcode(&self) -> OpCode {
        match self {
            Self::Map(_) => OpCode::Map,
            Self::Peer(_) => OpCode::Peer,
            Self::Announce(_) => OpCode::Announce,
        }
    }
}

/// PCP response packet
///
/// # Format
///
/// ```plain
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  Version = 2  |1|   Opcode    |   Reserved    |  Result Code  |
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
pub struct Response {
    /// The version of the PCP protocol
    ///
    /// This field is used for version negotiation,
    /// PCP clients and servers compliant with the RFC 6887
    /// use the value `2`
    pub version: u8,
    /// The result code for this response
    pub result_code: ResultCode,
    /// Validity period of this response, the meaning depends on the `result_code`
    ///
    /// On an error response, this indicates how long
    /// clients should assume they'll get the same error response from
    /// that PCP server if they repeat the same request
    ///
    /// On a success response for the PCP Opcodes that create a mapping
    /// (MAP and PEER), this field indicates the lifetime for
    /// this mapping
    pub lifetime: u32,
    /// The server's Epoch Time value
    pub epoch: Epoch,
    /// Wrapper around the payload and the options
    pub payload: ResponsePayload,
}

impl Response {
    /// Size of the PCP request header in bytes
    pub const HEADER_SIZE: usize = 24;
}

impl util::Serialize for &Response {
    fn serialize<const S: usize>(self, mut buffer: Serializer<S>) -> util::Result<Serializer<S>> {
        buffer = buffer
            .serialize(self.version)?
            .serialize(self.payload.opcode() as u8 | 0b10000000)?
            .serialize([0; 1])?
            .serialize(self.result_code)?
            .serialize(self.lifetime)?
            .serialize(self.epoch.0)?
            .serialize([0; 12])?;
        match &self.payload {
            ResponsePayload::Map(p) => buffer.serialize(p),
            ResponsePayload::Peer(p) => buffer.serialize(p),
            ResponsePayload::Announce(p) => buffer.serialize(p),
        }
    }
}

impl util::Deserialize for Response {
    fn deserialize(data: &mut Deserializer) -> util::Result<Self> {
        let version = data.deserialize()?;
        let opcode: u8 = data.deserialize()?;
        if opcode & 0b10000000 == 0 {
            return Err(Error::NotAResponse);
        }
        let opcode = (opcode & 0b01111111).try_into()?;
        let result_code = data.skip(1)?.deserialize()?;
        let lifetime = data.deserialize()?;
        let epoch = Epoch(data.deserialize()?);
        let payload = match opcode {
            OpCode::Map => ResponsePayload::Map(data.deserialize()?),
            OpCode::Peer => ResponsePayload::Peer(data.deserialize()?),
            OpCode::Announce => ResponsePayload::Announce(data.deserialize()?),
        };
        Ok(Self {
            version,
            result_code,
            lifetime,
            epoch,
            payload,
        })
    }
}
