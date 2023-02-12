use core::num::NonZeroU16;

use std::net::Ipv6Addr;

use super::{op_code::ROpCode, payload::Payload, util, Error, OpCode, ProtocolNumber};
use util::{Deserializer, Serializer};

pub type Nonce = [u8; 12];

/// PCP [`Map`](OpCode::Map) request payload
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
/// |        Internal Port          |    Suggested External Port    |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// |           Suggested External IP Address (128 bits)            |
/// |                                                               |
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// ```
#[derive(PartialEq, Debug, Clone, Copy)]
pub struct Map {
    /// Random value chosen by the PCP client
    pub mapping_nonce: Nonce,
    /// Upper-layer protocol associated with this mapping
    ///
    /// The value [`ProtocolNumber::Hopopt`] (0) has a special
    /// meaning for _all protocols_.
    pub protocol: ProtocolNumber,
    /// Internal port for the mapping
    ///
    /// The value `0` indicates _all ports_, and is legal when the lifetime
    /// is zero (a delete request), if the protocol does not use 16-bit
    /// port numbers, or the client is requesting _all ports_.
    ///
    /// If the `protocol` is [`ProtocolNumber::Hopopt`] (zero, meaning _all protocols_),
    /// then internal port **must** be zero on transmission and **must** be
    /// ignored on reception.
    pub internal_port: u16,
    /// Suggested external port for the mapping
    ///
    /// This is useful for refreshing a mapping, especially after the PCP
    /// server loses state.
    ///
    /// If the PCP client does not know the external
    /// port, or does not have a preference, it **must** use 0.
    pub suggested_external_port: u16,
    /// Suggested external IPv4 or IPv6 address
    ///
    /// This is useful for refreshing a mapping, especially
    /// after the PCP server loses state.
    ///
    /// If the PCP client does not know
    /// the external address, or does not have a preference, it **must** use
    /// the address-family-specific all-zeros address, which is
    /// [`Ipv4Addr::UNSPECIFIED`] for IPv4 and [`Ipv6Addr::UNSPECIFIED`] for IPv6.
    ///
    /// An IPv6 address is represented directly, and an IPv4 address is represented
    /// using the IPv4-mapped address syntax, check [`Ipv4Addr::to_ipv6_mapped`].
    ///
    /// [`Ipv4Addr::UNSPECIFIED`]: std::net::Ipv4Addr::UNSPECIFIED
    /// [`Ipv6Addr::UNSPECIFIED`]: std::net::Ipv6Addr::UNSPECIFIED
    pub suggested_external_addr: Ipv6Addr,
}

impl Map {
    pub const SIZE: usize = 36;
}

impl util::Serialize for &Map {
    fn serialize<const S: usize>(self, buffer: Serializer<S>) -> util::Result<Serializer<S>> {
        buffer
            .serialize(self.mapping_nonce)?
            .serialize(self.protocol as u8)?
            .serialize([0; 3])?
            .serialize(self.internal_port)?
            .serialize(self.suggested_external_port)?
            .serialize(self.suggested_external_addr)
    }
}

impl util::Deserialize for Map {
    fn deserialize(data: &mut Deserializer) -> util::Result<Self> {
        Ok(Map {
            mapping_nonce: data.deserialize()?,
            protocol: data.deserialize()?,
            internal_port: data.skip(3)?.deserialize()?,
            suggested_external_port: data.deserialize()?,
            suggested_external_addr: data.deserialize()?,
        })
    }
}

/// PCP [`Peer`](OpCode::Peer) request payload
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
#[derive(PartialEq, Debug, Clone, Copy)]
pub struct Peer {
    /// Random value chosen by the PCP client
    pub mapping_nonce: Nonce,
    /// Upper-layer protocol associated with this mapping
    ///
    /// The value [`ProtocolNumber::Hopopt`] (0) has a special
    /// meaning for _all protocols_.
    pub protocol: ProtocolNumber,
    /// Internal port for the mapping
    ///
    /// The value `0` indicates _all ports_, and is legal when the lifetime
    /// is zero (a delete request), if the protocol does not use 16-bit
    /// port numbers, or the client is requesting _all ports_.
    ///
    /// If the `protocol` is [`ProtocolNumber::Hopopt`] (zero, meaning _all protocols_),
    /// then internal port **must** be zero on transmission and **must** be
    /// ignored on reception.
    pub internal_port: u16,
    /// Suggested external port for the mapping
    ///
    /// This is useful for refreshing a mapping, especially after the PCP
    /// server loses state.
    ///
    /// If the PCP client does not know the external
    /// port, or does not have a preference, it **must** use 0.
    pub suggested_external_port: u16,
    /// Suggested external IPv4 or IPv6 address
    ///
    /// This is useful for refreshing a mapping, especially
    /// after the PCP server loses state.
    ///
    /// If the PCP client does not know
    /// the external address, or does not have a preference, it **must** use
    /// the address-family-specific all-zeros address, which is
    /// [`Ipv4Addr::UNSPECIFIED`] for IPv4 and [`Ipv6Addr::UNSPECIFIED`] for IPv6.
    ///
    /// An IPv6 address is represented directly, and an IPv4 address is represented
    /// using the IPv4-mapped address syntax, check [`Ipv4Addr::to_ipv6_mapped`].
    ///
    /// [`Ipv4Addr::UNSPECIFIED`]: std::net::Ipv4Addr::UNSPECIFIED
    /// [`Ipv6Addr::UNSPECIFIED`]: std::net::Ipv6Addr::UNSPECIFIED
    pub suggested_external_addr: Ipv6Addr,
    /// Remote peer's port for the mapping
    pub remote_peer_port: NonZeroU16,
    /// Remote peer's IP address.
    ///
    /// This is from the perspective of the PCP client,
    /// so that the PCP client does not need to concern itself with
    /// NAT64 or NAT46 (which both cause the client's idea of the
    /// remote peer's IP address to differ from the remote peer's actual
    /// IP address).
    ///
    /// This field allows the PCP client and PCP server to disambiguate multiple
    /// connections from the same port on the internal host to different servers.
    ///
    /// An IPv6 address is represented directly, and an IPv4 address is represented
    /// using the IPv4-mapped address syntax, check [`Ipv4Addr::to_ipv6_mapped`].
    pub remote_peer_addr: Ipv6Addr,
}

impl Peer {
    pub const SIZE: usize = 56;
}

impl util::Serialize for &Peer {
    fn serialize<const S: usize>(self, buffer: Serializer<S>) -> util::Result<Serializer<S>> {
        buffer
            .serialize(self.mapping_nonce)?
            .serialize(self.protocol as u8)?
            .serialize([0; 3])?
            .serialize(self.internal_port)?
            .serialize(self.suggested_external_port)?
            .serialize(self.suggested_external_addr)?
            .serialize(u16::from(self.remote_peer_port))?
            .serialize([0; 2])?
            .serialize(self.remote_peer_addr)
    }
}

impl util::Deserialize for Peer {
    fn deserialize(data: &mut Deserializer) -> util::Result<Self> {
        Ok(Peer {
            mapping_nonce: data.deserialize()?,
            protocol: data.deserialize()?,
            internal_port: data.skip(3)?.deserialize()?,
            suggested_external_port: data.deserialize()?,
            suggested_external_addr: data.deserialize()?,
            remote_peer_port: NonZeroU16::new(data.deserialize()?)
                .ok_or(Error::ZeroRemotePeerPort)?,
            remote_peer_addr: data.skip(2)?.deserialize()?,
        })
    }
}

/// PCP [`Announce`](OpCode::Announce) request payload
#[derive(PartialEq, Debug, Clone, Copy)]
pub struct Announce;

impl util::Serialize for Announce {
    fn serialize<const S: usize>(self, buffer: Serializer<S>) -> util::Result<Serializer<S>> {
        Ok(buffer)
    }
}

impl util::Deserialize for Announce {
    fn deserialize(_data: &mut Deserializer) -> util::Result<Self> {
        Ok(Self)
    }
}

/// Returns the maximum size the options can take up in the packet,
/// considering the given payload size and the constant header size
const fn max_options_size(payload_size: usize) -> usize {
    super::MAX_PACKET_SIZE - Request::HEADER_SIZE - payload_size
}

/// [`Payload`] for a PCP map request
pub type MapPayload = Payload<Map, { max_options_size(Map::SIZE) }>;

/// [`Payload`] for a PCP peer request
pub type PeerPayload = Payload<Peer, { max_options_size(Peer::SIZE) }>;

/// [`Payload`] for a PCP announce request
pub type AnnouncePayload = Payload<Announce, { max_options_size(0) }>;

/// PCP request payload
///
/// This enum has a discriminant for each [`OpCode`]
/// which contains the payload and the options requested.
///
/// The tag of this enum could be compared to the `Opcode`
/// field of the request header (check [`RequestPacket`])
#[derive(PartialEq, Debug)]
pub enum RequestPayload {
    /// Payload data for a **map** request
    Map(MapPayload),
    /// Payload data for a **peer** request
    Peer(PeerPayload),
    /// Payload data for a **announce** request
    Announce(AnnouncePayload),
}

impl RequestPayload {
    /// Returns the [`OpCode`] of this request
    pub const fn opcode(&self) -> OpCode {
        match self {
            Self::Map(_) => OpCode::Map,
            Self::Peer(_) => OpCode::Peer,
            Self::Announce(_) => OpCode::Announce,
        }
    }
}

/// PCP request packet
///
/// # Format
///
/// ```plain
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
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
pub struct Request {
    /// The version of the PCP protocol
    ///
    /// This field is used for version negotiation,
    /// PCP clients and servers compliant with the RFC 6887
    /// use the value `2`
    pub version: u8,
    /// Requested lifetime of this mapping, in seconds
    ///
    /// The value 0 indicates _delete_
    pub lifetime: u32,
    /// The source IP address used by the PCP client when
    /// sending this PCP request
    ///
    /// An IPv4 address is represented using an IPv4-mapped IPv6 address,
    /// check [`Ipv4Addr::to_ipv6_mapped()`](std::net::Ipv4Addr::to_ipv6_mapped()).
    ///
    /// The PCP Client IP Address in the PCP message header is used to
    /// detect an unexpected NAT on the path between the PCP client and
    /// the PCP-controlled NAT or firewall device.
    pub address: Ipv6Addr,
    /// Wrapper around the payload and the options
    pub payload: RequestPayload,
}

impl Request {
    /// Size of the PCP request header in bytes
    pub const HEADER_SIZE: usize = 24;
}

impl util::Serialize for &Request {
    fn serialize<const S: usize>(self, mut buffer: Serializer<S>) -> util::Result<Serializer<S>> {
        buffer = buffer
            .serialize(self.version)?
            .serialize(self.payload.opcode() as u8 & 0b01111111)?
            .serialize([0; 2])?
            .serialize(self.lifetime)?
            .serialize(self.address)?;
        match &self.payload {
            RequestPayload::Map(p) => buffer.serialize(p),
            RequestPayload::Peer(p) => buffer.serialize(p),
            RequestPayload::Announce(p) => buffer.serialize(p),
        }
    }
}

impl util::Deserialize for Request {
    fn deserialize(data: &mut Deserializer) -> util::Result<Self> {
        let version = data.deserialize()?;
        let ROpCode::Request(opcode) = data.deserialize()? else {
            return Err(Error::NotARequest);
        };
        let lifetime = data.skip(2)?.deserialize()?;
        let address = data.deserialize()?;
        let payload = match opcode {
            OpCode::Map => RequestPayload::Map(data.deserialize()?),
            OpCode::Peer => RequestPayload::Peer(data.deserialize()?),
            OpCode::Announce => RequestPayload::Announce(data.deserialize()?),
        };
        Ok(Request {
            version,
            lifetime,
            address,
            payload,
        })
    }
}
